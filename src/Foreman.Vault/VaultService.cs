using System.Security.Cryptography;
using Foreman.Core.Vault;

namespace Foreman.Vault;

/// <summary>
/// The vault lifecycle the App drives: enroll (first run) → unlock (per session) → lock (panic / exit). Holds ONE
/// long-lived <see cref="AeadVaultStore"/> + <see cref="VaultResolver"/>, so the injection hooks always have a resolver
/// that simply fails closed while the store is locked. The composite key is the master password plus a random key
/// component that the <see cref="IVaultKeyProtector"/> binds to this user+machine at rest (DPAPI, App-side). The
/// presence/Hello gate on each release is applied by the caller (<see cref="WeakeningAction.ResolveVaultCredential"/>).
/// </summary>
public sealed class VaultService
{
    private readonly string _vaultPath;
    private readonly string _componentPath;
    private readonly IVaultKeyProtector _protector;
    private readonly AeadVaultStore _store;
    private readonly VaultResolver _resolver;
    private readonly object _gate = new();
    // Rate guard for agent self-signup (a WRITE). SECONDARY brake only: the primary control is that each signup is now
    // an explicitly operator-approved CU action (the fast-path auditor HOLDs it) plus a distinct presence tap. This caps
    // SUCCESSFUL creations in a sliding window, both overall and per harness (so one runaway harness can't exhaust the
    // budget for others). In-memory by design - a relaunch resets it, but the operator-approval gate above still fires
    // on every attempt, so a reset can't enable silent spam.
    private readonly List<(DateTimeOffset At, string Who)> _recentSignups = new();
    private const int MaxSignupsPerWindow = 5;            // overall
    private const int MaxSignupsPerHarnessPerWindow = 3;  // per submitting harness
    private static readonly TimeSpan SignupWindow = TimeSpan.FromMinutes(10);

    public VaultService(string vaultPath, string componentPath, IVaultKeyProtector protector)
    {
        _vaultPath = vaultPath;
        _componentPath = componentPath;
        _protector = protector;
        _store = new AeadVaultStore(vaultPath);
        _resolver = new VaultResolver(_store);   // stable; reflects _store.IsUnlocked, so it fails closed while locked
    }

    /// <summary>A vault exists on disk (both the sealed component and the encrypted vault file).</summary>
    public bool IsEnrolled => File.Exists(_vaultPath) && File.Exists(_componentPath);
    public bool IsUnlocked => _store.IsUnlocked;

    /// <summary>Always non-null; resolves only while unlocked (otherwise returns a "vault is locked" failure).</summary>
    public IVaultResolver Resolver => _resolver;

    /// <summary>First-run: generate a random key component, protect it for this user+machine, and create the vault.</summary>
    public void Enroll(string masterPassword)
    {
        lock (_gate)
        {
            if (IsEnrolled) throw new InvalidOperationException("vault is already enrolled");
            var component = RandomNumberGenerator.GetBytes(32);
            try
            {
                var dir = Path.GetDirectoryName(_componentPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllBytes(_componentPath, _protector.Protect(component));
                _store.Provision(masterPassword, component);
            }
            finally { Array.Clear(component); }
        }
    }

    /// <summary>Open the vault: the protector releases the component (this user+machine), then the master password
    /// completes the composite key. Throws on a wrong password / wrong machine / tampered file.</summary>
    public void Unlock(string masterPassword)
    {
        lock (_gate)
        {
            if (!IsEnrolled) throw new InvalidOperationException("vault is not enrolled");
            var component = _protector.Unprotect(File.ReadAllBytes(_componentPath));
            try { _store.Open(masterPassword, component); }
            finally { Array.Clear(component); }
        }
    }

    /// <summary>Forget the in-memory key + decrypted document (panic / exit). Safe to call when already locked.</summary>
    public void Lock() => _store.WipeInMemoryKeys();

    /// <summary>Operator mutation: add or replace an item, then persist. Requires an unlocked vault.</summary>
    public void Upsert(VaultEntry entry)
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) throw new InvalidOperationException("vault is locked");
            _store.Upsert(entry);
        }
    }

    /// <summary>Operator mutation: edit the item named <paramref name="originalName"/> (a blank secret field keeps the
    /// existing value; rename supported). Returns false if no item matched. Requires an unlocked vault.</summary>
    public bool UpdateItem(string originalName, VaultEntry updated)
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) throw new InvalidOperationException("vault is locked");
            return _store.UpdateItem(originalName, updated);
        }
    }

    /// <summary>Operator mutation: delete the item named <paramref name="name"/>. Returns false if none matched.
    /// Requires an unlocked vault.</summary>
    public bool Delete(string name)
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) throw new InvalidOperationException("vault is locked");
            return _store.Delete(name);
        }
    }

    /// <summary>
    /// Agent self-signup: GENERATE a strong password, store it as a NEW credential bound to <paramref name="origin"/>,
    /// and return it for the agent to fill into the signup form (the agent never picks or sees a stored secret). Gated:
    /// vault unlocked; the requested origin must match the LIVE target (no cross-site); a credential must NOT already
    /// exist under that origin OR name (never clobber an existing login - non-destructive add); and a per-harness +
    /// overall rate guard. The caller additionally requires the operator-approved CU action + a distinct presence tap.
    /// The new item is stored OPERATOR-ONLY (empty harness ACL): an agent can never self-authorize a credential it
    /// could later auto-resolve for an origin it chose (phishing-grant); the operator confirms + grants reuse via the
    /// management UI. A Note marks it machine-created. Returns (ok, generated-password, reason); reason is "" on success.
    /// </summary>
    public (bool Ok, string? Value, string Reason) SelfSignup(string origin, string liveOrigin, string? byHarness)
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) return (false, null, "vault is locked");

            var host = VaultDomainBinding.NormalizeHost(origin);
            if (string.IsNullOrEmpty(host)) return (false, null, "invalid signup origin");
            if (!string.Equals(host, VaultDomainBinding.NormalizeHost(liveOrigin), StringComparison.OrdinalIgnoreCase))
                return (false, null, $"signup origin does not match the live target '{liveOrigin}'");

            var who = string.IsNullOrEmpty(byHarness) ? "operator" : byHarness;
            var now = DateTimeOffset.UtcNow;
            _recentSignups.RemoveAll(t => now - t.At > SignupWindow);
            if (_recentSignups.Count >= MaxSignupsPerWindow
                || _recentSignups.Count(t => string.Equals(t.Who, who, StringComparison.OrdinalIgnoreCase)) >= MaxSignupsPerHarnessPerWindow)
                return (false, null, "too many sign-ups in a short window; try again shortly");

            // OPERATOR-ONLY (no harness on the ACL): the creating agent cannot later auto-resolve this credential.
            var entry = new VaultEntry
            {
                Name = host,
                Origins = { host },
                Password = VaultPasswordGenerator.Generate(20),
                Notes = $"created via agent self-signup ({who})",
            };
            // Non-destructive add: refuses on a Name OR origin collision, so the WRITE can never clobber an operator login.
            if (!_store.TryAddNew(entry))
                return (false, null, "a credential already exists for this site; signup would overwrite it");

            _recentSignups.Add((now, who));
            return (true, entry.Password, "");
        }
    }

    /// <summary>Item metadata for the management UI (no secret values). Requires an unlocked vault.</summary>
    public IReadOnlyList<VaultItemInfo> ListItems()
    {
        lock (_gate)
        {
            if (!_store.IsUnlocked) throw new InvalidOperationException("vault is locked");
            return _store.ListItems();
        }
    }
}
