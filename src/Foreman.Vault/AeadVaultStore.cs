using System.Text.Json;
using Foreman.Core.Vault;

namespace Foreman.Vault;

/// <summary>
/// Native authenticated credential store: AES-256-GCM + Argon2id, composite key = master password + a TPM-sealed key
/// component (the seal of the component is wired App-side; this store just takes the bytes). Cross-platform. Implements
/// <see cref="IVaultStore"/> so Core's <see cref="VaultResolver"/> works against it unchanged. The decrypted document
/// lives in memory only while unlocked and is dropped on <see cref="WipeInMemoryKeys"/>.
/// </summary>
public sealed class AeadVaultStore(string path) : IVaultStore
{
    private readonly string _path = path;
    private readonly object _gate = new();
    private string? _password;
    private byte[]? _keyComponent;
    private VaultDocument? _doc;

    public bool IsUnlocked { get { lock (_gate) return _doc is not null; } }

    /// <summary>Provision THIS instance as a brand-new empty vault (first-run enrollment) and persist it. Overwrites
    /// any existing file at the path. Lets a long-lived store instance be enrolled in place (stable resolver).</summary>
    public void Provision(string masterPassword, byte[] keyComponent)
    {
        lock (_gate)
        {
            _password = masterPassword;
            _keyComponent = (byte[])keyComponent.Clone();
            _doc = new VaultDocument();
            SaveLocked();
        }
    }

    /// <summary>Convenience: a new store provisioned as an empty vault at the path. Used by tests/enrollment.</summary>
    public static AeadVaultStore Create(string path, string masterPassword, byte[] keyComponent)
    {
        var store = new AeadVaultStore(path);
        store.Provision(masterPassword, keyComponent);
        return store;
    }

    /// <summary>Open + decrypt. Throws on wrong master password / wrong key component / tampered file (AES-GCM tag mismatch).</summary>
    public void Open(string masterPassword, byte[] keyComponent)
    {
        var json = VaultCrypto.Decrypt(File.ReadAllText(_path), masterPassword, keyComponent);
        var doc = JsonSerializer.Deserialize<VaultDocument>(json) ?? new VaultDocument();
        lock (_gate)
        {
            _password = masterPassword;
            _keyComponent = (byte[])keyComponent.Clone();
            _doc = doc;
        }
    }

    public VaultItemInfo? FindByOrigin(string origin)
    {
        lock (_gate)
        {
            var e = FindEntryLocked(origin);
            return e is null ? null : ToInfo(e);
        }
    }

    /// <summary>Metadata for every item (names/origins/which fields/ACL — never secret VALUES), for the management UI.
    /// Returns empty while locked.</summary>
    public IReadOnlyList<VaultItemInfo> ListItems()
    {
        lock (_gate) return _doc is null ? [] : _doc.Items.Select(ToInfo).ToArray();
    }

    private static VaultItemInfo ToInfo(VaultEntry e) =>
        new(e.Name, e.Origins.ToArray(), e.Harnesses.ToArray(), HasTotp: !string.IsNullOrWhiteSpace(e.TotpSeedBase32))
        {
            HasUsername = !string.IsNullOrWhiteSpace(e.Username),
            HasPassword = !string.IsNullOrWhiteSpace(e.Password),
        };

    public string? GetSecret(string origin, VaultField field)
    {
        lock (_gate)
        {
            var e = FindEntryLocked(origin);
            if (e is null) return null;
            return field switch
            {
                VaultField.Username => e.Username,
                VaultField.Password => e.Password,
                VaultField.Note     => e.Notes,
                VaultField.Totp     => string.IsNullOrWhiteSpace(e.TotpSeedBase32)
                                         ? null
                                         : VaultTotp.FromBase32(e.TotpSeedBase32!, DateTime.UtcNow),
                _ => null,
            };
        }
    }

    /// <summary>Add or replace the item with the same name (operator mutation) and persist. Requires an unlocked vault.</summary>
    public void Upsert(VaultEntry entry)
    {
        lock (_gate)
        {
            EnsureUnlockedLocked();
            _doc!.Items.RemoveAll(i => string.Equals(i.Name, entry.Name, StringComparison.OrdinalIgnoreCase));
            _doc.Items.Add(entry);
            SaveLocked();
        }
    }

    /// <summary>
    /// Edit the item currently named <paramref name="originalName"/>, replacing it with <paramref name="updated"/>.
    /// A null/blank secret field (Username/Password/TotpSeedBase32/Notes) in <paramref name="updated"/> KEEPS the
    /// existing value — the management UI never sees secret values, so "leave blank to keep" is the only safe edit.
    /// Supports rename (originalName may differ from updated.Name). Returns false if no item matched. Operator
    /// mutation; requires an unlocked vault.
    /// </summary>
    public bool UpdateItem(string originalName, VaultEntry updated)
    {
        lock (_gate)
        {
            EnsureUnlockedLocked();
            var existing = _doc!.Items.FirstOrDefault(i => string.Equals(i.Name, originalName, StringComparison.OrdinalIgnoreCase));
            if (existing is null) return false;
            // Preserve unchanged secrets (blank field == keep), since the UI can't round-trip the real value.
            updated.Username       = string.IsNullOrEmpty(updated.Username)       ? existing.Username       : updated.Username;
            updated.Password       = string.IsNullOrEmpty(updated.Password)       ? existing.Password       : updated.Password;
            updated.TotpSeedBase32 = string.IsNullOrWhiteSpace(updated.TotpSeedBase32) ? existing.TotpSeedBase32 : updated.TotpSeedBase32;
            updated.Notes          = string.IsNullOrEmpty(updated.Notes)          ? existing.Notes          : updated.Notes;
            // Remove the old record (and any item already holding the NEW name, so a rename can't duplicate).
            _doc.Items.RemoveAll(i => string.Equals(i.Name, originalName, StringComparison.OrdinalIgnoreCase)
                                   || string.Equals(i.Name, updated.Name, StringComparison.OrdinalIgnoreCase));
            _doc.Items.Add(updated);
            SaveLocked();
            return true;
        }
    }

    /// <summary>Remove the item named <paramref name="name"/> and persist. Returns false if none matched. Operator
    /// mutation; requires an unlocked vault.</summary>
    public bool Delete(string name)
    {
        lock (_gate)
        {
            EnsureUnlockedLocked();
            var removed = _doc!.Items.RemoveAll(i => string.Equals(i.Name, name, StringComparison.OrdinalIgnoreCase));
            if (removed > 0) SaveLocked();
            return removed > 0;
        }
    }

    public void WipeInMemoryKeys()
    {
        lock (_gate)
        {
            if (_keyComponent is not null) Array.Clear(_keyComponent);
            _keyComponent = null;
            _password = null;
            _doc = null;   // drop the plaintext document (managed strings can't be zeroed; see docs/vault-design.md)
        }
    }

    private VaultEntry? FindEntryLocked(string origin) =>
        _doc?.Items.FirstOrDefault(i => i.Origins.Any(o => VaultDomainBinding.HostMatches(o, origin)));

    private void EnsureUnlockedLocked()
    {
        if (_doc is null || _password is null || _keyComponent is null)
            throw new InvalidOperationException("vault is locked");
    }

    private void SaveLocked()
    {
        EnsureUnlockedLocked();
        var envelope = VaultCrypto.Encrypt(JsonSerializer.Serialize(_doc), _password!, _keyComponent!);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, envelope);
        if (File.Exists(_path)) File.Replace(tmp, _path, null); else File.Move(tmp, _path);   // atomic-ish swap
    }
}
