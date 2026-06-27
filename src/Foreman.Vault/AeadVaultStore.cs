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
            return e is null
                ? null
                : new VaultItemInfo(e.Name, e.Origins.ToArray(), e.Harnesses.ToArray(),
                    HasTotp: !string.IsNullOrWhiteSpace(e.TotpSeedBase32));
        }
    }

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
