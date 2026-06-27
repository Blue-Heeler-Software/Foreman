namespace Foreman.Vault;

/// <summary>The decrypted vault contents (held in memory only while unlocked). Serialized to JSON, then sealed by
/// <see cref="VaultCrypto"/> at rest. Secret fields are plaintext strings in memory while unlocked — a managed-memory
/// limitation noted in docs/vault-design.md (future hardening: ProtectedString/spans end to end).</summary>
public sealed class VaultDocument
{
    public List<VaultEntry> Items { get; set; } = [];
}

/// <summary>One credential. <see cref="Origins"/> drives domain-binding; <see cref="Harnesses"/> is the resolve ACL
/// (empty = operator-only). <see cref="TotpSeedBase32"/> is an RFC-6238 seed (resolved to a live code on demand).</summary>
public sealed class VaultEntry
{
    public string Name { get; set; } = "";
    public List<string> Origins { get; set; } = [];
    public List<string> Harnesses { get; set; } = [];
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? TotpSeedBase32 { get; set; }
    public string? Notes { get; set; }
}
