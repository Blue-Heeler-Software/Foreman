namespace Foreman.Vault;

/// <summary>The decrypted vault contents (held in memory only while unlocked). Serialized to JSON, then sealed by
/// <see cref="VaultCrypto"/> at rest. Secret fields are plaintext strings in memory while unlocked — a managed-memory
/// limitation noted in docs/vault-design.md (future hardening: ProtectedString/spans end to end).</summary>
public sealed class VaultDocument
{
    public List<VaultEntry> Items { get; set; } = [];

    /// <summary>The locked-vault DEPOSIT keypair (P-256), generated at enroll (or lazily on the first unlock of an
    /// older vault). The PRIVATE key lives only here, inside the sealed document; a copy of the PUBLIC key is also
    /// mirrored to a clear sidecar so a locked Foreman can encrypt new sign-ups to it. On unlock the clear sidecar is
    /// compared against this sealed public key to detect a swapped sidecar. See DepositCrypto / DepositQueue.</summary>
    public byte[]? DepositPublicKeySpki { get; set; }
    public byte[]? DepositPrivateKeyPkcs8 { get; set; }
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
