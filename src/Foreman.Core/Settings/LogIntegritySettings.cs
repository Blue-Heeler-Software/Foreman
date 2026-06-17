namespace Foreman.Core.Settings;

/// <summary>
/// Tamper-evidence for the on-disk event log. The append-only hash chain needs no hardware; the signed head adds
/// an asymmetric seal over a TPM/Platform-Crypto-Provider key (groundwork — at the same-user boundary it removes
/// the at-rest seal secret and makes verification asymmetric; it becomes genuinely unforgeable once the elevated
/// guardian owns the key). Encryption-at-rest is deliberately omitted — the log is readable; the goal is a
/// tamper-evident, ideally tamper-proof seal, not confidentiality.
/// </summary>
public sealed class LogIntegritySettings
{
    /// <summary>Compute + verify the append-only hash chain. On by default — cheap, needs no hardware, and is
    /// backward-compatible (a pre-chain log is treated as an unverifiable "legacy prefix", not as tampered).</summary>
    public bool HashChainEnabled { get; set; } = true;

    /// <summary>Sign the chain head with a TPM/PCP key (retiring the no-op signer). On by default but degrades
    /// silently to unsigned on a box without a usable Platform Crypto Provider — never a hard requirement.</summary>
    public bool SealHeadEnabled { get; set; } = true;

    /// <summary>CNG key name for the head-seal key in the Platform Crypto Provider. Stable across runs.</summary>
    public string HeadKeyName { get; set; } = "Foreman.LogHeadSeal.v1";

    /// <summary>
    /// Trust-on-first-use pin of the head-seal key's PUBLIC half (base64 SubjectPublicKeyInfo). Empty until the
    /// first seal is written, then set by the host. Verification runs against THIS, so a later key swap (TPM clear
    /// or an attacker substituting their own key) fails verification instead of silently passing.
    /// </summary>
    public string? PinnedHeadPublicKeyB64 { get; set; }
}
