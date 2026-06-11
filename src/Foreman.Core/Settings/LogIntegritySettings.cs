namespace Foreman.Core.Settings;

/// <summary>
/// Tamper-evidence for the on-disk event log. P1 ships the append-only hash chain (no hardware needed); the
/// TPM/Hello-sealed head + the seal-key fields are added in P3 (so a same-user agent can't forge a rewritten
/// chain). Encryption-at-rest is deliberately omitted — the log is readable; the goal is a tamper-proof key,
/// not confidentiality.
/// </summary>
public sealed class LogIntegritySettings
{
    /// <summary>Compute + verify the append-only hash chain. On by default — cheap, needs no hardware, and is
    /// backward-compatible (a pre-chain log is treated as an unverifiable "legacy prefix", not as tampered).</summary>
    public bool HashChainEnabled { get; set; } = true;

    // P3 adds: SealHeadEnabled, HeadKeyName, PinnedHeadPublicKey — the TPM head-seal seam. The chain head is
    // already sealed through ILogHeadSigner at the EventLogStore ctor; P1 wires the no-op NullHeadSigner.
}
