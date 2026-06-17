using Foreman.Core.Ipc.Guardian;

namespace Foreman.Core.Guardian;

/// <summary>
/// The app's view of the opt-in LocalSystem guardian (circle-back Phase A). When a guardian is installed, the
/// operations whose authority moved behind the SYSTEM boundary (signing the event-log head, computing/verifying
/// the settings seal) are performed by the guardian over the control pipe; the same-user agent can no longer forge
/// them because it can neither use the SYSTEM key nor read the SYSTEM-held secret.
///
/// CASUAL-USER CONTRACT: when no guardian is installed this resolves to <see cref="NullGuardianClient"/>
/// (<see cref="IsAvailable"/> == false), and every call returns the "absent" sentinel so callers fall back to the
/// existing local logic (per-user TPM signer, in-app HMAC seal). One code path, byte-identical default behavior.
///
/// AVAILABILITY/ROBUSTNESS: a present-but-slow/crashed guardian must NEVER block the app. Implementations use
/// tight timeouts and return the absent sentinel on timeout — the event-log head is best-effort (a null seal just
/// means "unsigned this append", which the store already tolerates).
/// </summary>
public interface IGuardianClient
{
    /// <summary>True only when a guardian is installed and reachable. False ⇒ callers use the local fallback path.</summary>
    bool IsAvailable { get; }

    /// <summary>Liveness + capability probe; null when the guardian is absent/unreachable.</summary>
    Task<HelloResult?> HelloAsync(CancellationToken ct = default);

    /// <summary>Signs (headHash|count) with the SYSTEM key; null ⇒ unsigned this append (caller tolerates).</summary>
    Task<string?> SealHeadAsync(string headHash, long recordCount, CancellationToken ct = default);

    /// <summary>The SYSTEM head-seal key's public half (base64 SPKI) for the app to pin; null when unavailable.</summary>
    Task<string?> GetPinnedHeadKeyAsync(CancellationToken ct = default);

    /// <summary>Verifies a settings seal with the SYSTEM-held secret; null when the guardian is absent/unreachable.</summary>
    Task<VerifySettingsResult?> VerifySettingsAsync(string securityProjection, string? storedSeal, CancellationToken ct = default);

    /// <summary>(Re-)seals settings; for a weakening action the guardian enforces presence server-side and may deny.</summary>
    Task<SealSettingsResult> SealSettingsAsync(SealSettingsArgs args, CancellationToken ct = default);
}

/// <summary>
/// The "no guardian installed" implementation — the default. Every method returns the absent sentinel so the app
/// runs its existing local logic unchanged. This is what makes the casual (non-opt-in) user's behavior identical
/// to today: <see cref="IsAvailable"/> is false, so guardian-aware seams never take the remote path.
/// </summary>
public sealed class NullGuardianClient : IGuardianClient
{
    public static readonly NullGuardianClient Instance = new();

    public bool IsAvailable => false;

    public Task<HelloResult?> HelloAsync(CancellationToken ct = default) => Task.FromResult<HelloResult?>(null);
    public Task<string?> SealHeadAsync(string headHash, long recordCount, CancellationToken ct = default) => Task.FromResult<string?>(null);
    public Task<string?> GetPinnedHeadKeyAsync(CancellationToken ct = default) => Task.FromResult<string?>(null);
    public Task<VerifySettingsResult?> VerifySettingsAsync(string securityProjection, string? storedSeal, CancellationToken ct = default)
        => Task.FromResult<VerifySettingsResult?>(null);
    public Task<SealSettingsResult> SealSettingsAsync(SealSettingsArgs args, CancellationToken ct = default)
        => Task.FromResult(new SealSettingsResult { Denied = false, Reason = "guardian-absent" });
}
