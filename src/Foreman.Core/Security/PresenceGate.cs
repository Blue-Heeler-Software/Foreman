namespace Foreman.Core.Security;

/// <summary>A gate decision, for the operator log — a DENIED weakening attempt is itself a signal worth recording.</summary>
public sealed record PresenceDecision(bool Granted, WeakeningAction Action, string Detail, string? AuthenticatorLabel);

/// <summary>
/// Wraps <see cref="PresenceLockPolicy"/> + an <see cref="IPresenceVerifier"/> into the runtime gate that
/// actually guards weakening actions. <b>FAIL-CLOSED</b>: when presence is required, the action proceeds ONLY
/// on a verified tap — a user cancel, an auth failure, a missing/unenrolled authenticator, or a verifier error
/// all BLOCK. Every gated decision (granted or denied) is reported via <c>onDecision</c> so a denied attempt is
/// recorded, never silent. A short approval-TTL caches a recent tap so rapid follow-up actions don't each
/// prompt (mitigates Strict's friction). The policy + fail-closed semantics are unit-tested here with a fake
/// verifier; the live WebAuthn prompt is the app-layer part.
/// </summary>
public sealed class PresenceGate
{
    /// <summary>
    /// Hard ceiling on the approval cache (B9 polish): however high the operator sets ApprovalTtlSeconds, a cached
    /// tap expires within this window, so an old approval can't be replayed to keep weakening Foreman indefinitely
    /// — there's always a re-tap at least this often. 5 minutes balances Strict-mode friction against staleness.
    /// </summary>
    public const int MaxApprovalTtlSeconds = 300;

    private readonly Func<PresenceLockSettings> _settings;
    private readonly IPresenceVerifier _verifier;
    private readonly Action<PresenceDecision> _onDecision;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _lock = new();
    private DateTimeOffset _lastApproval = DateTimeOffset.MinValue;

    public PresenceGate(
        Func<PresenceLockSettings> settings,
        IPresenceVerifier verifier,
        Action<PresenceDecision> onDecision,
        Func<DateTimeOffset>? now = null)
    {
        _settings = settings;
        _verifier = verifier;
        _onDecision = onDecision;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// True to PROCEED with the action, false to BLOCK it. Non-gated actions (lock off, or action not in scope)
    /// proceed silently without a prompt. <paramref name="detail"/> describes the specific change (e.g. the
    /// harness + the old→new value) for the audit record.
    /// </summary>
    public async Task<bool> AuthorizeAsync(WeakeningAction action, string detail, CancellationToken ct = default)
    {
        var s = _settings();
        if (!PresenceLockPolicy.RequiresPresence(action, s)) return true;

        // A recent successful tap covers rapid follow-ups within the configured window — but never longer than
        // MaxApprovalTtlSeconds, so a stale approval can't be replayed indefinitely (B9 polish).
        if (s.ApprovalTtlSeconds > 0)
        {
            var ttl = Math.Min(s.ApprovalTtlSeconds, MaxApprovalTtlSeconds);
            lock (_lock)
            {
                if (_now() - _lastApproval < TimeSpan.FromSeconds(ttl))
                {
                    Report(true, action, detail + " (within approval window)", null);
                    return true;
                }
            }
        }

        if (string.IsNullOrEmpty(s.CredentialId))
        {
            // Lock on but nothing enrolled → cannot prompt. Fail CLOSED: a misconfiguration must not become a bypass.
            Report(false, action, detail + " — no authenticator enrolled", null);
            return false;
        }

        PresenceResult r;
        try
        {
            r = await _verifier.VerifyAsync(s.CredentialId, PromptReason(action), ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Report(false, action, detail + $" — verifier error ({ex.GetType().Name})", null);   // fail closed
            return false;
        }

        if (r.Verified)
            lock (_lock) { _lastApproval = _now(); }

        Report(r.Verified, action, r.Verified ? detail : detail + $" — {r.FailureReason}", r.AuthenticatorLabel);
        return r.Verified;
    }

    private void Report(bool granted, WeakeningAction action, string detail, string? label)
    {
        try { _onDecision(new PresenceDecision(granted, action, detail, label)); }
        catch { /* logging a decision must never break the gate */ }
    }

    private static string PromptReason(WeakeningAction action) => action switch
    {
        WeakeningAction.LowerTrust           => "Authorize lowering a harness's Trust",
        WeakeningAction.MuteProtectedAlert   => "Authorize muting a protected alert",
        WeakeningAction.DisableMonitoring    => "Authorize disabling monitoring of a harness",
        WeakeningAction.DisableReadAuditing  => "Authorize disabling credential read-auditing",
        WeakeningAction.DisableLogPersist    => "Authorize disabling the persistent log",
        WeakeningAction.ClearOrRotateLog     => "Authorize clearing the event log",
        WeakeningAction.EditHarnessSysprompt => "Authorize editing a harness's modalities",
        WeakeningAction.ExitForeman          => "Authorize quitting Foreman",
        _                                    => "Authorize a Foreman security change",
    };
}
