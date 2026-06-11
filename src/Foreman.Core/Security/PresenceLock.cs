namespace Foreman.Core.Security;

/// <summary>
/// The watchdog-weakening actions a rogue or prompt-injected agent would use to blind Foreman or erase its
/// tracks. The presence lock (P3) makes the gated ones require a hardware user-presence tap (Windows
/// Hello/PIN, passkey, YubiKey, U2F) — the one thing a same-user process can't satisfy programmatically.
/// </summary>
public enum WeakeningAction
{
    LowerTrust,
    MuteProtectedAlert,
    DisableMonitoring,
    DisableReadAuditing,    // decoys / SACL read-auditing
    DisableLogPersist,
    ClearOrRotateLog,
    EditHarnessSysprompt,
    ExitForeman,
}

/// <summary>How much the presence lock gates. Strict additionally gates quitting Foreman.</summary>
public enum LockScope { Standard, Strict }

/// <summary>
/// Presence-lock configuration. Off until the user enrolls a hardware authenticator (P3 enrollment, which
/// pins the credential). C3 (user, 2026-06-12): default Standard; Strict is opt-in and the UI must warn that
/// gating Exit is annoying. <see cref="ApprovalTtlSeconds"/> &gt; 0 caches an approval so rapid actions don't
/// each prompt (mitigates Strict's friction); 0 = tap every time.
/// </summary>
public sealed class PresenceLockSettings
{
    public bool Enabled { get; set; } = false;
    public LockScope Scope { get; set; } = LockScope.Standard;
    public int ApprovalTtlSeconds { get; set; } = 0;

    // P3 enrollment adds the pinned authenticator/credential id + the TPM-sealed log-signing key handle.
}

/// <summary>
/// Pure decision: does an action require a presence tap, given the lock config? Unit-tested. The actual
/// WebAuthn prompt + the action-interception wiring are the runtime/live-verified parts.
/// </summary>
public static class PresenceLockPolicy
{
    // The Standard set — always gated when the lock is on (C3). Exit is handled separately (Strict only).
    private static readonly HashSet<WeakeningAction> StandardGated =
    [
        WeakeningAction.LowerTrust,
        WeakeningAction.MuteProtectedAlert,
        WeakeningAction.DisableMonitoring,
        WeakeningAction.DisableReadAuditing,
        WeakeningAction.DisableLogPersist,
        WeakeningAction.ClearOrRotateLog,
        WeakeningAction.EditHarnessSysprompt,
    ];

    public static bool RequiresPresence(WeakeningAction action, PresenceLockSettings settings)
    {
        if (!settings.Enabled) return false;                                  // lock off → nothing gated
        if (action == WeakeningAction.ExitForeman) return settings.Scope == LockScope.Strict;
        return StandardGated.Contains(action);
    }
}
