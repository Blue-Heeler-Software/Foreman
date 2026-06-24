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
    RelaxHarnessCapabilityRestriction,
    ResumeComputerUse,      // un-halt Foreman-mediated computer/browser use after a panic STOP
    BindCuWindow,           // bind the desktop CU target window (operator gesture; spec INV-10/INV-17)
    EnrollLocalAgentHost,   // authorize a local AI agent to drive desktop CU (spec INV-16)
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

    /// <summary>
    /// The enrolled authenticator's credential id (base64url), pinned at enrollment. The presence prompt
    /// asserts THIS credential — Windows Hello (platform: PIN/face/fingerprint) or a roaming FIDO2/U2F key
    /// (YubiKey), whichever the user enrolled; Windows' WebAuthn picker covers all of them. Empty until
    /// enrolled — the gate then has nothing to prompt and fails closed. (Recovery from a lost authenticator is
    /// editing this file, the same-user boundary the threat model already concedes.)
    /// </summary>
    public string? CredentialId { get; set; }

    /// <summary>Friendly label of the enrolled authenticator for the UI ("Windows Hello", "Security key"). Cosmetic.</summary>
    public string? AuthenticatorLabel { get; set; }
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
        WeakeningAction.RelaxHarnessCapabilityRestriction,
        WeakeningAction.ResumeComputerUse,
        WeakeningAction.BindCuWindow,
        WeakeningAction.EnrollLocalAgentHost,
    ];

    public static bool RequiresPresence(WeakeningAction action, PresenceLockSettings settings)
    {
        if (!settings.Enabled) return false;                                  // lock off → nothing gated
        if (action == WeakeningAction.ExitForeman) return settings.Scope == LockScope.Strict;
        return StandardGated.Contains(action);
    }
}
