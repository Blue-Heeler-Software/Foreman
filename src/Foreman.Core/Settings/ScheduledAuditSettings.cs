namespace Foreman.Core.Settings;

/// <summary>
/// Proactive cross-harness auditing: periodically have a DIFFERENT connected model review a harness's recent
/// behavior, rather than only auditing reactively on escalation. The auditor is chosen from
/// <see cref="LlmTriageSettings"/> (which already enforces auditor != audited). Off by default; defaults are
/// deliberately conservative so it never turns into a token firehose.
/// </summary>
public sealed class ScheduledAuditSettings
{
    public bool Enabled { get; set; } = false;

    /// <summary>Audit a harness once this many of its events accrue since its last audit. 0 = don't trigger by count.</summary>
    public int EveryNEvents { get; set; } = 50;

    /// <summary>Also audit an active harness this many minutes after its last audit. 0 = don't trigger by time.</summary>
    public int IntervalMinutes { get; set; } = 0;

    /// <summary>Minimum gap between audits of the SAME harness, so an active one isn't audited back-to-back.</summary>
    public int CooldownMinutes { get; set; } = 30;
}
