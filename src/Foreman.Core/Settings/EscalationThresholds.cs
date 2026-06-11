namespace Foreman.Core.Settings;

/// <summary>
/// The escalation knobs a harness's Trust level resolves to. Trust 3 == the global baseline (today's
/// behavior); a harness with no Trust override uses <see cref="FromGlobal"/>, so nothing changes until a
/// slider is moved. <see cref="BehaviorTracker"/> reads these per-harness instead of the flat global fields.
/// </summary>
public sealed record EscalationThresholds(
    int AlertLevelMediumCount,
    int AlarmLevelHighCount,
    int AlarmLevelUniqueRules,
    int AlarmLevelCategories,
    int EmergencyLevelTotalAlerts,
    string[] EmergencyRuleIds)
{
    /// <summary>The current global thresholds — the Trust-3 baseline and the default for unset harnesses.</summary>
    public static EscalationThresholds FromGlobal(ForemanSettings s) => new(
        s.AlertLevelMediumCount,
        s.AlarmLevelHighCount,
        s.AlarmLevelUniqueRules,
        s.AlarmLevelCategories,
        s.EmergencyLevelTotalAlerts,
        s.EmergencyRuleIds);
}
