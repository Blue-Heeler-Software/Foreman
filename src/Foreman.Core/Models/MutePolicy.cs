namespace Foreman.Core.Models;

/// <summary>
/// Decides what an operator may mute and whether an event is currently muted. The guardrail: muting
/// only ever quiets the tray notification (never stops detection/recording/escalation), AND a
/// "protected" alert — Critical severity, an emergency-tier rule, or a credential/network/privilege
/// category — can only be <b>time-boxed snoozed</b> (≤ <see cref="MaxProtectedSnooze"/>), never
/// permanently silenced. Everything here is pure and unit-tested.
/// </summary>
public static class MutePolicy
{
    public static readonly TimeSpan MaxProtectedSnooze = TimeSpan.FromMinutes(60);

    // Categories that carry real safety weight — never permanently silenceable.
    private static readonly HashSet<string> _protectedCategories =
        new(StringComparer.OrdinalIgnoreCase) { "cred", "net", "priv" };

    /// <summary>The (ruleId, category, source) used to match mutes and assess protection.</summary>
    public static (string? RuleId, string? Category, string Source) Describe(ForemanEvent evt) => evt switch
    {
        CommandAlertEvent c       => (c.RuleId, CategoryOf(c.RuleId), c.Source),
        HangDetectedEvent         => (null, "hang", evt.Source),
        OrphanDetectedEvent       => (null, "orphan", evt.Source),
        NonzeroExitEvent          => (null, "exit", evt.Source),
        PermissionViolationEvent  => (null, "permission", evt.Source),
        EscalationEvent           => (null, "escalation", evt.Source),
        MonitoringNoticeEvent     => (null, "monitoring", evt.Source),
        _                         => (null, null, evt.Source),
    };

    private static string CategoryOf(string ruleId) =>
        ruleId.Contains('-') ? ruleId[..ruleId.IndexOf('-')] : ruleId;

    /// <summary>True if this alert is too important to ever permanently silence.</summary>
    public static bool IsProtected(ForemanEvent evt, IEnumerable<string> emergencyRuleIds)
    {
        if (evt.Severity >= ForemanSeverity.Critical) return true;
        var (ruleId, category, _) = Describe(evt);
        if (ruleId is not null && emergencyRuleIds.Contains(ruleId, StringComparer.OrdinalIgnoreCase)) return true;
        return category is not null && _protectedCategories.Contains(category);
    }

    /// <summary>Longest mute allowed for this alert: a capped snooze if protected, else null (permanent OK).</summary>
    public static TimeSpan? MaxMuteDuration(ForemanEvent evt, IEnumerable<string> emergencyRuleIds) =>
        IsProtected(evt, emergencyRuleIds) ? MaxProtectedSnooze : null;

    /// <summary>Is this event's notification currently silenced by an active (non-expired) mute?</summary>
    public static bool IsSuppressed(ForemanEvent evt, IEnumerable<MuteEntry> mutes, DateTimeOffset now)
    {
        var (ruleId, category, source) = Describe(evt);
        foreach (var m in mutes)
        {
            if (m.Until is { } until && until <= now) continue;   // expired
            var matches = m.Scope switch
            {
                "rule"     => ruleId   is not null && string.Equals(m.Value, ruleId,   StringComparison.OrdinalIgnoreCase),
                "category" => category is not null && string.Equals(m.Value, category, StringComparison.OrdinalIgnoreCase),
                "source"   => string.Equals(m.Value, source, StringComparison.OrdinalIgnoreCase),
                _          => false,
            };
            if (matches) return true;
        }
        return false;
    }

    /// <summary>
    /// Builds a mute for THIS alert at the requested duration (null = permanent), clamped by the
    /// guardrail. Returns null if the request is disallowed (permanent or over-cap on a protected alert)
    /// so the caller can refuse. Scopes as narrowly as the event allows: rule > category > source.
    /// </summary>
    public static MuteEntry? CreateMute(
        ForemanEvent evt, TimeSpan? duration, IEnumerable<string> emergencyRuleIds, DateTimeOffset now)
    {
        if (MaxMuteDuration(evt, emergencyRuleIds) is { } cap)   // protected
        {
            if (duration is null || duration > cap) return null; // refuse permanent / too-long
        }
        if (duration is { } d0 && d0 <= TimeSpan.Zero) return null;

        var (ruleId, category, source) = Describe(evt);
        // Hang/orphan/exit alerts all share Source "Foreman.Monitor", so a source-scoped mute
        // would silence all three when the user only asked to quiet one kind — category keeps
        // them distinct. Source remains the last resort for events with no category at all.
        var (scope, value, label) = ruleId is not null
            ? ("rule",     ruleId,   $"rule {ruleId}")
            : category is not null
            ? ("category", category, $"{category} alerts")
            : ("source",   source,   $"events from {source}");

        return new MuteEntry
        {
            Scope     = scope,
            Value     = value,
            Until     = duration is { } d ? now + d : null,
            CreatedAt = now,
            Label     = label,
        };
    }
}
