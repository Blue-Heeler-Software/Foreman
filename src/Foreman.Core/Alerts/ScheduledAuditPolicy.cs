using Foreman.Core.Settings;

namespace Foreman.Core.Alerts;

/// <summary>Per-harness state the scheduled-audit policy needs (fed by the runtime each tick).</summary>
public sealed record HarnessAuditState(
    string HarnessId,
    DateTimeOffset? LastAuditUtc,
    int EventsSinceLastAudit,
    bool HasRecentActivity);

/// <summary>A due audit: who reviews whom.</summary>
public sealed record ScheduledAudit(string TargetHarnessId, string AuditorId);

/// <summary>
/// Pure decision logic for proactive cross-harness auditing: given the cadence config + per-harness state +
/// an auditor selector, decide which harnesses are due and who audits each. Unit-tested; the timer + the
/// actual dispatch (which reuses the Ask-Harness/Audit path) are runtime wiring.
///
/// A harness is due when: scheduled audits are ON, it has had recent activity, it's past the per-harness
/// cooldown, and EITHER its event count since the last audit reached <c>EveryNEvents</c> OR
/// <c>IntervalMinutes</c> elapsed — and a valid auditor (a DIFFERENT connected harness/model) is available.
/// The auditor != audited rule is enforced here as a backstop on top of the selector's own PreventSelfAudit.
/// </summary>
public static class ScheduledAuditPolicy
{
    public static IReadOnlyList<ScheduledAudit> DueAudits(
        DateTimeOffset now,
        ScheduledAuditSettings cfg,
        IEnumerable<HarnessAuditState> harnesses,
        Func<string, string?> pickAuditor)
    {
        var due = new List<ScheduledAudit>();
        if (!cfg.Enabled) return due;

        foreach (var h in harnesses)
        {
            if (!h.HasRecentActivity) continue;

            // Cooldown: never re-audit the same harness within CooldownMinutes of its last audit.
            if (h.LastAuditUtc is { } last && now - last < TimeSpan.FromMinutes(Math.Max(0, cfg.CooldownMinutes)))
                continue;

            var byCount = cfg.EveryNEvents > 0 && h.EventsSinceLastAudit >= cfg.EveryNEvents;
            var byTime = cfg.IntervalMinutes > 0
                && (h.LastAuditUtc is not { } l || now - l >= TimeSpan.FromMinutes(cfg.IntervalMinutes));
            if (!byCount && !byTime) continue;

            var auditor = pickAuditor(h.HarnessId);
            if (string.IsNullOrWhiteSpace(auditor)
                || string.Equals(auditor, h.HarnessId, StringComparison.OrdinalIgnoreCase))
                continue;   // no auditor available, or it would be a self-audit — skip

            due.Add(new ScheduledAudit(h.HarnessId, auditor));
        }
        return due;
    }
}
