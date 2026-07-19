using Foreman.Core.Settings;

namespace Foreman.Core.Alerts;

public sealed record ScheduledAuditObservation(string HarnessId, int EventCount, bool HasRecentActivity);

/// <summary>
/// Session-scoped cadence state for scheduled audits. It converts cumulative per-harness counters into
/// events-since-last-audit and delegates the actual due decision to <see cref="ScheduledAuditPolicy"/>.
/// </summary>
public sealed class ScheduledAuditTracker
{
    private sealed record State(DateTimeOffset? LastAuditUtc, int BaselineEventCount);
    private readonly object _gate = new();
    private readonly Dictionary<string, State> _states = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<ScheduledAudit> DueAudits(
        DateTimeOffset now,
        ScheduledAuditSettings settings,
        IEnumerable<ScheduledAuditObservation> observations,
        Func<string, string?> pickAuditor)
    {
        List<HarnessAuditState> states;
        lock (_gate)
        {
            states = observations
                .Where(o => !string.IsNullOrWhiteSpace(o.HarnessId))
                .Select(o =>
                {
                    var count = Math.Max(0, o.EventCount);
                    _states.TryGetValue(o.HarnessId, out var prior);
                    var baseline = prior is null || count < prior.BaselineEventCount
                        ? 0
                        : prior.BaselineEventCount;
                    if (prior is not null && baseline != prior.BaselineEventCount)
                        _states[o.HarnessId] = prior with { BaselineEventCount = baseline };
                    return new HarnessAuditState(
                        o.HarnessId,
                        prior?.LastAuditUtc,
                        Math.Max(0, count - baseline),
                        o.HasRecentActivity);
                })
                .ToList();
        }

        return ScheduledAuditPolicy.DueAudits(now, settings, states, pickAuditor);
    }

    public void MarkAudited(string harnessId, DateTimeOffset now, int currentEventCount)
    {
        if (string.IsNullOrWhiteSpace(harnessId)) return;
        lock (_gate)
            _states[harnessId] = new State(now, Math.Max(0, currentEventCount));
    }
}
