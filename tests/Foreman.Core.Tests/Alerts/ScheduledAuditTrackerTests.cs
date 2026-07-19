using Foreman.Core.Alerts;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Alerts;

public sealed class ScheduledAuditTrackerTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 1, 2, 3, TimeSpan.Zero);

    [Fact]
    public void MarkAudited_ResetsCountBaselineAndEnforcesCooldown()
    {
        var tracker = new ScheduledAuditTracker();
        var cfg = new ScheduledAuditSettings { Enabled = true, EveryNEvents = 5, CooldownMinutes = 10 };
        var initial = tracker.DueAudits(Now, cfg, [new("codex", 5, true)], _ => "claude-code");
        Assert.Single(initial);

        tracker.MarkAudited("codex", Now, 5);
        Assert.Empty(tracker.DueAudits(Now.AddMinutes(11), cfg, [new("codex", 9, true)], _ => "claude-code"));
        Assert.Single(tracker.DueAudits(Now.AddMinutes(11), cfg, [new("codex", 10, true)], _ => "claude-code"));
    }

    [Fact]
    public void CounterReset_DoesNotProduceNegativeOrPhantomEvents()
    {
        var tracker = new ScheduledAuditTracker();
        var cfg = new ScheduledAuditSettings { Enabled = true, EveryNEvents = 5, CooldownMinutes = 0 };
        tracker.MarkAudited("codex", Now, 20);

        Assert.Empty(tracker.DueAudits(Now.AddMinutes(1), cfg, [new("codex", 1, true)], _ => "claude-code"));
        Assert.Single(tracker.DueAudits(Now.AddMinutes(2), cfg, [new("codex", 5, true)], _ => "claude-code"));
    }

    [Fact]
    public void InactiveOrSelfAuditedHarness_IsSkipped()
    {
        var tracker = new ScheduledAuditTracker();
        var cfg = new ScheduledAuditSettings { Enabled = true, EveryNEvents = 1, CooldownMinutes = 0 };
        Assert.Empty(tracker.DueAudits(Now, cfg, [new("codex", 10, false)], _ => "claude-code"));
        Assert.Empty(tracker.DueAudits(Now, cfg, [new("codex", 10, true)], _ => "codex"));
    }
}
