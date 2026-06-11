using Foreman.Core.Alerts;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Alerts;

public sealed class ScheduledAuditPolicyTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch.AddDays(1);
    private static readonly Func<string, string?> Codex = _ => "codex";   // always picks codex as auditor

    private static ScheduledAuditSettings Cfg(bool enabled = true, int everyN = 50, int interval = 0, int cooldown = 30)
        => new() { Enabled = enabled, EveryNEvents = everyN, IntervalMinutes = interval, CooldownMinutes = cooldown };

    private static HarnessAuditState State(string id = "claude-code", DateTimeOffset? last = null, int events = 0, bool active = true)
        => new(id, last, events, active);

    [Fact]
    public void Disabled_ReturnsNothing()
        => Assert.Empty(ScheduledAuditPolicy.DueAudits(Now, Cfg(enabled: false), [State(events: 999)], Codex));

    [Fact]
    public void NoRecentActivity_NotDue()
        => Assert.Empty(ScheduledAuditPolicy.DueAudits(Now, Cfg(), [State(events: 999, active: false)], Codex));

    [Fact]
    public void EventCountReached_IsDue_WithAuditor()
    {
        var due = ScheduledAuditPolicy.DueAudits(Now, Cfg(everyN: 50), [State(events: 50)], Codex);
        var a = Assert.Single(due);
        Assert.Equal("claude-code", a.TargetHarnessId);
        Assert.Equal("codex", a.AuditorId);
    }

    [Fact]
    public void BelowCount_NoInterval_NotDue()
        => Assert.Empty(ScheduledAuditPolicy.DueAudits(Now, Cfg(everyN: 50, interval: 0), [State(events: 49)], Codex));

    [Fact]
    public void IntervalElapsed_IsDue()
    {
        var cfg = Cfg(everyN: 0, interval: 30);
        var due = ScheduledAuditPolicy.DueAudits(Now, cfg, [State(last: Now.AddMinutes(-31), events: 0)], Codex);
        Assert.Single(due);
    }

    [Fact]
    public void IntervalNotYetElapsed_NotDue()
    {
        var cfg = Cfg(everyN: 0, interval: 30);
        Assert.Empty(ScheduledAuditPolicy.DueAudits(Now, cfg, [State(last: Now.AddMinutes(-10), events: 0)], Codex));
    }

    [Fact]
    public void Cooldown_BlocksEvenWhenCountHit()
    {
        var cfg = Cfg(everyN: 50, cooldown: 30);
        Assert.Empty(ScheduledAuditPolicy.DueAudits(Now, cfg, [State(last: Now.AddMinutes(-5), events: 99)], Codex));
    }

    [Fact]
    public void NoAuditorAvailable_Skipped()
        => Assert.Empty(ScheduledAuditPolicy.DueAudits(Now, Cfg(everyN: 50), [State(events: 99)], _ => null));

    [Fact]
    public void SelfAudit_Skipped()   // auditor != audited enforced
        => Assert.Empty(ScheduledAuditPolicy.DueAudits(Now, Cfg(everyN: 50), [State("codex", events: 99)], Codex));

    [Fact]
    public void NeverAudited_WithInterval_IsDue()
    {
        var cfg = Cfg(everyN: 0, interval: 30);
        Assert.Single(ScheduledAuditPolicy.DueAudits(Now, cfg, [State(last: null, events: 0)], Codex));
    }

    [Fact]
    public void OnlyDueHarnesses_AreReturned()
    {
        var due = ScheduledAuditPolicy.DueAudits(Now, Cfg(everyN: 50),
            [State("claude-code", events: 60), State("opencode", events: 5)], Codex);
        var a = Assert.Single(due);
        Assert.Equal("claude-code", a.TargetHarnessId);
    }
}
