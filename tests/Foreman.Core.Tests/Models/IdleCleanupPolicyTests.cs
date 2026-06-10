using Foreman.Core.Models;

namespace Foreman.Core.Tests.Models;

public sealed class IdleCleanupPolicyTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch.AddDays(1000);

    private static ProcessRecord Rec(
        int silentMinutes, int uptimeMinutes = 600, bool unavailable = false,
        ProcessState state = ProcessState.Active, bool isHarness = false)
        => new()
        {
            Pid              = 1,
            Name             = "p.exe",
            StartTime        = Now - TimeSpan.FromMinutes(uptimeMinutes),
            LastIoChangeTime = Now - TimeSpan.FromMinutes(silentMinutes),
            IoCountersUnavailable = unavailable,
            State            = state,
            IsHarness        = isHarness,
        };

    // ── IsTreeIdle ────────────────────────────────────────────────────────────
    [Fact] public void AllSilent_IsIdle()
        => Assert.True(IdleCleanupPolicy.IsTreeIdle([Rec(60), Rec(90)], 45, Now));

    [Fact] public void OneActiveChild_NotIdle()
        => Assert.False(IdleCleanupPolicy.IsTreeIdle([Rec(60), Rec(5)], 45, Now));

    [Fact] public void RecentSpawn_CountsAsActivity()
        => Assert.False(IdleCleanupPolicy.IsTreeIdle([Rec(60), Rec(60, uptimeMinutes: 10)], 45, Now));

    [Fact] public void UnavailableCounters_DontVetoIdleness()
        => Assert.True(IdleCleanupPolicy.IsTreeIdle([Rec(60), Rec(0, unavailable: true)], 45, Now));

    [Fact] public void AllUnavailable_NeverIdle()
        => Assert.False(IdleCleanupPolicy.IsTreeIdle([Rec(60, unavailable: true)], 45, Now));

    [Fact] public void EmptyTree_NotIdle()
        => Assert.False(IdleCleanupPolicy.IsTreeIdle([], 45, Now));

    [Fact] public void TerminatedRecords_Ignored()
        => Assert.True(IdleCleanupPolicy.IsTreeIdle([Rec(60), Rec(1, state: ProcessState.Terminated)], 45, Now));

    [Fact] public void ExactlyAtThreshold_IsIdle()
        => Assert.True(IdleCleanupPolicy.IsTreeIdle([Rec(45)], 45, Now));

    // ── TreeIdleMinutes ───────────────────────────────────────────────────────
    [Fact] public void TreeIdleMinutes_IsMinAcrossReadable()
        => Assert.Equal(30, IdleCleanupPolicy.TreeIdleMinutes([Rec(90), Rec(30), Rec(5, unavailable: true)], Now));

    [Fact] public void TreeIdleMinutes_NoReadable_Zero()
        => Assert.Equal(0, IdleCleanupPolicy.TreeIdleMinutes([Rec(90, unavailable: true)], Now));

    // ── ShouldAutoRequest ─────────────────────────────────────────────────────
    [Fact] public void NeverAsked_MayRequest()
        => Assert.True(IdleCleanupPolicy.ShouldAutoRequest(null, 120, Now));

    [Fact] public void WithinCooldown_MayNot()
        => Assert.False(IdleCleanupPolicy.ShouldAutoRequest(Now.AddMinutes(-30), 120, Now));

    [Fact] public void CooldownElapsed_MayRequestAgain()
        => Assert.True(IdleCleanupPolicy.ShouldAutoRequest(Now.AddMinutes(-121), 120, Now));

    // ── ShouldEscalate ────────────────────────────────────────────────────────
    [Fact] public void PendingIdlePastGrace_Escalates()
        => Assert.True(IdleCleanupPolicy.ShouldEscalate(Now.AddMinutes(-20), stillPending: true, stillIdle: true, alreadyEscalated: false, 15, Now));

    [Fact] public void Answered_DoesNotEscalate()
        => Assert.False(IdleCleanupPolicy.ShouldEscalate(Now.AddMinutes(-20), stillPending: false, stillIdle: true, alreadyEscalated: false, 15, Now));

    [Fact] public void WokeUp_DoesNotEscalate()
        => Assert.False(IdleCleanupPolicy.ShouldEscalate(Now.AddMinutes(-20), stillPending: true, stillIdle: false, alreadyEscalated: false, 15, Now));

    [Fact] public void OnlyOnce()
        => Assert.False(IdleCleanupPolicy.ShouldEscalate(Now.AddMinutes(-20), stillPending: true, stillIdle: true, alreadyEscalated: true, 15, Now));

    [Fact] public void WithinGrace_Waits()
        => Assert.False(IdleCleanupPolicy.ShouldEscalate(Now.AddMinutes(-10), stillPending: true, stillIdle: true, alreadyEscalated: false, 15, Now));

    // ── BuildPrompts ──────────────────────────────────────────────────────────
    [Fact]
    public void Prompts_NameTheHarness_AndTheReplyTool()
    {
        var (system, user) = IdleCleanupPolicy.BuildPrompts("claude-code", 50, ["bash.exe", "node.exe"], manual: false);
        Assert.Contains("claude-code", system);
        Assert.Contains("50 minute", user);
        Assert.Contains("ReplyToAskHarnessRequest", user);
        Assert.Contains("bash.exe", user);
    }

    [Fact]
    public void ManualPrompt_SaysOperator_NotIdleMinutes()
    {
        var (_, user) = IdleCleanupPolicy.BuildPrompts("codex", 0, [], manual: true);
        Assert.Contains("operator", user, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("no I/O activity for about", user);
    }

    [Fact]
    public void Prompts_AreNotAccusatory()
    {
        var (system, _) = IdleCleanupPolicy.BuildPrompts("codex", 60, [], manual: false);
        Assert.Contains("not an accusation", system);
    }
}
