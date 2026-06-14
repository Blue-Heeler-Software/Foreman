using Foreman.Core.Alerts;

namespace Foreman.Core.Tests.Alerts;

public sealed class AlertCadenceGovernorTests
{
    // A movable clock so window-sliding is deterministic (no wall-clock dependence).
    private sealed class Clock
    {
        public DateTimeOffset Now = DateTimeOffset.UnixEpoch;
        public DateTimeOffset Read() => Now;
        public void Advance(TimeSpan d) => Now += d;
    }

    private static (AlertCadenceGovernor gov, Clock clk) Make(int burst = 3, int window = 90, bool enabled = true)
    {
        var clk = new Clock();
        var gov = new AlertCadenceGovernor(
            new CadenceGovernorSettings { Enabled = enabled, BurstThreshold = burst, WindowSeconds = window },
            clk.Read);
        return (gov, clk);
    }

    [Fact]   // disabled → every toast shows, nothing is ever coalesced
    public void Disabled_AlwaysNotifies()
    {
        var (gov, _) = Make(enabled: false);
        for (var i = 0; i < 50; i++) Assert.True(gov.ShouldNotify("codex"));
        Assert.Empty(gov.Flush());
    }

    [Fact]   // first BurstThreshold toasts of a class show; the rest within the window are coalesced
    public void Burst_NotifiesUpToBudget_ThenCoalesces()
    {
        var (gov, _) = Make(burst: 3, window: 90);
        Assert.True(gov.ShouldNotify("codex"));    // 1
        Assert.True(gov.ShouldNotify("codex"));    // 2
        Assert.True(gov.ShouldNotify("codex"));    // 3 — budget
        Assert.False(gov.ShouldNotify("codex"));   // 4 → coalesced
        Assert.False(gov.ShouldNotify("codex"));   // 5 → coalesced
    }

    [Fact]   // the budget is PER CLASS — a flood from one harness can't suppress the first alert of another
    public void Budget_IsPerClass()
    {
        var (gov, _) = Make(burst: 2, window: 90);
        Assert.True(gov.ShouldNotify("codex"));
        Assert.True(gov.ShouldNotify("codex"));
        Assert.False(gov.ShouldNotify("codex"));   // codex over budget
        Assert.True(gov.ShouldNotify("claude-code")); // ...but claude-code's first alert still shows
        Assert.True(gov.ShouldNotify("claude-code"));
    }

    [Fact]   // once the window slides past the early toasts, the budget refills
    public void Window_Slides_BudgetRefills()
    {
        var (gov, clk) = Make(burst: 2, window: 90);
        Assert.True(gov.ShouldNotify("codex"));
        Assert.True(gov.ShouldNotify("codex"));
        Assert.False(gov.ShouldNotify("codex"));   // over budget now
        clk.Advance(TimeSpan.FromSeconds(91));     // both early toasts age out of the window
        Assert.True(gov.ShouldNotify("codex"));    // budget refilled
    }

    [Fact]   // Flush drains the coalesced counts (for the rollup notice) and resets them
    public void Flush_ReturnsCoalescedCounts_ThenResets()
    {
        var (gov, _) = Make(burst: 1, window: 90);
        gov.ShouldNotify("codex");                 // 1 — shown
        gov.ShouldNotify("codex");                 // coalesced (1)
        gov.ShouldNotify("codex");                 // coalesced (2)
        gov.ShouldNotify("claude-code");           // shown
        gov.ShouldNotify("claude-code");           // coalesced (1)

        var rolled = gov.Flush().ToDictionary(x => x.ClassKey, x => x.Suppressed);
        Assert.Equal(2, rolled["codex"]);
        Assert.Equal(1, rolled["claude-code"]);

        Assert.Empty(gov.Flush());                 // drained — second flush is empty
    }

    [Fact]   // a class that never exceeded budget contributes nothing to the rollup
    public void Flush_OmitsClassesWithNoSuppression()
    {
        var (gov, _) = Make(burst: 5, window: 90);
        gov.ShouldNotify("codex");
        gov.ShouldNotify("codex");
        Assert.Empty(gov.Flush());
    }

    [Fact]   // BurstThreshold below 1 is clamped to 1 (always allow at least the first toast through)
    public void BurstThreshold_ClampedToAtLeastOne()
    {
        var (gov, _) = Make(burst: 0, window: 90);
        Assert.True(gov.ShouldNotify("codex"));    // first still shows despite a 0 budget
        Assert.False(gov.ShouldNotify("codex"));
    }

    [Fact]   // hygiene: a one-off harness key whose window fully ages out is GC'd by Flush, not kept forever
    public void Flush_PrunesFullyAgedClassKeys()
    {
        var (gov, clk) = Make(burst: 5, window: 90);
        gov.ShouldNotify("transient-harness-1");
        gov.ShouldNotify("transient-harness-2");
        clk.Advance(TimeSpan.FromSeconds(91));     // both queues age out of the window
        gov.Flush();                               // GC sweep drops the now-empty per-class queues

        // After GC, those keys are gone — a fresh burst from a NEW key still works (nothing is corrupted).
        for (var i = 0; i < 5; i++) Assert.True(gov.ShouldNotify("transient-harness-3"));
        Assert.False(gov.ShouldNotify("transient-harness-3"));
        Assert.Equal(0, gov.RecentKeyCount("transient-harness-1"));
        Assert.Equal(0, gov.RecentKeyCount("transient-harness-2"));
    }
}
