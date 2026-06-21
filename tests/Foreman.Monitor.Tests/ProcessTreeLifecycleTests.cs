using Foreman.Core.Models;
using Foreman.Monitor;

namespace Foreman.Monitor.Tests;

public sealed class ProcessTreeLifecycleTests
{
    private static ProcessRecord Rec(int pid, int parentPid, string name, bool isHarness = false, string? harnessType = null)
        => new()
        {
            Pid = pid,
            ParentPid = parentPid,
            Name = name,
            StartTime = DateTimeOffset.UtcNow,
            IsHarness = isHarness,
            HarnessType = harnessType,
        };

    [Fact]
    public void OnProcessDeleted_ReturnsDeletedRecord_AndMarksChildrenOrphaned()
    {
        var tree = new ProcessTreeTracker();
        var harness = Rec(910_001, 900_000, "codex.exe", isHarness: true, harnessType: "codex");
        var child = Rec(910_002, harness.Pid, "python.exe");
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(child);

        var orphans = tree.OnProcessDeleted(harness.Pid, harness.StartTime, out var deleted);

        Assert.Same(harness, deleted);
        Assert.Single(orphans);
        Assert.Same(child, orphans[0]);
        Assert.Equal(ProcessState.Orphaned, child.State);
    }

    [Fact]
    public void OnProcessDeleted_UsesStartTime_WhenPidWasReused()
    {
        var tree = new ProcessTreeTracker();
        var oldStart = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(5);
        var newStart = DateTimeOffset.UtcNow;
        var old = new ProcessRecord
        {
            Pid = 910_101,
            ParentPid = 0,
            Name = "old.exe",
            StartTime = oldStart,
        };
        var newer = new ProcessRecord
        {
            Pid = 910_101,
            ParentPid = 0,
            Name = "new.exe",
            StartTime = newStart,
        };

        tree.OnProcessCreated(old);
        tree.OnProcessCreated(newer);

        tree.OnProcessDeleted(old.Pid, oldStart, out var deleted);

        Assert.Same(old, deleted);
        Assert.Same(newer, tree.GetByPid(newer.Pid));
    }

    [Fact]
    public void Prune_EvictsDeadRecords_KeepsLiveOnes()
    {
        var tree = new ProcessTreeTracker();
        var now = DateTimeOffset.UtcNow;
        var aged = TimeSpan.FromMinutes(5);
        var live = new ProcessRecord { Pid = 920_001, Name = "live.exe", StartTime = now - aged };
        var dead = new ProcessRecord { Pid = 920_002, Name = "dead.exe", StartTime = now - aged };
        tree.OnProcessCreated(live);
        tree.OnProcessCreated(dead);

        var livePids = new HashSet<int> { live.Pid };
        tree.Prune(livePids, now, TimeSpan.FromSeconds(60));                          // pass 1: grace defers
        var evicted = tree.Prune(livePids, now, TimeSpan.FromSeconds(60)).Evicted;    // pass 2: evicts

        Assert.Single(evicted);
        Assert.Same(dead, evicted[0]);
        Assert.NotNull(tree.GetByPid(live.Pid));
        Assert.Null(tree.GetByPid(dead.Pid));
    }

    [Fact]
    public void Prune_DefersEviction_UntilAbsentOnTwoConsecutivePasses()
    {
        var tree = new ProcessTreeTracker();
        var now = DateTimeOffset.UtcNow;
        var dead = new ProcessRecord { Pid = 920_031, Name = "dead.exe", StartTime = now - TimeSpan.FromMinutes(5) };
        tree.OnProcessCreated(dead);
        var noLive = new HashSet<int>();

        var firstPass = tree.Prune(noLive, now, TimeSpan.FromSeconds(60)).Evicted;
        Assert.Empty(firstPass);                  // grace gives the WMI deletion event time to win the race
        Assert.NotNull(tree.GetByPid(dead.Pid));  // still tracked after one pass

        var secondPass = tree.Prune(noLive, now, TimeSpan.FromSeconds(60)).Evicted;
        Assert.Single(secondPass);                // absent on two consecutive passes -> evicted
        Assert.Null(tree.GetByPid(dead.Pid));
    }

    [Fact]
    public void Prune_ResetsGrace_WhenPidReappearsBetweenPasses()
    {
        var tree = new ProcessTreeTracker();
        var now = DateTimeOffset.UtcNow;
        var rec = new ProcessRecord { Pid = 920_041, Name = "flap.exe", StartTime = now - TimeSpan.FromMinutes(5) };
        tree.OnProcessCreated(rec);

        tree.Prune(new HashSet<int>(), now, TimeSpan.FromSeconds(60));             // absent -> defer
        tree.Prune(new HashSet<int> { rec.Pid }, now, TimeSpan.FromSeconds(60));   // present -> grace reset
        var evicted = tree.Prune(new HashSet<int>(), now, TimeSpan.FromSeconds(60)).Evicted; // absent again -> defer

        Assert.Empty(evicted);
        Assert.NotNull(tree.GetByPid(rec.Pid));
    }

    [Fact]
    public void Prune_KeepsYoungRecords_EvenWhenAbsentFromLiveSet()
    {
        var tree = new ProcessTreeTracker();
        var now = DateTimeOffset.UtcNow;
        var young = new ProcessRecord { Pid = 920_011, Name = "young.exe", StartTime = now - TimeSpan.FromSeconds(5) };
        tree.OnProcessCreated(young);

        var evicted = tree.Prune(new HashSet<int>(), now, TimeSpan.FromSeconds(60)).Evicted;

        Assert.Empty(evicted);
        Assert.NotNull(tree.GetByPid(young.Pid));   // minAge guards a just-created process from a snapshot race
    }

    [Fact]
    public void Prune_NeverEvictsLivePid_EvenWhenRecordIsOld()
    {
        var tree = new ProcessTreeTracker();
        var now = DateTimeOffset.UtcNow;
        var rec = new ProcessRecord { Pid = 920_021, Name = "harness.exe", StartTime = now - TimeSpan.FromHours(2), IsHarness = true };
        tree.OnProcessCreated(rec);

        var evicted = tree.Prune(new HashSet<int> { rec.Pid }, now, TimeSpan.FromSeconds(60)).Evicted;

        Assert.Empty(evicted);
        Assert.NotNull(tree.GetByPid(rec.Pid));
    }

    [Fact]
    public void Prune_RecoversOrphans_WhenParentsDeathEventWasMissed()
    {
        var tree = new ProcessTreeTracker();
        var now = DateTimeOffset.UtcNow;
        var aged = TimeSpan.FromMinutes(5);
        // A harness parent whose WMI termination event was dropped (still tracked) + a live child of it.
        var parent = new ProcessRecord { Pid = 930_001, ParentPid = 0, Name = "codex.exe", StartTime = now - aged, HarnessType = "codex" };
        var child  = new ProcessRecord { Pid = 930_002, ParentPid = parent.Pid, Name = "python.exe", StartTime = now - aged };
        tree.OnProcessCreated(parent);
        tree.OnProcessCreated(child);

        var liveWithoutParent = new HashSet<int> { child.Pid };   // parent gone from the OS; child still alive
        tree.Prune(liveWithoutParent, now, TimeSpan.FromSeconds(60));                  // pass 1: grace defers
        var outcome = tree.Prune(liveWithoutParent, now, TimeSpan.FromSeconds(60));    // pass 2: evict + recover

        Assert.Contains(outcome.Evicted, r => r.Pid == parent.Pid);
        var orphan = Assert.Single(outcome.Orphans);
        Assert.Same(child, orphan.Child);
        Assert.Same(parent, orphan.Parent);
        Assert.Equal(ProcessState.Orphaned, child.State);   // flagged, so a second pass won't re-emit it
    }

    [Fact]
    public void GetTreeByHarnessType_IncludesHarnessDescendants()
    {
        var tree = new ProcessTreeTracker();
        var harness = Rec(910_201, 0, "codex.exe", isHarness: true, harnessType: "codex");
        var child = Rec(910_202, harness.Pid, "powershell.exe");
        tree.OnProcessCreated(harness);
        tree.OnProcessCreated(child);

        var pids = tree.GetTreeByHarnessType("codex").Select(r => r.Pid).ToHashSet();

        Assert.Contains(harness.Pid, pids);
        Assert.Contains(child.Pid, pids);
    }

    [Fact]
    public void AttributeOrphanHarness_HarnessParent_AttributesToParent()
    {
        var tree = new ProcessTreeTracker();
        var parent = Rec(940_001, 0, "codex.exe", isHarness: true, harnessType: "codex");
        var child = Rec(940_002, parent.Pid, "python.exe");
        Assert.Same(parent, tree.AttributeOrphanHarness(child, parent));
    }

    [Fact]
    public void AttributeOrphanHarness_NonHarnessTree_ReturnsNull()
    {
        // The real-world false positive: SIHClient.exe whose upfc.exe launcher exits — neither is a harness, so
        // no orphan alert should be raised (and there is no harness to attribute it to).
        var tree = new ProcessTreeTracker();
        var parent = Rec(940_011, 940_010, "upfc.exe");
        var child = Rec(940_012, parent.Pid, "SIHClient.exe");
        Assert.Null(tree.AttributeOrphanHarness(child, parent));
    }

    [Fact]
    public void AttributeOrphanHarness_HarnessGrandparent_AttributesUpTheChain()
    {
        // Dead parent is a plain shell (no HarnessType) but its OWN parent is the harness node, still tracked.
        var tree = new ProcessTreeTracker();
        var harness = Rec(940_021, 0, "claude.exe", isHarness: true, harnessType: "claude-code");
        tree.OnProcessCreated(harness);
        var shell = Rec(940_022, harness.Pid, "powershell.exe");
        var child = Rec(940_023, shell.Pid, "node.exe");
        Assert.Same(harness, tree.AttributeOrphanHarness(child, shell));
    }

    [Fact]
    public void AttributeOrphanHarness_ChildIsItselfHarness_AttributesToChild()
    {
        // The harness node itself orphaned because its plain (non-harness) launcher exited.
        var tree = new ProcessTreeTracker();
        var launcher = Rec(940_031, 940_030, "cmd.exe");
        var child = Rec(940_032, launcher.Pid, "codex.exe", isHarness: true, harnessType: "codex");
        Assert.Same(child, tree.AttributeOrphanHarness(child, launcher));
    }
}
