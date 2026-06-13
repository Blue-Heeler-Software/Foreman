using Foreman.Core.Models;
using Foreman.Monitor;

namespace Foreman.Monitor.Tests;

/// <summary>
/// A hook or shell spawned by a harness matches no harness rule itself, so it must be attributed
/// to the harness it descends from by walking the process tree. These tests cover that walk.
/// </summary>
public sealed class ProcessTreeAttributionTests
{
    private static ProcessRecord Rec(int pid, int parentPid, string name, bool isHarness = false, string? harnessType = null)
        => new()
        {
            Pid         = pid,
            ParentPid   = parentPid,
            Name        = name,
            StartTime   = DateTimeOffset.UtcNow,
            IsHarness   = isHarness,
            HarnessType = harnessType,
        };

    [Fact]
    public void FindHarnessTypeAncestor_AttributesHookChildToHarness()
    {
        var tree    = new ProcessTreeTracker();
        var node    = Rec(1000, 900, "node.exe", isHarness: true, harnessType: "claude-code");
        var pwsh    = Rec(1001, node.Pid, "powershell.exe");           // the hook launcher
        var pwshInner = Rec(1002, pwsh.Pid, "powershell.exe");         // the script host it spawns
        tree.OnProcessCreated(node);
        tree.OnProcessCreated(pwsh);
        tree.OnProcessCreated(pwshInner);

        Assert.Equal("claude-code", tree.FindHarnessTypeAncestor(pwsh.Pid)?.HarnessType);
        Assert.Equal("claude-code", tree.FindHarnessTypeAncestor(pwshInner.Pid)?.HarnessType);
        Assert.Equal(node.Pid,      tree.FindHarnessAncestor(pwshInner.Pid)?.Pid);
    }

    [Fact]
    public void FindHarnessTypeAncestor_ReturnsNull_OutsideAnyHarnessTree()
    {
        var tree = new ProcessTreeTracker();
        var lone = Rec(2001, 2000, "RuntimeBroker.exe");   // parent 2000 not tracked
        tree.OnProcessCreated(lone);

        Assert.Null(tree.FindHarnessTypeAncestor(lone.Pid));
        Assert.Null(tree.FindHarnessAncestor(lone.Pid));
    }

    [Fact]
    public void FindHarnessTypeAncestor_AttributesDisabledHarness_ButFindHarnessAncestorDoesNot()
    {
        // A disabled harness keeps its HarnessType but has IsHarness == false.
        // Attribution (HarnessType) should still resolve; active-monitoring (IsHarness) should not.
        var tree  = new ProcessTreeTracker();
        var node  = Rec(3000, 2900, "node.exe", isHarness: false, harnessType: "codex");
        var child = Rec(3001, node.Pid, "bash.exe");
        tree.OnProcessCreated(node);
        tree.OnProcessCreated(child);

        Assert.Equal("codex", tree.FindHarnessTypeAncestor(child.Pid)?.HarnessType);
        Assert.Null(tree.FindHarnessAncestor(child.Pid));
    }

    [Fact]
    public void FindHarnessTypeAncestor_StopsAtSystemHost_NoMisattribution()
    {
        // PID-reuse / stale-ppid corruption: an OS process (LockApp) chains through svchost up to a harness
        // node. A genuine harness child never descends through svchost, so the walk must STOP at the OS host
        // and attribute nothing — otherwise every idle OS process is tagged to the harness and hang-spammed.
        var tree    = new ProcessTreeTracker();
        var node    = Rec(4000, 3900, "claude.exe", isHarness: true, harnessType: "claude-code");
        var svchost = Rec(4001, node.Pid, "svchost.exe");      // bogus edge: svchost "under" the harness
        var lockApp = Rec(4002, svchost.Pid, "LockApp.exe");
        tree.OnProcessCreated(node);
        tree.OnProcessCreated(svchost);
        tree.OnProcessCreated(lockApp);

        Assert.Null(tree.FindHarnessTypeAncestor(lockApp.Pid));   // NOT attributed to claude-code
        Assert.Null(tree.FindHarnessAncestor(lockApp.Pid));

        // sanity: a REAL harness child (no OS host in its chain) still attributes correctly
        var realChild = Rec(4003, node.Pid, "bash.exe");
        tree.OnProcessCreated(realChild);
        Assert.Equal("claude-code", tree.FindHarnessTypeAncestor(realChild.Pid)?.HarnessType);
    }
}
