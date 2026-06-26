using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;

namespace Foreman.Monitor.Tests;

/// <summary>
/// Idle Harness self-cleanup: the detector asks an abandoned harness (whole tree I/O-silent)
/// to pack up via the injected mailbox delegate, at most once per cooldown, and raises a
/// visible notice when a request goes unanswered past the grace window.
///
/// EventBus is a process-wide singleton, so each test uses a unique PID range / harness type
/// and filters captured events to stay isolated from other tests.
/// </summary>
public sealed class IdleHarnessDetectorTests
{
    private readonly EventBus _bus = new();   // isolated per test

    private static ProcessRecord Proc(
        int pid, int parentPid, string name, string? harnessType, int silentMinutes, int uptimeMinutes = 600)
        => new()
        {
            Pid              = pid,
            ParentPid        = parentPid,
            Name             = name,
            StartTime        = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(uptimeMinutes),
            LastIoChangeTime = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(silentMinutes),
            IsHarness        = harnessType is not null,
            HarnessType      = harnessType,
            State            = ProcessState.Active,
        };

    private (IdleHarnessDetector Sut, ProcessTreeTracker Tree, List<string> Requests) Make(
        string harnessType, ForemanSettings settings, int basePid, bool pending = true)
    {
        var tree = new ProcessTreeTracker();
        tree.OnProcessCreated(Proc(basePid, basePid - 1, "claude.exe", harnessType, silentMinutes: 90));
        tree.OnProcessCreated(Proc(basePid + 1, basePid, "bash.exe", null, silentMinutes: 90));

        var requests = new List<string>();
        var sut = new IdleHarnessDetector(_bus, settings, tree)
        {
            CreateCleanupRequest = (harnessId, alertId, sys, usr, pid, name) =>
            {
                lock (requests) requests.Add(harnessId);
                return $"req-{requests.Count}";
            },
            IsRequestPending = _ => pending,
        };
        return (sut, tree, requests);
    }

    [Fact]
    public void IdleTree_AutoRequestsOnce_ThenCooldownHolds()
    {
        var settings = new ForemanSettings { IdleCleanupEnabled = true, IdleCleanupAfterMinutes = 45, IdleCleanupCooldownMinutes = 120 };
        var (sut, _, requests) = Make("custom:idletest-a.exe", settings, 910_100);

        sut.CheckNow();
        sut.CheckNow();   // immediately again — cooldown must hold

        Assert.Single(requests);
        Assert.Equal("custom:idletest-a.exe", requests[0]);
    }

    [Fact]
    public void Disabled_NeverAutoRequests_ButManualWorks()
    {
        var settings = new ForemanSettings { IdleCleanupEnabled = false, IdleCleanupAfterMinutes = 45 };
        var (sut, _, requests) = Make("custom:idletest-b.exe", settings, 910_200);

        sut.CheckNow();
        Assert.Empty(requests);

        var (ok, msg) = sut.TriggerCleanup("custom:idletest-b.exe");
        Assert.True(ok);
        Assert.Single(requests);
        Assert.Contains("req-1", msg);
    }

    [Fact]
    public void ActiveTree_NotAskedAutomatically()
    {
        var settings = new ForemanSettings { IdleCleanupEnabled = true, IdleCleanupAfterMinutes = 45 };
        var tree = new ProcessTreeTracker();
        tree.OnProcessCreated(Proc(910_300, 910_299, "claude.exe", "custom:idletest-c.exe", silentMinutes: 90));
        tree.OnProcessCreated(Proc(910_301, 910_300, "bash.exe", null, silentMinutes: 2));   // busy child

        var requests = new List<string>();
        var sut = new IdleHarnessDetector(_bus, settings, tree)
        {
            CreateCleanupRequest = (h, _, _, _, _, _) => { requests.Add(h); return "req"; },
        };

        sut.CheckNow();
        Assert.Empty(requests);
    }

    [Fact]
    public void DisabledHarness_Skipped()
    {
        var settings = new ForemanSettings { IdleCleanupEnabled = true, IdleCleanupAfterMinutes = 45 };
        settings.DisabledHarnesses.Add("custom:idletest-d.exe");
        var (sut, _, requests) = Make("custom:idletest-d.exe", settings, 910_400);

        sut.CheckNow();
        Assert.Empty(requests);
    }

    [Fact]
    public void UnansweredRequest_PastGrace_RaisesNotice_Once()
    {
        var settings = new ForemanSettings
        { IdleCleanupEnabled = true, IdleCleanupAfterMinutes = 45, IdleCleanupGraceMinutes = 15, IdleCleanupCooldownMinutes = 600 };
        var (sut, _, requests) = Make("custom:idletest-e.exe", settings, 910_500, pending: true);

        var notices = new List<MonitoringNoticeEvent>();
        _bus.Subscribe(evt =>
        {
            if (evt is MonitoringNoticeEvent n && n.Message.Contains("custom:idletest-e.exe"))
                lock (notices) notices.Add(n);
        });

        var t0 = DateTimeOffset.UtcNow;
        sut.CheckNow(t0);                       // creates the request
        sut.CheckNow(t0.AddMinutes(20));        // grace elapsed, still pending + idle → notice
        sut.CheckNow(t0.AddMinutes(25));        // must not repeat

        Assert.Single(requests);
        Assert.Single(notices);
        Assert.Equal(ForemanSeverity.Low, notices[0].Severity);
    }

    [Fact]
    public void AnsweredRequest_NoNotice()
    {
        var settings = new ForemanSettings
        { IdleCleanupEnabled = true, IdleCleanupAfterMinutes = 45, IdleCleanupGraceMinutes = 15, IdleCleanupCooldownMinutes = 600 };
        var (sut, _, _) = Make("custom:idletest-f.exe", settings, 910_600, pending: false);

        var notices = new List<MonitoringNoticeEvent>();
        _bus.Subscribe(evt =>
        {
            if (evt is MonitoringNoticeEvent n && n.Message.Contains("custom:idletest-f.exe"))
                lock (notices) notices.Add(n);
        });

        var t0 = DateTimeOffset.UtcNow;
        sut.CheckNow(t0);
        sut.CheckNow(t0.AddMinutes(20));

        Assert.Empty(notices);
    }

    [Fact]
    public void ManualTrigger_NoProcesses_FailsGracefully()
    {
        var settings = new ForemanSettings();
        var sut = new IdleHarnessDetector(_bus, settings, new ProcessTreeTracker());

        var (ok, msg) = sut.TriggerCleanup("custom:nothere.exe");
        Assert.False(ok);
        Assert.Contains("No running processes", msg);
    }

    // PrepareForUpdate is PER SESSION: one idle session is selected for reap while an ACTIVE session of the SAME
    // harness type is spared and asked to checkpoint. Odd PIDs are used so KillProcess's real-kill path safely no-ops
    // (Windows PIDs are multiples of 4, so an odd PID never resolves to a live process) — we assert on the reap DECISION
    // (recorded in the termination ledger before the kill) + the checkpoint ask, not on a real kill.
    [Fact]
    public void PrepareForUpdate_ReapsIdleSession_SparesActiveSameTypeSession()
    {
        var settings = new ForemanSettings { IdleCleanupAfterMinutes = 45 };
        var tree = new ProcessTreeTracker();
        const string type = "custom:prep-iso.exe";

        // Idle session: root + child, both I/O-silent past the threshold.
        tree.OnProcessCreated(Proc(920_101, 920_099, "claude.exe", type, silentMinutes: 90));
        tree.OnProcessCreated(Proc(920_103, 920_101, "bash.exe", null, silentMinutes: 90));
        // ACTIVE session of the SAME type: root quiet but a busy child → not idle.
        tree.OnProcessCreated(Proc(920_201, 920_199, "claude.exe", type, silentMinutes: 90));
        tree.OnProcessCreated(Proc(920_203, 920_201, "node.exe", null, silentMinutes: 2));

        var ledger = new Foreman.Core.Termination.ExpectedTerminationLedger();
        var requests = new List<string>();
        var sut = new IdleHarnessDetector(_bus, settings, tree)
        {
            ExpectedTerminations = ledger,
            CreateCleanupRequest = (h, _, _, _, _, _) => { lock (requests) requests.Add(h); return "req"; },
        };

        sut.PrepareForUpdate();

        // The idle session is selected for reap → its whole tree is recorded as expected terminations.
        Assert.True(ledger.WasExpected(920_101));
        Assert.True(ledger.WasExpected(920_103));
        // The active same-type session is spared → never recorded for reap...
        Assert.False(ledger.WasExpected(920_201));
        Assert.False(ledger.WasExpected(920_203));
        // ...and asked to checkpoint instead (type-level cooperative request).
        Assert.Contains(type, requests);
    }
}
