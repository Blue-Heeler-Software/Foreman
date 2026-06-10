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

    private static (IdleHarnessDetector Sut, ProcessTreeTracker Tree, List<string> Requests) Make(
        string harnessType, ForemanSettings settings, int basePid, bool pending = true)
    {
        var tree = new ProcessTreeTracker();
        tree.OnProcessCreated(Proc(basePid, basePid - 1, "claude.exe", harnessType, silentMinutes: 90));
        tree.OnProcessCreated(Proc(basePid + 1, basePid, "bash.exe", null, silentMinutes: 90));

        var requests = new List<string>();
        var sut = new IdleHarnessDetector(EventBus.Instance, settings, tree)
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
        var sut = new IdleHarnessDetector(EventBus.Instance, settings, tree)
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
        EventBus.Instance.Subscribe(evt =>
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
        EventBus.Instance.Subscribe(evt =>
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
        var sut = new IdleHarnessDetector(EventBus.Instance, settings, new ProcessTreeTracker());

        var (ok, msg) = sut.TriggerCleanup("custom:nothere.exe");
        Assert.False(ok);
        Assert.Contains("No running processes", msg);
    }
}
