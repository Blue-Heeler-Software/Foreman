using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Heuristics;
using Foreman.Core.Models;
using Foreman.Core.Profiles;
using Foreman.Core.Security;
using Foreman.Core.Settings;
using Foreman.Monitor;
using Foreman.Platform;

namespace Foreman.Agent;

/// <summary>
/// Linux composition of Foreman's portable safety policy with /proc-backed observation.
/// The service is deliberately unprivileged: unreadable process fields degrade to missing
/// observations and never grant additional authority.
/// </summary>
public sealed class LinuxMonitorService : IDisposable
{
    private readonly ForemanSettings _settings;
    private readonly EventBus _bus;
    private readonly IProcessSnapshotProvider _snapshots;
    private readonly IProcessEventSource _events;
    private readonly IProcessIoReader _io;
    private readonly ProfileStore _profileStore;
    private readonly ViolationDetector _violations;
    private readonly CredentialSweepAggregator _credentialSweep;
    private readonly HangDetector _hangDetector;
    private readonly CancellationTokenSource _stop = new();
    private Task? _ioLoop;
    private bool _started;
    private bool _ioDegradedReported;

    public ProcessTreeTracker Tree { get; } = new();
    public BehaviorTracker Behavior { get; }
    public ProfileMatcher Profiles { get; }
    public McpInventoryMonitor McpInventory { get; }

    public LinuxMonitorService(
        ForemanSettings settings,
        EventBus bus,
        IProcessSnapshotProvider snapshots,
        IProcessEventSource events,
        IProcessIoReader io,
        string stateDirectory)
    {
        _settings = settings;
        _bus = bus;
        _snapshots = snapshots;
        _events = events;
        _io = io;
        _profileStore = new ProfileStore(settings.ProfilesDirectory);
        _profileStore.Initialize();
        Profiles = new ProfileMatcher(_profileStore);
        _violations = new ViolationDetector(Profiles, bus, pid => Tree.FindProfileAncestor(pid));
        _credentialSweep = new CredentialSweepAggregator(
            settings.CredentialSweepDistinctThreshold,
            settings.CredentialSweepWindowSeconds);
        _hangDetector = new HangDetector(bus, settings, Tree);
        Behavior = new BehaviorTracker(
            settings,
            bus,
            pid => Tree.GetByPid(pid),
            pid => Tree.FindHarnessTypeAncestor(pid),
            settings.EffectiveThresholds);
        McpInventory = new McpInventoryMonitor(bus, settings.McpPort, stateDirectory);
    }

    public void Start()
    {
        if (_started) return;
        _started = true;

        var initial = _snapshots.Snapshot();
        foreach (var record in initial)
        {
            ClassifyAndProfile(record);
            Tree.OnProcessCreated(record);
        }
        foreach (var record in initial.Where(static p => p.ProfileName is null))
            ApplyProfileInheritance(record);

        _events.ProcessStarted += OnProcessStarted;
        _events.ProcessExited += OnProcessExited;
        _events.Start();
        McpInventory.Start();
        _ioLoop = PollIoAsync(_stop.Token);

        var harnesses = initial.Where(static p => p.IsHarness)
            .Select(static p => $"{p.HarnessType} (pid {p.Pid})")
            .ToArray();
        _bus.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman.Monitor.Linux",
            harnesses.Length == 0
                ? $"Initial /proc scan complete — {initial.Count} processes, no known harnesses running."
                : $"Initial /proc scan complete — {initial.Count} processes; harnesses: {string.Join(", ", harnesses)}"));
    }

    private void OnProcessStarted(ProcessRecord record)
    {
        try
        {
            ClassifyAndProfile(record);
            Tree.OnProcessCreated(record);
            ApplyProfileInheritance(record);
            CheckForemanImpersonation(record);

            if (!string.IsNullOrWhiteSpace(record.CommandLine))
                ThreadPool.QueueUserWorkItem(_ => Analyze(record));
        }
        catch
        {
            // A process can disappear between /proc reads. Monitoring must remain alive.
        }
    }

    private void OnProcessExited(int pid, DateTimeOffset? startTime)
    {
        try
        {
            var orphans = Tree.OnProcessDeleted(pid, startTime, out var deleted);
            _hangDetector.Forget(pid);
            if (KnownHarnesses.IsLocalModelHost(deleted?.HarnessType)) return;

            foreach (var orphan in orphans)
            {
                var harness = Tree.AttributeOrphanHarness(orphan, deleted);
                if (harness is null) continue;
                _ = PublishOrphanAfterGraceAsync(orphan, deleted, harness, pid);
            }
        }
        catch { }
    }

    private async Task PublishOrphanAfterGraceAsync(
        ProcessRecord orphan,
        ProcessRecord? deleted,
        ProcessRecord harness,
        int parentPid)
    {
        try
        {
            // Shell pipelines commonly outlive their parent shell by a few milliseconds. Confirm that the
            // exact process (including start time, for PID-reuse safety) survives another observation cycle
            // before presenting it as an operator-facing orphan.
            await Task.Delay(TimeSpan.FromSeconds(2), _stop.Token).ConfigureAwait(false);
            var current = Tree.GetByPid(orphan.Pid);
            if (current is null || current.StartTime != orphan.StartTime) return;

            _bus.Publish(new OrphanDetectedEvent(
                DateTimeOffset.UtcNow,
                "Foreman.Monitor.Linux",
                $"{current.Name} (pid {current.Pid}) is orphaned — parent {deleted?.Name ?? "unknown"} " +
                $"(pid {parentPid}) exited [harness: {harness.HarnessType ?? harness.Name}]",
                current.Pid,
                current.Name,
                parentPid,
                deleted?.Name ?? "unknown",
                current.UptimeMinutes,
                harness.Pid,
                harness.HarnessType,
                harness.Name) { ProcessStartTime = current.StartTime });
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch { }
    }

    private void Analyze(ProcessRecord record)
    {
        try
        {
            var profile = ResolveProfile(record);
            var match = CommandAnalyzer.Instance.Analyze(record.CommandLine, record.Name, profile);
            _violations.CheckCommandLine(record, match);
            if (match is null) return;

            var now = DateTimeOffset.UtcNow;
            var severity = match.Severity;
            var message = $"[{match.RuleId}] {match.RuleName}: {Truncate(record.CommandLine)}";
            if (match.Category is "cred" or "net"
                && Tree.FindInstallAncestor(record.Pid) is { } install
                && Tree.FindHarnessTypeAncestor(record.Pid) is { } owner)
            {
                severity = Severities.EscalateOneLevel(severity);
                message = $"[{match.RuleId}] {match.RuleName} during a package install " +
                          $"({Truncate(install.CommandLine)}) under {owner.HarnessType}: {Truncate(record.CommandLine)}";
            }

            _bus.Publish(new CommandAlertEvent(
                now, severity, $"{record.Name} (pid {record.Pid})", message,
                record.CommandLine, match.RuleId, match.RuleName, match.Description, match.Guidance,
                record.Pid) { ProcessStartTime = record.StartTime });

            if (match.Category != "cred") return;
            var harness = Tree.FindHarnessTypeAncestor(record.Pid);
            var sweepRule = match.RuleId == "cred-013-harness" ? "cred-013" : match.RuleId;
            if (_credentialSweep.Observe((harness ?? record).Key, sweepRule, now) is not { } swept) return;

            var who = harness?.HarnessType ?? record.Name;
            _bus.Publish(new CommandAlertEvent(
                now, ForemanSeverity.Critical, $"{who} (pid {record.Pid})",
                $"Credential-store sweep: {swept.Count} distinct stores read by {who} " +
                $"within {_settings.CredentialSweepWindowSeconds}s ({string.Join(", ", swept)}).",
                record.CommandLine, "cred-sweep", "Credential-store sweep",
                "One harness tree read several credential stores in quick succession.",
                "Stop and inspect the process, preserve evidence, and rotate credentials it could have read.",
                record.Pid) { ProcessStartTime = record.StartTime });
        }
        catch { }
    }

    private async Task PollIoAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(1, _settings.IoPollerIntervalSeconds)));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                foreach (var record in Tree.GetAll())
                {
                    if (_io.TryReadIo(record.Pid, out var reads, out var writes, out var reason))
                    {
                        Tree.UpdateIoCounters(record.Pid, reads, writes);
                        record.IoCountersUnavailable = false;
                    }
                    else
                    {
                        record.IoCountersUnavailable = true;
                        if (!_ioDegradedReported && !string.IsNullOrWhiteSpace(reason))
                        {
                            _ioDegradedReported = true;
                            _bus.Publish(new MonitoringNoticeEvent(
                                DateTimeOffset.UtcNow, ForemanSeverity.Low, "Foreman.Monitor.Linux",
                                $"Some /proc I/O counters are unavailable ({reason}); hang detection degrades safely for those processes."));
                        }
                    }
                    _hangDetector.Check(record);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    private void ClassifyAndProfile(ProcessRecord record)
    {
        HarnessClassifier.Classify(record, _settings.DisabledHarnesses, _settings.CustomHarnessExes);
        if (Profiles.Match(record) is { } profile)
            record.ProfileName = profile.Name;
        else if (record.HarnessType is { } harnessId
                 && HarnessIntegrationRegistry.GetDefaultProfileName(harnessId) is { } defaultProfile
                 && Profiles.Get(defaultProfile) is not null)
            record.ProfileName = defaultProfile;
    }

    private void ApplyProfileInheritance(ProcessRecord record)
    {
        if (record.ProfileName is not null) return;
        if (Tree.FindProfileAncestor(record.ParentPid)?.ProfileName is { } inherited)
            record.ProfileName = inherited;
    }

    private HarnessProfile? ResolveProfile(ProcessRecord record)
    {
        if (record.ProfileName is not null && Profiles.Get(record.ProfileName) is { } existing)
            return existing;
        ClassifyAndProfile(record);
        ApplyProfileInheritance(record);
        return record.ProfileName is null ? null : Profiles.Get(record.ProfileName);
    }

    private void CheckForemanImpersonation(ProcessRecord record)
    {
        if (!string.Equals(record.Name, "foreman-agent", StringComparison.OrdinalIgnoreCase)) return;
        var ownPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(ownPath) || string.IsNullOrWhiteSpace(record.ExecutablePath)) return;
        if (Path.GetFullPath(record.ExecutablePath) == Path.GetFullPath(ownPath)) return;
        _bus.Publish(new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Integrity",
            $"A process named foreman-agent (pid {record.Pid}) is running from '{record.ExecutablePath}', not '{ownPath}'."));
    }

    private static string Truncate(string value, int max = 160) =>
        value.Length <= max ? value : value[..max] + "…";

    public void Dispose()
    {
        _stop.Cancel();
        try { _ioLoop?.GetAwaiter().GetResult(); }
        catch (OperationCanceledException) { }
        _events.ProcessStarted -= OnProcessStarted;
        _events.ProcessExited -= OnProcessExited;
        _events.Dispose();
        McpInventory.Dispose();
        _profileStore.Dispose();
        _stop.Dispose();
    }
}
