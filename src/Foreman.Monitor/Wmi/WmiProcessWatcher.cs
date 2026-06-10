using Foreman.Core.Events;
using Foreman.Core.Heuristics;
using Foreman.Core.Models;
using Foreman.Core.Profiles;
using Foreman.Core.Settings;
using System.Collections.Generic;
using System.Globalization;
using System.Management;

namespace Foreman.Monitor.Wmi;

/// <summary>
/// Listens for process creation and termination via WMI event subscriptions.
/// Fires at medium IL (no admin required). ~1s latency vs. ETW, acceptable for Phase 1.
/// </summary>
public sealed class WmiProcessWatcher : IDisposable
{
    private readonly ProcessTreeTracker _tree;
    private readonly EventBus _bus;
    private readonly ForemanSettings _settings;
    private readonly ProfileMatcher? _profileMatcher;
    private readonly ViolationDetector? _violationDetector;
    private ManagementEventWatcher? _createWatcher;
    private ManagementEventWatcher? _deleteWatcher;
    private bool _started;

    private readonly object _armLock = new();
    private volatile bool _healthy;
    private bool _degraded;          // have we already announced degradation? (guards notice spam)
    private Timer? _watchdog;
    private volatile bool _disposed;

    public WmiProcessWatcher(
        ProcessTreeTracker tree,
        EventBus bus,
        ForemanSettings settings,
        ProfileMatcher? profileMatcher = null,
        ViolationDetector? violationDetector = null)
    {
        _tree = tree;
        _bus = bus;
        _settings = settings;
        _profileMatcher = profileMatcher;
        _violationDetector = violationDetector;
    }

    public void Start()
    {
        if (_started) return;
        _started = true;

        // initial snapshot — detect already-running harnesses before WMI watchers start
        Task.Run(RunInitialScan);

        ArmWatchers();

        // Watchdog: a WMI event sink can die silently (WMI service restart, COM fault) — which used to
        // end process monitoring with no signal. Re-arm any stopped watcher so detection recovers instead
        // of going quietly dark. Cheap: only does work when a watcher is known-unhealthy.
        _watchdog = new Timer(_ => Watchdog(), null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>Creates (or recreates) and starts both WMI watchers. Safe to call repeatedly.</summary>
    private void ArmWatchers()
    {
        lock (_armLock)
        {
            if (_disposed) return;
            try
            {
                TeardownWatchers();   // detach + dispose any previous instances first

                // process creation — WITHIN 1 means polling every 1 second
                _createWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"));
                _createWatcher.EventArrived += OnProcessCreated;
                _createWatcher.Stopped += OnWatcherStopped;
                _createWatcher.Start();

                // process termination — 2s is fine since we track final state
                _deleteWatcher = new ManagementEventWatcher(
                    new WqlEventQuery("SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'"));
                _deleteWatcher.EventArrived += OnProcessDeleted;
                _deleteWatcher.Stopped += OnWatcherStopped;
                _deleteWatcher.Start();

                _healthy = true;
                if (_degraded)   // recovered from a previous failure
                {
                    _degraded = false;
                    _bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Monitor",
                        "Process monitoring recovered — WMI watchers restarted."));
                }
            }
            catch (Exception ex)
            {
                _healthy = false;
                TeardownWatchers();   // don't leave a half-armed state
                if (!_degraded)
                {
                    _degraded = true;
                    _bus.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Monitor",
                        $"Process monitoring is DEGRADED — WMI watchers failed to start ({ex.Message}). " +
                        "Hang/orphan/command detection is paused; Foreman will keep retrying every 30s."));
                }
            }
        }
    }

    private void TeardownWatchers()
    {
        // Detach BEFORE Stop()/Dispose() so our own intentional teardown never trips OnWatcherStopped.
        if (_createWatcher is not null)
        {
            _createWatcher.EventArrived -= OnProcessCreated;
            _createWatcher.Stopped -= OnWatcherStopped;
            try { _createWatcher.Stop(); } catch { }
            _createWatcher.Dispose();
            _createWatcher = null;
        }
        if (_deleteWatcher is not null)
        {
            _deleteWatcher.EventArrived -= OnProcessDeleted;
            _deleteWatcher.Stopped -= OnWatcherStopped;
            try { _deleteWatcher.Stop(); } catch { }
            _deleteWatcher.Dispose();
            _deleteWatcher = null;
        }
    }

    // Fires on unexpected stops (we detach before our own teardown, so this is always involuntary).
    // Mark unhealthy; the watchdog re-arms on its next tick.
    private void OnWatcherStopped(object sender, StoppedEventArgs e)
    {
        if (!_disposed) _healthy = false;
    }

    private void Watchdog()
    {
        if (_disposed || _healthy) return;
        ArmWatchers();
    }

    private void RunInitialScan()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name, CommandLine, ExecutablePath, CreationDate " +
                "FROM Win32_Process");

            var harnessesFound = new List<string>();

            foreach (ManagementObject proc in searcher.Get())
            {
                try
                {
                    using var _ = proc;
                    var record = BuildRecord(proc);
                    _tree.OnProcessCreated(record);

                    if (record.HarnessType is not null)
                        harnessesFound.Add($"{record.HarnessType} (pid {record.Pid})");
                }
                catch { /* process may have exited mid-scan */ }
            }

            var msg = harnessesFound.Count > 0
                ? $"Initial scan — {harnessesFound.Count} harness process(es) already running: {string.Join(", ", harnessesFound)}"
                : "Initial scan complete — no harnesses currently running";

            _bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Monitor", msg));
        }
        catch (Exception ex)
        {
            _bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Monitor",
                $"Initial process scan failed: {ex.Message}"));
        }
    }

    private void OnProcessCreated(object sender, EventArrivedEventArgs e)
    {
        try
        {
            using var proc = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var record = BuildRecord(proc);
            _tree.OnProcessCreated(record);
            ApplyProfileInheritance(record);

            // heuristic analysis on the thread pool — don't block the WMI callback
            if (!string.IsNullOrWhiteSpace(record.CommandLine))
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    var profile = ResolveProfile(record);
                    var match = CommandAnalyzer.Instance.Analyze(record.CommandLine, record.Name, profile);
                    _violationDetector?.CheckCommandLine(record, match);
                    if (match is null) return;

                    _bus.Publish(new CommandAlertEvent(
                        DateTimeOffset.UtcNow,
                        match.Severity,
                        $"{record.Name} (pid {record.Pid})",
                        $"[{match.RuleId}] {match.RuleName}: {TruncateCmdLine(record.CommandLine)}",
                        record.CommandLine,
                        match.RuleId,
                        match.RuleName,
                        match.Description,
                        match.Guidance,
                        record.Pid
                    ) { ProcessStartTime = record.StartTime });
                });
            }
        }
        catch (ManagementException) { /* process died before we could read it */ }
        catch (Exception) { /* never crash the watcher thread */ }
    }

    private void OnProcessDeleted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            using var proc = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            var pid = Convert.ToInt32(proc["ProcessId"]);
            var name = proc["Name"]?.ToString() ?? string.Empty;
            var exitCode = proc["ExitCode"] is uint code ? (int)code : 0;
            var startTime = ParseDmtfDate(proc["CreationDate"]?.ToString());

            var orphans = _tree.OnProcessDeleted(pid, startTime, out var deleted);

            // publish orphan events for any children that survived
            foreach (var orphan in orphans)
            {
                _bus.Publish(new OrphanDetectedEvent(
                    DateTimeOffset.UtcNow,
                    "Foreman.Monitor",
                    $"{orphan.Name} (pid {orphan.Pid}) is orphaned — parent {name} (pid {pid}) exited",
                    orphan.Pid,
                    orphan.Name,
                    pid,
                    name,
                    orphan.UptimeMinutes
                ) { ProcessStartTime = orphan.StartTime });
            }

            // flag nonzero exits from harness-classified processes
            if (exitCode != 0 && deleted?.IsHarness == true)
            {
                _bus.Publish(new NonzeroExitEvent(
                    DateTimeOffset.UtcNow,
                    "Foreman.Monitor",
                    $"{name} (pid {pid}) exited with code {exitCode}",
                    pid, name, exitCode, null
                ));
            }
        }
        catch { }
    }

    private ProcessRecord BuildRecord(ManagementBaseObject proc)
    {
        var pid = Convert.ToInt32(proc["ProcessId"]);
        var parentPid = Convert.ToInt32(proc["ParentProcessId"]);
        var name = proc["Name"]?.ToString() ?? string.Empty;
        var cmdLine = proc["CommandLine"]?.ToString() ?? string.Empty;
        var exePath = proc["ExecutablePath"]?.ToString() ?? string.Empty;

        // WMI CreationDate is a DMTF datetime string
        var startTime = ParseDmtfDate(proc["CreationDate"]?.ToString());

        var record = new ProcessRecord
        {
            Pid = pid,
            ParentPid = parentPid,
            Name = name,
            CommandLine = cmdLine,
            ExecutablePath = exePath,
            StartTime = startTime,
            LastIoChangeTime = DateTimeOffset.UtcNow,
        };

        HarnessClassifier.Classify(record, _settings.DisabledHarnesses, _settings.CustomHarnessExes);
        ApplyDirectProfile(record);
        return record;
    }

    private static DateTimeOffset ParseDmtfDate(string? dmtf)
    {
        if (string.IsNullOrEmpty(dmtf))
            return DateTimeOffset.UtcNow;

        if (TryParseDmtfDateTimeOffset(dmtf, out var parsed))
            return parsed;

        try
        {
            var local = ManagementDateTimeConverter.ToDateTime(dmtf);
            if (local.Kind == DateTimeKind.Unspecified)
                local = DateTime.SpecifyKind(local, DateTimeKind.Local);
            return new DateTimeOffset(local);
        }
        catch
        {
            return DateTimeOffset.UtcNow;
        }
    }

    private static bool TryParseDmtfDateTimeOffset(string dmtf, out DateTimeOffset value)
    {
        value = default;
        if (dmtf.Length < 25 || dmtf[14] != '.')
            return false;

        var sign = dmtf[21];
        if (sign is not ('+' or '-'))
            return false;

        try
        {
            var year = ParseInt(dmtf, 0, 4);
            var month = ParseInt(dmtf, 4, 2);
            var day = ParseInt(dmtf, 6, 2);
            var hour = ParseInt(dmtf, 8, 2);
            var minute = ParseInt(dmtf, 10, 2);
            var second = ParseInt(dmtf, 12, 2);
            var microsecond = ParseInt(dmtf, 15, 6);
            var offsetMinutes = ParseInt(dmtf, 22, 3);
            if (sign == '-') offsetMinutes = -offsetMinutes;

            value = new DateTimeOffset(
                year, month, day, hour, minute, second,
                TimeSpan.FromMinutes(offsetMinutes)).AddTicks(microsecond * 10L);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int ParseInt(string value, int start, int length) =>
        int.Parse(value.AsSpan(start, length), NumberStyles.None, CultureInfo.InvariantCulture);

    private void ApplyDirectProfile(ProcessRecord record)
    {
        if (_profileMatcher?.Match(record) is { } profile)
            record.ProfileName = profile.Name;
    }

    private void ApplyProfileInheritance(ProcessRecord record)
    {
        if (record.ProfileName is not null) return;
        if (_tree.FindProfileAncestor(record.Pid)?.ProfileName is { } profileName)
            record.ProfileName = profileName;
    }

    private HarnessProfile? ResolveProfile(ProcessRecord record)
    {
        if (record.ProfileName is not null && _profileMatcher?.Get(record.ProfileName) is { } byName)
            return byName;
        ApplyDirectProfile(record);
        ApplyProfileInheritance(record);
        return record.ProfileName is not null
            ? _profileMatcher?.Get(record.ProfileName)
            : null;
    }

    private static string TruncateCmdLine(string cmd, int max = 120) =>
        cmd.Length <= max ? cmd : cmd[..max] + "…";

    public void Dispose()
    {
        _disposed = true;
        _watchdog?.Dispose();
        lock (_armLock)
            TeardownWatchers();
    }
}
