using Foreman.App.Tray;
using Foreman.App.Windows;
using Foreman.Core.Events;
using Foreman.Core.Heuristics;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.McpServer;
using Foreman.Monitor;
using System.Threading;
using System.Windows;

namespace Foreman.App;

public partial class App : Application
{
    private static readonly Mutex _singleInstance = new(true, "ForemanSingleInstanceMutex");
    private TrayController? _tray;
    private MonitorService? _monitor;
    private McpServerHost? _mcpHost;
    private ElevatedSidecarController? _sidecar;
    private McpToolScanMonitor? _toolScan;
    private CancellationTokenSource? _cts;

    protected override void OnStartup(StartupEventArgs e)
    {
        if (!_singleInstance.WaitOne(0, false))
        {
            MessageBox.Show("Foreman is already running.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        base.OnStartup(e);

        var settings = SettingsStore.Load();
        _cts = new CancellationTokenSource();

        PatternLibrary.Instance.Initialize();

        _tray = new TrayController(settings, EventBus.Instance);
        _tray.Initialize();

        _monitor = new MonitorService(settings, EventBus.Instance);
        _monitor.Start();

        _mcpHost = new McpServerHost(settings, EventBus.Instance);
        // Lock the MCP token file to the current user so another principal on the box can't read it.
        TokenFileProtector.RestrictToCurrentUser(_mcpHost.TokenFilePath);

        // wire monitor's live process snapshot into MCP state and tray Harnesses window
        _mcpHost.State.GetProcessSnapshot    = () => _monitor.Tree.GetAll();
        _mcpHost.State.GetBehaviorProfiles   = () => _monitor.Behavior.Profiles;
        _mcpHost.State.ResetBehaviorProfile  = id => _monitor.Behavior.ResetProfile(id);
        _mcpHost.State.GetProfileByName      = name => _monitor.Profiles.Get(name);
        _mcpHost.State.GetDefaultProfileNameByHarnessId = Foreman.Core.Models.HarnessIntegrationRegistry.GetDefaultProfileName;
        _mcpHost.State.FindHarnessAncestorByPid = pid => _monitor.Tree.FindHarnessTypeAncestor(pid);
        _mcpHost.State.GetMcpInventory       = () => _monitor.McpInventory.Current;
        _tray.GetProcessSnapshot            = () => _monitor.Tree.GetAll();
        _tray.GetMcpClientCount             = () => _mcpHost.Sessions.Count;
        _tray.GetMcpToken                   = () => _mcpHost.McpToken;
        _tray.GetConnectedClients           = () => _mcpHost.Sessions.DescribeSessions();

        // allow AlertDetailWindow to resolve a live ProcessRecord from a PID
        // so the ORIGINATING PROCESS section can show process name + harness type
        AlertDetailWindow.GetProcessByPid      = pid => _monitor.Tree.GetByPid(pid);
        // allow it to also show the harness's current escalation level + session alert count
        AlertDetailWindow.GetProfileByHarness  = id  => _monitor.Behavior.GetProfile(id);
        // attribute hook / spawned-shell processes to the harness they descend from
        AlertDetailWindow.GetHarnessAncestorByPid = pid => _monitor.Tree.FindHarnessTypeAncestor(pid);
        AlertDetailWindow.GetProcessSnapshot = () => _monitor.Tree.GetAll();
        AlertDetailWindow.GetLlmTriageSettings = () => settings.LlmTriage;
        AlertDetailWindow.KillProcessByPid = (pid, startTime) => _monitor.Tree.KillProcess(pid, startTime);
        AlertDetailWindow.QueueAskHarnessRequest = (harnessId, sys, usr, alertId, pid, processName) =>
            _mcpHost.State.CreateAskHarnessRequest(harnessId, sys, usr, alertId, pid, processName);
        AlertDetailWindow.RecordAskHarnessReply = (requestId, reply, actionTaken, harnessId, pid) =>
            _mcpHost.State.ReplyToAskHarnessRequest(requestId, reply, actionTaken, harnessId, pid).Ok;
        // Ask Harness delivers a justify/act prompt to the offender's own MCP session when reachable.
        AlertDetailWindow.AskOffender = (harnessId, sys, usr, requestId, ct) =>
            _mcpHost.Sessions.AskOffenderAsync(harnessId, sys, usr, requestId, ct);

        // wire behavior tracker into tray (metrics window + kill + disable actions)
        _tray.GetBehaviorProfiles   = () => _monitor.Behavior.Profiles;
        _tray.ResetBehaviorProfile  = id => _monitor.Behavior.ResetProfile(id);
        _tray.GetProcessesByHarness = type => _monitor.Tree.GetByHarnessType(type);
        _tray.KillHarness           = type => _monitor.Tree.KillHarness(type);
        _tray.DisableHarness        = id =>
        {
            settings.DisabledHarnesses.Add(id);
            SettingsStore.Save(settings);
        };

        // Optional elevated, capture-only ETW network sidecar. Only this sidecar runs elevated;
        // the app stays at medium IL. Off unless the user opts in (Settings → Run elevated).
        _sidecar = new ElevatedSidecarController();
        if (settings.RunElevated) _sidecar.Start();
        _tray.GetNetRate = pid => _sidecar.GetRate(pid);
        _tray.GetNetCaptureActive = () => _sidecar?.IsConnected ?? false;
        // SettingsWindow already persists the flag; this just starts/stops the sidecar
        // (enabling raises the UAC prompt for the sidecar).
        _tray.ApplyRunElevated = on =>
        {
            if (on) _sidecar.Start(); else _sidecar.Stop();
        };

        // Tier 1 (opt-in): MCP tool-description injection scan. Constructed always so the Settings
        // toggle can start/stop it at runtime, but it only connects out when enabled. When off, the
        // ListMcpToolFindings MCP tool reports "scanning disabled" (GetMcpToolScan stays null).
        _toolScan = new McpToolScanMonitor(EventBus.Instance, () => _monitor.McpInventory.Current, settings.McpPort);
        void ApplyScanMcpTools(bool on)
        {
            if (on)
            {
                _mcpHost.State.GetMcpToolScan = () => (_toolScan!.Current, _toolScan.LastSummary);
                _toolScan!.Start();
            }
            else
            {
                _toolScan!.Stop();
                _mcpHost.State.GetMcpToolScan = null;
            }
        }
        _tray.ApplyScanMcpTools = ApplyScanMcpTools;
        ApplyScanMcpTools(settings.ScanMcpTools);

        // start MCP on a background thread so we don't block the WPF message pump
        _ = _mcpHost.StartAsync(_cts.Token);

        // publish startup event — this ensures the log window always has at least one entry
        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman",
            $"Monitoring started · MCP on :{settings.McpPort} · " +
            $"{KnownHarnesses.All.Count} built-in harness types" +
            (settings.CustomHarnessExes.Count > 0 ? $" + {settings.CustomHarnessExes.Count} custom" : "")));

        // first-run dialog deferred to idle so it doesn't block server startup
        var port = settings.McpPort;
        var mcpToken = _mcpHost.McpToken;
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.ApplicationIdle,
            () => FirstRunDetector.RunIfNeeded(port, mcpToken, () => _mcpHost.Sessions.DescribeSessions()));
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _cts?.Cancel();
        _toolScan?.Dispose();
        _sidecar?.Dispose();
        _mcpHost?.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(3));
        _monitor?.Dispose();
        _tray?.Dispose();
        _singleInstance.ReleaseMutex();
        base.OnExit(e);
    }
}
