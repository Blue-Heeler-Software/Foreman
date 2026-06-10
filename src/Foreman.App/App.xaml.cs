using Foreman.App.Tray;
using Foreman.App.Windows;
using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
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
    private static Mutex? _singleInstance;
    private static bool _ownsSingleInstance;
    private TrayController? _tray;
    private MonitorService? _monitor;
    private McpServerHost? _mcpHost;
    private ElevatedSidecarController? _sidecar;
    private McpToolScanMonitor? _toolScan;
    private AlertResolver? _alertResolver;
    private AlertResponseRunner? _alertResponseRunner;
    private CancellationTokenSource? _cts;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Track ownership explicitly: the second instance must NOT call ReleaseMutex in
        // OnExit (releasing an unowned mutex throws and crashed the duplicate on exit).
        _singleInstance = new Mutex(initiallyOwned: true, "ForemanSingleInstanceMutex", out _ownsSingleInstance);
        if (!_ownsSingleInstance)
        {
            MessageBox.Show("Foreman Agent Safety is already running.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        base.OnStartup(e);

        var settings = SettingsStore.Load();
        _cts = new CancellationTokenSource();

        // If "start with Windows" is on but the install moved (registered exe gone),
        // re-point the HKCU Run entry at the exe that's actually running. Best-effort.
        StartupManager.RepairIfNeeded();

        PatternLibrary.Instance.Initialize();

        // Durable event log: persist every published event to disk (JSONL) so the Event Log tab
        // survives restarts. Subscribe before anything publishes. The Log VIEW merges these
        // prior-session events with the in-memory session history; EventBus history stays
        // session-scoped so reloading the log never resurrects old alerts as "active".
        if (settings.EventLogPersist)
        {
            var eventLog = new EventLogStore();
            EventBus.Instance.Subscribe(e => eventLog.Append(e));
            LogWindow.LoadPersisted = () => eventLog.Load();
        }

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
        _tray.MintHarnessToken              = id => _mcpHost.MintHarnessToken(id);
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
        // Click-to-mute: persist an operator mute (notification suppression only; guardrailed by MutePolicy).
        AlertDetailWindow.AddMute = m => { settings.Mutes.Add(m); SettingsStore.Save(settings); };
        AlertDetailWindow.GetEmergencyRuleIds = () => settings.EmergencyRuleIds;
        AlertDetailWindow.QueueAskHarnessRequest = (harnessId, sys, usr, alertId, pid, processName) =>
            _mcpHost.State.CreateAskHarnessRequest(harnessId, sys, usr, alertId, pid, processName);
        AlertDetailWindow.RecordAskHarnessReply = (requestId, reply, actionTaken, harnessId, pid) =>
            _mcpHost.State.ReplyToAskHarnessRequest(requestId, reply, actionTaken, harnessId, pid).Ok;
        // Ask Harness delivers a justify/act prompt to the offender's own MCP session when reachable.
        AlertDetailWindow.AskOffender = (harnessId, sys, usr, requestId, ct) =>
            _mcpHost.Sessions.AskOffenderAsync(harnessId, sys, usr, requestId, ct);

        // Idle Harness self-cleanup: detector (Monitor) ↔ Ask-Harness mailbox + live push (McpServer).
        // The cleanup request rides the same mailbox agents already poll (ListAskHarnessRequests).
        _monitor.IdleCleanup.CreateCleanupRequest = (harnessId, alertId, sys, usr, pid, name) =>
            _mcpHost.State.CreateAskHarnessRequest(harnessId, sys, usr, alertId, pid, name).RequestId;
        _monitor.IdleCleanup.IsRequestPending = id =>
            _mcpHost.State.GetAskHarnessRequest(id)?.Status == "pending";
        _monitor.IdleCleanup.PushToOffender = async (harnessId, sys, usr, requestId) =>
        {
            var res = await _mcpHost.Sessions.AskOffenderAsync(harnessId, sys, usr, requestId).ConfigureAwait(false);
            if (res.Outcome == AskOutcome.Sampled && !string.IsNullOrWhiteSpace(res.ReplyText))
                _mcpHost.State.ReplyToAskHarnessRequest(requestId, res.ReplyText!, "replied via sampling round-trip", harnessId, null);
        };
        _tray.RequestHarnessCleanup = type => _monitor.IdleCleanup.TriggerCleanup(type);

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

        // Alert lifecycle: periodically auto-resolve alerts whose condition has cleared (a hung process
        // resumed I/O or exited, an orphan exited, a nonzero-exit aged out) so the tray doesn't stay
        // amber forever. It flags the shared event instances, so tray, dashboard, and MCP all agree.
        _alertResolver = new AlertResolver(
            EventBus.Instance,
            () => EventBus.Instance.GetHistory(),
            () => _monitor.Tree.GetAll().ToList());
        _alertResolver.Start();

        // Automatic responses (Settings → Automatic responses): when a harness escalates, fire the
        // operator-configured non-destructive actions. Decision + guardrails live in AlertResponsePolicy;
        // these delegates reuse the existing mailbox, audit routing, and idle-cleanup plumbing.
        _alertResponseRunner = new AlertResponseRunner(settings)
        {
            AskHarness = esc =>
            {
                var (sys, usr) = BuildEscalationAskPrompt(esc);
                var req = _mcpHost!.State.CreateAskHarnessRequest(esc.HarnessId, sys, usr, esc.Id, null, null);
                _ = SafeAsk(esc.HarnessId, sys, usr, req.RequestId);
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.AutoResponse",
                    $"Auto-response [{esc.NewLevel}]: asked '{esc.HarnessId}' to justify its escalation (request {req.RequestId})."));
            },
            AdversarialAudit = esc =>
            {
                var severity = esc.NewLevel >= EscalationLevel.Emergency ? ForemanSeverity.Critical : ForemanSeverity.High;
                var auditor = settings.LlmTriage.SelectAuditor(esc.HarnessId, severity);
                if (auditor is null)
                {
                    EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.AutoResponse",
                        $"Auto-audit skipped for '{esc.HarnessId}' [{esc.NewLevel}]: no eligible auditor configured (Settings → LLM triage)."));
                    return;
                }
                var (sys, usr) = BuildEscalationAuditPrompt(esc, auditor.AuditorId);
                var req = _mcpHost!.State.CreateAskHarnessRequest(auditor.AuditorId, sys, usr, esc.Id, null, null);
                _ = SafeAsk(auditor.AuditorId, sys, usr, req.RequestId);
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.AutoResponse",
                    $"Auto-response [{esc.NewLevel}]: routed '{esc.HarnessId}' to auditor '{auditor.AuditorId}' for review (request {req.RequestId})."));
            },
            RequestSelfCleanup = esc =>
            {
                var (_, msg) = _monitor!.IdleCleanup.TriggerCleanup(esc.HarnessId, manual: false);
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.AutoResponse",
                    $"Auto-response [{esc.NewLevel}]: {msg}"));
            },
        };
        EventBus.Instance.Subscribe(_alertResponseRunner);

        // Start MCP on a background thread so we don't block the WPF message pump — but never
        // silently: a bind failure (port in use) used to leave Foreman looking healthy with no
        // MCP at all. Surface it as a High notice so the tray goes red and the log explains.
        var mcpPort = settings.McpPort;
        _ = StartMcpSurfacingFailureAsync(_mcpHost, mcpPort, _cts.Token);

        // publish startup event — this ensures the log window always has at least one entry
        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman",
            $"Monitoring started · MCP on :{settings.McpPort} · " +
            $"{KnownHarnesses.All.Count} built-in harness types" +
            (settings.CustomHarnessExes.Count > 0 ? $" + {settings.CustomHarnessExes.Count} custom" : "")));

        // If settings.json was unreadable at launch it was quarantined and defaults loaded. Surface that
        // now (the bus + event log are wired) so a corrupt file isn't a silent reset of security posture.
        if (SettingsStore.LastLoadFault is { } settingsFault)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.Settings", settingsFault));

        // first-run dialog deferred to idle so it doesn't block server startup
        var port = settings.McpPort;
        var mcpToken = _mcpHost.McpToken;
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.ApplicationIdle,
            () => FirstRunDetector.RunIfNeeded(port, mcpToken, () => _mcpHost.Sessions.DescribeSessions(),
                id => _mcpHost.MintHarnessToken(id)));
    }

    // Best-effort live delivery of an auto-response prompt to the target's MCP session; the mailbox copy
    // (already created) remains regardless. Records a sampling round-trip reply when one comes back.
    private async Task SafeAsk(string harnessId, string systemPrompt, string userPrompt, string requestId)
    {
        try
        {
            var res = await _mcpHost!.Sessions.AskOffenderAsync(harnessId, systemPrompt, userPrompt, requestId).ConfigureAwait(false);
            if (res.Outcome == AskOutcome.Sampled && !string.IsNullOrWhiteSpace(res.ReplyText))
                _mcpHost.State.ReplyToAskHarnessRequest(requestId, res.ReplyText!, "replied via sampling round-trip", harnessId, null);
        }
        catch { /* best-effort — mailbox copy persists */ }
    }

    private static (string System, string User) BuildEscalationAskPrompt(EscalationEvent esc)
    {
        var system =
            $"You are the '{esc.HarnessId}' coding agent. Foreman Agent Safety (the local watchdog) escalated you " +
            $"to {esc.NewLevel} based on your recent activity. This is a self-audit prompt — answer honestly and briefly.";
        var user =
            $"Foreman escalated you to {esc.NewLevel}: {esc.TotalAlerts} alert(s), {esc.UniqueRules} distinct rule(s), " +
            $"triggered by [{esc.TriggerRuleId}] {esc.TriggerRuleName}. Explain what you were doing and whether it is " +
            "expected, then justify it or take corrective action. " +
            $"Reply via ReplyToAskHarnessRequest(requestId, response, actionTaken, harnessId: \"{esc.HarnessId}\").";
        return (system, user);
    }

    private static (string System, string User) BuildEscalationAuditPrompt(EscalationEvent esc, string auditorId)
    {
        var system =
            $"You are '{auditorId}', acting as an INDEPENDENT auditor for Foreman Agent Safety. Review ANOTHER agent's " +
            "behavior objectively — weigh the evidence rather than assuming it is benign or malicious.";
        var user =
            $"Foreman escalated the '{esc.HarnessDisplayName}' agent to {esc.NewLevel}: {esc.TotalAlerts} alert(s), " +
            $"{esc.UniqueRules} rule(s) across categories [{string.Join(", ", esc.CategoryList)}], triggered by " +
            $"[{esc.TriggerRuleId}] {esc.TriggerRuleName}. Independently assess whether this looks dangerous, the likely " +
            "intent, and recommend an action (allow / keep watching / stop the harness / escalate to the operator). " +
            $"Reply via ReplyToAskHarnessRequest(requestId, response, actionTaken, harnessId: \"{auditorId}\").";
        return (system, user);
    }

    private static async Task StartMcpSurfacingFailureAsync(McpServerHost host, int port, CancellationToken ct)
    {
        try
        {
            await host.StartAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
        catch (Exception ex)
        {
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Mcp",
                $"MCP server failed to start on port {port}: {ex.Message} " +
                "Agent connections, Ask Harness, and audits are unavailable. " +
                "Is another Foreman instance or app using the port? Change the port in Settings and restart."));
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _cts?.Cancel();
        _alertResolver?.Dispose();
        _toolScan?.Dispose();
        _sidecar?.Dispose();
        _mcpHost?.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(3));
        _monitor?.Dispose();
        _tray?.Dispose();
        if (_ownsSingleInstance) _singleInstance?.ReleaseMutex();
        base.OnExit(e);
    }
}
