using Foreman.App.Tray;
using Foreman.App.Windows;
using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Heuristics;
using Foreman.Core.Models;
using Foreman.Core.Notifications;
using Foreman.Core.Security;
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
    // Blackbox handoff: Foreman's own lifecycle + significant events mirrored to the OS event log (Defender-style),
    // so the record survives the app being killed/tampered. Null sink until OnStartup picks the platform impl.
    private IOsEventLogSink _osLog = NullOsEventLogSink.Instance;
    // Gate for the DIRECT lifecycle/crash writes (the bus forwarder has its own gate). Defaults true so an early
    // crash before settings load is still recorded; set from settings.OsEventLog.Enabled once loaded so the
    // operator's opt-out is honoured for stop + crash too, not just start.
    private bool _osLogEnabled = true;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Track ownership explicitly: the second instance must NOT call ReleaseMutex in
        // OnExit (releasing an unowned mutex throws and crashed the duplicate on exit).
        _singleInstance = new Mutex(initiallyOwned: true, "ForemanSingleInstanceMutex", out _ownsSingleInstance);
        if (!_ownsSingleInstance)
        {
            // Record the blocked duplicate launch to the OS log (best-effort, transient sink — _osLog isn't set
            // up on this early-exit path). A burst of these can indicate a relaunch loop or tampering.
            try
            {
                new WindowsEventLogSink().Write(OsEventIds.SecondInstanceBlocked, OsEventCategory.Lifecycle,
                    ForemanSeverity.Info, $"A second Foreman instance was blocked (pid {Environment.ProcessId}).");
            }
            catch { /* never let the duplicate-exit path throw */ }
            MessageBox.Show("Foreman Agent Safety is already running.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        base.OnStartup(e);

        // Pick the OS event-log sink before wiring crash handlers, so a crash on the way up is still handed off.
        _osLog = new WindowsEventLogSink();

        // A tray watchdog must survive transient UI faults (e.g. a flaky Shell_NotifyIcon tray call) and
        // RECORD them, not crash. Recover on the dispatcher thread; log everything (incl. truly-fatal ones).
        DispatcherUnhandledException += (_, args) =>
        {
            CrashLog.Note("DispatcherUnhandledException", args.Exception);
            // Redact: an exception .Message can echo secret-bearing input (URLs with userinfo, KEY=token, …).
            if (_osLogEnabled)
                _osLog.Write(OsEventIds.CrashHandled, OsEventCategory.Lifecycle, ForemanSeverity.High,
                    SecretRedactor.Redact($"Foreman recovered from an unhandled UI exception: {args.Exception.GetType().Name}: {args.Exception.Message}"));
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
            {
                CrashLog.Note("AppDomain.UnhandledException (fatal)", ex);
                if (_osLogEnabled)
                    _osLog.Write(OsEventIds.CrashFatal, OsEventCategory.Lifecycle, ForemanSeverity.Critical,
                        SecretRedactor.Redact($"Foreman is terminating on an unhandled exception: {ex.GetType().Name}: {ex.Message}"));
            }
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            CrashLog.Note("TaskScheduler.UnobservedTaskException", args.Exception);
            if (_osLogEnabled)
                _osLog.Write(OsEventIds.CrashUnobservedTask, OsEventCategory.Lifecycle, ForemanSeverity.High,
                    SecretRedactor.Redact($"Foreman observed a faulted background task: {args.Exception.GetType().Name}: {args.Exception.Message}"));
            args.SetObserved();
        };

        // Seal the security-significant settings with the install secret BEFORE loading, so the load can detect a
        // direct (non-Foreman) edit of settings.json — the same-user agent's way around the UI presence gates.
        var installSecret = new McpAuthToken().Value;
        SettingsStore.IntegritySecret = () => installSecret;

        var settings = SettingsStore.Load();
        _cts = new CancellationTokenSource();

        // Honour the operator's opt-out for the direct lifecycle/crash writes from here on (start/stop/crash).
        _osLogEnabled = settings.OsEventLog.Enabled;

        // Mirror the security-significant event stream to the OS event log (blackbox handoff). Lifecycle events
        // are written directly (below); this forwarder handles escalations/detections/violations, redacted.
        EventBus.Instance.Subscribe(new OsEventLogForwarder(_osLog, () => settings.OsEventLog.Enabled));

        // If "start with Windows" is on but the install moved (registered exe gone),
        // re-point the HKCU Run entry at the exe that's actually running. Best-effort.
        StartupManager.RepairIfNeeded();

        // Warn if auto-start points at a drive that may be absent at sign-in (removable / network / a secondary
        // disk like W:) — HKCU Run fails silently when the drive isn't mounted, the classic "didn't start at
        // boot" trap. Surface it as a notice (log + tray), not fatal.
        if (StartupManager.GetDriveWarning() is { } startupDriveWarning)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.Startup", startupDriveWarning));

        PatternLibrary.Instance.Initialize();

        // Durable event log: persist every published event to disk (JSONL) so the Event Log tab
        // survives restarts. Subscribe before anything publishes. The Log VIEW merges these
        // prior-session events with the in-memory session history; EventBus history stays
        // session-scoped so reloading the log never resurrects old alerts as "active".
        if (settings.EventLogPersist)
        {
            // P1: tamper-evident hash chain (no-op head signer until P3 adds the TPM seal).
            var eventLog = new EventLogStore(integrity: settings.LogIntegrity, signer: new NullHeadSigner());
            // Verify the PRIOR-session chain before we append anything this session; surface tamper as a
            // High notice rather than throwing into startup (a pre-chain "legacy" log verifies clean).
            var integrity = eventLog.Verify();
            var eventLogFailureReported = 0;
            EventBus.Instance.Subscribe(e =>
            {
                if (eventLog.TryAppend(e, out var error) ||
                    Interlocked.Exchange(ref eventLogFailureReported, 1) != 0)
                {
                    return;
                }

                EventBus.Instance.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.EventLog",
                    "Event log persistence failed; live monitoring continues, but disk evidence is stale. " +
                    $"Reason: {error}"));
            });
            LogWindow.LoadPersisted = () => eventLog.Load();
            if (!integrity.Ok)
                EventBus.Instance.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.LogIntegrity",
                    $"Event log integrity check FAILED ({integrity.Status}): {integrity.Message}. " +
                    "The on-disk audit log may have been tampered with."));
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
        _tray.BeginPairing                  = () => _mcpHost.BeginExtensionPairing();

        // AlertDetailWindow's data + action dependencies, set once as one object (required members, so a
        // forgotten one is a compile error). The ORIGINATING PROCESS section, escalation/profile display,
        // kill, mute, and Ask Harness all flow through these.
        AlertDetailWindow.Services = new AlertDetailServices
        {
            GetProcessByPid         = pid => _monitor.Tree.GetByPid(pid),
            GetProfileByHarness     = id  => _monitor.Behavior.GetProfile(id),
            GetHarnessAncestorByPid = pid => _monitor.Tree.FindHarnessTypeAncestor(pid),
            GetProcessSnapshot      = () => _monitor.Tree.GetAll(),
            GetLlmTriageSettings    = () => settings.LlmTriage,
            KillProcessByPid        = (pid, startTime) => _monitor.Tree.KillProcess(pid, startTime),
            // Click-to-mute: persist an operator mute (notification suppression only; guardrailed by MutePolicy).
            AddMute                 = m => { settings.Mutes.Add(m); SettingsStore.Save(settings); },
            GetEmergencyRuleIds     = () => settings.EmergencyRuleIds,
            QueueAskHarnessRequest  = (harnessId, sys, usr, alertId, pid, processName) =>
                _mcpHost.State.CreateAskHarnessRequest(harnessId, sys, usr, alertId, pid, processName),
            RecordAskHarnessReply   = (requestId, reply, actionTaken, harnessId, pid) =>
                _mcpHost.State.ReplyToAskHarnessRequest(requestId, reply, actionTaken, harnessId, pid).Ok,
            // Adaptive alerts learn from THIS (operator, in-UI) dismissal — never the agent's own MCP ack.
            OnOperatorAck           = evt => HandleOperatorAck(evt, settings),
            // Ask Harness delivers a justify/act prompt to the offender's own MCP session when reachable.
            AskOffender             = (harnessId, sys, usr, requestId, ct) =>
                _mcpHost.Sessions.AskOffenderAsync(harnessId, sys, usr, requestId, ct),
        };

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
        // A SACL-audited read of a decoy credential (reported by the elevated sidecar, which has already
        // excluded Foreman's own re-validation reads) is a Critical credential-theft incident.
        _sidecar.OnDecoyRead = d => EventBus.Instance.Publish(new CommandAlertEvent(
            DateTimeOffset.FromUnixTimeMilliseconds(d.TimestampUnixMs),
            ForemanSeverity.Critical,
            $"{(string.IsNullOrWhiteSpace(d.Image) ? "process" : System.IO.Path.GetFileName(d.Image))} (pid {d.Pid})",
            $"Decoy credential READ: {d.Path} was opened by " +
            $"{(string.IsNullOrWhiteSpace(d.Image) ? "an unknown process" : d.Image)} (pid {d.Pid}). " +
            "Nothing legitimate reads a decoy you planted as bait.",
            d.Image, "cred-decoy-read", "Decoy credential read",
            "A process read one of Foreman's decoy (canary) credential files — fake credentials planted at " +
            "paths you don't use, so any read is the behaviour of a credential harvester.",
            "Treat as active credential theft: identify and stop the reading process, then rotate the real " +
            "credentials adjacent to the decoy paths.",
            d.Pid));
        // The one elevated helper serves both opt-ins: per-PID network capture (Run elevated) and SACL
        // read-auditing of planted decoys (Decoy credentials → read auditing). Configure from current
        // settings and (re)launch only when at least one is on. Re-applying on a toggle re-prompts UAC.
        void ApplySidecarState()
        {
            // Read-audit only the BAIT decoys + canonical .npmrc — NOT every planted path. Canonical cred
            // paths (.netrc, .git-credentials, .aws/credentials, …) are read by real tools (git over HTTPS
            // reads ~/.netrc on every push), so SACL-auditing them produces guaranteed false positives.
            var auditDecoys = settings.DecoyCredentials is { Enabled: true, EnableReadAuditing: true }
                ? DecoyCredentialPolicy.ReadAuditPaths(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    settings.DecoyCredentials.PlantedPaths)
                : (IReadOnlyList<string>)new List<string>();
            _sidecar!.Configure(settings.RunElevated, auditDecoys);
            if (settings.RunElevated || auditDecoys.Count > 0) _sidecar.Restart();
            else _sidecar.Stop();
        }

        ApplySidecarState();
        _tray.GetNetRate = pid => _sidecar.GetRate(pid);
        _tray.GetNetCaptureActive = () => _sidecar?.IsConnected ?? false;
        // SettingsWindow persists the flags; these just re-apply the sidecar state (enabling an elevated
        // feature raises the UAC prompt).
        _tray.ApplyRunElevated  = _ => ApplySidecarState();
        _tray.ApplyDecoyAuditing = () => ApplySidecarState();

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
                // A "proc:<image>" offender is an unrecognized OS/system process, not a connected agent — there is
                // no MCP channel to it, so an Ask-Harness request would hang unanswered forever (e.g. the Windows
                // Search indexer tripping a decoy). Record the truth for the human instead of feigning interrogation.
                if (IsUninterrogableProcess(esc.HarnessId))
                {
                    EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.AutoResponse",
                        $"Auto-response [{esc.NewLevel}]: offender '{esc.HarnessId}' is an OS process with no MCP channel — cannot self-justify; logged for human review."));
                    return;
                }
                var (sys, usr) = BuildEscalationAskPrompt(esc);
                var req = _mcpHost!.State.CreateAskHarnessRequest(esc.HarnessId, sys, usr, esc.Id, null, null);
                _ = SafeAsk(esc.HarnessId, sys, usr, req.RequestId);
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.AutoResponse",
                    $"Auto-response [{esc.NewLevel}]: asked '{esc.HarnessId}' to justify its escalation (request {req.RequestId})."));
            },
            AdversarialAudit = esc =>
            {
                // An OS-process offender ("proc:…") is not an auditable agent — no auditor can interrogate the
                // Windows Search indexer. Skip honestly rather than implying a missing-config (Settings → triage).
                if (IsUninterrogableProcess(esc.HarnessId))
                {
                    EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.AutoResponse",
                        $"Auto-audit skipped for '{esc.HarnessId}' [{esc.NewLevel}]: offender is an OS process, not an auditable agent — logged for human review."));
                    return;
                }
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

        // Arm the presence authorizer (P3): weakening actions require a Windows Hello / security-key tap. Off
        // until the user enrolls; UI handlers call PresenceGuard.AuthorizeAsync(...) before a weakening change.
        Security.PresenceGuard.Configure(settings, EventBus.Instance);

        // Start MCP on a background thread so we don't block the WPF message pump — but never
        // silently: a bind failure (port in use) used to leave Foreman looking healthy with no
        // MCP at all. Surface it as a High notice so the tray goes red and the log explains.
        var mcpPort = settings.McpPort;
        _ = StartMcpSurfacingFailureAsync(_mcpHost, mcpPort, _cts.Token);

        // Age out unanswered Ask-Harness requests (harness never connected / ignored the prompt) so they don't
        // dangle "pending" forever. Mirrors the AlertResolver sweep; logs each expiry (never a silent drop) and
        // a late reply is still accepted afterwards.
        _ = RunAskHarnessReaperAsync(_mcpHost, settings, _cts.Token);

        // publish startup event — this ensures the log window always has at least one entry
        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Foreman",
            $"Monitoring started · MCP on :{settings.McpPort} · " +
            $"{KnownHarnesses.All.Count} built-in harness types" +
            (settings.CustomHarnessExes.Count > 0 ? $" + {settings.CustomHarnessExes.Count} custom" : "")));

        // Blackbox handoff: stamp startup into the OS event log directly (lifecycle isn't routed through the bus).
        if (_osLogEnabled)
        {
            var ver = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1";
            _osLog.Write(OsEventIds.Started, OsEventCategory.Lifecycle, ForemanSeverity.Info,
                $"Foreman Agent Safety started — v{ver}, pid {Environment.ProcessId}, MCP :{settings.McpPort}.");
            if (!_osLog.IsAvailable && _osLog.UnavailableReason is { } why)
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.OsLog", why));
        }

        // If settings.json was unreadable at launch it was quarantined and defaults loaded. Surface that
        // now (the bus + event log are wired) so a corrupt file isn't a silent reset of security posture.
        if (SettingsStore.LastLoadFault is { } settingsFault)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.Settings", settingsFault));

        // Tamper canary: settings.json was edited by something other than Foreman (the seal didn't match). A
        // same-user agent can't be PREVENTED from editing a file it owns, but this makes it LOUD — High so it
        // hits the tray and the OS event log (the durable external record), not a silent posture weakening.
        if (SettingsStore.LastSealVerdict == SettingsSealVerdict.Tampered)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Settings",
                "settings.json was modified outside Foreman — its security posture (presence lock, log persistence, " +
                "decoy auditing, disabled harnesses, mutes, Trust) may have been weakened. Review Settings and re-apply " +
                "from the UI to re-seal; investigate if you didn't make this change."));

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

    // Periodically ages out unanswered Ask-Harness requests so the pending list reflects reality. The TTL is
    // read live from settings each tick (0 disables). A bad sweep must never crash the app or stop the loop.
    private static async Task RunAskHarnessReaperAsync(McpServerHost host, ForemanSettings settings, CancellationToken ct)
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(60));
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                var ttl = TimeSpan.FromMinutes(Math.Max(0, settings.AskHarnessTimeoutMinutes));
                if (ttl <= TimeSpan.Zero) continue;
                var now = DateTimeOffset.UtcNow;
                foreach (var r in host.State.ExpireStale(now, ttl))
                {
                    var mins = (int)Math.Round((now - r.CreatedAt).TotalMinutes);
                    EventBus.Instance.Publish(new InfoEvent(now, "Foreman.AutoResponse",
                        $"Ask Harness request {r.RequestId} to '{r.HarnessId}' expired after {mins} min unanswered " +
                        $"(alert {r.AlertId}) — harness offline or unresponsive. A late reply is still accepted."));
                }
            }
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
        catch { /* a bad sweep must never crash the app */ }
    }

    // Adaptive alerts: the operator dismissed an OPERATIONAL alert in the UI. Feed the advisor (learns from the
    // human, never the agent), persist the tally, and surface a one-time quieting tip when a class reads as noise.
    private void HandleOperatorAck(ForemanEvent evt, ForemanSettings settings)
    {
        var type = evt switch
        {
            HangDetectedEvent    => "hang",
            OrphanDetectedEvent  => "orphan",
            NonzeroExitEvent     => "nonzero-exit",
            _                    => null,            // security/behavioural acks never train the advisor
        };
        if (type is null || _monitor is null) return;

        var pid = evt switch
        {
            HangDetectedEvent h   => h.ParentHarnessPid ?? h.ProcessId,
            OrphanDetectedEvent o => o.ProcessId,
            NonzeroExitEvent x    => x.ParentHarnessPid ?? x.ProcessId,
            _                     => 0,
        };
        var harness = _monitor.Tree.FindHarnessTypeAncestor(pid)?.HarnessType ?? "";
        var suggestion = SuppressionAdvisor.RecordOperatorAck(settings.AdaptiveAlerts, harness, type, DateTimeOffset.UtcNow);
        SettingsStore.Save(settings);

        if (suggestion is { } s)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Info, "Foreman.Adaptive",
                $"Adaptive noise tip: {s.Rationale} " + (s.Kind == SuppressionSuggestionKind.RaiseHangThreshold
                    ? $"Raise '{s.HarnessId}'s hang tolerance via its Trust level (Harnesses ▸ Trust), or mute the class."
                    : $"Mute the '{s.HarnessId} · {s.AlertType}' class from the alert's right-click → Mute menu.")));
    }

    // A behavior profile keyed "proc:<image>" belongs to an unrecognized OS/system process the classifier could
    // not attribute to a connected harness. It has no MCP channel, so it cannot answer an Ask-Harness request or
    // be routed to an auditor — the agent-to-agent response machinery does not apply to it.
    private static bool IsUninterrogableProcess(string harnessId) =>
        harnessId.StartsWith("proc:", StringComparison.Ordinal);

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
        // Blackbox handoff: record the clean stop BEFORE the disposal cascade, so the OS log shows a deliberate
        // shutdown (a missing StoppedClean between two Started entries = the process was killed or crashed).
        if (_osLogEnabled)
            _osLog.Write(OsEventIds.StoppedClean, OsEventCategory.Lifecycle, ForemanSeverity.Info,
                $"Foreman Agent Safety stopped (clean shutdown), pid {Environment.ProcessId}.");

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
