using Foreman.App.Security;
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
using System.IO;
using System.Threading;
using System.Windows;

namespace Foreman.App;

public partial class App : Application
{
    private static Mutex? _singleInstance;
    private static bool _ownsSingleInstance;
    private TrayController? _tray;
    private Foreman.App.ComputerUse.PanicHotkey? _panicHotkey;
    private Foreman.App.ComputerUse.BindHotkey? _cuBindHotkey;
    private Foreman.App.ComputerUse.DesktopCuController? _desktopCu;
    private Foreman.App.ComputerUse.PilotChannelController? _pilotChannel;
    private Foreman.Core.ComputerUse.CuExecutorPump? _cuPump;
    private System.IO.FileStream? _cuSidecarPin;
    private System.IO.FileStream? _cuPilotPin;
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
    // For the external rollback-anchor (B8): the on-disk audit log path + the chain head this launch inherited.
    // We stamp the head into the OS event log at start and at clean stop so the next launch can detect a rollback.
    private string? _eventLogPath;
    private LogAnchor? _launchAnchor;
    // TPM head-seal key handle (circle-back Phase B); held for the app's lifetime, disposed at exit.
    private IDisposable? _headSealKey;
    // The same head-seal signer, used to MAC the external rollback anchors written to the OS log (so a same-user
    // agent can't forge a counterfeit witness). Null until the persisted-log path wires it; no-op under NullHeadSigner.
    private ILogHeadSigner? _headSigner;

    protected override void OnStartup(StartupEventArgs e)
    {
#if DEBUG
        // Developer on-device smoke test for the desktop CU injector (Foreman.exe --cu-smoketest). Runs the real
        // controller->sidecar->SendInput path against Notepad + a panic test, writes a temp log, and exits. Branches
        // BEFORE the single-instance mutex + the full app wiring so it can run standalone alongside a real instance.
        // DEBUG-only: excluded from release builds entirely (zero shipping surface).
        if (e.Args.Contains(ComputerUse.CuSmokeTest.FlagE2E))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            ComputerUse.CuSmokeTest.RunE2EToFileAndExit(this);
            return;
        }
        if (e.Args.Contains(ComputerUse.CuSmokeTest.Flag))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            ComputerUse.CuSmokeTest.RunToFileAndExit(this);
            return;
        }
#endif

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

        // Watchdog-of-the-watchdog: ask Windows to relaunch Foreman if it terminates abnormally (crash/hang), and
        // note whether THIS launch is such a relaunch. Best-effort; the OS-event-log kill detection below stands on
        // its own even when the OS doesn't auto-restart (e.g. a hard TerminateProcess).
        AppRecovery.RegisterForRestart();
        var restartedByOs = AppRecovery.WasRestartedByOs(e.Args);

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
        // Phase A step 7: when the opt-in guardian is installed + SYSTEM-verified, seal settings through it (secret
        // behind the SYSTEM boundary). Set BEFORE Load so the verdict uses the right key; null ⇒ local secret path.
        SettingsStore.Sealer = GuardianSettingsSealer.TryCreate(() => installSecret);

        var settings = SettingsStore.Load();
        _cts = new CancellationTokenSource();

        // Honour the operator's opt-out for the direct lifecycle/crash writes from here on (start/stop/crash).
        _osLogEnabled = settings.OsEventLog.Enabled;

        // Read back Foreman's own recent OS-event-log entries ONCE (the durable external record): used below for the
        // anti-rollback anchor (was the last witnessed chain head reverted?) and the kill detector (did the prior
        // instance die without a clean stop or crash record?). Empty when the OS log is off/unavailable → no alarm.
        var recentOsLog = _osLogEnabled ? _osLog.ReadOwnRecent(256) : (IReadOnlyList<OsEventRecord>)[];
        var priorShutdown = LifecycleForensics.ClassifyFrom(recentOsLog);
        var anchorVerdict = AnchorVerdict.NoPriorAnchor;
        var anchorForged = false;
        LogAnchor? witnessedAnchor = null;
        string? headSealNotice = null;   // Phase B: a head-seal key-change warning to publish once the bus/tray are live.

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
        // B9 polish: arm the per-install decoy sentinel (random, not in the binary) so cred-040 fires if a harvester
        // grabs a decoy. Empty until decoys are first planted; re-armed live by the Settings decoy-apply path.
        CommandAnalyzer.DecoySentinelToken = settings.DecoyCredentials.InstanceSentinel;

        // Durable event log: persist every published event to disk (JSONL) so the Event Log tab
        // survives restarts. Subscribe before anything publishes. The Log VIEW merges these
        // prior-session events with the in-memory session history; EventBus history stays
        // session-scoped so reloading the log never resurrects old alerts as "active".
        if (settings.EventLogPersist)
        {
            // Tamper-evident hash chain + signed head. Routes through the opt-in LocalSystem guardian when it's
            // installed (key behind the SYSTEM boundary, unforgeable by the agent), else the per-user TPM/unsigned
            // path (Phase B) — the casual user is unchanged. TOFU-pins the key's public half on first run.
            var headSeal = GuardianSignerFactory.Build(settings, SettingsStore.Save);
            _headSealKey = headSeal.Owns;
            _headSigner = headSeal.Signer;
            headSealNotice = headSeal.Notice;
            var eventLog = new EventLogStore(integrity: settings.LogIntegrity, signer: headSeal.Signer);
            // Verify the PRIOR-session chain before we append anything this session; surface tamper as a
            // High notice rather than throwing into startup (a pre-chain "legacy" log verifies clean).
            var integrity = eventLog.Verify();

            // External anti-rollback anchor (B8): snapshot the on-disk chain heads BEFORE this session appends, and
            // compare against the head we last witnessed in the OS event log. The in-file chain alone can't catch a
            // rollback — the agent reverts the JSONL and its seal together, so Verify still passes — but a revert
            // removes the externally-witnessed head from the file, which the out-of-band OS-log witness exposes.
            _eventLogPath = eventLog.FilePath;
            // recentOsLog is newest-first, so the parsed anchors are too. When head-sealing is on, Evaluate trusts
            // only an authentically-sealed anchor — a same-user agent can WriteEntry under our OS-log source, so an
            // unsealed/badly-sealed anchor it plants to mask a rollback is rejected (and a bad seal is flagged).
            var anchorCandidates = new List<LogAnchor>();
            foreach (var r in recentOsLog)
                if (r.EventId == OsEventIds.LogChainAnchor && LogAnchor.TryParse(r.Message) is { } a)
                    anchorCandidates.Add(a);
            var anchorEval = AnchorPolicy.Evaluate(
                LogHeadReader.ReadChainedHashes(_eventLogPath), anchorCandidates, headSeal.Signer);
            anchorVerdict = anchorEval.Verdict;
            anchorForged = anchorEval.ForgedSealSeen;
            witnessedAnchor = anchorEval.TrustedAnchor;
            _launchAnchor = LogHeadReader.CurrentAnchor(_eventLogPath);

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
            LogWindow.RotateAndReseal = () => RotateEventLogAsync(eventLog);
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
        _tray.GetRecentlyConnectedHarnessIds = () => _mcpHost.Sessions.RecentlyActiveHarnessIds(TimeSpan.FromMinutes(5));
        _tray.GetMcpInventory               = () => _monitor.McpInventory.Current;
        _tray.GetPendingAskCount            = id => _mcpHost.State.CountAskHarnessRequests(id);
        _tray.BeginPairing                  = () => _mcpHost.BeginExtensionPairing();
        _tray.IsLiveWeaveConnected          = () => _mcpHost.State.LiveWeave.IsConnected;

        // Computer-use panic kill (mediated-CU Phase 0): a process-global halt + a SYSTEM-global hotkey that keeps
        // working even if the UI is busy. Halt is the safe direction (unguarded); resume is presence-gated in the
        // controller. The halt flag is shared into MCP state so the computer_use_status tool can report it.
        var panicState = new Foreman.Core.Security.CuPanicState();
        _mcpHost.State.Panic = panicState;
        // Mediated computer-use broker (Phase 0.5): every CU action is audited (local fast-path; the cloud deep judge
        // stays OFF until the operator enables it) before it can execute, and the panic halt empties it. Reachable
        // via the cu_* MCP tools.
        var cuBroker = new Foreman.Core.ComputerUse.CuBroker(
            new Foreman.Core.ComputerUse.AuditPipeline(new Foreman.Core.ComputerUse.FastPathAuditor()),
            () => panicState.IsHalted);
        // Restore the persisted CU driver, THEN wire the persister, so the startup seed doesn't re-save. After
        // this, any driver change (the picker OR the cu_set_driver MCP tool) sticks across relaunches.
        cuBroker.SetDriver(settings.CuDriver);
        cuBroker.DriverPersister = d =>
        {
            settings.CuDriver = d;
            try { SettingsStore.Save(settings); } catch { /* in-memory driver still applies this session */ }
        };
        cuBroker.AllowTabOverride = settings.CuTabOverride;   // opt-in: off-focus changes may proceed if justified
        cuBroker.DesktopAutoGrant = settings.CuDesktopAutoGrant;   // INV-15: default OFF -> desktop actions land Held
        cuBroker.WindowProbe = new Foreman.App.ComputerUse.Win32WindowProbe();   // INV-2: recycled-handle re-gate at Claim
        cuBroker.OperatorIdle = Foreman.App.ComputerUse.OperatorActivity.IdleTime;   // INV-15: pause auto-grant when away
        // Operator HUD overlay: announce AI piloting (localised safe flash + shake) when a CU action starts running.
        // Held by the broker's OnExecuting closure, so it lives for the app lifetime; marshalled to the UI thread.
        var cuOverlay = new Foreman.App.ComputerUse.CuOverlayWindow();
        cuBroker.OnExecuting = item => Dispatcher.BeginInvoke(new Action(() =>
        {
            try { cuOverlay.ShowDriving($"{item.Action.Modality.ToString().ToLowerInvariant()}: {item.Action.Verb}"); }
            catch { /* HUD is best-effort; never disturb the broker */ }
        }));
        _mcpHost.State.Cu = cuBroker;
        // INV-16: approving a HELD desktop CU action over MCP requires a fresh presence tap, not just the operator
        // bearer token. PresenceGuard.Configure runs later in startup; this delegate is only INVOKED at approve-time.
        _mcpHost.State.CuDesktopApprovalGate = () => Security.PresenceGuard.AuthorizeAsync(
            Foreman.Core.Security.WeakeningAction.ApproveCuDesktopAction,
            "approve a held desktop computer-use action", forcePresence: true, freshTap: true);
        // Connect-Agent window's "Browser-use driver" picker reads/sets the CU driver in-process (operator).
        _tray.GetCuDriver = () => _mcpHost.State.Cu?.Driver;
        _tray.SetCuDriver = id => _mcpHost.State.Cu?.SetDriver(id);
        var panicController = new Foreman.App.ComputerUse.PanicController(
            panicState, EventBus.Instance, _osLog, () => _osLogEnabled);
        _tray.Panic = panicController;
        // Keep the tray STOP/RESUME label correct even when a halt/resume doesn't change the tray status colour.
        panicState.Changed += _ => Dispatcher.BeginInvoke(new Action(() => _tray?.RefreshMenu()));
        // INV-20: on panic, the broker rejects every pending/in-flight DESKTOP item and bumps the panic epoch so a stale
        // relayed proposal can't execute post-halt. Unconditional (fires even when desktop CU isn't armed - the desktop
        // queue is then simply empty), so it never depends on the arm block running.
        panicState.Changed += halted => { if (halted) cuBroker.OnPanicHalt(); };
        _panicHotkey = new Foreman.App.ComputerUse.PanicHotkey(
            () => panicController.Halt($"hotkey {Foreman.App.ComputerUse.PanicHotkey.ChordText}"));
        if (!_panicHotkey.Registered)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow, ForemanSeverity.Low,
                "Foreman.ComputerUse",
                $"Panic hotkey ({Foreman.App.ComputerUse.PanicHotkey.ChordText}) could not be registered (another " +
                "app may own it). Use the tray STOP item to halt computer use."));

        // Pin the desktop CU sidecar binary write/delete-locked for the app's whole lifetime so a same-user process
        // cannot swap it AT REST. Done REGARDLESS of CuDesktopEnabled: the at-rest window is exactly when the feature
        // is off (the file is otherwise unlocked), and on an unsigned dev build this lock - not Authenticode - is the
        // integrity safeguard for the binary that can later be granted input authority.
        // Pin BOTH desktop-CU sidecar binaries (injector + pilot shim) write/delete-locked for the app's whole
        // lifetime so a same-user process cannot swap either AT REST. Done REGARDLESS of the feature toggles: the
        // at-rest window is exactly when the feature is off, and on an unsigned dev build this lock - not Authenticode -
        // is the integrity safeguard for a binary that can later be granted input authority.
        _cuSidecarPin = Foreman.App.ComputerUse.DesktopCuController.PinBinaryAtRest();
        _cuPilotPin = Foreman.App.ComputerUse.PilotChannelController.PinBinaryAtRest();

        // Desktop computer-use + Local Agent Host (off by default; never reachable over MCP, INV-7). When either is on,
        // the App launches the relevant signed medium-IL helper, verifies it three ways, and wires the ACTIVE panic
        // floor that on halt hard-kills BOTH helpers (INV-3 + INV-20 KillPilotNow) + BlockInput shield + release-all +
        // an independent watchdog - independent of which feature armed it, and not dependent on any helper noticing.
        // INV-16: desktop CU / the Local Agent Host REFUSE to arm unless an enrolled presence credential exists
        // (Windows Hello / FIDO2) - so a same-user flip of the enable bit can't silently grant input authority without
        // the operator's hardware tap also being possible. Checked against settings directly (PresenceGuard.Configure
        // runs later in startup).
        var cuPresenceArmed = settings.PresenceLock.Enabled
            && !string.IsNullOrEmpty(settings.PresenceLock.CredentialId)
            && Foreman.App.Security.PresenceGuard.IsAvailable;
        if ((settings.CuDesktopEnabled || settings.CuDriverHostEnabled) && !cuPresenceArmed)
        {
            EventBus.Instance.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow, ForemanSeverity.High,
                "Foreman.ComputerUse",
                "Desktop computer-use / Local Agent Host is enabled but no presence credential is armed (Windows " +
                "Hello / FIDO2) - REFUSING to arm it (INV-16). Enroll a presence credential first."));
        }
        else if (settings.CuDesktopEnabled || settings.CuDriverHostEnabled)
        {
            var cuFloor = new Foreman.App.ComputerUse.CuDesktopPanicFloor(() =>
            {
                var killedSidecar = _desktopCu?.KillSidecarNow() ?? false;
                var killedPilot = _pilotChannel?.KillPilotNow() ?? false;
                return killedSidecar || killedPilot;
            });

            Foreman.App.ComputerUse.CuSharedPanicFlag? cuPanicFlag = null;
            if (settings.CuDesktopEnabled)
            {
                cuPanicFlag = new Foreman.App.ComputerUse.CuSharedPanicFlag();
                cuPanicFlag.SetHalted(panicState.IsHalted);
                _desktopCu = new Foreman.App.ComputerUse.DesktopCuController { PanicFlag = cuPanicFlag };
                // INV-5: a result that fails the App's independent foreground check escalates to a full halt.
                _desktopCu.OnVerificationFailure = () =>
                    panicController.Halt("desktop CU result failed independent verification (INV-5)");
                // Keep the injector's authoritative bound window (the MMF it reads) in sync with the broker's
                // operator-bound window, so a bind via the hotkey actually confines the injector. SetBound is thread-safe.
                cuBroker.OnWindowSwitch = (_, now) =>
                {
                    try { cuPanicFlag!.SetBound(now?.Hwnd.ToInt64() ?? 0); } catch { /* best-effort sync */ }
                };
                // Executor pump (the payoff): run APPROVED desktop actions through the verified sidecar injector,
                // in-process. Claim re-gates driver-auth + panic epoch + one-window confinement at delivery; the
                // controller verifies each result (INV-5). Idle until an item is approved + the sidecar is connected.
                var cuExecutor = new Foreman.App.ComputerUse.DesktopCuExecutor(_desktopCu, () => cuPanicFlag!.BoundHwnd);
                // INV-18: the pump confirms the HUD is ACTUALLY visible (topmost + un-cloaked + un-occluded) before
                // delivering any input; if it can't, it withholds (fail closed) and warns - so piloting can never be
                // invisible. The CuOverlayWindow implements the adversarial occlusion test.
                _cuPump = new Foreman.Core.ComputerUse.CuExecutorPump(cuBroker, cuExecutor, batch: 4,
                    hud: cuOverlay,
                    onHudWithheld: () => EventBus.Instance.Publish(new MonitoringNoticeEvent(
                        DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.ComputerUse",
                        "HUD could not be confirmed visible - desktop piloting PAUSED until the banner is unobscured (INV-18).")));
                _ = _cuPump.RunAsync(TimeSpan.FromMilliseconds(300), _cts!.Token);
            }
            if (settings.CuDriverHostEnabled)
            {
                // INV-14: enroll the local-agent-host id as a DESKTOP driver. Derived from the sealed + presence-armed
                // CuDriverHostEnabled flag and re-applied each startup (never persisted), so a settings edit alone can't
                // enroll it. After this the broker's CanDriveModality(Desktop) admits exactly this id.
                cuBroker.EnrollDesktopDriver(Foreman.Core.ComputerUse.LocalDriverIpc.LocalAgentHostId);

                _pilotChannel = new Foreman.App.ComputerUse.PilotChannelController();
                if (!string.IsNullOrWhiteSpace(settings.CuAgentCommand))
                    _pilotChannel.AgentSpec = new Foreman.Core.ComputerUse.StartAgentArgs(
                        settings.CuAgentCommand!, settings.CuAgentArguments, settings.CuAgentWorkingDir);
                // L5: a relayed agent proposal arrives as a trusted, rebuilt CuAction -> submit it into the AUDITED
                // broker. The broker rejects unknown verbs + unauthorized drivers and, with auto-grant OFF, lands every
                // desktop action HELD for the operator (INV-15). Fire-and-forget: the operator acts on the Held item via
                // the HUD/dashboard; nothing executes without approval.
                _pilotChannel.OnDriverSubmit = action =>
                {
                    var ctx = new Foreman.Core.ComputerUse.CuContext(
                        Foreman.Core.ComputerUse.LocalDriverIpc.LocalAgentHostId);
                    _ = cuBroker.SubmitAsync(action, ctx).ContinueWith(t =>
                    {
                        if (t.IsCompletedSuccessfully)
                            EventBus.Instance.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow,
                                ForemanSeverity.Info, "Foreman.LocalAgentHost",
                                $"Local agent proposed: {action.Verb} -> {t.Result.State}."));
                        else if (t.IsFaulted)   // never swallow a faulted submit silently
                            EventBus.Instance.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow,
                                ForemanSeverity.Low, "Foreman.LocalAgentHost",
                                $"Local agent proposal '{action.Verb}' failed to submit: {t.Exception?.GetBaseException().Message}"));
                    }, TaskScheduler.Default);
                };
            }

            panicState.Changed += halted =>
            {
                cuPanicFlag?.SetHalted(halted);   // fast in-sidecar abort (desktop injector)
                if (halted) cuFloor.Trigger();    // hard floor: kill both helpers + BlockInput + release-all
            };

            // INV-17: the operator binds the desktop CU target window via a global hotkey that captures the window while
            // it is FOREGROUND (before Foreman steals focus), gated by a fresh presence tap; the bind carries a one-time
            // token the broker validates + consumes, so a caller can't fabricate a CuWindowRef for an attacker window.
            var cuBindStore = new Foreman.App.ComputerUse.BindTokenStore();
            cuBroker.BindTokenValidator = cuBindStore.Validate;
            var cuBindProbe = cuBroker.WindowProbe ?? new Foreman.App.ComputerUse.Win32WindowProbe();
            _cuBindHotkey = new Foreman.App.ComputerUse.BindHotkey(
                () => _ = BindCuForegroundWindowAsync(cuBroker, cuBindProbe, cuBindStore));
            if (!_cuBindHotkey.Registered)
                EventBus.Instance.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow, ForemanSeverity.Low,
                    "Foreman.ComputerUse",
                    $"CU bind hotkey ({Foreman.App.ComputerUse.BindHotkey.ChordText}) could not be registered (another " +
                    "app may own it). Desktop CU can't bind a target window until it's free."));

            _desktopCu?.Start();
            _pilotChannel?.Start();
        }

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
            GetConnectedHarnessIds  = () => BuildConnectedHarnessIds(_mcpHost.Sessions.DescribeSessions()),
            SaveAuditorPreference   = (target, auditor, display) =>
            {
                settings.LlmTriage.UpsertAuditorPreference(target, auditor, display);
                SettingsStore.Save(settings);
            },
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

        // Outbound handoff (request_harness_review): push the Ask to the target's live MCP session if it has one,
        // else it's already queued for the target's next poll. Mirrors the auto-audit / idle-cleanup delivery.
        _mcpHost.State.DeliverHarnessAsk = async (harnessId, sys, usr, requestId) =>
        {
            var res = await _mcpHost.Sessions.AskOffenderAsync(harnessId, sys, usr, requestId).ConfigureAwait(false);
            return res.Outcome switch
            {
                AskOutcome.Sampled => "sampled",
                AskOutcome.Notified => "notified",
                _ => "no_session",
            };
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
            _sidecar!.Configure(settings.RunElevated, auditDecoys, captureWakeRequests: true);
            if (settings.RunElevated || auditDecoys.Count > 0) _sidecar.Restart();
            else _sidecar.Stop();
        }

        ApplySidecarState();
        _tray.GetNetRate = pid => _sidecar.GetRate(pid);
        _tray.GetWakeRequests = () => _sidecar.GetWakeRequests();
        _tray.GetContextUsage = id => _mcpHost.State.GetContextUsage(id);
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
                // Use the full route resolver (not SelectAuditor, which only consults configured preferences and
                // returns null when none target this offender). Resolve falls back to any other running/connected
                // harness, so an un-preconfigured escalation still gets a second pair of eyes instead of silently
                // dropping to "no eligible auditor."
                var snapshot = _monitor!.Tree.GetAll().ToList();
                var connected = BuildConnectedHarnessIds(_mcpHost!.Sessions.DescribeSessions());
                var selection = AuditRouteResolver.Resolve(settings.LlmTriage, esc.HarnessId, severity, snapshot, connected);
                var auditor = selection.Selected;
                if (auditor is null)
                {
                    EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.AutoResponse",
                        $"Auto-audit skipped for '{esc.HarnessId}' [{esc.NewLevel}]: {selection.Reason}"));
                    return;
                }
                var (sys, usr) = BuildEscalationAuditPrompt(esc, auditor.AuditorId);
                var req = _mcpHost!.State.CreateAskHarnessRequest(auditor.AuditorId, sys, usr, esc.Id, null, null);
                _ = SafeAsk(auditor.AuditorId, sys, usr, req.RequestId);
                EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.AutoResponse",
                    $"Auto-response [{esc.NewLevel}]: routed '{esc.HarnessId}' to auditor '{auditor.AuditorId}'" +
                    $"{(selection.UsedFallback ? " (fallback — no configured preference)" : "")} for review (request {req.RequestId})."));
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
            // Stamp the chain head this launch inherited into the OS log as the external rollback witness for the
            // NEXT launch (also re-stamped at clean stop). count 0 = nothing persisted yet, so nothing to witness.
            if (_launchAnchor is { Count: > 0 } launchAnchor)
                _osLog.Write(OsEventIds.LogChainAnchor, OsEventCategory.Lifecycle, ForemanSeverity.Info, SealAnchor(launchAnchor).Format());
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

        // Guardian-scheme seal present but the guardian (the SYSTEM key-holder) was unreachable, so the seal could
        // be neither confirmed nor refuted. Don't block load and don't cry tamper — but don't silently pass it off
        // as Sealed either: surface that the posture is UNVERIFIED this launch (Medium). Usually a transient outage
        // of the auto-start service; persistent means the guardian was disabled (itself worth a look).
        if (SettingsStore.LastSealVerdict == SettingsSealVerdict.Unverified)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.Settings",
                "settings.json carries a guardian-backed seal but the guardian service was unreachable at launch, so " +
                "its security posture could not be verified this session. If this persists, check that the Foreman " +
                "guardian service is running — a disabled guardian can't catch out-of-band edits to your settings."));

        // Anti-rollback canary (B8): the chain head Foreman last witnessed in the OS event log is gone from the
        // on-disk log — it was reverted to an earlier state while Foreman was down. The in-file hash chain can't
        // catch this (the agent rolls the chain + seal back together); the external OS-log witness can. Critical.
        if (anchorVerdict == AnchorVerdict.Rolledback)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Critical, "Foreman.LogIntegrity",
                "Event log ROLLBACK detected: the audit-chain head Foreman last recorded externally" +
                (witnessedAnchor is { } w ? $" (count {w.Count})" : "") +
                " is no longer present on disk. The on-disk log was reverted to an earlier state while Foreman was " +
                "down — the classic same-user move to erase tracks. Treat recent on-disk history as untrustworthy and investigate."));

        // Anchor forgery (anchor-MAC): a candidate witness in the OS event log carried a seal that did NOT verify
        // under Foreman's pinned head-seal key. Once the OS-log source is registered a same-user agent can write
        // entries under it, so it can plant a counterfeit anchor to mask a rollback — but it can't produce a valid
        // seal without the key. Verdict Forged = no authentic anchor survived (a rollback may be masked → Critical);
        // ForgedSealSeen alongside a valid anchor = an attempt that didn't take (still High — someone tried).
        // GATE: when the pinned key itself changed this launch (TPM reset / re-key), OLD-key anchors legitimately
        // fail verification — that's the key-change notice's job to report (above), not a forgery. BUT an attacker
        // can FORCE a key change by rewriting the pinned key in settings.json, which trips the settings-tamper seal
        // (Tampered). So only treat a key change as innocent when settings are NOT tampered; a key change that
        // coincides with settings tampering is the attack chain itself -> let the forgery alarm fire.
        var keyChangeExplainsBadSeals = headSealNotice is not null
            && SettingsStore.LastSealVerdict != SettingsSealVerdict.Tampered;
        if ((anchorVerdict == AnchorVerdict.Forged || anchorForged) && !keyChangeExplainsBadSeals)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow,
                anchorVerdict == AnchorVerdict.Forged ? ForemanSeverity.Critical : ForemanSeverity.High,
                "Foreman.LogIntegrity",
                "Event-log anchor FORGERY detected: an external rollback witness in the OS event log was not signed " +
                "by Foreman's pinned head-seal key — a same-user agent planted a counterfeit witness. " +
                (anchorVerdict == AnchorVerdict.Forged
                    ? "No authentic anchor remained, so an offline rollback may be masked; treat on-disk history as untrustworthy and investigate."
                    : "An authentic anchor still verified this launch, but the attempt itself means an agent is trying to erase tracks; investigate.")));

        // Watchdog-of-the-watchdog (B9): the prior instance left a dangling run in the OS log — no clean stop and no
        // crash record, the signature of a forced kill (an agent disabling its watchdog). Reconstructed here and
        // re-logged, so the kill itself becomes a durable, surviving Critical.
        if (priorShutdown == PriorShutdown.Killed)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Critical, "Foreman.Watchdog",
                "The previous Foreman instance was terminated WITHOUT a clean shutdown or crash record — the " +
                "signature of a forced kill. " + (restartedByOs ? "Windows auto-restarted Foreman. " : "") +
                "Monitoring has resumed; review what a monitored agent was doing when Foreman stopped."));

        // Phase B: the TPM head-seal key no longer matches the pinned public key (TPM reset / profile move / key
        // substitution). High — new seals won't verify until the key is re-pinned.
        if (headSealNotice is { } sealNotice)
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.LogIntegrity", sealNotice));

        // first-run dialog deferred to idle so it doesn't block server startup
        var port = settings.McpPort;
        var mcpToken = _mcpHost.McpToken;
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.ApplicationIdle,
            () => FirstRunDetector.RunIfNeeded(port, mcpToken, () => _mcpHost.Sessions.DescribeSessions(),
                id => _mcpHost.MintHarnessToken(id)));
    }

    // Bind an external rollback anchor to Foreman's pinned head-seal key before it goes into the OS event log, so a
    // same-user agent (which can WriteEntry under our source) can't forge a counterfeit witness. Under NullHeadSigner
    // or a key-less run SealHead returns null and the anchor stays unsealed — verified accordingly on the next launch.
    private LogAnchor SealAnchor(LogAnchor anchor) =>
        _headSigner?.SealHead(anchor.SealPayloadHead(), anchor.Count) is { } seal ? anchor with { Seal = seal } : anchor;

    // Operator action (presence-gated): rotate + re-seal the event log. Archives the current chain, starts a
    // fresh sealed one, and publishes a SUPERSEDING external anchor so the next launch doesn't read the stale
    // witness and (correctly) flag the now-absent head as a rollback. Re-baselining the tamper witness is a
    // weakening action, so it is gated behind presence (Windows Hello) and recorded loudly in the new chain +
    // the OS log — a silent reset would let a rogue same-user agent erase its tracks.
    private async Task<(bool Ok, string Message)> RotateEventLogAsync(EventLogStore eventLog)
    {
        if (!await PresenceGuard.AuthorizeAsync(WeakeningAction.ClearOrRotateLog,
                "rotate + re-seal the event log (reset the tamper-evidence baseline)").ConfigureAwait(false))
            return (false, "Presence not verified — the event log was not rotated.");
        try
        {
            var result = eventLog.RotateAndReseal("operator rotate + re-seal", DateTimeOffset.UtcNow);
            var detail = $"Prior chain ({result.PriorCount} record(s)) archived to " +
                         $"{Path.GetFileName(result.ArchivePath)}; fresh tamper-evidence baseline established.";
            if (_osLogEnabled)
            {
                // Superseding external anchor: next launch compares the FRESH chain against this FRESH witness.
                _osLog.Write(OsEventIds.LogChainAnchor, OsEventCategory.Lifecycle, ForemanSeverity.Info,
                    SealAnchor(result.NewAnchor).Format());
                // DISTINCT durable record — the bare anchor above is indistinguishable from a routine lifecycle
                // bump, so also write an explicit security-significant entry. The OS log is the one witness a
                // same-user agent can't surgically edit, so a re-baseline must be unmistakable there.
                _osLog.Write(OsEventIds.SecuritySignificant, OsEventCategory.Security, ForemanSeverity.High,
                    $"Operator presence-verified event-log rotate + re-seal. {detail}");
            }
            // In-chain record (lands in the fresh chain via the bus subscriber).
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Medium, "Foreman.LogRotate",
                $"Operator rotated + re-sealed the event log (presence-verified). {detail}"));
            return (true, $"Event log rotated — prior chain ({result.PriorCount} records) archived, fresh baseline sealed.");
        }
        catch (Exception ex)
        {
            // A FAILED re-baseline must be as loud + durable as a success — a partial rotate could leave the chain
            // inconsistent (Core re-seeds so the next append re-anchors, but the operator must still see it).
            var verify = SafeVerifyStatus(eventLog);
            if (_osLogEnabled)
                _osLog.Write(OsEventIds.SecuritySignificant, OsEventCategory.Security, ForemanSeverity.High,
                    $"Operator-initiated event-log rotate FAILED ({ex.GetType().Name}). On-disk chain verify: {verify}.");
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.LogRotate",
                $"Event-log rotate FAILED ({ex.GetType().Name}); on-disk chain verify: {verify}. Retry the rotate."));
            return (false, $"Rotate failed: {ex.Message} (chain verify: {verify}).");
        }
    }

    // INV-17 bind flow: capture the CURRENT foreground window (the operator pressed the bind hotkey while their target
    // was foreground, before Foreman could steal focus), require a fresh presence tap, then mint a one-time token and
    // bind. The token is validated + consumed by the broker, so a fabricated CuWindowRef can't be bound without the tap.
    private static async Task BindCuForegroundWindowAsync(
        Foreman.Core.ComputerUse.CuBroker broker,
        Foreman.Core.ComputerUse.IDesktopWindowProbe probe,
        Foreman.App.ComputerUse.BindTokenStore store)
    {
        void Notice(ForemanSeverity sev, string msg) => EventBus.Instance.Publish(
            new MonitoringNoticeEvent(DateTimeOffset.UtcNow, sev, "Foreman.ComputerUse", msg));
        try
        {
            var w = probe.CaptureForeground();
            if (w is null) { Notice(ForemanSeverity.Low, "Bind hotkey: no foreground window to bind."); return; }
            if (w.OwnerPid == Environment.ProcessId)
            { Notice(ForemanSeverity.Low, "Bind hotkey: refusing to bind Foreman's own window."); return; }

            var ok = await Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.BindCuWindow,
                $"bind desktop computer-use to '{w.TitleAtBind}' (pid {w.OwnerPid})",
                forcePresence: true, freshTap: true).ConfigureAwait(false);
            if (!ok) { Notice(ForemanSeverity.Low, "Bind not authorized (no presence tap) - the CU target was not bound."); return; }

            var (bound, reason) = broker.SetActiveWindow(w, store.Mint());
            Notice(bound ? ForemanSeverity.Info : ForemanSeverity.Low, reason);
        }
        catch (Exception ex) { Notice(ForemanSeverity.Low, "Bind failed: " + ex.Message); }
    }

    private static string SafeVerifyStatus(EventLogStore log)
    {
        try { return log.Verify().Status.ToString(); } catch { return "unknown"; }
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
    private static HashSet<string> BuildConnectedHarnessIds(IReadOnlyList<McpClientInfo> clients)
    {
        var connected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var harness in KnownHarnesses.All)
        {
            if (clients.Any(c => SseSessionManager.MatchesHarness(c.Name, null, harness.Id)))
                connected.Add(harness.Id);
        }
        return connected;
    }

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
        {
            // Re-stamp the FINAL chain head as the external rollback witness: after a clean stop the file is
            // untouched until the next launch, so next launch's anchor head must equal this — a mismatch then = an
            // offline revert. Recompute from disk (the session appended since the start-anchor).
            if (_eventLogPath is { } logPath && LogHeadReader.CurrentAnchor(logPath) is { Count: > 0 } finalAnchor)
                _osLog.Write(OsEventIds.LogChainAnchor, OsEventCategory.Lifecycle, ForemanSeverity.Info, SealAnchor(finalAnchor).Format());
            _osLog.Write(OsEventIds.StoppedClean, OsEventCategory.Lifecycle, ForemanSeverity.Info,
                $"Foreman Agent Safety stopped (clean shutdown), pid {Environment.ProcessId}.");
        }

        _cts?.Cancel();
        _alertResolver?.Dispose();
        _toolScan?.Dispose();
        _headSealKey?.Dispose();
        _sidecar?.Dispose();
        _mcpHost?.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(3));
        _monitor?.Dispose();
        _panicHotkey?.Dispose();
        _cuBindHotkey?.Dispose();
        _tray?.Dispose();
        if (_ownsSingleInstance) _singleInstance?.ReleaseMutex();
        base.OnExit(e);
    }
}
