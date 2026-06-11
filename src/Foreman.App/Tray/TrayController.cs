using Foreman.App.Windows;
using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Integration;
using Foreman.Core.Models;
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

    // Game mode: pauses on-screen popups while a fullscreen game/app is detected; counts what was held.
    private GameModeWatcher? _gameMode;
    private int _gmSuppressedTotal;
    private int _gmSuppressedCritical;

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

    /// <summary>Injected from App — asks a harness to pack up cleanly (Idle Harness self-cleanup).</summary>
    public Func<string, (bool Ok, string Message)>?           RequestHarnessCleanup { get; set; }

    /// <summary>Injected from App — per-PID network bytes/sec from the elevated sidecar (null when off).</summary>
    public Func<int, double?>?                                GetNetRate            { get; set; }

    /// <summary>Injected from App — applies the Run Elevated toggle (persist + start/stop the sidecar).</summary>
    public Action<bool>?                                      ApplyRunElevated      { get; set; }

    /// <summary>Injected from App — applies the Scan MCP tools toggle (start/stop the opt-in outbound probe).</summary>
    public Action<bool>?                                      ApplyScanMcpTools     { get; set; }

    /// <summary>Injected from App — re-applies decoy read-auditing (re-launch the elevated sidecar with the decoy paths).</summary>
    public Action?                                            ApplyDecoyAuditing    { get; set; }

    /// <summary>Injected from App — the MCP bearer token, for building Claude Code connect config/commands.</summary>
    public Func<string>?                                      GetMcpToken           { get; set; }

    /// <summary>Injected from App — mints a scoped per-harness MCP token for the Connect-Agent flow.</summary>
    public Func<string, string>?                              MintHarnessToken      { get; set; }

    /// <summary>Injected from App — connected MCP clients + capabilities, for the Connect-agent guide.</summary>
    public Func<IReadOnlyList<McpClientInfo>>?                GetConnectedClients   { get; set; }

    /// <summary>Injected from App — true when the elevated network sidecar is connected and feeding.</summary>
    public Func<bool>?                                        GetNetCaptureActive   { get; set; }

    public TrayController(ForemanSettings settings, EventBus bus)
    {
        _settings = settings;
        _bus = bus;
    }

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
                _tray?.ShowNotification("Foreman Agent Safety — game mode ended",
                    $"Held {_gmSuppressedTotal} on-screen alert(s){crit} while you were in a game. Click to review the log.",
                    _gmSuppressedCritical > 0 ? H.NotifyIcon.Core.NotificationIcon.Error : H.NotifyIcon.Core.NotificationIcon.Warning);
                _gmSuppressedTotal = 0;
                _gmSuppressedCritical = 0;
            }
            RefreshAlertState();   // refresh the tooltip's game-mode indicator
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
        Application.Current.Dispatcher.BeginInvoke(() =>
        {
            RefreshAlertState();

            if (evt is InfoEvent || evt.Acknowledged)
                return;

            ShowBalloonIfNeeded(evt);

            // escalation-specific handling
            if (evt is EscalationEvent esc)
                HandleEscalation(esc);
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
                id => DisableHarness?.Invoke(id));
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
            _tray.ShowNotification(title,
                $"{esc.HarnessDisplayName}: {esc.TotalAlerts} alerts, {esc.UniqueRules} rules\n(Click for details)",
                icon);
            return;
        }

        if (evt.Severity >= ForemanSeverity.High)
        {
            _lastBalloonEvent = evt;
            _tray.ShowNotification("Foreman Agent Safety — Critical Alert",
                evt.Message + "\n(Click for details)",
                H.NotifyIcon.Core.NotificationIcon.Error);
        }
        else if (evt.Severity == ForemanSeverity.Medium)
        {
            _lastBalloonEvent = evt;
            _tray.ShowNotification("Foreman Agent Safety — Warning",
                evt.Message + "\n(Click for details)",
                H.NotifyIcon.Core.NotificationIcon.Warning);
        }
    }

    private void SetStatus(TrayStatus status)
    {
        _status = status;
        if (_tray is null) return;

        _tray.Icon = status switch
        {
            TrayStatus.Red   => TrayIconSet.Red,
            TrayStatus.Amber => TrayIconSet.Amber,
            _                => TrayIconSet.Green,
        };

        var escalationStr = _highestEscalation > EscalationLevel.Watch
            ? $" · {_highestEscalation.ToString().ToUpperInvariant()}"
            : "";
        var gameStr = GameModeActive && _settings.GameMode.Enabled ? " · 🎮 game mode (popups paused)" : "";
        _tray.ToolTipText = $"Foreman Agent Safety — {(_activeAlerts > 0 ? $"{_activeAlerts} alert(s){escalationStr}" : "All clear")}{gameStr}";
        _tray.ContextMenu = BuildMenu();
    }

    private void RefreshAlertState()
    {
        var active = EventBus.Instance.GetHistory()
            .Where(AlertActivity.IsActive)   // the one shared definition (tray/dashboard/MCP agree)
            .ToList();

        _activeAlerts = active.Count;
        _highestEscalation = active
            .OfType<EscalationEvent>()
            .Select(e => e.NewLevel)
            .DefaultIfEmpty(EscalationLevel.Watch)
            .Max();

        var status = active.Any(e => e.Severity >= ForemanSeverity.High)
            ? TrayStatus.Red
            : active.Any(e => e.Severity >= ForemanSeverity.Low)
                ? TrayStatus.Amber
                : TrayStatus.Green;
        SetStatus(status);
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
            w.GetMcpClientCount = GetMcpClientCount;
            w.GetNetCaptureConnected = GetNetCaptureActive;
            w.GetConnectedClients = GetConnectedClients;
            // "Agents running" = distinct harness types currently in the process tree (live), which is
            // far more intuitive than a count of behaviour profiles (which sits at 0 until something fires).
            w.GetRunningAgentCount = () => GetProcessSnapshot?.Invoke()
                .Where(p => p.IsHarness)
                .Select(p => p.HarnessType)
                .Where(t => !string.IsNullOrEmpty(t))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count() ?? 0;
            w.McpPort = _settings.McpPort;

            // The monitoring views are now tabs inside the dashboard; build them here (the tray is the
            // composition root that holds the data providers) and hand them to the dashboard to host.
            Func<IEnumerable<Foreman.Core.Models.ProcessRecord>> snap = GetProcessSnapshot ?? (() => []);
            w.HostViews(
                processes: new ProcessMonitorWindow(snap, GetNetRate, RequestHarnessCleanup),
                harnesses: new HarnessesWindow(_settings, snap),
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

    private ContextMenu BuildMenu()
    {
        var menu = new ContextMenu();

        var levelStr = _highestEscalation > EscalationLevel.Watch
            ? $"  [{_highestEscalation.ToString().ToUpperInvariant()}]" : "";
        AddMenuItem(menu, $"Foreman Agent Safety v{GetVersion()}  ●  {_activeAlerts} alert(s){levelStr}", null, enabled: false);
        menu.Items.Add(new Separator());
        AddMenuItem(menu, "Dashboard", () => OpenDashboardWindow());
        AddMenuItem(menu, "Open Log", () => OpenLogWindow());
        AddMenuItem(menu, "Process Monitor…", () => OpenProcessMonitorWindow());
        AddMenuItem(menu, "Harnesses…", () => OpenHarnessesWindow());
        AddMenuItem(menu, "Behavior Metrics…", () => OpenBehaviorMetricsWindow());
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
        AddMenuItem(menu, "Exit", () => Application.Current.Shutdown());

        return menu;
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
            var w = new ConnectAgentWindow(_settings.McpPort, token, GetConnectedClients, MintHarnessToken);
            w.Closed += (_, _) => _connectWindow = null;
            _connectWindow = w;
            w.Show();
        }
        WindowActivation.Surface(_connectWindow);
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
        _gameMode?.Dispose();
        _dashboardWindow?.Close();   // disposes its hosted Process/Harness/Behavior/Log views
        _settingsWindow?.Close();
        _connectWindow?.Close();
        _muteWindow?.Close();
        _tray?.Dispose();
    }
}
