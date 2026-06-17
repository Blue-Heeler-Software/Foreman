using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Power;
using Foreman.Core.Settings;
using Foreman.McpServer;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace Foreman.App.Windows;

/// <summary>
/// Main at-a-glance dashboard window — opened by left-clicking the tray icon.
/// Shows per-harness escalation status chips, then a scrollable feed of the 50 most
/// recent security-relevant events (command alerts, escalations, hangs, orphans).
/// Clicking any row opens the AlertDetailWindow for that event.
/// Refreshes live (via IEventSink) and every 30 s for relative-time ("X ago") text.
/// </summary>
public partial class DashboardWindow : Window, IEventSink
{
    private readonly Func<IEnumerable<BehaviorProfile>> _getProfiles;
    private readonly ObservableCollection<DashboardAlertVm> _alerts = [];
    private readonly DispatcherTimer _refreshTimer;
    private readonly DispatcherTimer _usageTimer;
    private readonly ResourceSampler _usageSampler = new();
    private Dictionary<int, ResourceSampler.Metrics> _liveMetrics = [];
    private readonly List<IDisposable> _hostedViews = [];
    private HarnessesWindow? _harnessView;
    private LogWindow? _logView;   // for tile deep-links that pre-set the severity filter

    /// <summary>Wired by TrayController — Settings and Connect-agent stay as separate dialogs.</summary>
    public Action? OpenSettingsRequested { get; set; }

    /// <summary>Live status providers for the strip/footer, wired by TrayController.</summary>
    public Func<int>?  GetMcpClientCount      { get; set; }
    public Func<bool>? GetNetCaptureConnected { get; set; }
    public int         McpPort                { get; set; } = 54321;

    /// <summary>Connected MCP clients + capabilities, for the MCP CLIENTS tooltip.</summary>
    public Func<IReadOnlyList<McpClientInfo>>? GetConnectedClients { get; set; }

    /// <summary>Live count of agents currently running (distinct harness types), wired by TrayController.</summary>
    public Func<int>? GetRunningAgentCount { get; set; }

    /// <summary>Process snapshot for harness running/MCP attribution.</summary>
    public Func<IEnumerable<ProcessRecord>>? GetProcessSnapshot { get; set; }

    /// <summary>Settings for trust levels and disabled harnesses.</summary>
    public Func<ForemanSettings>? GetSettings { get; set; }

    public Func<string, IEnumerable<ProcessRecord>>? GetProcessesByHarness { get; set; }
    public Func<int, double?>? GetNetRate { get; set; }
    public Func<WakeRequestSnapshot>? GetWakeRequests { get; set; }
    public Func<string?, int>? GetPendingAskCount { get; set; }
    public Func<bool>? GetGameModeActive { get; set; }

    /// <summary>An agent's self-reported context/token budget (via the report_usage MCP tool); null if never reported.</summary>
    public Func<string, HarnessContextUsage?>? GetContextUsage { get; set; }

    /// <summary>Polite MCP "pack up cleanly" request for a harness (Idle Harness self-cleanup); wired by TrayController.</summary>
    public Func<string, (bool Ok, string Message)>? RequestHarnessCleanup { get; set; }

    /// <summary>Reset a harness's escalation/behavior metrics; wired by TrayController.</summary>
    public Action<string>? ResetBehaviorMetrics { get; set; }

    /// <summary>Opens the "Connect agent" guide window.</summary>
    public Action? OpenConnectAgentRequested { get; set; }

    public DashboardWindow(Func<IEnumerable<BehaviorProfile>> getProfiles)
    {
        _getProfiles = getProfiles;
        InitializeComponent();

        AlertList.ItemsSource = _alerts;

        Refresh();
        EventBus.Instance.Subscribe(this);

        // Periodic refresh so relative time labels stay accurate
        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _refreshTimer.Tick += (_, _) => Refresh();
        _refreshTimer.Start();

        _usageTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _usageTimer.Tick += (_, _) => SampleUsage();
        _usageTimer.Start();

        SetPadlockVisual(Security.PresenceGuard.IsEnabled, animate: false);
        Activated += (_, _) => { if (!_padlockBusy) SetPadlockVisual(Security.PresenceGuard.IsEnabled, animate: false); };
    }

    // ── Presence padlock ─────────────────────────────────────────────────────
    private bool _padlockBusy;
    private static readonly System.Windows.Media.Color LockedColor =
        (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF3FB950");
    private static readonly System.Windows.Media.Color UnlockedColor =
        (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF8B949E");

    private void SetPadlockVisual(bool locked, bool animate)
    {
        PadlockLabel.Text = locked ? "Locked" : "Unlocked";
        PadlockLabel.Foreground = new System.Windows.Media.SolidColorBrush(locked ? LockedColor : UnlockedColor);
        var angle = locked ? 0.0 : -30.0;
        var color = locked ? LockedColor : UnlockedColor;

        if (!animate)
        {
            ShackleRotate.Angle = angle;
            LockBodyBrush.Color = color; ShackleBrush.Color = color;
            PadlockGlow.BlurRadius = 0; PadlockScale.ScaleX = PadlockScale.ScaleY = 1;
            return;
        }

        // shackle swings shut/open with a springy overshoot
        ShackleRotate.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty,
            new System.Windows.Media.Animation.DoubleAnimation(angle, TimeSpan.FromSeconds(0.55))
            { EasingFunction = new System.Windows.Media.Animation.BackEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut, Amplitude = 0.7 } });

        var recolor = new System.Windows.Media.Animation.ColorAnimation(color, TimeSpan.FromSeconds(0.45));
        LockBodyBrush.BeginAnimation(System.Windows.Media.SolidColorBrush.ColorProperty, recolor);
        ShackleBrush.BeginAnimation(System.Windows.Media.SolidColorBrush.ColorProperty, recolor.Clone());

        if (locked)
        {
            // satisfying snap + green glow pulse on arming
            var snap = new System.Windows.Media.Animation.DoubleAnimation
            {
                From = 1.22, To = 1.0, Duration = TimeSpan.FromSeconds(0.6),
                EasingFunction = new System.Windows.Media.Animation.ElasticEase
                { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut, Oscillations = 2, Springiness = 5 },
            };
            PadlockScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, snap);
            PadlockScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, snap.Clone());

            PadlockGlow.Color = LockedColor;
            PadlockGlow.BeginAnimation(System.Windows.Media.Effects.DropShadowEffect.BlurRadiusProperty,
                new System.Windows.Media.Animation.DoubleAnimation { From = 20, To = 4, Duration = TimeSpan.FromSeconds(0.75),
                    EasingFunction = new System.Windows.Media.Animation.CubicEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut } });
        }
        else
        {
            PadlockGlow.BeginAnimation(System.Windows.Media.Effects.DropShadowEffect.BlurRadiusProperty,
                new System.Windows.Media.Animation.DoubleAnimation(0, TimeSpan.FromSeconds(0.3)));
        }
    }

    private async void PadlockClick(object sender, RoutedEventArgs e)
    {
        _padlockBusy = true;
        try
        {
            if (Security.PresenceGuard.IsEnabled)
            {
                var (ok, msg) = await Security.PresenceGuard.DisableAsync();
                if (ok) SetPadlockVisual(false, animate: true);
                else MessageBox.Show(msg, "Foreman Agent Safety — Presence lock", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!Security.PresenceGuard.IsAvailable)
            {
                MessageBox.Show("No authenticator available. Set up Windows Hello (a PIN or biometric) or attach a FIDO2 security key, then try again.",
                    "Foreman Agent Safety — Presence lock", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var choice = MessageBox.Show(
                "Require a Windows Hello or security-key tap to WEAKEN Foreman?\n\n" +
                "YES = Strict (also requires a tap to QUIT Foreman)\nNO = Standard (recommended)\nCancel = don't enable",
                "Foreman Agent Safety — Enable presence lock", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (choice == MessageBoxResult.Cancel) return;
            var scope = choice == MessageBoxResult.Yes ? Foreman.Core.Security.LockScope.Strict : Foreman.Core.Security.LockScope.Standard;
            var (ok2, msg2) = await Security.PresenceGuard.EnableAsync(scope);
            if (ok2) SetPadlockVisual(true, animate: true);
            else MessageBox.Show(msg2, "Foreman Agent Safety — Presence lock", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally { _padlockBusy = false; }
    }

    // ── IEventSink ────────────────────────────────────────────────────────────

    void IEventSink.OnEvent(ForemanEvent evt)
    {
        // Info events (startup messages etc.) don't appear in the dashboard
        if (evt is InfoEvent) return;
        Dispatcher.BeginInvoke(Refresh);
    }

    // ── Data refresh ──────────────────────────────────────────────────────────

    private void Refresh()
    {
        // ── Alert feed ────────────────────────────────────────────────────────
        var history = EventBus.Instance.GetHistory();
        var relevant = history
            .Where(static e => e is CommandAlertEvent
                                  or EscalationEvent
                                  or HangDetectedEvent
                                  or OrphanDetectedEvent
                                  or MonitoringNoticeEvent)
            .OrderByDescending(e => e.Timestamp)
            .Take(50)
            .ToList();

        _alerts.Clear();
        foreach (var evt in relevant)
            _alerts.Add(DashboardAlertVm.From(evt));

        var allProfiles = _getProfiles().ToList();
        var settings = GetSettings?.Invoke() ?? new ForemanSettings();
        var connectedClients = GetConnectedClients?.Invoke() ?? [];
        var snapshot = GetProcessSnapshot?.Invoke()?.ToList() ?? [];
        var wake = GetWakeRequests?.Invoke();
        var pendingTotal = GetPendingAskCount?.Invoke(null) ?? 0;

        MetaLightsPanel.ItemsSource = BuildMetaLights(settings, connectedClients, pendingTotal);

        var runningIds = snapshot
            .Where(p => !string.IsNullOrEmpty(p.HarnessType))
            .Select(p => p.HarnessType!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var profileById = allProfiles.ToDictionary(p => p.HarnessId, StringComparer.OrdinalIgnoreCase);
        var wakeByHarness = wake is { Available: true }
            ? BuildWakeMap(snapshot, wake)
            : new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        var chipHarnesses = KnownHarnesses.All
            .Where(h => !settings.DisabledHarnesses.Contains(h.Id))
            .Select(h => new HarnessChipVm(
                h,
                profileById.GetValueOrDefault(h.Id),
                runningIds.Contains(h.Id),
                IsMcpConnected(connectedClients, h.Id),
                settings.HarnessTrust.TryGetValue(h.Id, out var trust) ? Math.Clamp(trust, 1, 5) : 3))
            .Where(c => c.IsRunning || c.McpConnected || c.AlertCount > 0)
            .OrderByDescending(c => (int)c.EscalationLevel)
            .ThenByDescending(c => c.AlertCount)
            .ThenBy(c => c.DisplayName)
            .ToList();

        HarnessPanel.ItemsSource = chipHarnesses;

        HarnessOverviewPanel.ItemsSource = KnownHarnesses.All
            .Where(h => !settings.DisabledHarnesses.Contains(h.Id))
            .Select(h =>
            {
                var procs = GetProcessesByHarness?.Invoke(h.Id)?.ToList()
                            ?? snapshot.Where(p => string.Equals(p.HarnessType, h.Id, StringComparison.OrdinalIgnoreCase)).ToList();
                var usage = HarnessUsageAggregator.Aggregate(procs, _liveMetrics, GetNetRate);
                var pending = GetPendingAskCount?.Invoke(h.Id) ?? 0;
                wakeByHarness.TryGetValue(h.Id, out var wakeCount);
                return new DashboardHarnessCardVm(
                    h,
                    profileById.GetValueOrDefault(h.Id),
                    runningIds.Contains(h.Id),
                    IsMcpConnected(connectedClients, h.Id),
                    settings.HarnessTrust.TryGetValue(h.Id, out var trust2) ? Math.Clamp(trust2, 1, 5) : 3,
                    procs.Count,
                    usage,
                    pending,
                    wakeCount,
                    GetContextUsage?.Invoke(h.Id));
            })
            // Show every harness that's running, MCP-connected, OR has alerts (same set as the header chips), so
            // your agents stay visible even when none currently holds a live MCP session. The card itself shows
            // connection state ("MCP linked" vs "No MCP", Running vs Idle).
            .Where(c => c.IsRunning || c.McpConnected || c.AlertCount > 0)
            .OrderByDescending(c => c.IsRunning)
            .ThenByDescending(c => (int)c.EscalationLevel)
            .ThenBy(c => c.DisplayName)
            .ToList();

        NoConnectedHarnessText.Visibility =
            ((IReadOnlyCollection<DashboardHarnessCardVm>)HarnessOverviewPanel.ItemsSource).Count == 0
                ? Visibility.Visible
                : Visibility.Collapsed;

        UpdateAgentUsageFootnote(snapshot);

        // ── Header summary ────────────────────────────────────────────────────
        // "Active alerts" = unacknowledged events ABOVE Info severity.
        var active = history
            .Where(AlertActivity.IsActive)   // the one shared definition (tray/dashboard/MCP agree)
            .ToList();

        SummaryLabel.Text = active.Count == 0
            ? "all clear"
            : $"{active.Count} active alert{(active.Count == 1 ? "" : "s")}";

        ActiveAlertCountLabel.Text = active.Count.ToString(CultureInfo.InvariantCulture);
        AckAllButton.Visibility = active.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        HarnessCountLabel.Text = (GetRunningAgentCount?.Invoke() ?? allProfiles.Count)
            .ToString(CultureInfo.InvariantCulture);
        HighAlertCountLabel.Text = active
            .Count(e => e.Severity >= ForemanSeverity.High)
            .ToString(CultureInfo.InvariantCulture);
        LastEventLabel.Text = relevant.FirstOrDefault() is { } last
            ? RelativeSummary(last.Timestamp)
            : "none";

        McpClientsLabel.Text = (GetMcpClientCount?.Invoke() ?? 0).ToString(CultureInfo.InvariantCulture);
        NetCaptureLabel.Text = GetNetCaptureConnected?.Invoke() == true ? "On" : "Off";

        // Per-session capability breakdown on the MCP CLIENTS card (hover).
        McpClientsCard.ToolTip = connectedClients.Count == 0
            ? "No agents connected to Foreman Agent Safety's MCP.\nClick to open the Connect agent guide."
            : "Connected agents:\n" + string.Join("\n", connectedClients.Select(c =>
                $"  • {c.Name}{(string.IsNullOrWhiteSpace(c.Version) ? "" : $" v{c.Version}")} — " +
                $"sampling: {(c.Sampling ? "yes (Ask Harness gets a reply)" : "no (Ask Harness notifies one-way)")}"))
              + "\n\nClick to open the Connect agent guide.";

        // ── Footer ────────────────────────────────────────────────────────────
        var meta = $"Foreman Agent Safety v{Version}  ·  up {Uptime()}  ·  MCP :{McpPort}";
        FooterText.Text = relevant.Count == 0
            ? meta
            : $"{meta}  ·  {relevant.Count} recent event{(relevant.Count == 1 ? "" : "s")}  ·  click any row for detail";

        // ── Show / hide empty state ───────────────────────────────────────────
        var hasItems = relevant.Count > 0;
        EmptyPanel.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
        AlertList.Visibility  = hasItems ? Visibility.Visible   : Visibility.Collapsed;
    }

    // ── UI event handlers ─────────────────────────────────────────────────────

    private void AlertList_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        var item = FindAncestor<ListViewItem>(e.OriginalSource as DependencyObject);
        if (item?.DataContext is not DashboardAlertVm vm) return;

        OpenAlertDetail(vm);
        e.Handled = true;
    }

    private void AlertList_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key is not (Key.Enter or Key.Space)) return;
        if (AlertList.SelectedItem is not DashboardAlertVm vm) return;

        OpenAlertDetail(vm);
        e.Handled = true;
    }

    private void OpenAlertDetail(DashboardAlertVm vm)
    {
        AlertList.SelectedItem = null;
        AlertDetailWindow.ShowFor(vm.OriginalEvent, this);
    }

    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match) return match;
            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private void OpenSettingsClick(object sender, RoutedEventArgs e) =>
        OpenSettingsRequested?.Invoke();

    private void ConnectAgentClick(object sender, RoutedEventArgs e) =>
        OpenConnectAgentRequested?.Invoke();

    // ── Metric tile clicks ────────────────────────────────────────────────────
    // Each tile deep-links to the most useful view for that number.

    private void ActiveAlertsTileClick(object sender, MouseButtonEventArgs e)
    {
        _logView?.SetMinimumSeverity(ForemanSeverity.Low);   // alerts, without Info noise
        ShowTab(DashboardTab.Log);
    }

    private void AgentsTileClick(object sender, MouseButtonEventArgs e) =>
        ShowTab(DashboardTab.Processes);

    private void HighCriticalTileClick(object sender, MouseButtonEventArgs e)
    {
        _logView?.SetMinimumSeverity(ForemanSeverity.High);
        ShowTab(DashboardTab.Log);
    }

    private void LastEventTileClick(object sender, MouseButtonEventArgs e)
    {
        if (_alerts.FirstOrDefault() is { } vm)
            AlertDetailWindow.ShowFor(vm.OriginalEvent, this);
    }

    private void McpClientsTileClick(object sender, MouseButtonEventArgs e) =>
        OpenConnectAgentRequested?.Invoke();

    private void NetworkTileClick(object sender, MouseButtonEventArgs e) =>
        OpenSettingsRequested?.Invoke();

    // Meta-light dots deep-link to the pertinent view (so a red dot like "Ask pending" isn't a dead end).
    // Routed by the light's Label so this doesn't depend on the VM carrying a target.
    private void MetaLightClick(object sender, MouseButtonEventArgs e)
    {
        if (FindDataContext<DashboardMetaLightVm>(e.OriginalSource) is not { } light) return;
        switch (light.Label)
        {
            case "Ask pending":  ShowTab(DashboardTab.Harnesses); break;   // act on the harness holding the prompt
            case "Event log":    ShowTab(DashboardTab.Log); break;
            case "Extension":
            case "MCP clients":  OpenConnectAgentRequested?.Invoke(); break;
            default:             OpenSettingsRequested?.Invoke(); break;    // Presence, Game mode, Sidecar, MCP scan
        }
        e.Handled = true;
    }

    private void HarnessChipClick(object sender, MouseButtonEventArgs e)
    {
        if (FindDataContext<HarnessChipVm>(e.OriginalSource) is { } chip)
            OpenHarnessDetail(chip.HarnessId);
        else
            ShowTab(DashboardTab.Harnesses);
    }

    private void HarnessOverviewClick(object sender, MouseButtonEventArgs e)
    {
        if (FindDataContext<DashboardHarnessCardVm>(e.OriginalSource) is { } card)
            OpenHarnessDetail(card.HarnessId);
        else
            ShowTab(DashboardTab.Harnesses);
    }

    // Clicking a harness opens the verbose detail view (live usage + behavior + MCP + processes).
    // "Harness settings" inside that window is the path to the editable trust/modality dialog.
    private void OpenHarnessDetail(string harnessId)
    {
        if (GetSettings is null) return;

        var ctx = new HarnessDetailContext
        {
            HarnessId = harnessId,
            GetProcesses = () => GetProcessesByHarness?.Invoke(harnessId)
                                 ?? (GetProcessSnapshot?.Invoke() ?? [])
                                     .Where(p => string.Equals(p.HarnessType, harnessId, StringComparison.OrdinalIgnoreCase)),
            GetProfile = () => _getProfiles().FirstOrDefault(p =>
                string.Equals(p.HarnessId, harnessId, StringComparison.OrdinalIgnoreCase)),
            GetClients = () => GetConnectedClients?.Invoke() ?? [],
            GetSettings = () => GetSettings?.Invoke() ?? new ForemanSettings(),
            GetPendingAsk = () => GetPendingAskCount?.Invoke(harnessId) ?? 0,
            GetWakeLocks = () => WakeLocksFor(harnessId),
            GetNetRate = GetNetRate,
            OpenSettings = () => OpenHarnessSettings(harnessId),
            OpenConnectAgent = () => OpenConnectAgentRequested?.Invoke(),
            GetContextUsage = () => GetContextUsage?.Invoke(harnessId),
            RequestCleanup = RequestHarnessCleanup is null ? null : () => RequestHarnessCleanup(harnessId),
            ResetMetrics = ResetBehaviorMetrics is null ? null : () => ResetBehaviorMetrics(harnessId),
        };

        new HarnessDetailWindow(ctx) { Owner = this }.Show();
    }

    private int WakeLocksFor(string harnessId)
    {
        var wake = GetWakeRequests?.Invoke();
        if (wake is not { Available: true }) return 0;
        var snapshot = GetProcessSnapshot?.Invoke()?.ToList() ?? [];
        return BuildWakeMap(snapshot, wake).GetValueOrDefault(harnessId);
    }

    private void OpenHarnessSettings(string harnessId)
    {
        var settings = GetSettings?.Invoke();
        if (settings is null) return;

        var display = KnownHarnesses.GetById(harnessId)?.DisplayName ?? harnessId;
        var w = new HarnessSettingsWindow(harnessId, display, settings) { Owner = this };
        if (w.ShowDialog() == true)
            Refresh();
    }

    private void SampleUsage()
    {
        var pids = GetProcessSnapshot?.Invoke()?.Select(p => p.Pid).ToList();
        if (pids is null || pids.Count == 0)
        {
            _liveMetrics = [];
            return;
        }

        _liveMetrics = _usageSampler.Sample(pids);
        Refresh();
    }

    private void UpdateAgentUsageFootnote(IReadOnlyList<ProcessRecord> snapshot)
    {
        if (AgentUsageLabel is null) return;
        var harnessPids = snapshot.Where(p => p.IsHarness || !string.IsNullOrEmpty(p.HarnessType)).Select(p => p.Pid).ToList();
        if (harnessPids.Count == 0)
        {
            AgentUsageLabel.Text = string.Empty;
            return;
        }

        double cpu = 0;
        long mem = 0;
        foreach (var pid in harnessPids)
        {
            if (_liveMetrics.TryGetValue(pid, out var m))
            {
                cpu += m.CpuPercent;
                mem += m.MemoryBytes;
            }
        }

        AgentUsageLabel.Text = cpu > 0.5 || mem > 0
            ? $"Σ {HarnessUsageAggregator.FormatCpu(cpu)} CPU · {HarnessUsageAggregator.FormatMem(mem)} RAM"
            : string.Empty;
    }

    private IReadOnlyList<DashboardMetaLightVm> BuildMetaLights(
        ForemanSettings settings,
        IReadOnlyList<McpClientInfo> clients,
        int pendingAsk)
    {
        var sidecarOn = GetNetCaptureConnected?.Invoke() == true;
        var gameOn = GetGameModeActive?.Invoke() == true && settings.GameMode.Enabled;
        var extPaired = settings.PairedExtensionOrigins.Count > 0;

        return
        [
            new DashboardMetaLightVm(
                "Presence",
                Security.PresenceGuard.IsEnabled ? MetaLightState.Ok : MetaLightState.Off,
                Security.PresenceGuard.IsEnabled
                    ? $"Presence lock armed ({Security.PresenceGuard.AuthenticatorLabel})."
                    : "Presence lock off — weakening actions need no tap."),
            new DashboardMetaLightVm(
                "Game mode",
                gameOn ? MetaLightState.Warn : MetaLightState.Off,
                gameOn
                    ? "Fullscreen detected — on-screen popups paused."
                    : settings.GameMode.Enabled ? "Game mode enabled, no fullscreen app detected." : "Game mode off."),
            new DashboardMetaLightVm(
                "Extension",
                extPaired ? MetaLightState.Ok : MetaLightState.Off,
                extPaired
                    ? $"{settings.PairedExtensionOrigins.Count} browser extension origin(s) paired."
                    : "Browser extension not paired — use Connect agent."),
            new DashboardMetaLightVm(
                "Sidecar",
                sidecarOn ? MetaLightState.Ok
                    : settings.RunElevated ? MetaLightState.Warn : MetaLightState.Off,
                sidecarOn
                    ? "Elevated sidecar connected — network + wake telemetry live."
                    : settings.RunElevated
                        ? "Run elevated is on but the sidecar is not connected."
                        : "Elevated sidecar off (enable in Settings for network/wake columns)."),
            new DashboardMetaLightVm(
                "MCP scan",
                settings.ScanMcpTools ? MetaLightState.Warn : MetaLightState.Off,
                settings.ScanMcpTools
                    ? "Opt-in MCP tool-description scan is ON (outbound HTTP/SSE)."
                    : "MCP tool scan off."),
            new DashboardMetaLightVm(
                "Event log",
                settings.EventLogPersist ? MetaLightState.Ok : MetaLightState.Off,
                settings.EventLogPersist
                    ? "Event log persisted to disk (hash-chained JSONL)."
                    : "Event log is session-only."),
            new DashboardMetaLightVm(
                "Ask pending",
                pendingAsk > 0 ? MetaLightState.Alert : MetaLightState.Off,
                pendingAsk > 0
                    ? $"{pendingAsk} unanswered Ask Harness / audit prompt(s) waiting on a harness."
                    : "No pending Ask Harness requests."),
            new DashboardMetaLightVm(
                "MCP clients",
                clients.Count > 0 ? MetaLightState.Ok : MetaLightState.Off,
                clients.Count > 0
                    ? $"{clients.Count} agent(s) connected to Foreman's MCP."
                    : "No MCP clients connected."),
        ];
    }

    private static Dictionary<string, int> BuildWakeMap(IReadOnlyList<ProcessRecord> snapshot, WakeRequestSnapshot wake)
    {
        var byPid = snapshot.ToDictionary(p => p.Pid);
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var request in wake.Requests.Where(r => string.Equals(r.RequesterType, "PROCESS", StringComparison.OrdinalIgnoreCase)))
        {
            foreach (var process in snapshot.Where(p => MatchesWakeImage(p, request.Image)))
            {
                var harness = FindHarnessAncestor(byPid, process.Pid)?.HarnessType;
                if (string.IsNullOrWhiteSpace(harness)) continue;
                map[harness] = map.GetValueOrDefault(harness) + 1;
            }
        }
        return map;
    }

    private static bool MatchesWakeImage(ProcessRecord process, string image)
    {
        if (string.IsNullOrWhiteSpace(image)) return false;
        var name = Path.GetFileName(image.Replace('/', '\\'));
        return string.Equals(name, process.Name, StringComparison.OrdinalIgnoreCase)
               || (!string.IsNullOrWhiteSpace(process.ExecutablePath)
                   && string.Equals(Path.GetFileName(process.ExecutablePath), name, StringComparison.OrdinalIgnoreCase));
    }

    private static ProcessRecord? FindHarnessAncestor(IReadOnlyDictionary<int, ProcessRecord> byPid, int pid)
    {
        var seen = new HashSet<int>();
        while (byPid.TryGetValue(pid, out var current) && seen.Add(pid))
        {
            if (!string.IsNullOrWhiteSpace(current.HarnessType)) return current;
            if (current.ParentPid == 0 || current.ParentPid == current.Pid) break;
            pid = current.ParentPid;
        }
        return null;
    }

    private static bool IsMcpConnected(IReadOnlyList<McpClientInfo> clients, string harnessId) =>
        clients.Any(c => SseSessionManager.MatchesHarness(c.Name, null, harnessId));

    private static T? FindDataContext<T>(object? source) where T : class
    {
        if (source is not DependencyObject d) return null;
        while (d is not null)
        {
            if (d is FrameworkElement { DataContext: T ctx }) return ctx;
            d = VisualTreeHelper.GetParent(d);
        }
        return null;
    }

    // Bulk acknowledge: events are shared instances across EventBus history, ForemanState,
    // and the views, so flipping Acknowledged here clears the tray, the MCP counts, and this
    // dashboard together. The InfoEvent is the audit trail (and pokes event-driven refreshes).
    private void AcknowledgeAllClick(object sender, RoutedEventArgs e)
    {
        var acked = 0;
        foreach (var evt in EventBus.Instance.GetHistory())
        {
            if (evt.Severity > ForemanSeverity.Info && !evt.Acknowledged)
            {
                evt.Acknowledged = true;
                acked++;
            }
        }

        if (acked > 0)
        {
            EventBus.Instance.Publish(new InfoEvent(
                DateTimeOffset.UtcNow, "Foreman.Dashboard",
                $"Operator acknowledged all alerts ({acked})."));
        }

        Refresh();
    }

    // ── Tabs / hosted views ───────────────────────────────────────────────────

    public enum DashboardTab { Overview = 0, Processes = 1, Harnesses = 2, Behavior = 3, Log = 4 }

    public void ShowTab(DashboardTab tab) => Tabs.SelectedIndex = (int)tab;

    /// <summary>Injects the monitoring views (built by the tray) into their tabs; disposed on close.</summary>
    public void HostViews(UIElement? processes, UIElement? harnesses, UIElement? behavior, UIElement? log)
    {
        ProcessSlot.Content  = processes;
        HarnessSlot.Content  = harnesses;
        BehaviorSlot.Content = behavior;
        LogSlot.Content      = log;
        _harnessView = harnesses as HarnessesWindow;   // for the unsaved-changes prompt on navigate-away
        _logView     = log as LogWindow;               // for tile deep-links with a pre-set severity filter
        if (_harnessView is not null)
            _harnessView.OpenConnectAgent = () => OpenConnectAgentRequested?.Invoke();
        foreach (var v in new object?[] { processes, harnesses, behavior, log })
            if (v is IDisposable d) _hostedViews.Add(d);
    }

    // Prompt to save Harnesses-tab edits when the user navigates away (switches tab) or closes.
    private async void TabsSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // TabControl SelectionChanged bubbles from child ListViews too — only react to the tabs themselves.
        if (!ReferenceEquals(e.OriginalSource, Tabs)) return;
        if (_harnessView is null || e.RemovedItems.Count == 0) return;
        if (e.RemovedItems[0] is not TabItem leftTab) return;
        if (Tabs.Items.IndexOf(leftTab) != (int)DashboardTab.Harnesses) return;
        if (!_harnessView.HasUnsavedChanges()) return;

        switch (PromptSaveHarnesses("switching tabs"))
        {
            case MessageBoxResult.Yes:
                if (!await _harnessView.SaveChanges())                  // denied → reverted; snap back to Harnesses tab
                    Dispatcher.BeginInvoke(() => Tabs.SelectedItem = leftTab);
                break;
            case MessageBoxResult.No:     _harnessView.Revert();      break;
            case MessageBoxResult.Cancel:
                // Re-select the Harnesses tab once this event settles.
                Dispatcher.BeginInvoke(() => Tabs.SelectedItem = leftTab);
                break;
        }
    }

    private bool _forceClose;

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (!_forceClose && _harnessView?.HasUnsavedChanges() == true)
        {
            switch (PromptSaveHarnesses("closing"))
            {
                case MessageBoxResult.Yes:
                    e.Cancel = true;                 // hold the close until the gated save resolves, then re-close
                    _ = SaveThenCloseAsync();
                    return;
                case MessageBoxResult.No:     break;                       // discard, allow close
                case MessageBoxResult.Cancel: e.Cancel = true; return;     // stay open
            }
        }
        base.OnClosing(e);
    }

    // Await the gated save (deny reverts, never persists), then close for real — so a denied tap can't be
    // outraced by the window closing first (the adversarial-review fix).
    private async Task SaveThenCloseAsync()
    {
        await _harnessView!.SaveChanges();
        _forceClose = true;
        Close();
    }

    private static MessageBoxResult PromptSaveHarnesses(string action) =>
        MessageBox.Show(
            $"You have unsaved changes on the Harnesses tab.\n\nSave them before {action}?",
            "Foreman Agent Safety — Unsaved changes", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);

    private static string Version =>
        System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1";

    private static string Uptime()
    {
        try
        {
            var up = DateTime.Now - System.Diagnostics.Process.GetCurrentProcess().StartTime;
            if (up.TotalMinutes < 1) return "<1m";
            if (up.TotalHours   < 1) return $"{(int)up.TotalMinutes}m";
            if (up.TotalDays    < 1) return $"{(int)up.TotalHours}h {up.Minutes:D2}m";
            return $"{(int)up.TotalDays}d {up.Hours}h";
        }
        catch { return "?"; }
    }

    protected override void OnClosed(EventArgs e)
    {
        EventBus.Instance.Unsubscribe(this);
        _refreshTimer.Stop();
        _usageTimer.Stop();
        _usageSampler.Dispose();
        foreach (var d in _hostedViews) { try { d.Dispose(); } catch { /* best-effort */ } }
        _hostedViews.Clear();
        base.OnClosed(e);
    }

    private static string RelativeSummary(DateTimeOffset ts)
    {
        var ago = DateTimeOffset.UtcNow - ts;
        if (ago.TotalSeconds < 30) return "just now";
        if (ago.TotalMinutes < 60) return $"{Math.Max(1, (int)ago.TotalMinutes)}m ago";
        if (ago.TotalHours < 24) return $"{(int)ago.TotalHours}h ago";
        return $"{(int)ago.TotalDays}d ago";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DashboardAlertVm — one row in the alert feed
// ─────────────────────────────────────────────────────────────────────────────

public sealed class DashboardAlertVm
{
    public string     SeverityLabel     { get; }
    public Brush      SeverityBrush     { get; }
    public string     TagBadge          { get; }  // "NET", "CRED", "ESC", "HANG" …
    public Brush      TagBg             { get; }
    public Brush      TagFg             { get; }
    public string     Headline          { get; }  // primary display text
    public string     SubLine           { get; }  // command / categories / detail
    public Visibility SubLineVisibility { get; }
    public string     TimeAgo           { get; }
    public ForemanEvent OriginalEvent   { get; }

    private DashboardAlertVm(
        string severityLabel, Brush severityBrush,
        string tagBadge, Brush tagBg, Brush tagFg,
        string headline, string subLine, string timeAgo,
        ForemanEvent originalEvent)
    {
        SeverityLabel     = severityLabel;
        SeverityBrush     = severityBrush;
        TagBadge          = tagBadge;
        TagBg             = tagBg;
        TagFg             = tagFg;
        Headline          = headline;
        SubLine           = subLine;
        SubLineVisibility = string.IsNullOrEmpty(subLine) ? Visibility.Collapsed : Visibility.Visible;
        TimeAgo           = timeAgo;
        OriginalEvent     = originalEvent;
    }

    public static DashboardAlertVm From(ForemanEvent evt)
    {
        var (tag, tagBg, tagFg) = GetTag(evt);
        var (headline, subLine) = GetContent(evt);

        return new DashboardAlertVm(
            evt.Severity.ToString().ToUpperInvariant(),
            SeverityToBrush(evt.Severity),
            tag, tagBg, tagFg,
            headline, subLine,
            RelativeTime(evt.Timestamp),
            evt);
    }

    // ── Tag badge ─────────────────────────────────────────────────────────────

    private static (string tag, Brush bg, Brush fg) GetTag(ForemanEvent evt) => evt switch
    {
        CommandAlertEvent cmd => CommandTag(cmd.RuleId),

        EscalationEvent esc => esc.NewLevel switch
        {
            EscalationLevel.Emergency => ("ESC",
                new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
                new SolidColorBrush(Color.FromRgb(0xFF, 0x77, 0x77))),
            EscalationLevel.Alarm => ("ESC",
                new SolidColorBrush(Color.FromRgb(0x3A, 0x1A, 0x04)),
                new SolidColorBrush(Color.FromRgb(0xFF, 0xAA, 0x55))),
            _ => ("ESC",
                new SolidColorBrush(Color.FromRgb(0x2C, 0x22, 0x06)),
                new SolidColorBrush(Color.FromRgb(0xE8, 0xC0, 0x55))),
        },

        HangDetectedEvent => ("HANG",
            new SolidColorBrush(Color.FromRgb(0x1C, 0x18, 0x06)),
            new SolidColorBrush(Color.FromRgb(0xCC, 0xAA, 0x44))),

        OrphanDetectedEvent => ("ORPHAN",
            new SolidColorBrush(Color.FromRgb(0x18, 0x14, 0x04)),
            new SolidColorBrush(Color.FromRgb(0xAA, 0x88, 0x33))),

        _ => ("EVENT",
            new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x24)),
            new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
    };

    private static (string tag, Brush bg, Brush fg) CommandTag(string ruleId)
    {
        var cat = ruleId.Split('-')[0].ToUpperInvariant();
        return cat switch
        {
            "CRED" => (cat,
                new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
                new SolidColorBrush(Color.FromRgb(0xFF, 0x88, 0x88))),
            "NET" => (cat,
                new SolidColorBrush(Color.FromRgb(0x0A, 0x1C, 0x38)),
                new SolidColorBrush(Color.FromRgb(0x66, 0xAA, 0xFF))),
            "PRIV" => (cat,
                new SolidColorBrush(Color.FromRgb(0x28, 0x0A, 0x2C)),
                new SolidColorBrush(Color.FromRgb(0xCC, 0x77, 0xFF))),
            "WIN" => (cat,
                new SolidColorBrush(Color.FromRgb(0x10, 0x14, 0x34)),
                new SolidColorBrush(Color.FromRgb(0x88, 0x99, 0xFF))),
            "DEL" => (cat,
                new SolidColorBrush(Color.FromRgb(0x2E, 0x1E, 0x04)),
                new SolidColorBrush(Color.FromRgb(0xEE, 0xCC, 0x44))),
            _ => (cat,
                new SolidColorBrush(Color.FromRgb(0x18, 0x1A, 0x22)),
                new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
        };
    }

    // ── Headline + subLine ────────────────────────────────────────────────────

    private static (string headline, string subLine) GetContent(ForemanEvent evt) => evt switch
    {
        CommandAlertEvent cmd =>
            (
                $"{cmd.RuleName}  ·  {ProcessName(cmd.Source)}",
                cmd.CommandLine.Length > 120
                    ? cmd.CommandLine[..120] + "…"
                    : cmd.CommandLine
            ),

        EscalationEvent esc =>
            (
                $"{esc.HarnessDisplayName}  →  {esc.NewLevel.ToString().ToUpperInvariant()}",
                BuildEscSubLine(esc)
            ),

        HangDetectedEvent hang =>
            (
                $"{hang.ProcessName}  (pid {hang.ProcessId})  -  no I/O for {hang.SilentMinutes}min",
                $"{HangOwnerLine(hang)}  -  running {hang.UptimeMinutes}min total"
            ),

        OrphanDetectedEvent orphan =>
            (
                $"{orphan.ProcessName}  —  orphaned after parent exited",
                $"was child of {orphan.DeadParentName} (pid {orphan.DeadParentPid})" +
                $"  ·  running {orphan.UptimeMinutes}min"
            ),

        _ => (
            evt.Message.Length > 100 ? evt.Message[..100] + "…" : evt.Message,
            string.Empty
        ),
    };

    private static string BuildEscSubLine(EscalationEvent esc)
    {
        var parts = new List<string>
        {
            $"{esc.TotalAlerts} alert{(esc.TotalAlerts == 1 ? "" : "s")}",
        };
        if (esc.UniqueRules > 0)
            parts.Add($"{esc.UniqueRules} rule{(esc.UniqueRules == 1 ? "" : "s")}");
        if (esc.CategoryList.Length > 0)
            parts.Add(string.Join(", ", esc.CategoryList).ToUpperInvariant());
        return string.Join("  ·  ", parts);
    }

    private static string HangOwnerLine(HangDetectedEvent hang)
    {
        var parts = new List<string>();

        if (hang.SpawnerPid is int spawnerPid)
        {
            if (hang.ParentHarnessPid == spawnerPid && !string.IsNullOrWhiteSpace(hang.ParentHarnessType))
            {
                parts.Add(string.IsNullOrWhiteSpace(hang.SpawnerName)
                    ? $"spawned by {hang.ParentHarnessType} pid {spawnerPid}"
                    : $"spawned by {hang.ParentHarnessType} ({hang.SpawnerName}, pid {spawnerPid})");
            }
            else
            {
                parts.Add(string.IsNullOrWhiteSpace(hang.SpawnerName)
                    ? $"spawned by pid {spawnerPid}"
                    : $"spawned by {hang.SpawnerName} (pid {spawnerPid})");
            }
        }

        if (hang.ParentHarnessPid is int ownerPid && ownerPid != hang.SpawnerPid)
        {
            var type = string.IsNullOrWhiteSpace(hang.ParentHarnessType)
                ? "harness"
                : hang.ParentHarnessType;
            var owner = string.IsNullOrWhiteSpace(hang.ParentHarnessName)
                ? $"{type} pid {ownerPid}"
                : $"{type} ({hang.ParentHarnessName}, pid {ownerPid})";
            parts.Add($"owned by {owner}");
        }

        return parts.Count == 0 ? "owner unknown" : string.Join(" - ", parts);
    }

    private static string ProcessName(string source)
    {
        // Source format: "processName (pid 12345)"
        var idx = source.IndexOf(" (pid", StringComparison.Ordinal);
        return idx > 0 ? source[..idx] : source;
    }

    // ── Severity brush ────────────────────────────────────────────────────────

    private static Brush SeverityToBrush(ForemanSeverity s) => s switch
    {
        ForemanSeverity.Critical => new SolidColorBrush(Color.FromRgb(0xCC, 0x22, 0x22)),
        ForemanSeverity.High     => new SolidColorBrush(Color.FromRgb(0xCC, 0x55, 0x22)),
        ForemanSeverity.Medium   => new SolidColorBrush(Color.FromRgb(0xAA, 0x77, 0x11)),
        ForemanSeverity.Low      => new SolidColorBrush(Color.FromRgb(0x33, 0x77, 0x33)),
        _                        => new SolidColorBrush(Color.FromRgb(0x33, 0x66, 0x99)),
    };

    // ── Relative time ─────────────────────────────────────────────────────────

    private static string RelativeTime(DateTimeOffset ts)
    {
        var ago = DateTimeOffset.UtcNow - ts;
        if (ago.TotalSeconds < 30) return "just now";
        if (ago.TotalMinutes <  2) return $"{(int)ago.TotalSeconds}s ago";
        if (ago.TotalMinutes < 60) return $"{(int)ago.TotalMinutes}m ago";
        if (ago.TotalHours   < 24) return $"{(int)ago.TotalHours}h ago";
        return $"{(int)ago.TotalDays}d ago";
    }
}

// HarnessChipVm — compact header chip for active harnesses
// ─────────────────────────────────────────────────────────────────────────────

public sealed class HarnessChipVm
{
    public string HarnessId { get; }
    public string DisplayName { get; }
    public string LevelLabel { get; }
    public Brush LevelBg { get; }
    public Brush LevelFg { get; }
    public string TrustLabel { get; }
    public string McpLabel { get; }
    public string ToolTip { get; }
    public bool IsRunning { get; }
    public bool McpConnected { get; }
    public int AlertCount { get; }
    public EscalationLevel EscalationLevel { get; }

    public HarnessChipVm(KnownHarness harness, BehaviorProfile? profile, bool isRunning, bool mcpConnected, int trust)
    {
        HarnessId = harness.Id;
        DisplayName = harness.DisplayName;
        IsRunning = isRunning;
        McpConnected = mcpConnected;
        AlertCount = profile?.TotalAlerts ?? 0;
        EscalationLevel = profile?.CurrentLevel ?? EscalationLevel.Watch;
        LevelLabel = EscalationLevel.ToString().ToUpperInvariant();
        TrustLabel = $"  ·  T{trust}";
        McpLabel = mcpConnected ? "  ·  MCP" : string.Empty;
        (LevelBg, LevelFg) = EscalationColors(EscalationLevel);
        ToolTip = BuildToolTip(harness.DisplayName, isRunning, mcpConnected, trust, AlertCount, EscalationLevel);
    }

    private static (Brush bg, Brush fg) EscalationColors(EscalationLevel level) => level switch
    {
        EscalationLevel.Emergency => (
            new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66))),
        EscalationLevel.Alarm => (
            new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0xAA, 0x44))),
        EscalationLevel.Alert => (
            new SolidColorBrush(Color.FromRgb(0x30, 0x28, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
        _ => (
            new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x28)),
            new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
    };

    private static string BuildToolTip(string name, bool running, bool mcp, int trust, int alerts, EscalationLevel level) =>
        $"{name}\n{(running ? "Running" : "Not running")} · Trust {trust} · {level}\n" +
        $"{alerts} alert{(alerts == 1 ? "" : "s")}" +
        (mcp ? " · MCP connected" : " · MCP not connected") +
        "\nClick for live detail.";
}

// ─────────────────────────────────────────────────────────────────────────────
// DashboardHarnessCardVm — overview tab card per harness
// ─────────────────────────────────────────────────────────────────────────────

public sealed class DashboardHarnessCardVm
{
    public string HarnessId { get; }
    public string DisplayName { get; }
    public string Subtitle { get; }
    public string StatusText { get; }
    public Brush StatusBackground { get; }
    public Brush StatusForeground { get; }
    public string TrustLabel { get; }
    public string EscalationLabel { get; }
    public Brush EscalationForeground { get; }
    public string DetailLine { get; }
    public Brush BorderBrush { get; }
    public string ToolTip { get; }
    public bool IsRunning { get; }
    public bool McpConnected { get; }
    public int AlertCount { get; }
    public EscalationLevel EscalationLevel { get; }
    public IReadOnlyList<HarnessLightVm> Lights { get; }

    public DashboardHarnessCardVm(
        KnownHarness harness,
        BehaviorProfile? profile,
        bool isRunning,
        bool mcpConnected,
        int trust,
        int processCount,
        HarnessUsage usage,
        int pendingAsk,
        int wakeLocks,
        HarnessContextUsage? contextUsage = null)
    {
        HarnessId = harness.Id;
        DisplayName = harness.DisplayName;
        IsRunning = isRunning;
        McpConnected = mcpConnected;
        EscalationLevel = profile?.CurrentLevel ?? EscalationLevel.Watch;
        Subtitle = harness.Developer;

        StatusText = isRunning ? "Running" : "Idle";
        StatusBackground = isRunning
            ? new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x1A))
            : new SolidColorBrush(Color.FromRgb(0x1E, 0x20, 0x28));
        StatusForeground = isRunning
            ? new SolidColorBrush(Color.FromRgb(0x7E, 0xC8, 0x78))
            : new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90));

        TrustLabel = $"Trust {trust}";
        EscalationLabel = EscalationLevel.ToString().ToUpperInvariant();
        EscalationForeground = EscalationColors(EscalationLevel).fg;

        var alerts = profile?.TotalAlerts ?? 0;
        AlertCount = alerts;
        var detail = mcpConnected
            ? $"MCP linked · {processCount} proc{(processCount == 1 ? "" : "s")} · {alerts} alert{(alerts == 1 ? "" : "s")}"
            : isRunning
                ? $"No MCP · {processCount} proc{(processCount == 1 ? "" : "s")} · {alerts} alert{(alerts == 1 ? "" : "s")}"
                : alerts > 0
                    ? $"{alerts} alert{(alerts == 1 ? "" : "s")} · not running"
                    : "Not running · connect MCP for Ask Harness";
        // Append the agent's self-reported context budget (via report_usage), when it has reported one.
        DetailLine = contextUsage?.ShortLabel is { } ctx ? $"{detail} · {ctx}" : detail;

        BorderBrush = EscalationLevel >= EscalationLevel.Alarm
            ? new SolidColorBrush(Color.FromRgb(0x66, 0x33, 0x11))
            : mcpConnected
                ? new SolidColorBrush(Color.FromRgb(0x2A, 0x4A, 0x2A))
                : new SolidColorBrush(Color.FromRgb(0x2A, 0x2F, 0x37));

        Lights = BuildLights(isRunning, mcpConnected, usage, pendingAsk, wakeLocks, EscalationLevel);
        ToolTip = $"{harness.DisplayName} ({harness.Id})\n{DetailLine}\n{DescribeLights(Lights)}\nClick for live detail.";
    }

    private static IReadOnlyList<HarnessLightVm> BuildLights(
        bool running, bool mcp, HarnessUsage usage, int pendingAsk, int wakeLocks, EscalationLevel esc)
    {
        var lights = new List<HarnessLightVm>
        {
            new(running ? MetaLightState.Ok : MetaLightState.Off,
                running ? "Process tree active" : "Not running"),
            new(mcp ? MetaLightState.Ok : MetaLightState.Off,
                mcp ? "MCP session linked" : "No MCP connection"),
        };

        if (esc >= EscalationLevel.Alert)
            lights.Add(new(esc >= EscalationLevel.Alarm ? MetaLightState.Alert : MetaLightState.Warn,
                $"Escalation: {esc}"));

        if (pendingAsk > 0)
            lights.Add(new(MetaLightState.Alert, $"{pendingAsk} pending Ask Harness prompt(s)"));

        if (wakeLocks > 0)
            lights.Add(new(MetaLightState.Warn, $"{wakeLocks} wake lock(s) attributed"));

        if (usage.CpuPercent >= 5)
            lights.Add(new(MetaLightState.Warn, $"CPU {HarnessUsageAggregator.FormatCpu(usage.CpuPercent)} (tree)"));

        if (usage.MemoryBytes >= 512L * 1024 * 1024)
            lights.Add(new(MetaLightState.Ok, $"RAM {HarnessUsageAggregator.FormatMem(usage.MemoryBytes)} (tree)"));

        if (usage.GpuPercent is >= 5)
            lights.Add(new(MetaLightState.Warn, $"GPU {usage.GpuPercent:0}% (peak)"));

        if (usage.NetBytesPerSec is > 1024)
            lights.Add(new(MetaLightState.Ok, $"Net {HarnessUsageAggregator.FormatRate(usage.NetBytesPerSec.Value)} (tree)"));

        if (usage.IoBytesPerSec > 256 * 1024)
            lights.Add(new(MetaLightState.Ok, $"I/O {HarnessUsageAggregator.FormatRate(usage.IoBytesPerSec)} (tree)"));

        return lights;
    }

    private static string DescribeLights(IReadOnlyList<HarnessLightVm> lights) =>
        string.Join("\n", lights.Select(l => l.ToolTip));

    private static (Brush bg, Brush fg) EscalationColors(EscalationLevel level) => level switch
    {
        EscalationLevel.Emergency => (
            new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66))),
        EscalationLevel.Alarm => (
            new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0xAA, 0x44))),
        EscalationLevel.Alert => (
            new SolidColorBrush(Color.FromRgb(0x30, 0x28, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
        _ => (
            new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x28)),
            new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
    };
}
