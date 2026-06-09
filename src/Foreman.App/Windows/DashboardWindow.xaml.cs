using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.McpServer;
using System.Collections.ObjectModel;
using System.Globalization;
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
    private readonly List<IDisposable> _hostedViews = [];
    private HarnessesWindow? _harnessView;

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

        // ── Harness chips ─────────────────────────────────────────────────────
        var allProfiles = _getProfiles().ToList();
        var profiles = allProfiles
            .Where(p => p.TotalAlerts > 0)
            .OrderByDescending(p => (int)p.CurrentLevel)
            .ThenByDescending(p => p.TotalAlerts)
            .ToList();

        HarnessPanel.ItemsSource = profiles
            .Select(p => new HarnessChipVm(p))
            .ToList();

        // ── Header summary ────────────────────────────────────────────────────
        // "Active alerts" = unacknowledged events ABOVE Info severity. Counting by severity (not by
        // InfoEvent type) keeps Info-severity notices — e.g. the MCP tool-scan summary, a
        // MonitoringNoticeEvent at Info — from inflating the count. The header summary now mirrors this
        // exact count, so "all clear" can no longer contradict a non-zero ACTIVE ALERTS card.
        var active = history
            .Where(static e => e.Severity > ForemanSeverity.Info && !e.Acknowledged)
            .ToList();

        SummaryLabel.Text = active.Count == 0
            ? "all clear"
            : $"{active.Count} active alert{(active.Count == 1 ? "" : "s")}";

        ActiveAlertCountLabel.Text = active.Count.ToString(CultureInfo.InvariantCulture);
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

        // Per-session capability breakdown on the MCP CLIENTS card (hover): which connected agents
        // support the sampling round-trip that makes Ask Harness a true poll vs. a one-way notify.
        var clients = GetConnectedClients?.Invoke() ?? [];
        McpClientsCard.ToolTip = clients.Count == 0
            ? "No agents connected to Foreman Agent Safety's MCP.\nRight-click the tray → Connect agent, or use the Connect agent button."
            : "Connected agents:\n" + string.Join("\n", clients.Select(c =>
                $"  • {c.Name}{(string.IsNullOrWhiteSpace(c.Version) ? "" : $" v{c.Version}")} — " +
                $"sampling: {(c.Sampling ? "yes (Ask Harness gets a reply)" : "no (Ask Harness notifies one-way)")}"));

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
        foreach (var v in new object?[] { processes, harnesses, behavior, log })
            if (v is IDisposable d) _hostedViews.Add(d);
    }

    // Prompt to save Harnesses-tab edits when the user navigates away (switches tab) or closes.
    private void TabsSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // TabControl SelectionChanged bubbles from child ListViews too — only react to the tabs themselves.
        if (!ReferenceEquals(e.OriginalSource, Tabs)) return;
        if (_harnessView is null || e.RemovedItems.Count == 0) return;
        if (e.RemovedItems[0] is not TabItem leftTab) return;
        if (Tabs.Items.IndexOf(leftTab) != (int)DashboardTab.Harnesses) return;
        if (!_harnessView.HasUnsavedChanges()) return;

        switch (PromptSaveHarnesses("switching tabs"))
        {
            case MessageBoxResult.Yes:    _harnessView.SaveChanges(); break;
            case MessageBoxResult.No:     _harnessView.Revert();      break;
            case MessageBoxResult.Cancel:
                // Re-select the Harnesses tab once this event settles.
                Dispatcher.BeginInvoke(() => Tabs.SelectedItem = leftTab);
                break;
        }
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (_harnessView?.HasUnsavedChanges() == true)
        {
            switch (PromptSaveHarnesses("closing"))
            {
                case MessageBoxResult.Yes:    _harnessView.SaveChanges(); break;
                case MessageBoxResult.No:     break;                       // discard
                case MessageBoxResult.Cancel: e.Cancel = true; return;     // stay open
            }
        }
        base.OnClosing(e);
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

// ─────────────────────────────────────────────────────────────────────────────
// HarnessChipVm — one status chip in the header strip
// ─────────────────────────────────────────────────────────────────────────────

public sealed class HarnessChipVm
{
    public string DisplayName { get; }
    public string LevelLabel  { get; }   // "WATCH", "ALERT", "ALARM", "EMERGENCY"
    public Brush  LevelBg     { get; }
    public Brush  LevelFg     { get; }
    public string CountLabel  { get; }   // "5 alerts"

    public HarnessChipVm(BehaviorProfile profile)
    {
        DisplayName = profile.DisplayName;
        LevelLabel  = profile.CurrentLevel.ToString().ToUpperInvariant();
        CountLabel  = $"{profile.TotalAlerts} alert{(profile.TotalAlerts == 1 ? "" : "s")}";
        (LevelBg, LevelFg) = profile.CurrentLevel switch
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
}
