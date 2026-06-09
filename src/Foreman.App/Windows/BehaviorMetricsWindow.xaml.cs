using Foreman.Core.Behavior;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace Foreman.App.Windows;

public partial class BehaviorMetricsWindow : UserControl, IDisposable
{
    private readonly Func<IEnumerable<BehaviorProfile>>   _getProfiles;
    private readonly Action<string>                        _resetProfile;
    private readonly Func<string, IEnumerable<ProcessRecord>> _getByHarness;
    private readonly Action<string>                        _killHarness;
    private readonly ForemanSettings                       _settings;
    private readonly DispatcherTimer                       _timer;

    public BehaviorMetricsWindow(
        ForemanSettings settings,
        Func<IEnumerable<BehaviorProfile>> getProfiles,
        Action<string> resetProfile,
        Func<string, IEnumerable<ProcessRecord>> getByHarness,
        Action<string> killHarness)
    {
        _settings      = settings;
        _getProfiles   = getProfiles;
        _resetProfile  = resetProfile;
        _getByHarness  = getByHarness;
        _killHarness   = killHarness;

        InitializeComponent();
        Loaded += (_, _) => Refresh();

        ThresholdSummary.Text =
            $"Alert ≥{settings.AlertLevelMediumCount} med  ·  " +
            $"Alarm ≥{settings.AlarmLevelHighCount} high / {settings.AlarmLevelUniqueRules} rules / {settings.AlarmLevelCategories} cats  ·  " +
            $"Emergency ≥{settings.EmergencyLevelTotalAlerts} total";

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
    }

    private void Refresh()
    {
        var profiles = _getProfiles().ToList();

        if (profiles.Count == 0)
        {
            MetricsList.ItemsSource = new[]
            {
                new PlaceholderVm("No behavioral data yet — alerts will appear here as harnesses run suspicious commands.")
            };
            return;
        }

        var vms = profiles
            .OrderByDescending(p => (int)p.CurrentLevel)
            .ThenByDescending(p => p.TotalAlerts)
            .Select(p => new BehaviorMetricVm(p, _settings, _getByHarness(p.HarnessId).Any()))
            .ToList();

        MetricsList.ItemsSource = vms;
    }

    private void ResetClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: BehaviorMetricVm vm })
        {
            _resetProfile(vm.HarnessId);
            Refresh();
        }
    }

    private void KillClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: BehaviorMetricVm vm })
        {
            var r = MessageBox.Show(
                $"Kill all running '{vm.DisplayName}' processes?\n\nThis will immediately terminate the harness.",
                "Foreman Agent Safety — Confirm Kill",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (r == MessageBoxResult.Yes)
            {
                _killHarness(vm.HarnessId);
                Refresh();
            }
        }
    }

    private void ResetAllClick(object sender, RoutedEventArgs e)
    {
        foreach (var p in _getProfiles().ToList())
            _resetProfile(p.HarnessId);
        Refresh();
    }

    // Called by the host (DashboardWindow) when it closes, since a UserControl has no OnClosed.
    public void Dispose()
    {
        _timer.Stop();
    }
}

// ─── ViewModels ────────────────────────────────────────────────────────────────

public sealed class PlaceholderVm
{
    public string DisplayName     { get; }
    public string LevelLabel      { get; } = "";
    public Brush  LevelBackground { get; } = Brushes.Transparent;
    public Brush  LevelForeground { get; } = Brushes.Gray;
    public int    TotalAlerts     { get; } = 0;
    public string AlertThresholdLabel  { get; } = "";
    public int    UniqueRules     { get; } = 0;
    public string RulesThresholdLabel  { get; } = "";
    public object[] CategoryBadges { get; } = [];
    public string SessionDuration { get; } = "";
    public bool   CanKill         { get; } = false;
    public string HarnessId       { get; } = "";

    public PlaceholderVm(string msg) => DisplayName = msg;
}

public sealed class BehaviorMetricVm
{
    public string HarnessId    { get; }
    public string DisplayName  { get; }

    public string LevelLabel      { get; }
    public Brush  LevelBackground { get; }
    public Brush  LevelForeground { get; }

    public int    TotalAlerts         { get; }
    public string AlertThresholdLabel { get; }
    public Brush  AlertCountBrush     { get; }

    public int    UniqueRules         { get; }
    public string RulesThresholdLabel { get; }

    public IReadOnlyList<CategoryBadgeVm> CategoryBadges { get; }
    public string SessionDuration { get; }
    public bool   CanKill         { get; }

    public BehaviorMetricVm(BehaviorProfile p, ForemanSettings s, bool isRunning)
    {
        HarnessId   = p.HarnessId;
        DisplayName = p.DisplayName;

        (LevelLabel, LevelBackground, LevelForeground) = LevelVisuals(p.CurrentLevel);

        TotalAlerts         = p.TotalAlerts;
        AlertThresholdLabel = $"/{s.EmergencyLevelTotalAlerts}";
        AlertCountBrush     = p.CurrentLevel switch
        {
            EscalationLevel.Emergency => new SolidColorBrush(Color.FromRgb(0xDD, 0x44, 0x44)),
            EscalationLevel.Alarm     => new SolidColorBrush(Color.FromRgb(0xEE, 0x88, 0x33)),
            EscalationLevel.Alert     => new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C)),
            _                         => new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90)),
        };

        UniqueRules         = p.UniqueRulesCount;
        RulesThresholdLabel = $"/{s.AlarmLevelUniqueRules}";

        CategoryBadges = p.Categories
            .Select(c => new CategoryBadgeVm(c))
            .ToList();

        var dur = p.SessionDuration;
        SessionDuration = dur.TotalHours >= 1
            ? $"{(int)dur.TotalHours:D1}:{dur.Minutes:D2}:{dur.Seconds:D2}"
            : $"{dur.Minutes:D2}:{dur.Seconds:D2}";

        CanKill = isRunning && p.TotalAlerts > 0;
    }

    private static (string label, Brush bg, Brush fg) LevelVisuals(EscalationLevel level) => level switch
    {
        EscalationLevel.Emergency => ("EMERGENCY",
            new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66))),
        EscalationLevel.Alarm => ("ALARM",
            new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0xAA, 0x44))),
        EscalationLevel.Alert => ("ALERT",
            new SolidColorBrush(Color.FromRgb(0x30, 0x28, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
        _ => ("WATCH",
            new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x24)),
            new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
    };
}

public sealed class CategoryBadgeVm
{
    public string Label { get; }
    public Brush  Bg    { get; }
    public Brush  Fg    { get; }

    public CategoryBadgeVm(string category)
    {
        Label = category.ToUpperInvariant();
        (Bg, Fg) = category.ToLowerInvariant() switch
        {
            "cred" => (new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
                       new SolidColorBrush(Color.FromRgb(0xFF, 0x88, 0x88))),
            "priv" => (new SolidColorBrush(Color.FromRgb(0x3A, 0x10, 0x38)),
                       new SolidColorBrush(Color.FromRgb(0xDD, 0x88, 0xDD))),
            "net"  => (new SolidColorBrush(Color.FromRgb(0x0A, 0x28, 0x44)),
                       new SolidColorBrush(Color.FromRgb(0x66, 0xAA, 0xFF))),
            "win"  => (new SolidColorBrush(Color.FromRgb(0x20, 0x20, 0x44)),
                       new SolidColorBrush(Color.FromRgb(0x88, 0x88, 0xFF))),
            "del"  => (new SolidColorBrush(Color.FromRgb(0x30, 0x28, 0x08)),
                       new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
            "cmd"  => (new SolidColorBrush(Color.FromRgb(0x30, 0x28, 0x08)),   // legacy alias
                       new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
            _      => (new SolidColorBrush(Color.FromRgb(0x1E, 0x20, 0x28)),
                       new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
        };
    }
}
