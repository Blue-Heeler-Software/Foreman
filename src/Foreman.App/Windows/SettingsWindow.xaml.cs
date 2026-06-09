using Foreman.Core.Settings;
using System.Windows;

namespace Foreman.App.Windows;

public partial class SettingsWindow : Window
{
    private readonly ForemanSettings _settings;
    private readonly Action<bool>? _onRunElevatedChanged;
    private readonly Action<bool>? _onScanMcpToolsChanged;

    public SettingsWindow(ForemanSettings settings,
                          Action<bool>? onRunElevatedChanged = null,
                          Action<bool>? onScanMcpToolsChanged = null)
    {
        _settings = settings;
        _onRunElevatedChanged = onRunElevatedChanged;
        _onScanMcpToolsChanged = onScanMcpToolsChanged;
        InitializeComponent();
        Populate();
    }

    private void Populate()
    {
        // MCP
        McpPortBox.Text    = _settings.McpPort.ToString();

        // Process thresholds
        HangBox.Text       = _settings.HangThresholdMinutes.ToString();
        HookBox.Text       = _settings.HookJamThresholdMinutes.ToString();
        SuppressBox.Text   = _settings.AlertSuppressWindowMinutes.ToString();
        HangRealertBox.Text = _settings.HangRealertCooldownMinutes.ToString();

        // Notifications
        NotifyHangCheck.IsChecked    = _settings.NotifyOnHang;
        NotifyOrphanCheck.IsChecked  = _settings.NotifyOnOrphan;
        NotifyCriticalCheck.IsChecked = _settings.NotifyOnCriticalCommand;
        PersistLogCheck.IsChecked    = _settings.EventLogPersist;
        MonitorAllCheck.IsChecked    = _settings.MonitorAllProcesses;
        RunElevatedCheck.IsChecked   = _settings.RunElevated;
        ScanMcpToolsCheck.IsChecked  = _settings.ScanMcpTools;

        // Escalation thresholds
        AlertMediumBox.Text    = _settings.AlertLevelMediumCount.ToString();
        AlarmHighBox.Text      = _settings.AlarmLevelHighCount.ToString();
        AlarmRulesBox.Text     = _settings.AlarmLevelUniqueRules.ToString();
        AlarmCatsBox.Text      = _settings.AlarmLevelCategories.ToString();
        EmergencyTotalBox.Text = _settings.EmergencyLevelTotalAlerts.ToString();
        EmergencyRulesBox.Text = string.Join(", ", _settings.EmergencyRuleIds);
    }

    private void SaveClick(object sender, RoutedEventArgs e)
    {
        // ── MCP ─────────────────────────────────────────────────────────────
        if (!int.TryParse(McpPortBox.Text, out var port) || port is < 1024 or > 65535)
        { MessageBox.Show("Port must be 1024–65535.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        // ── Process thresholds ───────────────────────────────────────────────
        if (!int.TryParse(HangBox.Text, out var hang) || hang < 1)
        { MessageBox.Show("Hang threshold must be ≥ 1 minute.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(HookBox.Text, out var hook) || hook < 1)
        { MessageBox.Show("Hook jam threshold must be ≥ 1 minute.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(HangRealertBox.Text, out var hangRealert) || hangRealert < 0)
        { MessageBox.Show("Hang re-alert cooldown must be ≥ 0 minutes.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(SuppressBox.Text, out var suppress) || suppress < 0)
        { MessageBox.Show("Alert suppress window must be ≥ 0.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        // ── Escalation thresholds ────────────────────────────────────────────
        if (!int.TryParse(AlertMediumBox.Text, out var alertMed) || alertMed < 1)
        { MessageBox.Show("Alert medium threshold must be ≥ 1.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AlarmHighBox.Text, out var alarmHigh) || alarmHigh < 1)
        { MessageBox.Show("Alarm high threshold must be ≥ 1.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AlarmRulesBox.Text, out var alarmRules) || alarmRules < 1)
        { MessageBox.Show("Alarm rules threshold must be ≥ 1.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AlarmCatsBox.Text, out var alarmCats) || alarmCats < 1)
        { MessageBox.Show("Alarm category threshold must be ≥ 1.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(EmergencyTotalBox.Text, out var emergencyTotal) || emergencyTotal < 1)
        { MessageBox.Show("Emergency total threshold must be ≥ 1.", "Foreman", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        var emergencyRules = EmergencyRulesBox.Text
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(r => r.ToLowerInvariant())
            .Distinct()
            .ToArray();

        // ── Commit ───────────────────────────────────────────────────────────
        var portChanged         = port != _settings.McpPort;
        var runElevatedChanged  = (RunElevatedCheck.IsChecked == true) != _settings.RunElevated;
        var scanMcpToolsChanged = (ScanMcpToolsCheck.IsChecked == true) != _settings.ScanMcpTools;

        _settings.McpPort                    = port;
        _settings.RunElevated                = RunElevatedCheck.IsChecked == true;
        _settings.ScanMcpTools               = ScanMcpToolsCheck.IsChecked == true;
        _settings.HangThresholdMinutes       = hang;
        _settings.HookJamThresholdMinutes    = hook;
        _settings.AlertSuppressWindowMinutes = suppress;
        _settings.HangRealertCooldownMinutes = hangRealert;
        _settings.NotifyOnHang               = NotifyHangCheck.IsChecked == true;
        _settings.NotifyOnOrphan             = NotifyOrphanCheck.IsChecked == true;
        _settings.NotifyOnCriticalCommand    = NotifyCriticalCheck.IsChecked == true;
        _settings.EventLogPersist            = PersistLogCheck.IsChecked == true;
        _settings.MonitorAllProcesses        = MonitorAllCheck.IsChecked == true;

        _settings.AlertLevelMediumCount      = alertMed;
        _settings.AlarmLevelHighCount        = alarmHigh;
        _settings.AlarmLevelUniqueRules      = alarmRules;
        _settings.AlarmLevelCategories       = alarmCats;
        _settings.EmergencyLevelTotalAlerts  = emergencyTotal;
        _settings.EmergencyRuleIds           = emergencyRules;

        SettingsStore.Save(_settings);

        if (portChanged)
            MessageBox.Show("Port change takes effect after restart.", "Foreman",
                MessageBoxButton.OK, MessageBoxImage.Information);

        // Apply the elevation toggle (starts/stops the sidecar; enabling prompts UAC).
        if (runElevatedChanged)
            _onRunElevatedChanged?.Invoke(_settings.RunElevated);

        // Apply the MCP tool-scan toggle (starts/stops the opt-in outbound probe).
        if (scanMcpToolsChanged)
            _onScanMcpToolsChanged?.Invoke(_settings.ScanMcpTools);

        Close();
    }

    private void CancelClick(object sender, RoutedEventArgs e) => Close();
}
