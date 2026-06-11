using Foreman.Core.Alerts;
using Foreman.Core.Security;
using Foreman.Core.Settings;
using System.Windows;
using System.Windows.Controls;

namespace Foreman.App.Windows;

public partial class SettingsWindow : Window
{
    private readonly ForemanSettings _settings;
    private readonly Action<bool>? _onRunElevatedChanged;
    private readonly Action<bool>? _onScanMcpToolsChanged;
    private readonly Action? _onDecoyAuditChanged;

    public SettingsWindow(ForemanSettings settings,
                          Action<bool>? onRunElevatedChanged = null,
                          Action<bool>? onScanMcpToolsChanged = null,
                          Action? onDecoyAuditChanged = null)
    {
        _settings = settings;
        _onRunElevatedChanged = onRunElevatedChanged;
        _onScanMcpToolsChanged = onScanMcpToolsChanged;
        _onDecoyAuditChanged = onDecoyAuditChanged;
        InitializeComponent();
        Populate();
    }

    private void Populate()
    {
        // General — the HKCU Run entry is the source of truth, not a settings field,
        // so the checkbox always reflects what Windows will actually do at sign-in.
        StartWithWindowsCheck.IsChecked = StartupManager.IsEnabled();
        GameModeCheck.IsChecked             = _settings.GameMode.Enabled;
        GameModeBreakThroughCheck.IsChecked = _settings.GameMode.AllowCriticalBreakThrough;

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
        IdleCleanupCheck.IsChecked   = _settings.IdleCleanupEnabled;
        IdleCleanupAfterBox.Text     = _settings.IdleCleanupAfterMinutes.ToString();

        // Decoy credentials
        var dc = _settings.DecoyCredentials;
        DecoyCredsCheck.IsChecked     = dc.Enabled;
        DecoyReadAuditCheck.IsChecked = dc.EnableReadAuditing;
        DecoyAwsCanaryCheck.IsChecked = dc.IncludeAwsCanaryToken;
        DecoyAwsKeyIdBox.Text         = dc.AwsCanaryAccessKeyId ?? string.Empty;
        DecoyAwsSecretBox.Text        = dc.AwsCanarySecretAccessKey ?? string.Empty;
        DecoyStatusText.Text          = dc.PlantedPaths.Count > 0
            ? $"Currently planted: {dc.PlantedPaths.Count} decoy file(s)."
            : "No decoys planted yet.";

        // Escalation thresholds
        AlertMediumBox.Text    = _settings.AlertLevelMediumCount.ToString();
        AlarmHighBox.Text      = _settings.AlarmLevelHighCount.ToString();
        AlarmRulesBox.Text     = _settings.AlarmLevelUniqueRules.ToString();
        AlarmCatsBox.Text      = _settings.AlarmLevelCategories.ToString();
        EmergencyTotalBox.Text = _settings.EmergencyLevelTotalAlerts.ToString();
        EmergencyRulesBox.Text = string.Join(", ", _settings.EmergencyRuleIds);

        // Automatic responses per tier (Alert audit stays disabled — not audit-worthy on its own).
        var ar = _settings.AlertResponses;
        AlertAskCheck.IsChecked        = ar.OnAlert.HasFlag(EscalationAction.AskHarness);
        AlertCleanupCheck.IsChecked    = ar.OnAlert.HasFlag(EscalationAction.RequestSelfCleanup);
        AlarmAskCheck.IsChecked        = ar.OnAlarm.HasFlag(EscalationAction.AskHarness);
        AlarmAuditCheck.IsChecked      = ar.OnAlarm.HasFlag(EscalationAction.AdversarialAudit);
        AlarmCleanupCheck.IsChecked    = ar.OnAlarm.HasFlag(EscalationAction.RequestSelfCleanup);
        EmergencyAskCheck.IsChecked     = ar.OnEmergency.HasFlag(EscalationAction.AskHarness);
        EmergencyAuditCheck.IsChecked   = ar.OnEmergency.HasFlag(EscalationAction.AdversarialAudit);
        EmergencyCleanupCheck.IsChecked = ar.OnEmergency.HasFlag(EscalationAction.RequestSelfCleanup);
        AutoResponseCooldownBox.Text   = ar.CooldownMinutes.ToString();
    }

    private static EscalationAction Compose(CheckBox? ask, CheckBox? audit, CheckBox? cleanup)
    {
        var a = EscalationAction.None;
        if (ask?.IsChecked == true)     a |= EscalationAction.AskHarness;
        if (audit?.IsChecked == true)   a |= EscalationAction.AdversarialAudit;
        if (cleanup?.IsChecked == true) a |= EscalationAction.RequestSelfCleanup;
        return AlertResponsePolicy.Sanitize(a);   // clamp to the allowed non-destructive set
    }

    private void SaveClick(object sender, RoutedEventArgs e)
    {
        // ── MCP ─────────────────────────────────────────────────────────────
        if (!int.TryParse(McpPortBox.Text, out var port) || port is < 1024 or > 65535)
        { MessageBox.Show("Port must be 1024–65535.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        // ── Process thresholds ───────────────────────────────────────────────
        if (!int.TryParse(HangBox.Text, out var hang) || hang < 1)
        { MessageBox.Show("Hang threshold must be ≥ 1 minute.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(HookBox.Text, out var hook) || hook < 1)
        { MessageBox.Show("Hook jam threshold must be ≥ 1 minute.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(HangRealertBox.Text, out var hangRealert) || hangRealert < 0)
        { MessageBox.Show("Hang re-alert cooldown must be ≥ 0 minutes.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(SuppressBox.Text, out var suppress) || suppress < 0)
        { MessageBox.Show("Alert suppress window must be ≥ 0.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(IdleCleanupAfterBox.Text, out var idleAfter) || idleAfter < 5)
        { MessageBox.Show("Idle cleanup threshold must be ≥ 5 minutes.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        // ── Escalation thresholds ────────────────────────────────────────────
        if (!int.TryParse(AlertMediumBox.Text, out var alertMed) || alertMed < 1)
        { MessageBox.Show("Alert medium threshold must be ≥ 1.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AlarmHighBox.Text, out var alarmHigh) || alarmHigh < 1)
        { MessageBox.Show("Alarm high threshold must be ≥ 1.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AlarmRulesBox.Text, out var alarmRules) || alarmRules < 1)
        { MessageBox.Show("Alarm rules threshold must be ≥ 1.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AlarmCatsBox.Text, out var alarmCats) || alarmCats < 1)
        { MessageBox.Show("Alarm category threshold must be ≥ 1.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(EmergencyTotalBox.Text, out var emergencyTotal) || emergencyTotal < 1)
        { MessageBox.Show("Emergency total threshold must be ≥ 1.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AutoResponseCooldownBox.Text, out var arCooldown) || arCooldown < 0)
        { MessageBox.Show("Auto-response re-fire cooldown must be ≥ 0 minutes.", "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

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
        _settings.IdleCleanupEnabled         = IdleCleanupCheck.IsChecked == true;
        _settings.IdleCleanupAfterMinutes    = idleAfter;

        _settings.AlertLevelMediumCount      = alertMed;
        _settings.AlarmLevelHighCount        = alarmHigh;
        _settings.AlarmLevelUniqueRules      = alarmRules;
        _settings.AlarmLevelCategories       = alarmCats;
        _settings.EmergencyLevelTotalAlerts  = emergencyTotal;
        _settings.EmergencyRuleIds           = emergencyRules;

        // Automatic responses (live: the runner holds this same settings instance, so no restart needed).
        _settings.AlertResponses.OnAlert     = Compose(AlertAskCheck, null, AlertCleanupCheck);   // no Alert audit
        _settings.AlertResponses.OnAlarm     = Compose(AlarmAskCheck, AlarmAuditCheck, AlarmCleanupCheck);
        _settings.AlertResponses.OnEmergency = Compose(EmergencyAskCheck, EmergencyAuditCheck, EmergencyCleanupCheck);
        _settings.AlertResponses.CooldownMinutes = arCooldown;

        // Game mode (live: the tray watcher reads this same settings instance).
        _settings.GameMode.Enabled                   = GameModeCheck.IsChecked == true;
        _settings.GameMode.AllowCriticalBreakThrough = GameModeBreakThroughCheck.IsChecked == true;

        ApplyDecoyCredentials();

        SettingsStore.Save(_settings);

        // ── Start with Windows (registry, not settings JSON) ─────────────────
        var startupWanted = StartWithWindowsCheck.IsChecked == true;
        try
        {
            if (startupWanted != StartupManager.IsEnabled())
                StartupManager.SetEnabled(startupWanted);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Couldn't update the Windows startup entry: {ex.Message}", "Foreman Agent Safety",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        if (portChanged)
            MessageBox.Show("Port change takes effect after restart.", "Foreman Agent Safety",
                MessageBoxButton.OK, MessageBoxImage.Information);

        // Apply the elevation toggle (starts/stops the sidecar; enabling prompts UAC).
        if (runElevatedChanged)
            _onRunElevatedChanged?.Invoke(_settings.RunElevated);

        // Apply the MCP tool-scan toggle (starts/stops the opt-in outbound probe).
        if (scanMcpToolsChanged)
            _onScanMcpToolsChanged?.Invoke(_settings.ScanMcpTools);

        Close();
    }

    /// <summary>
    /// Plants / removes decoy credentials per the toggle. Gaps-only (never shadows a real file) and
    /// sentinel-gated (never deletes a real file). A slot the user reclaimed for real credentials is
    /// auto-retired first. Re-plants on each save so a changed canarytoken is applied.
    /// </summary>
    private void ApplyDecoyCredentials()
    {
        var dc = _settings.DecoyCredentials;
        var wasEnabled = dc.Enabled;
        var wasAuditing = dc.Enabled && dc.EnableReadAuditing;
        var wasCanary = (dc.IncludeAwsCanaryToken, dc.AwsCanaryAccessKeyId, dc.AwsCanarySecretAccessKey);
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        // Snapshot the audited path set BEFORE any change so we can re-apply the sidecar iff it actually changes.
        var wasAuditPaths = wasAuditing
            ? DecoyCredentialPolicy.ReadAuditPaths(home, dc.PlantedPaths)
            : (IReadOnlyList<string>)[];

        dc.Enabled                   = DecoyCredsCheck.IsChecked == true;
        dc.EnableReadAuditing        = DecoyReadAuditCheck.IsChecked == true;
        dc.IncludeAwsCanaryToken     = DecoyAwsCanaryCheck.IsChecked == true;
        dc.AwsCanaryAccessKeyId      = string.IsNullOrWhiteSpace(DecoyAwsKeyIdBox.Text)  ? null : DecoyAwsKeyIdBox.Text.Trim();
        dc.AwsCanarySecretAccessKey  = string.IsNullOrWhiteSpace(DecoyAwsSecretBox.Text) ? null : DecoyAwsSecretBox.Text.Trim();

        // Re-plant only when content/placement could actually differ (enabled flip or canary change) — an
        // unrelated Settings save must not churn files/SACLs or pop a "Planted N" dialog.
        var contentChanged = dc.Enabled != wasEnabled
            || (dc.IncludeAwsCanaryToken, dc.AwsCanaryAccessKeyId, dc.AwsCanarySecretAccessKey) != wasCanary;

        try
        {
            var mgr = new DecoyCredentialManager(new SystemDecoyFileSystem());
            var reval = mgr.Revalidate(dc.PlantedPaths);   // retire slots reclaimed for real credentials (never deleted)

            if (dc.Enabled && contentChanged)
            {
                mgr.Remove(reval.StillDecoys);             // clear our own decoys so re-plant reflects current settings
                var plant = mgr.Plant(dc);
                dc.PlantedPaths = plant.Planted.ToList();
                var retired = reval.Reclaimed.Count > 0
                    ? $"  Retired {reval.Reclaimed.Count} slot(s) you reclaimed for real credentials (left untouched)." : "";
                MessageBox.Show(
                    $"Planted {plant.Planted.Count} decoy credential file(s); skipped {plant.SkippedExisting.Count} path(s) you already use.{retired}",
                    "Foreman Agent Safety — Decoy credentials", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else if (dc.Enabled)
            {
                // Already enabled, nothing decoy-related changed: keep the planted decoys, just stop tracking
                // any slot the user reclaimed for real credentials (so its SACL is dropped on re-apply below).
                dc.PlantedPaths = reval.StillDecoys.ToList();
            }
            else
            {
                var removed = mgr.Remove(reval.StillDecoys);
                dc.PlantedPaths = [];
                if (wasEnabled)
                    MessageBox.Show($"Removed {removed.Count} decoy credential file(s).",
                        "Foreman Agent Safety — Decoy credentials", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Couldn't update decoy credentials: {ex.Message}",
                "Foreman Agent Safety", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        // Re-apply the elevated auditor whenever the AUDITED PATH SET changed — enable/disable, a reclaimed
        // slot, or a re-plant that added/removed bait — not just when the on/off boolean flipped. Otherwise the
        // sidecar can keep a stale SACL on a path the user just reclaimed for real credentials. UAC re-prompts
        // only on a genuine change (an unrelated save leaves the set identical → no prompt).
        var nowAuditPaths = (dc.Enabled && dc.EnableReadAuditing)
            ? DecoyCredentialPolicy.ReadAuditPaths(home, dc.PlantedPaths)
            : (IReadOnlyList<string>)[];
        if (!AuditSetEqual(wasAuditPaths, nowAuditPaths))
            _onDecoyAuditChanged?.Invoke();
    }

    private static bool AuditSetEqual(IReadOnlyList<string> a, IReadOnlyList<string> b)
        => a.Count == b.Count && new HashSet<string>(a, StringComparer.OrdinalIgnoreCase).SetEquals(b);

    private void CancelClick(object sender, RoutedEventArgs e) => Close();
}
