using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;

namespace Foreman.App.Linux;

public sealed partial class MainWindow : Window
{
    private readonly ForemanApiClient _api = new();
    private readonly DispatcherTimer _timer;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly HashSet<string> _seenAlerts = new(StringComparer.Ordinal);
    private bool _hasInitialAlertSnapshot;

    public MainWindow()
    {
        InitializeComponent();
        CodexInstructionsText.Text = BuildCodexInstructions();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _timer.Tick += async (_, _) => await RefreshNowAsync();
        Opened += async (_, _) =>
        {
            _timer.Start();
            await RefreshNowAsync();
        };
        Closed += (_, _) =>
        {
            _timer.Stop();
            _api.Dispose();
            _refreshGate.Dispose();
        };
    }

    public async Task RefreshNowAsync()
    {
        if (!await _refreshGate.WaitAsync(0)) return;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var statusTask = _api.GetStatusAsync(timeout.Token);
            var processesTask = _api.GetProcessesAsync(timeout.Token);
            var alertsTask = _api.GetAlertsAsync(timeout.Token);
            var behaviorTask = _api.GetBehaviorAsync(timeout.Token);
            var mcpTask = _api.GetMcpInventoryAsync(timeout.Token);
            var eventsTask = _api.GetEventsAsync(timeout.Token);
            var settingsTask = _api.GetSettingsAsync(timeout.Token);
            await Task.WhenAll(statusTask, processesTask, alertsTask, behaviorTask, mcpTask, eventsTask, settingsTask);

            var status = await statusTask;
            var processes = await processesTask ?? [];
            var alerts = await alertsTask ?? [];
            var behavior = await behaviorTask ?? [];
            var mcp = await mcpTask ?? [];
            var events = await eventsTask ?? [];
            var settings = await settingsTask;

            ApplyStatus(status);
            var active = alerts.Where(static a => !a.Acknowledged && !a.AutoResolved).ToList();
            OverviewAlertsList.ItemsSource = active.Take(8).ToArray();
            OverviewHarnessesList.ItemsSource = processes.Where(static p => p.IsHarness).ToArray();
            AlertsList.ItemsSource = alerts;
            ProcessesList.ItemsSource = processes;
            BehaviorList.ItemsSource = behavior;
            McpList.ItemsSource = mcp;
            EventsList.ItemsSource = events.OrderByDescending(static e => e.Timestamp).ToArray();
            ApplySettings(settings);
            NotifyNewAlerts(alerts);
            FooterText.Text = $"Updated {DateTime.Now:T} · API authenticated · {events.Count} live events";
            FooterText.Foreground = Brush.Parse("#8B949E");
        }
        catch (Exception ex)
        {
            ServiceStateText.Text = "SERVICE OFFLINE";
            ServiceStateText.Foreground = Brush.Parse("#FF6B6B");
            FooterText.Text = $"Cannot reach Foreman service on port {_api.Port}: {ex.Message}";
            FooterText.Foreground = Brush.Parse("#FF8A8A");
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private void ApplyStatus(ServiceStatus? status)
    {
        if (status is null) return;
        ServiceStateText.Text = status.HasCritical ? "ATTENTION REQUIRED" : "MONITORING";
        ServiceStateText.Foreground = Brush.Parse(status.HasCritical ? "#FF6B6B" : "#65D48A");
        UptimeText.Text = $"up {status.Uptime} · MCP :{status.McpPort}";
        ActiveAlertsText.Text = status.ActiveAlerts.ToString();
        ActiveAlertsText.Foreground = Brush.Parse(status.ActiveAlerts > 0 ? "#F0B94C" : "#E6EDF3");
        HarnessesText.Text = status.HarnessCount.ToString();
        ProcessesText.Text = status.ProcessCount.ToString();
        McpSessionsText.Text = status.McpSessions.ToString();
        PendingText.Text = status.PendingAskHarness.ToString();
        RiskText.Text = status.HasCritical ? "HIGH" : status.ActiveAlerts > 0 ? "WATCH" : "CLEAR";
        RiskText.Foreground = Brush.Parse(status.HasCritical ? "#FF6B6B" : status.ActiveAlerts > 0 ? "#F0B94C" : "#65D48A");
    }

    private void ApplySettings(SettingsInfo? settings)
    {
        if (settings is null) return;
        SettingsSummaryText.Text =
            $"MCP endpoint: http://127.0.0.1:{settings.McpPort}/mcp\n" +
            $"Process scope: {(settings.MonitorAllProcesses ? "all visible processes" : "harness trees")}\n" +
            $"Hang threshold: {settings.HangThresholdMinutes} minutes · I/O sample: {settings.IoPollerIntervalSeconds} seconds\n" +
            $"Audit persistence: {OnOff(settings.EventLogPersist)} · MCP tool scan: {OnOff(settings.ScanMcpTools)} · " +
            $"Peer binding enforcement: {OnOff(settings.McpPeerBindingEnforce)}\n" +
            $"Config: {_api.ConfigDirectory}\nState/evidence: {_api.StateDirectory}";
    }

    private void NotifyNewAlerts(IEnumerable<AlertInfo> alerts)
    {
        var list = alerts.ToList();
        if (!_hasInitialAlertSnapshot)
        {
            foreach (var item in list) _seenAlerts.Add(item.Id);
            _hasInitialAlertSnapshot = true;
            return;
        }
        foreach (var alert in list)
        {
            if (!_seenAlerts.Add(alert.Id) || alert.Acknowledged || alert.AutoResolved) continue;
            if (alert.Severity is not ("High" or "Critical")) continue;
            TryNotify($"Foreman: {alert.Severity} alert", alert.Message);
        }
    }

    private static void TryNotify(string title, string body)
    {
        try
        {
            var psi = new ProcessStartInfo("notify-send") { UseShellExecute = false, CreateNoWindow = true };
            psi.ArgumentList.Add("--app-name=Foreman Agent Safety");
            psi.ArgumentList.Add("--urgency=critical");
            psi.ArgumentList.Add(title);
            psi.ArgumentList.Add(body.Length <= 240 ? body : body[..240] + "…");
            Process.Start(psi)?.Dispose();
        }
        catch { }
    }

    private async void RefreshClick(object? sender, RoutedEventArgs e) => await RefreshNowAsync();

    private async void AcknowledgeClick(object? sender, RoutedEventArgs e)
    {
        if (AlertsList.SelectedItem is not AlertInfo alert) { await MessageAsync("Select an alert first."); return; }
        if (alert.Acknowledged) { await MessageAsync("That alert is already acknowledged."); return; }
        var ok = await _api.AcknowledgeAsync(alert.Id, CancellationToken.None);
        await MessageAsync(ok ? "Alert acknowledged and the action was audited." : "The alert could not be acknowledged.");
        await RefreshNowAsync();
    }

    private async void KillClick(object? sender, RoutedEventArgs e)
    {
        if (ProcessesList.SelectedItem is not ProcessInfo process) { await MessageAsync("Select a process first."); return; }
        if (!await ConfirmAsync("Terminate process?", $"Terminate {process.Name} (pid {process.Pid}) and its descendants?\n\nForeman verifies the process start time and refuses protected Linux/system processes.")) return;
        var result = await _api.KillAsync(process.Pid, CancellationToken.None);
        await MessageAsync(result.Ok ? "Process terminated. The action was written to the audit log." : $"Termination failed: {result.Reason}");
        await RefreshNowAsync();
    }

    private async void ResetBehaviorClick(object? sender, RoutedEventArgs e)
    {
        if (BehaviorList.SelectedItem is not BehaviorInfo behavior) { await MessageAsync("Select a harness behavior profile first."); return; }
        if (!await ConfirmAsync("Reset behavior metrics?", $"Reset this session's escalation metrics for {behavior.DisplayName}?\n\nThis is a security-significant action and will be logged.")) return;
        await _api.ResetBehaviorAsync(behavior.HarnessId, CancellationToken.None);
        await RefreshNowAsync();
    }

    private async void RestartServiceClick(object? sender, RoutedEventArgs e)
    {
        if (!await ConfirmAsync("Restart Foreman service?", "Monitoring and MCP connections will pause briefly.")) return;
        try
        {
            var psi = new ProcessStartInfo("systemctl") { UseShellExecute = false, CreateNoWindow = true };
            psi.ArgumentList.Add("--user"); psi.ArgumentList.Add("restart"); psi.ArgumentList.Add("foreman-agent.service");
            using var process = Process.Start(psi);
            if (process is not null) await process.WaitForExitAsync();
            await Task.Delay(1800);
            await RefreshNowAsync();
        }
        catch (Exception ex) { await MessageAsync($"Restart failed: {ex.Message}"); }
    }

    private void OpenConfigClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            var psi = new ProcessStartInfo("xdg-open") { UseShellExecute = false };
            psi.ArgumentList.Add(_api.ConfigDirectory);
            Process.Start(psi)?.Dispose();
        }
        catch { }
    }

    private async void CopyInstructionsClick(object? sender, RoutedEventArgs e)
    {
        var clipboard = GetTopLevel(this)?.Clipboard;
        if (clipboard is not null) await clipboard.SetTextAsync(CodexInstructionsText.Text ?? "");
        FooterText.Text = "Codex connection instructions copied.";
    }

    private string BuildCodexInstructions() =>
        $"# In your shell profile (restart Codex after setting):\n" +
        $"export FOREMAN_MCP_TOKEN_CODEX=\"$(foreman-agent token --harness codex)\"\n\n" +
        $"# Add to ~/.codex/config.toml:\n" +
        $"[mcp_servers.foreman]\n" +
        $"url = \"http://127.0.0.1:{_api.Port}/mcp\"\n" +
        $"bearer_token_env_var = \"FOREMAN_MCP_TOKEN_CODEX\"\n" +
        $"enabled = true";

    private async Task<bool> ConfirmAsync(string title, string text)
    {
        var result = false;
        var dialog = Dialog(title, text, includeCancel: true, onAccept: () => result = true);
        await dialog.ShowDialog(this);
        return result;
    }

    private async Task MessageAsync(string text) => await Dialog("Foreman Agent Safety", text, false, null).ShowDialog(this);

    private static Window Dialog(string title, string text, bool includeCancel, Action? onAccept)
    {
        var window = new Window
        {
            Title = title, Width = 470, Height = 230, CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = Brush.Parse("#10151D"), Foreground = Brush.Parse("#E6EDF3"),
        };
        var buttons = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, Spacing = 8, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right };
        if (includeCancel)
        {
            var cancel = new Button { Content = "Cancel", Padding = new Avalonia.Thickness(14, 8) };
            cancel.Click += (_, _) => window.Close();
            buttons.Children.Add(cancel);
        }
        var accept = new Button { Content = includeCancel ? "Continue" : "OK", Padding = new Avalonia.Thickness(14, 8), Background = Brush.Parse("#D8A93B"), Foreground = Brush.Parse("#11151B") };
        accept.Click += (_, _) => { onAccept?.Invoke(); window.Close(); };
        buttons.Children.Add(accept);
        window.Content = new Grid
        {
            RowDefinitions = new RowDefinitions("*,Auto"), Margin = new Avalonia.Thickness(22),
            Children =
            {
                new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, FontSize = 14 },
                buttons,
            },
        };
        Grid.SetRow(buttons, 1);
        return window;
    }

    private static string OnOff(bool value) => value ? "enabled" : "disabled";
}
