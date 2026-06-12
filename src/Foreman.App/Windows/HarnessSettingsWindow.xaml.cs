using Foreman.Core.Mcp;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using System.Windows;
using System.Windows.Controls;

namespace Foreman.App.Windows;

/// <summary>
/// Per-harness settings: the Trust 1-5 slider (drives escalation + auto-response via TrustPreset) and the
/// self-service modality selection (the restricted sysprompt, delivered over MCP). Both apply LIVE — the
/// BehaviorTracker resolver reads settings.EffectiveThresholds and the MCP state shares the modalities dict,
/// so no restart is needed. Opened as a modal from a harness row.
/// </summary>
public partial class HarnessSettingsWindow : Window
{
    private readonly string _harnessId;
    private readonly ForemanSettings _settings;
    private readonly List<CheckBox> _modalityChecks = [];

    public HarnessSettingsWindow(string harnessId, string displayName, ForemanSettings settings)
    {
        _harnessId = harnessId;
        _settings = settings;
        InitializeComponent();
        TitleText.Text = $"{displayName} — Foreman settings";
        Populate();
    }

    private void Populate()
    {
        // Badges: Trust, placement (on-device vs cloud), one-click integration.
        AddBadge($"🛡 Trust {(int)CurrentTrust()}");
        AddBadge(Placement(_harnessId));
        AddBadge(HarnessIntegrationRegistry.Get(_harnessId) is not null ? "🔌 One-click" : "manual setup");

        TrustSlider.Value = CurrentTrust();
        UpdateTrustSummary();

        var enabled = _settings.EnabledModalities(_harnessId);
        foreach (var m in ModalityCatalog.ForAudience(ModalityAudience.Agent))
        {
            var cb = new CheckBox
            {
                Content = $"{m.Title}  —  {m.Instruction}",
                IsChecked = enabled.Contains(m.Id, StringComparer.OrdinalIgnoreCase),
                Tag = m.Id,
                Margin = new Thickness(0, 4, 0, 4),
                Foreground = (System.Windows.Media.Brush)FindResource("TextPrimaryBrush"),
            };
            _modalityChecks.Add(cb);
            ModalityPanel.Children.Add(cb);
        }
    }

    private double CurrentTrust() =>
        _settings.HarnessTrust.TryGetValue(_harnessId, out var lvl) ? Math.Clamp(lvl, 1, 5) : 3;

    private void TrustSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        => UpdateTrustSummary();

    private void UpdateTrustSummary()
    {
        if (TrustSummary is null) return;
        TrustSummary.Text = (int)TrustSlider.Value switch
        {
            1 => "Locked-down — fires on the first hint; asks + audits aggressively; strict enforce.",
            2 => "Strict — fires early; audits on high severity.",
            3 => "Standard (default) — today's balanced thresholds.",
            4 => "Trusted — more rope before escalating; fewer prompts.",
            5 => "Hands-off — only sustained or catastrophic behaviour escalates (Emergency rules + Critical reads still fire).",
            _ => "",
        };
    }

    private void AddBadge(string text)
    {
        BadgePanel.Children.Add(new Border
        {
            Style = (Style)FindResource("Badge"),
            Child = new TextBlock
            {
                Text = text,
                FontSize = 11,
                Foreground = (System.Windows.Media.Brush)FindResource("TextPrimaryBrush"),
                FontFamily = new System.Windows.Media.FontFamily("Segoe UI, Arial"),
            },
        });
    }

    private static string Placement(string harnessId)
    {
        if (harnessId.Equals("lm-studio", StringComparison.OrdinalIgnoreCase)) return "🏠 On-device";
        if (harnessId.StartsWith("custom:", StringComparison.OrdinalIgnoreCase)) return "❓ Custom";
        return "☁ Cloud model";
    }

    private async void SaveClick(object sender, RoutedEventArgs e)
    {
        // Presence lock (P3): lowering Trust or editing modalities is a weakening — gate before persisting.
        var oldTrust = (int)CurrentTrust();
        var newTrust = (int)TrustSlider.Value;
        var newModalities = _modalityChecks.Where(cb => cb.IsChecked == true).Select(cb => (string)cb.Tag).ToList();
        var oldModalities = _settings.HarnessModalities.TryGetValue(_harnessId, out var m) ? m : [];
        var modalitiesChanged = !new HashSet<string>(oldModalities, StringComparer.OrdinalIgnoreCase).SetEquals(newModalities);

        if (newTrust < oldTrust && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.LowerTrust, $"{_harnessId}: Trust {oldTrust}→{newTrust}"))
            return;
        if (modalitiesChanged && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.EditHarnessSysprompt, $"{_harnessId}: modalities edited"))
            return;

        _settings.HarnessTrust[_harnessId] = newTrust;
        _settings.HarnessModalities[_harnessId] = newModalities;
        try
        {
            SettingsStore.Save(_settings);
            DialogResult = true;
            Close();
        }
        catch (System.Exception ex)
        {
            StatusText.Text = "Couldn't save: " + ex.Message;
        }
    }

    private void CancelClick(object sender, RoutedEventArgs e) => Close();
}
