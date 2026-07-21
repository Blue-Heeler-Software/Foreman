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
    private readonly Func<string?>? _getCuDriver;
    private readonly Action<string?>? _setCuDriver;
    private readonly Func<string?>? _getCuAttentionTab;

    public HarnessSettingsWindow(string harnessId, string displayName, ForemanSettings settings,
        Func<string?>? getCuDriver = null, Action<string?>? setCuDriver = null, Func<string?>? getCuAttentionTab = null)
    {
        _harnessId = harnessId;
        _settings = settings;
        _getCuDriver = getCuDriver;
        _setCuDriver = setCuDriver;
        _getCuAttentionTab = getCuAttentionTab;
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

        ComputerUseCombo.ItemsSource = Enum.GetValues<HarnessCapabilityAccess>();
        BrowserUseCombo.ItemsSource = Enum.GetValues<HarnessCapabilityAccess>();
        var capabilities = CurrentCapabilityRestrictions();
        ComputerUseCombo.SelectedItem = capabilities.ComputerUse;
        BrowserUseCombo.SelectedItem = capabilities.BrowserUse;

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

        // Foreman's shared browser/Android DRIVER set (global, operator-only). Distinct from the Allow/Ask/Block
        // capabilities above: policy says what THIS harness may request; the driver set says which harnesses Foreman
        // currently accepts cu_* submissions from. Hidden when the host didn't wire the hook (e.g. headless).
        if (_setCuDriver is null)
        {
            CuDriverPanel.Visibility = Visibility.Collapsed;
        }
        else
        {
            ForemanDriverCombo.SelectedIndex = 0;   // safe default: saving policy/trust edits does not reroute CU.
            var driver = _getCuDriver?.Invoke();
            var included = IsCurrentDriver(driver);
            CuDriverNote.Text =
                $"Current Foreman driver set: {FormatDriverSet(driver)}. " +
                $"This harness is {(included ? "included" : "not included")}. Choose a mode only if you want to change Foreman's shared routing.";

            var tab = _getCuAttentionTab?.Invoke();
            CuAttentionNote.Text = string.IsNullOrWhiteSpace(tab)
                ? "No shared attention tab is pinned. When the browser extension pins one, Foreman keeps it separately from driver routing."
                : $"Shared attention tab: {tab}. Changing the driver set keeps this background tab state, so another harness can hand off and you can return to the same pinned tab.";
        }
    }

    /// <summary>True if the current driver string (null / "*" / comma-joined ids) authorizes THIS harness.</summary>
    private bool IsCurrentDriver(string? driver)
    {
        if (string.IsNullOrWhiteSpace(driver)) return false;
        if (driver.Trim() == "*") return true;   // "any harness" includes this one
        return driver.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                     .Any(d => string.Equals(d, _harnessId, StringComparison.OrdinalIgnoreCase));
    }

    private static HashSet<string> ParseDriverSet(string? driver)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(driver)) return set;
        if (driver.Trim() == "*") { set.Add("any"); return set; }
        foreach (var d in driver.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            set.Add(string.Equals(d, "*", StringComparison.Ordinal) ? "any" : d.Trim().ToLowerInvariant());
        return set;
    }

    private static string? ComposeDriverSet(HashSet<string> set)
    {
        if (set.Contains("any")) return "any";
        var ids = set.Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim().ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return ids.Length == 0 ? null : string.Join(",", ids);
    }

    private static string FormatDriverSet(string? driver)
    {
        if (string.IsNullOrWhiteSpace(driver)) return "operator only";
        if (driver.Trim() == "*") return "any harness";
        return driver.Replace(",", ", ");
    }

    private string? EditedDriverSet(string? current)
    {
        var tag = (ForemanDriverCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "unchanged";
        var set = ParseDriverSet(current);
        switch (tag)
        {
            case "include":
                if (!set.Contains("any")) set.Add(_harnessId);
                return ComposeDriverSet(set);
            case "remove":
                set.Remove(_harnessId);
                return ComposeDriverSet(set);
            case "only":
                return _harnessId;
            case "any":
                return "any";
            case "operator":
                return null;
            default:
                return current;
        }
    }

    private bool DriverEditSelected() =>
        !string.Equals((ForemanDriverCombo.SelectedItem as ComboBoxItem)?.Tag as string, "unchanged",
            StringComparison.OrdinalIgnoreCase);

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
            2 => "Strict — less rope, more nope: fires early; audits on high severity.",
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

    private HarnessCapabilityRestrictions CurrentCapabilityRestrictions() =>
        _settings.EffectiveCapabilityRestrictions(_harnessId);

    private static HarnessCapabilityAccess SelectedAccess(ComboBox combo) =>
        combo.SelectedItem is HarnessCapabilityAccess access ? access : HarnessCapabilityAccess.Allow;

    private static bool IsDefault(HarnessCapabilityRestrictions restrictions) =>
        restrictions.ComputerUse == HarnessCapabilityAccess.Allow
        && restrictions.BrowserUse == HarnessCapabilityAccess.Allow;

    private static bool SameCapabilities(HarnessCapabilityRestrictions a, HarnessCapabilityRestrictions b) =>
        a.ComputerUse == b.ComputerUse && a.BrowserUse == b.BrowserUse;

    private static bool RelaxesCapabilities(HarnessCapabilityRestrictions oldRestrictions, HarnessCapabilityRestrictions newRestrictions) =>
        newRestrictions.ComputerUse < oldRestrictions.ComputerUse
        || newRestrictions.BrowserUse < oldRestrictions.BrowserUse;

    private async void SaveClick(object sender, RoutedEventArgs e)
    {
        // Presence lock (P3): lowering Trust or editing modalities is a weakening — gate before persisting.
        var oldTrust = (int)CurrentTrust();
        var newTrust = (int)TrustSlider.Value;
        var newModalities = _modalityChecks.Where(cb => cb.IsChecked == true).Select(cb => (string)cb.Tag).ToList();
        var oldModalities = _settings.HarnessModalities.TryGetValue(_harnessId, out var m) ? m : [];
        var modalitiesChanged = !new HashSet<string>(oldModalities, StringComparer.OrdinalIgnoreCase).SetEquals(newModalities);
        var oldCapabilities = CurrentCapabilityRestrictions();
        var newCapabilities = new HarnessCapabilityRestrictions
        {
            ComputerUse = SelectedAccess(ComputerUseCombo),
            BrowserUse = SelectedAccess(BrowserUseCombo),
        };
        var capabilitiesChanged = !SameCapabilities(oldCapabilities, newCapabilities);

        if (newTrust < oldTrust && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.LowerTrust, $"{_harnessId}: Trust {oldTrust}→{newTrust}"))
            return;
        if (modalitiesChanged && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.EditHarnessSysprompt, $"{_harnessId}: modalities edited"))
            return;
        if (capabilitiesChanged
            && RelaxesCapabilities(oldCapabilities, newCapabilities)
            && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.RelaxHarnessCapabilityRestriction,
                $"{_harnessId}: high-risk tool restrictions relaxed"))
            return;

        // Foreman's shared browser/Android driver set (global, operator-only, persisted via the CuBroker's own persister)
        // is separate from the per-harness policy dicts below. Edits preserve the existing set unless the operator
        // explicitly chooses "only", "any", or "operator only"; changing it does not clear the shared attention tab.
        if (_setCuDriver is not null && DriverEditSelected())
            _setCuDriver(EditedDriverSet(_getCuDriver?.Invoke()));

        _settings.HarnessTrust[_harnessId] = newTrust;
        _settings.HarnessModalities[_harnessId] = newModalities;
        if (IsDefault(newCapabilities))
            _settings.HarnessCapabilityRestrictions.Remove(_harnessId);
        else
            _settings.HarnessCapabilityRestrictions[_harnessId] = newCapabilities;
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
