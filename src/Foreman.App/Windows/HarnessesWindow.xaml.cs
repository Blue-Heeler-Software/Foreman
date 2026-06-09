using Foreman.Core.Models;
using Foreman.Core.Settings;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace Foreman.App.Windows;

public partial class HarnessesWindow : UserControl
{
    private readonly ForemanSettings _settings;
    private readonly Func<IEnumerable<ProcessRecord>> _getSnapshot;
    private readonly List<HarnessVm> _items = [];

    public HarnessesWindow(ForemanSettings settings, Func<IEnumerable<ProcessRecord>> getSnapshot)
    {
        _settings = settings;
        _getSnapshot = getSnapshot;
        InitializeComponent();
        Loaded += (_, _) => Refresh();
    }

    private void Refresh()
    {
        var running = _getSnapshot()
            .Where(r => r.HarnessType is not null)
            .Select(r => r.HarnessType!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        _items.Clear();

        // built-in harnesses
        foreach (var h in KnownHarnesses.All)
            _items.Add(new HarnessVm(h.Id, h.DisplayName, h.Developer, h.Description, isCustom: false, _settings, running));

        // user-added custom exes
        foreach (var exe in _settings.CustomHarnessExes)
        {
            var id = $"custom:{exe.ToLowerInvariant()}";
            _items.Add(new HarnessVm(id, exe, "Custom", $"Custom monitored process: {exe}", isCustom: true, _settings, running));
        }

        HarnessList.ItemsSource = null;
        HarnessList.ItemsSource = _items;
    }

    // ── Add custom exe ────────────────────────────────────────────────────

    private void AddExeBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) TryAdd();
    }

    private void AddClick(object sender, RoutedEventArgs e) => TryAdd();

    private void TryAdd()
    {
        var raw = AddExeBox.Text.Trim();
        if (string.IsNullOrEmpty(raw)) return;

        // normalise: append .exe if user forgot it on Windows
        if (!raw.Contains('.'))
            raw += ".exe";
        raw = raw.ToLowerInvariant();

        // don't duplicate
        if (_items.Any(v => v.Id == $"custom:{raw}"))
        {
            AddExeBox.Text = string.Empty;
            AddExePlaceholder.Visibility = Visibility.Visible;
            return;
        }

        var id = $"custom:{raw}";
        var running = _getSnapshot()
            .Where(r => r.HarnessType == id)
            .Any();
        var vm = new HarnessVm(id, raw, "Custom", $"Custom monitored process: {raw}", isCustom: true, _settings,
            running ? new HashSet<string> { id } : new HashSet<string>());

        _items.Add(vm);
        HarnessList.ItemsSource = null;
        HarnessList.ItemsSource = _items;

        AddExeBox.Text = string.Empty;
        AddExePlaceholder.Visibility = Visibility.Visible;
    }

    private void DeleteClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: HarnessVm vm })
        {
            _items.Remove(vm);
            HarnessList.ItemsSource = null;
            HarnessList.ItemsSource = _items;
        }
    }

    // ── Placeholder visibility ────────────────────────────────────────────

    private void AddExeBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (AddExePlaceholder is not null)
            AddExePlaceholder.Visibility = string.IsNullOrEmpty(AddExeBox.Text)
                ? Visibility.Visible : Visibility.Collapsed;
    }

    // ── Save / Cancel ─────────────────────────────────────────────────────

    private void SaveClick(object sender, RoutedEventArgs e) => SaveChanges();

    /// <summary>Persists the current toggles + custom exes. Public so the host can save on navigate-away.</summary>
    public void SaveChanges()
    {
        _settings.DisabledHarnesses = _items
            .Where(v => !v.IsMonitored)
            .Select(v => v.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        _settings.CustomHarnessExes = _items
            .Where(v => v.IsCustom)
            .Select(v => v.ExeName)
            .ToList();

        SettingsStore.Save(_settings);
        Refresh();   // reflect persisted state (this is a tab, so we stay put rather than closing)
    }

    // Revert: rebuild rows from the persisted settings, discarding unsaved toggles.
    private void CancelClick(object sender, RoutedEventArgs e) => Revert();

    /// <summary>Discards unsaved edits by reloading from persisted settings.</summary>
    public void Revert() => Refresh();

    /// <summary>True if the current toggles / custom-exe list diverge from what's persisted.</summary>
    public bool HasUnsavedChanges()
    {
        var disabledNow = new HashSet<string>(
            _items.Where(v => !v.IsMonitored).Select(v => v.Id), StringComparer.OrdinalIgnoreCase);
        var customNow = new HashSet<string>(
            _items.Where(v => v.IsCustom).Select(v => v.ExeName), StringComparer.OrdinalIgnoreCase);

        return !disabledNow.SetEquals(_settings.DisabledHarnesses)
            || !customNow.SetEquals(new HashSet<string>(_settings.CustomHarnessExes, StringComparer.OrdinalIgnoreCase));
    }
}

/// <summary>View model for a single harness row.</summary>
public sealed class HarnessVm : INotifyPropertyChanged
{
    private bool _isMonitored;
    public event PropertyChangedEventHandler? PropertyChanged;

    public string  Id          { get; }
    public string  ExeName     { get; }   // raw exe name for custom entries
    public string  DisplayName { get; }
    public string  Developer   { get; }
    public string  Description { get; }
    public bool    IsCustom    { get; }
    public bool    IsRunning   { get; }

    public Visibility DeleteVisibility => IsCustom ? Visibility.Visible : Visibility.Collapsed;

    public bool IsMonitored
    {
        get => _isMonitored;
        set { _isMonitored = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsMonitored))); }
    }

    public string StatusText       => IsRunning ? "Running"  : "Not found";
    public Brush  StatusBackground => IsRunning
        ? new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x1A))
        : new SolidColorBrush(Color.FromRgb(0x1E, 0x20, 0x28));
    public Brush  StatusForeground => IsRunning
        ? new SolidColorBrush(Color.FromRgb(0x7E, 0xC8, 0x78))
        : new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90));

    public HarnessVm(string id, string displayName, string developer, string description,
                     bool isCustom, ForemanSettings settings, HashSet<string> running)
    {
        Id          = id;
        ExeName     = isCustom ? displayName : string.Empty;   // for custom, displayName IS the exe
        DisplayName = displayName;
        Developer   = developer;
        Description = description;
        IsCustom    = isCustom;
        IsRunning   = running.Contains(id);
        _isMonitored = !settings.DisabledHarnesses.Contains(id);
    }
}
