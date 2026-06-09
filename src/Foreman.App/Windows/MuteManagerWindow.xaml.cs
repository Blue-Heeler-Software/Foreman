using Foreman.Core.Models;
using Foreman.Core.Settings;
using System.Windows;

namespace Foreman.App.Windows;

/// <summary>
/// Lists the operator's active alert mutes and lets them be removed. Mutes only quiet tray popups
/// (never stop detection), and the manager is what makes a non-expiring "until I clear it" mute safe —
/// there's now somewhere to clear it.
/// </summary>
public partial class MuteManagerWindow : Window
{
    private readonly ForemanSettings _settings;
    private readonly Action _persist;

    public MuteManagerWindow(ForemanSettings settings, Action persist)
    {
        _settings = settings;
        _persist = persist;
        InitializeComponent();
        Refresh();
    }

    private void Refresh()
    {
        var now = DateTimeOffset.UtcNow;
        var rows = _settings.Mutes
            .OrderBy(m => m.Until ?? DateTimeOffset.MaxValue)
            .Select(m => new MuteRowVm(m, now))
            .ToList();

        MuteList.ItemsSource = rows;
        EmptyLabel.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ClearExpiredButton.IsEnabled = _settings.Mutes.Any(m => m.Until is { } u && u <= now);
        ClearAllButton.IsEnabled = _settings.Mutes.Count > 0;
    }

    private void RemoveClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: MuteEntry entry })
        {
            _settings.Mutes.Remove(entry);
            _persist();
            Refresh();
        }
    }

    private void ClearExpiredClick(object sender, RoutedEventArgs e)
    {
        var now = DateTimeOffset.UtcNow;
        _settings.Mutes.RemoveAll(m => m.Until is { } u && u <= now);
        _persist();
        Refresh();
    }

    private void ClearAllClick(object sender, RoutedEventArgs e)
    {
        _settings.Mutes.Clear();
        _persist();
        Refresh();
    }

    private void CloseClick(object sender, RoutedEventArgs e) => Close();
}

/// <summary>Row VM for the mute list.</summary>
public sealed class MuteRowVm
{
    public MuteEntry Entry { get; }
    public string What { get; }
    public string Status { get; }

    public MuteRowVm(MuteEntry entry, DateTimeOffset now)
    {
        Entry = entry;
        What = string.IsNullOrWhiteSpace(entry.Label) ? $"{entry.Scope}: {entry.Value}" : entry.Label;
        Status = entry.Until switch
        {
            null                       => "Muted until cleared",
            { } u when u <= now        => "Expired (will clear on its own)",
            { } u                      => $"Muted until {u.ToLocalTime():g}",
        };
    }
}
