using Foreman.Core.Events;
using Foreman.Core.Models;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;

namespace Foreman.App.Windows;

public partial class LogWindow : UserControl, IEventSink, IDisposable
{
    private const int MaxEvents = 5000;

    /// <summary>Wired by App — loads prior-session events from the on-disk event log (null = persistence off).</summary>
    public static Func<IReadOnlyList<ForemanEvent>>? LoadPersisted { get; set; }

    private readonly ObservableCollection<EventViewModel> _events = [];
    private readonly ICollectionView _view;
    private bool _autoScroll = true;
    private string _searchText = "";
    private ForemanSeverity? _minSeverity = null;

    public LogWindow()
    {
        InitializeComponent();

        // Set up filtered view — bind list to this, not _events directly
        _view = CollectionViewSource.GetDefaultView(_events);
        _view.Filter = FilterPredicate;
        EventList.ItemsSource = _view;

        // Hydrate: merge persisted (prior-session) events with this session's in-memory history,
        // de-duped by Id, oldest first, capped at MaxEvents.
        var persisted = LoadPersisted?.Invoke() ?? [];
        var seen = new HashSet<string>();
        var merged = persisted.Concat(EventBus.Instance.GetHistory())
            .Where(e => seen.Add(e.Id))
            .OrderBy(e => e.Timestamp)
            .ToList();
        if (merged.Count > MaxEvents)
            merged = merged.GetRange(merged.Count - MaxEvents, MaxEvents);
        foreach (var evt in merged)
            _events.Add(EventViewModel.FromEvent(evt));

        // subscribe for future events
        EventBus.Instance.Subscribe(this);

        EventList.AddHandler(System.Windows.Controls.ScrollViewer.ScrollChangedEvent,
            new System.Windows.Controls.ScrollChangedEventHandler(OnScrollChanged));

        // scroll to bottom so the latest events are visible
        Loaded += (_, _) => ScrollToBottom();

        UpdateStatusLabel();
    }

    // ── IEventSink ───────────────────────────────────────────────────────────

    void IEventSink.OnEvent(ForemanEvent evt)
    {
        Dispatcher.BeginInvoke(() =>
        {
            if (_events.Count >= MaxEvents)
                _events.RemoveAt(0);

            _events.Add(EventViewModel.FromEvent(evt));
            UpdateStatusLabel();

            if (_autoScroll)
                ScrollToBottom();
        });
    }

    // ── Filtering ────────────────────────────────────────────────────────────

    private bool FilterPredicate(object obj)
    {
        if (obj is not EventViewModel vm) return false;

        // severity gate
        if (_minSeverity.HasValue && vm.OriginalEvent.Severity < _minSeverity.Value)
            return false;

        // text gate — matches source or message, case-insensitive
        if (_searchText.Length > 0)
        {
            return vm.Source.Contains(_searchText, StringComparison.OrdinalIgnoreCase)
                || vm.Message.Contains(_searchText, StringComparison.OrdinalIgnoreCase);
        }

        return true;
    }

    private void ApplyFilter()
    {
        // Guard: SeverityFilter fires SelectionChanged during InitializeComponent()
        // (XAML sets SelectedIndex="0" before the constructor assigns _view).
        if (_view is null) return;

        _view.Refresh();
        UpdateStatusLabel();

        if (_autoScroll)
            ScrollToBottom();
    }

    // ── Event handlers ───────────────────────────────────────────────────────

    private void SearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        _searchText = SearchBox.Text;
        SearchPlaceholder.Visibility = _searchText.Length == 0
            ? Visibility.Visible : Visibility.Collapsed;
        ApplyFilter();
    }

    private void SeverityFilter_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        _minSeverity = SeverityFilter.SelectedIndex switch
        {
            0 => null,                              // All levels
            1 => ForemanSeverity.Info,              // Info +
            2 => ForemanSeverity.Low,               // Low +
            3 => ForemanSeverity.Medium,            // Medium +
            4 => ForemanSeverity.High,              // High +
            5 => ForemanSeverity.Critical,          // Critical only
            _ => null,
        };
        ApplyFilter();
    }

    private void AutoScrollCheck_Changed(object sender, RoutedEventArgs e)
    {
        _autoScroll = AutoScrollCheck.IsChecked == true;
        if (_autoScroll) ScrollToBottom();
    }

    // Click a column header to sort by it; click again to flip direction.
    private string? _sortProp;
    private ListSortDirection _sortDir = ListSortDirection.Descending;

    private void ColumnHeaderClick(object sender, RoutedEventArgs e)
    {
        if (_view is null || e.OriginalSource is not GridViewColumnHeader header) return;
        var prop = (header.Column?.Header as string) switch
        {
            "Time"    => "OriginalEvent.Timestamp",
            "Sev"     => "OriginalEvent.Severity",
            "Source"  => "Source",
            "Message" => "Message",
            _         => null,
        };
        if (prop is null) return;   // ignore clicks on the templated padding header

        if (_sortProp == prop)
            _sortDir = _sortDir == ListSortDirection.Ascending ? ListSortDirection.Descending : ListSortDirection.Ascending;
        else
        {
            _sortProp = prop;
            _sortDir = prop == "OriginalEvent.Timestamp" ? ListSortDirection.Descending : ListSortDirection.Ascending;
        }

        _view.SortDescriptions.Clear();
        _view.SortDescriptions.Add(new SortDescription(_sortProp, _sortDir));
        _view.Refresh();
    }

    private void EventList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (EventList.SelectedItem is EventViewModel vm)
            AlertDetailWindow.ShowFor(vm.OriginalEvent);
    }

    private void ExportClick(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Title      = "Export Foreman Agent Safety Event Log",
            Filter     = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            FileName   = $"foreman-log-{DateTime.Now:yyyy-MM-dd-HHmm}.csv",
            DefaultExt = ".csv",
        };

        if (dlg.ShowDialog(Window.GetWindow(this)) != true) return;

        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("Timestamp,Severity,Source,Message");

            foreach (var vm in _view.Cast<EventViewModel>())
            {
                sb.Append(CsvEscape(vm.Timestamp)).Append(',');
                sb.Append(CsvEscape(vm.SeverityLabel)).Append(',');
                sb.Append(CsvEscape(vm.Source)).Append(',');
                sb.AppendLine(CsvEscape(vm.Message));
            }

            File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Export failed: {ex.Message}", "Foreman Agent Safety",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string CsvEscape(string s)
    {
        // Formula-injection guard: message/command text is agent-controlled, and Excel/Sheets
        // execute cells starting with = + - @ (or a tab). Prefix ' so they import as text.
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@' or '\t')
            s = "'" + s;

        // Wrap in quotes if the field contains comma, quote, or newline
        if (s.Contains(',') || s.Contains('"') || s.Contains('\n'))
            return $"\"{s.Replace("\"", "\"\"")}\"";
        return s;
    }

    private void ClearClick(object sender, RoutedEventArgs e)
    {
        _events.Clear();
        UpdateStatusLabel();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void ScrollToBottom()
    {
        // Guard: AutoScrollCheck's IsChecked="True" fires Checked during InitializeComponent()
        // — before the constructor assigns _view and before EventList exists. Same XAML-init
        // hazard as SeverityFilter.SelectionChanged.
        if (_view is null || EventList is null) return;

        // Enumerate the filtered view to find the last item
        object? last = null;
        foreach (var item in _view) last = item;
        if (last is not null) EventList.ScrollIntoView(last);
    }

    private void UpdateStatusLabel()
    {
        var visible = _view.Cast<object>().Count();
        var total   = _events.Count;
        StatusLabel.Text = visible == total
            ? $"{total} event{(total == 1 ? "" : "s")}"
            : $"{visible} of {total} event{(total == 1 ? "" : "s")}";
    }

    private void OnScrollChanged(object sender, System.Windows.Controls.ScrollChangedEventArgs e)
    {
        // Only disable auto-scroll when the user scrolls up (not when new items push height)
        if (e.ExtentHeightChange == 0)
            _autoScroll = e.VerticalOffset >= e.ExtentHeight - e.ViewportHeight - 1;
    }

    // Called by the host (DashboardWindow) when it closes, since a UserControl has no OnClosed.
    public void Dispose()
    {
        EventBus.Instance.Unsubscribe(this);
    }
}
