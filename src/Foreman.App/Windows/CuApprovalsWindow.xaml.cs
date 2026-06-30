using System.Windows;
using System.Windows.Threading;

namespace Foreman.App.Windows;

/// <summary>A held computer-use action shown to the operator for approval. Origin/harness/args are the agent's CLAIMS
/// (the auditor held precisely because it could not clear them), surfaced read-only; the operator decides.</summary>
public sealed record HeldCuView(string ActionId, string Verb, string Modality, string Harness, string Reason, string ArgsSummary)
{
    public string Title => $"{Verb} · {Modality} · by {Harness}";
}

/// <summary>
/// Operator approve/reject surface for CU actions the auditor HELD. Until now a held action (an agent self-signup, or a
/// default-held desktop action) could only be cleared via the operator-only cu_approve MCP tool - there was no in-app
/// control, so the human-in-the-loop the design rests on had nowhere to act. This is that control. Approve/Reject route
/// through the same broker path (and the same desktop presence tap) as the MCP tools.
/// </summary>
public partial class CuApprovalsWindow : Window
{
    private readonly Func<IReadOnlyList<HeldCuView>> _getHeld;
    private readonly Func<string, Task<(bool Ok, string Reason)>> _approve;
    private readonly Func<string, string?, (bool Ok, string Reason)> _reject;
    private readonly DispatcherTimer _timer;

    public CuApprovalsWindow(
        Func<IReadOnlyList<HeldCuView>> getHeld,
        Func<string, Task<(bool Ok, string Reason)>> approve,
        Func<string, string?, (bool Ok, string Reason)> reject)
    {
        _getHeld = getHeld;
        _approve = approve;
        _reject = reject;
        InitializeComponent();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += (_, _) => Refresh();
        Loaded += (_, _) => { Refresh(); _timer.Start(); };
        Closed += (_, _) => _timer.Stop();
    }

    private void Refresh()
    {
        IReadOnlyList<HeldCuView> held;
        try { held = _getHeld(); } catch { held = []; }
        HeldList.ItemsSource = held;
        EmptyText.Visibility = held.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void ApproveClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string id }) return;
        StatusText.Text = "Approving (complete any Hello prompt)…";
        try
        {
            var (ok, reason) = await _approve(id);
            StatusText.Text = ok ? "Approved." : $"Not approved: {reason}";
        }
        catch (Exception ex) { StatusText.Text = "Approve failed: " + ex.Message; }
        Refresh();
    }

    private void RejectClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string id }) return;
        var (ok, reason) = _reject(id, null);
        StatusText.Text = ok ? "Rejected." : $"Couldn't reject: {reason}";
        Refresh();
    }

    private void RefreshClick(object sender, RoutedEventArgs e) => Refresh();
    private void CloseClick(object sender, RoutedEventArgs e) => Close();
}
