using System.Windows;

namespace Foreman.App.Windows;

/// <summary>One queued locked-time sign-up, shown to the operator for review. Carries NO secret - just the agent's
/// (unverified) claims (site / harness / time) and an opaque id the App maps back to the real deposit.</summary>
public sealed record DepositReviewItem(string Id, string Origin, string Harness, string CreatedAt)
{
    public string Title => $"{Origin}   ·   claims harness: {Harness}";
    public string Sub => $"created (claimed): {CreatedAt}";
}

/// <summary>A drained snapshot: the reviewable items + how many queue lines failed to decrypt + whether the deposit
/// key itself was swapped (tamper). Failed/tamper are surfaced as warnings; nothing auto-commits.</summary>
public sealed record DepositReviewSnapshot(IReadOnlyList<DepositReviewItem> Items, int Failed, bool KeyTampered);

/// <summary>
/// Operator review of locked-time agent sign-ups (the P-BM4b deposit queue). The agent generated these passwords while
/// the vault was LOCKED and encrypted them to the deposit public key; on unlock the operator decides each one. Accept
/// commits via the same no-clobber, operator-only path as live self-signup; Reject discards it; Finish clears the queue.
/// Because the clear public key makes the queue forgeable, origin/harness/time are labeled as the agent's CLAIMS and
/// nothing commits without an explicit per-item operator action.
/// </summary>
public partial class DepositReviewWindow : Window
{
    private readonly Func<string, (bool Ok, string Reason)> _accept;
    private readonly Action<string> _reject;
    private readonly Action _clear;
    private readonly List<DepositReviewItem> _items;

    public DepositReviewWindow(DepositReviewSnapshot snapshot,
        Func<string, (bool Ok, string Reason)> accept, Action<string> reject, Action clear)
    {
        _accept = accept;
        _reject = reject;
        _clear = clear;
        _items = snapshot.Items.ToList();
        InitializeComponent();

        if (snapshot.KeyTampered)
        {
            WarningText.Text = "The deposit key sidecar does not match the sealed key - it may have been swapped since "
                + "these were queued. The queue is NOT trusted and was not decrypted. Treat any of these as suspect.";
            WarningBox.Visibility = Visibility.Visible;
            ClearButton.Content = "Discard the suspect queue";   // Clear is the only safe action on a tampered queue
        }
        else if (snapshot.Failed > 0)
        {
            WarningText.Text = $"{snapshot.Failed} queued line(s) could not be decrypted (possible tampering or "
                + "corruption). The readable sign-ups below are still shown; the bad lines are left for forensics.";
            WarningBox.Visibility = Visibility.Visible;
            // Be explicit that clearing also destroys the un-decryptable (forensic) lines, not just the reviewed ones.
            ClearButton.Content = $"Finish & clear (also discards {snapshot.Failed} unreadable line(s))";
        }
        Rebind();
    }

    private void Rebind()
    {
        DepositList.ItemsSource = null;
        DepositList.ItemsSource = _items;
        EmptyText.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void AcceptClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string id }) return;
        var (ok, reason) = _accept(id);
        if (ok) { _items.RemoveAll(i => i.Id == id); Rebind(); StatusText.Text = "Stored in the vault."; }
        else StatusText.Text = "Not stored: " + reason;
    }

    private void RejectClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string id }) return;
        _reject(id);
        _items.RemoveAll(i => i.Id == id);
        Rebind();
        StatusText.Text = "Discarded.";
    }

    private void ClearClick(object sender, RoutedEventArgs e)
    {
        _clear();
        Close();
    }

    private void CloseClick(object sender, RoutedEventArgs e) => Close();
}
