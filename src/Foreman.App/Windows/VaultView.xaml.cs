using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Foreman.App.Security;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Security;
using Foreman.Vault;

namespace Foreman.App.Windows;

/// <summary>
/// Operator-only vault UI: enroll (first run) -> unlock (master password + a Windows Hello tap) -> manage (list +
/// add / edit / delete credentials). A <see cref="UserControl"/> so it hosts both in the dashboard's Vault tab and
/// inside <see cref="VaultWindow"/> (tray -> Vault…). All mutations are operator-only by construction (this surface
/// is never reachable over MCP). Secret VALUES never appear here - only names/origins/which-fields/ACL. The
/// agent-facing resolve path is the injection hook (P1.4); this is the human's management surface.
/// </summary>
public partial class VaultView : UserControl
{
    private readonly VaultService _vault;
    private string? _editingOriginalName;   // non-null while the add form is editing an existing item (its original name)

    /// <summary>Injected by the composition root: number of locked-time sign-ups awaiting review (readable while
    /// unlocked), and the action that opens the review window. Wired so the deposit queue is reachable from the
    /// vault surface the operator actually manages credentials in — not only the tray.</summary>
    public Func<int>? PendingDepositCount { get; set; }
    public Action? OpenDepositReview { get; set; }

    public VaultView(VaultService vault)
    {
        _vault = vault;
        InitializeComponent();
        // Enter in any password field triggers that screen's primary action, so unlocking / enrolling / saving
        // never needs a mouse trip to the button.
        EnrollPw.KeyDown      += (_, e) => SubmitOnEnter(e, EnrollClick);
        EnrollConfirm.KeyDown += (_, e) => SubmitOnEnter(e, EnrollClick);
        UnlockPw.KeyDown      += (_, e) => SubmitOnEnter(e, UnlockClick);
        AddPw.KeyDown         += (_, e) => SubmitOnEnter(e, SaveItemClick);
        Loaded += (_, _) => RefreshState();
    }

    // Treat Enter in an input as a click of that screen's primary button.
    private void SubmitOnEnter(System.Windows.Input.KeyEventArgs e, RoutedEventHandler action)
    {
        if (e.Key != System.Windows.Input.Key.Enter) return;
        e.Handled = true;
        action(this, new RoutedEventArgs());
    }

    /// <summary>Re-read vault state and show the right panel. Safe to call when the tab is shown.</summary>
    public void RefreshState()
    {
        var enrolled = _vault.IsEnrolled;
        var unlocked = _vault.IsUnlocked;
        EnrollPanel.Visibility  = !enrolled ? Visibility.Visible : Visibility.Collapsed;
        UnlockPanel.Visibility  = enrolled && !unlocked ? Visibility.Visible : Visibility.Collapsed;
        ManagerPanel.Visibility = unlocked ? Visibility.Visible : Visibility.Collapsed;
        if (unlocked) { PopulateItems(); RefreshDepositBanner(); }
    }

    // Show the "pending sign-ups to review" banner when the vault is unlocked and the queue is non-empty.
    private void RefreshDepositBanner()
    {
        var pending = PendingDepositCount?.Invoke() ?? 0;
        DepositReviewBanner.Visibility = pending > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (pending > 0)
            DepositReviewText.Text = pending == 1
                ? "1 agent sign-up is waiting for your review"
                : $"{pending} agent sign-ups are waiting for your review";
    }

    // Opens the review window; the composition root refreshes this view when that window closes (a commit adds a
    // credential + drops the pending count), so the banner and list reflect the result without a manual reopen.
    private void ReviewDepositsClick(object sender, RoutedEventArgs e) => OpenDepositReview?.Invoke();

    private void EnrollClick(object sender, RoutedEventArgs e)
    {
        EnrollError.Text = string.Empty;
        var pw = EnrollPw.Password;
        if (pw.Length < 8) { EnrollError.Text = "Use at least 8 characters."; return; }
        if (pw != EnrollConfirm.Password) { EnrollError.Text = "Passwords do not match."; return; }
        try { _vault.Enroll(pw); }
        catch (Exception ex) { EnrollError.Text = ex.Message; return; }
        EnrollPw.Clear(); EnrollConfirm.Clear();
        Log("Credential vault created.");
        RefreshState();
    }

    private async void UnlockClick(object sender, RoutedEventArgs e)
    {
        UnlockError.Text = string.Empty;
        // Presence tap when the lock is on (no-op otherwise) — proving the human is here before the vault opens.
        if (!await PresenceGuard.AuthorizeAsync(WeakeningAction.ResolveVaultCredential, "unlock the credential vault"))
        { UnlockError.Text = "Presence not verified — the vault stays locked."; return; }
        try { _vault.Unlock(UnlockPw.Password); }
        catch { UnlockError.Text = "Wrong master password, or the vault can't be opened on this machine."; return; }
        UnlockPw.Clear();
        Log("Vault unlocked.");
        RefreshState();
    }

    private void LockClick(object sender, RoutedEventArgs e)
    {
        _vault.Lock();
        Log("Vault locked.");
        RefreshState();
    }

    private void PopulateItems()
    {
        var rows = _vault.ListItems().Select(VaultItemRow.From).ToList();
        ItemsList.ItemsSource = rows;
        EmptyHint.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (rows.Count == 0) OpenAddForm();   // empty vault (incl. first run) — jump straight to adding one
    }

    private void OpenAddForm()
    {
        _editingOriginalName = null;                       // a fresh open is always ADD mode
        AddFormTitle.Text = "Add credential";
        EditKeepHint.Visibility = Visibility.Collapsed;
        AddForm.Visibility = Visibility.Visible;
        AddButton.Visibility = Visibility.Collapsed;
        AddOrigins.Focus();   // the website is the one required field, so start there
    }

    private void ShowAddFormClick(object sender, RoutedEventArgs e) => OpenAddForm();

    // Edit an existing item: pre-fill the non-secret metadata; secrets stay blank and "leave blank to keep" them.
    private void EditItemClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not VaultItemRow row) return;
        _editingOriginalName = row.Name;
        AddFormTitle.Text = "Edit credential";
        EditKeepHint.Visibility = Visibility.Visible;
        AddOrigins.Text = string.Join(", ", row.OriginList);
        AddName.Text = row.Name;
        AddHarnesses.Text = string.Join(", ", row.HarnessList);
        AddUser.Text = string.Empty; AddPw.Clear(); AddTotp.Text = string.Empty; AddError.Text = string.Empty;
        AddForm.Visibility = Visibility.Visible;
        AddButton.Visibility = Visibility.Collapsed;
        AddOrigins.Focus();
    }

    private void DeleteItemClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not VaultItemRow row) return;
        if (MessageBox.Show($"Delete the credential \"{row.Name}\"? This can't be undone.",
                "Foreman Agent Safety — Vault", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        try { _vault.Delete(row.Name); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Foreman Agent Safety — Vault", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        Log($"Vault item '{row.Name}' deleted.");
        if (string.Equals(_editingOriginalName, row.Name, StringComparison.OrdinalIgnoreCase)) CloseAddForm();
        PopulateItems();
    }

    private void CancelAddClick(object sender, RoutedEventArgs e) => CloseAddForm();

    private void GeneratePwClick(object sender, RoutedEventArgs e) => AddPw.Password = VaultPasswordGenerator.Generate(20);

    private void SaveItemClick(object sender, RoutedEventArgs e)
    {
        AddError.Text = string.Empty;
        var origins = ParseOrigins(AddOrigins.Text);   // forgiving: a pasted URL or a bare host both reduce to the host
        if (origins.Count == 0) { AddError.Text = "Enter the website this is for (e.g. github.com)."; return; }
        var name = AddName.Text.Trim();
        if (name.Length == 0) name = origins[0];        // default the name to the website

        var entry = new VaultEntry
        {
            Name = name,
            Origins = origins,
            Harnesses = SplitCsv(AddHarnesses.Text),
            Username = NullIfBlank(AddUser.Text),
            Password = NullIfBlank(AddPw.Password),
            TotpSeedBase32 = NullIfBlank(AddTotp.Text.Replace(" ", string.Empty)),
        };
        try
        {
            if (_editingOriginalName is { } orig)
            {
                if (!_vault.UpdateItem(orig, entry)) { AddError.Text = "That item no longer exists — close and reopen the list."; return; }
            }
            else _vault.Upsert(entry);
        }
        catch (Exception ex) { AddError.Text = ex.Message; return; }
        Log(_editingOriginalName is null ? $"Vault item '{name}' saved." : $"Vault item '{name}' updated.");
        CloseAddForm();
        PopulateItems();
    }

    private void CloseAddForm()
    {
        AddName.Text = AddOrigins.Text = AddUser.Text = AddTotp.Text = AddHarnesses.Text = string.Empty;
        AddPw.Clear();
        AddError.Text = string.Empty;
        _editingOriginalName = null;
        AddFormTitle.Text = "Add credential";
        EditKeepHint.Visibility = Visibility.Collapsed;
        AddForm.Visibility = Visibility.Collapsed;
        AddButton.Visibility = Visibility.Visible;
    }

    private static List<string> SplitCsv(string? s) =>
        (s ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    // Forgiving website input: each comma-separated entry may be a full URL or a bare host; reduce each to a bare,
    // lowercase host (so "https://github.com/login", "github.com", and "GitHub.com" all become "github.com").
    private static List<string> ParseOrigins(string? raw)
    {
        var result = new List<string>();
        foreach (var part in (raw ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var host = NormalizeToHost(part);
            if (host.Length > 0 && !result.Contains(host, StringComparer.OrdinalIgnoreCase)) result.Add(host);
        }
        return result;
    }

    private static string NormalizeToHost(string s)
    {
        s = s.Trim();
        if (Uri.TryCreate(s, UriKind.Absolute, out var u) && !string.IsNullOrEmpty(u.Host)) return u.Host.ToLowerInvariant();
        if (Uri.TryCreate("https://" + s, UriKind.Absolute, out var u2) && !string.IsNullOrEmpty(u2.Host)) return u2.Host.ToLowerInvariant();
        return s.ToLowerInvariant();
    }

    private static string? NullIfBlank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;

    private static void Log(string msg) =>
        EventBus.Instance.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Vault", msg));

    /// <summary>Display row for the items list — names/origins/which-fields/ACL only, no secret values.</summary>
    public sealed class VaultItemRow
    {
        public string Name { get; init; } = string.Empty;
        public string Origins { get; init; } = string.Empty;
        public string Fields { get; init; } = string.Empty;
        public string Acl { get; init; } = string.Empty;
        // Raw lists carried for the Edit form to pre-fill (no secret VALUES — only origins + the agent ACL).
        public IReadOnlyList<string> OriginList { get; init; } = [];
        public IReadOnlyList<string> HarnessList { get; init; } = [];

        public static VaultItemRow From(Foreman.Core.Vault.VaultItemInfo i)
        {
            var fields = new List<string>();
            if (i.HasUsername) fields.Add("username");
            if (i.HasPassword) fields.Add("password");
            if (i.HasTotp) fields.Add("2FA");
            return new VaultItemRow
            {
                Name = i.Name,
                Origins = string.Join(", ", i.Origins),
                Fields = fields.Count > 0 ? string.Join(" · ", fields) : "(no fields)",
                Acl = i.Harnesses.Count > 0 ? "agents: " + string.Join(", ", i.Harnesses) : "operator only",
                OriginList = i.Origins,
                HarnessList = i.Harnesses,
            };
        }
    }
}
