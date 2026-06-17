using Foreman.Core.Alerts;
using Foreman.Core.Models;
using System.Windows;
using System.Windows.Controls;

namespace Foreman.App.Windows;

/// <summary>
/// Lightweight picker when Send for Audit needs the operator to choose among multiple harness auditors.
/// </summary>
internal static class AuditHarnessPickerDialog
{
    public static AuditRouteResolver.Candidate? Pick(
        Window owner,
        string? targetHarnessId,
        IReadOnlyList<AuditRouteResolver.Candidate> candidates,
        string? title = null,
        string? prompt = null)
    {
        if (candidates.Count == 0)
            return null;

        var targetLabel = string.IsNullOrWhiteSpace(targetHarnessId)
            ? "this harness"
            : KnownHarnesses.GetById(targetHarnessId)?.DisplayName ?? targetHarnessId;

        var dialog = new Window
        {
            Title = title ?? "Choose auditor harness",
            Width = 520,
            Height = 420,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = owner,
            ResizeMode = ResizeMode.NoResize,
            Background = owner.TryFindResource("BackgroundBrush") as System.Windows.Media.Brush
                         ?? System.Windows.Media.Brushes.Black,
        };

        var root = new Grid { Margin = new Thickness(16) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var header = new TextBlock
        {
            Text = prompt ?? $"Multiple harnesses can audit {targetLabel}. Pick one:",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 12),
            Foreground = owner.TryFindResource("TextPrimaryBrush") as System.Windows.Media.Brush
                         ?? System.Windows.Media.Brushes.White,
        };
        Grid.SetRow(header, 0);
        root.Children.Add(header);

        var list = new ListBox
        {
            ItemsSource = candidates,
            DisplayMemberPath = nameof(AuditRouteResolver.Candidate.DisplayName),
            Margin = new Thickness(0, 0, 0, 12),
        };
        if (candidates.Count > 0)
            list.SelectedIndex = 0;
        Grid.SetRow(list, 1);
        root.Children.Add(list);

        AuditRouteResolver.Candidate? picked = null;

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
        };

        var ok = new Button
        {
            Content = "Use selected",
            MinWidth = 110,
            Margin = new Thickness(0, 0, 8, 0),
            IsDefault = true,
        };
        ok.Click += (_, _) =>
        {
            picked = list.SelectedItem as AuditRouteResolver.Candidate;
            dialog.DialogResult = picked is not null;
            dialog.Close();
        };

        var cancel = new Button
        {
            Content = "Cancel",
            MinWidth = 90,
            IsCancel = true,
        };
        cancel.Click += (_, _) =>
        {
            dialog.DialogResult = false;
            dialog.Close();
        };

        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        dialog.Content = root;
        return dialog.ShowDialog() == true ? picked : null;
    }
}
