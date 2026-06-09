using Foreman.Core.Integration;
using Foreman.McpServer;
using System.Windows;

namespace Foreman.App.Windows;

/// <summary>
/// Beginner-friendly "connect your agent" guide. Shows who's connected now (with sampling capability),
/// one-click connect for Claude Code and Codex, and copy-paste self-config
/// (URL + Authorization header, token filled in) for any other MCP client.
/// </summary>
public partial class ConnectAgentWindow : Window
{
    private readonly int _port;
    private readonly string _token;
    private readonly Func<IReadOnlyList<McpClientInfo>>? _getClients;

    public ConnectAgentWindow(int port, string token, Func<IReadOnlyList<McpClientInfo>>? getClients)
    {
        _port = port;
        _token = token;
        _getClients = getClients;
        InitializeComponent();
        Populate();
    }

    private void Populate()
    {
        ClaudeJsonBox.Text = ClaudeMcpConnector.BuildClaudeConfigSnippet(_port, _token);
        CodexTomlBox.Text = CodexMcpConnector.BuildConfigSnippet(_port, _token);
        GenericBox.Text =
            $"URL:    {ClaudeMcpConnector.Url(_port)}\r\n" +
            $"Header: Authorization: Bearer {_token}\r\n\r\n" +
            "Server entry (JSON):\r\n" +
            ClaudeMcpConnector.BuildServerEntrySnippet(_port, _token);
        TokenNote.Text =
            "Your token lives at %LocalAppData%\\Foreman\\mcp.token. Keep it private — anything holding it " +
            "can call Foreman's MCP tools. /health is open; /mcp requires the token.";
        RefreshConnected();
    }

    private void RefreshConnected()
    {
        var clients = _getClients?.Invoke() ?? [];
        ConnectedText.Text = clients.Count == 0
            ? "No agents are connected to Foreman yet. Connect one below, then restart it."
            : "Connected now:\n" + string.Join("\n", clients.Select(c =>
                $"  • {c.Name}{(string.IsNullOrWhiteSpace(c.Version) ? "" : $" v{c.Version}")} — " +
                $"sampling: {(c.Sampling ? "yes" : "no")}"));
    }

    private void ConnectClaudeClick(object sender, RoutedEventArgs e)
    {
        var r = ClaudeMcpConnector.Connect(_port, _token);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Claude Code's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "Foreman — Connect Claude Code", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Claude Code to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "Foreman — Connect Claude Code", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectCodexClick(object sender, RoutedEventArgs e)
    {
        var r = CodexMcpConnector.Connect(_port, _token);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Codex's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste TOML below instead.",
                "Foreman — Connect Codex", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Codex to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "Foreman — Connect Codex", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void CopyCliClick(object sender, RoutedEventArgs e) =>
        Copy(ClaudeMcpConnector.BuildCliCommand(_port, _token), "CLI command copied — paste it into a terminal.");

    private void CopyClaudeJsonClick(object sender, RoutedEventArgs e) =>
        Copy(ClaudeJsonBox.Text, "Claude Code JSON copied.");

    private void CopyCodexTomlClick(object sender, RoutedEventArgs e) =>
        Copy(CodexTomlBox.Text, "Codex TOML copied.");

    private void CopyGenericClick(object sender, RoutedEventArgs e) =>
        Copy(GenericBox.Text, "Config copied.");

    private void Copy(string text, string ok)
    {
        try { Clipboard.SetText(text); StatusText.Text = ok + "  Restart your agent to apply."; }
        catch (Exception ex) { StatusText.Text = "Couldn't copy to the clipboard: " + ex.Message; }
    }

    private void CloseClick(object sender, RoutedEventArgs e) => Close();
}
