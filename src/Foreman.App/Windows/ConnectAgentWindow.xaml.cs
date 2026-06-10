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
    private readonly string _token;          // raw install token (operator/unscoped) — used for the generic path
    private readonly Func<string, string> _mint;   // mints a per-harness (scoped) token
    private readonly Func<IReadOnlyList<McpClientInfo>>? _getClients;

    public ConnectAgentWindow(int port, string token, Func<IReadOnlyList<McpClientInfo>>? getClients,
                              Func<string, string>? mintToken = null)
    {
        _port = port;
        _token = token;
        _mint = mintToken ?? (_ => token);   // fall back to the install token if minting isn't wired
        _getClients = getClients;
        InitializeComponent();
        Populate();
    }

    // Claude Code and Codex get scoped, per-harness tokens so each agent can only see/act on itself.
    private string ClaudeToken => _mint("claude-code");
    private string CodexToken  => _mint("codex");

    private void Populate()
    {
        ClaudeJsonBox.Text = ClaudeMcpConnector.BuildClaudeConfigSnippet(_port, ClaudeToken);
        CodexTomlBox.Text = CodexMcpConnector.BuildConfigSnippet(_port, CodexToken);
        GenericBox.Text =
            $"URL:    {ClaudeMcpConnector.Url(_port)}\r\n" +
            $"Header: Authorization: Bearer {_token}\r\n\r\n" +
            "Server entry (JSON):\r\n" +
            ClaudeMcpConnector.BuildServerEntrySnippet(_port, _token);
        TokenNote.Text =
            "Claude Code and Codex each get their own scoped token (they can only see themselves in Foreman). " +
            "The generic config above uses your full-access install token at %LocalAppData%\\Foreman\\mcp.token — " +
            "keep it private. /health is open; /mcp requires a token.";
        RefreshConnected();
    }

    private void RefreshConnected()
    {
        var clients = _getClients?.Invoke() ?? [];
        ConnectedText.Text = clients.Count == 0
            ? "No agents are connected to Foreman Agent Safety yet. Connect one below, then restart it."
            : "Connected now:\n" + string.Join("\n", clients.Select(c =>
                $"  • {c.Name}{(string.IsNullOrWhiteSpace(c.Version) ? "" : $" v{c.Version}")} — " +
                $"sampling: {(c.Sampling ? "yes" : "no")}"));
    }

    private void ConnectClaudeClick(object sender, RoutedEventArgs e)
    {
        var r = ClaudeMcpConnector.Connect(_port, ClaudeToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Claude Code's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "Foreman Agent Safety — Connect Claude Code", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Claude Code to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "Foreman Agent Safety — Connect Claude Code", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectCodexClick(object sender, RoutedEventArgs e)
    {
        var r = CodexMcpConnector.Connect(_port, CodexToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Codex's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste TOML below instead.",
                "Foreman Agent Safety — Connect Codex", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Codex to connect and load the Foreman Agent Safety instructions." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "Foreman Agent Safety — Connect Codex", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void CopyCliClick(object sender, RoutedEventArgs e) =>
        Copy(ClaudeMcpConnector.BuildCliCommand(_port, ClaudeToken), "CLI command copied — paste it into a terminal.");

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
