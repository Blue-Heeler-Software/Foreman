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

    // Each agent gets a scoped, per-harness token so it can only see/act on itself.
    private string ClaudeToken   => _mint("claude-code");
    private string CodexToken    => _mint("codex");
    private string CursorToken   => _mint("cursor");
    private string OpenCodeToken => _mint("opencode");
    private string CopilotToken  => _mint("github-copilot");
    private string GeminiToken   => _mint("gemini-cli");
    private string LmStudioToken => _mint("lm-studio");
    private string T3Token       => _mint("t3-code");

    private void Populate()
    {
        ClaudeJsonBox.Text = ClaudeMcpConnector.BuildClaudeConfigSnippet(_port, ClaudeToken);
        CodexTomlBox.Text = CodexMcpConnector.BuildConfigSnippet(_port, CodexToken);
        CursorJsonBox.Text = CursorMcpConnector.BuildConfigSnippet(_port, CursorToken);
        OpenCodeJsonBox.Text = OpenCodeMcpConnector.BuildConfigSnippet(_port, OpenCodeToken);
        CopilotJsonBox.Text = CopilotMcpConnector.BuildConfigSnippet(_port, CopilotToken);
        GeminiJsonBox.Text = GeminiMcpConnector.BuildConfigSnippet(_port, GeminiToken);
        LmStudioJsonBox.Text = LmStudioMcpConnector.BuildConfigSnippet(_port, LmStudioToken);
        T3Box.Text = ClaudeMcpConnector.BuildClaudeConfigSnippet(_port, T3Token);   // T3 uses the underlying agent's mcpServers shape
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

    private void ConnectCursorClick(object sender, RoutedEventArgs e)
    {
        var r = CursorMcpConnector.Connect(_port, CursorToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Cursor's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "Foreman Agent Safety — Connect Cursor", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Cursor, or refresh the \"foreman\" server in Settings → Tools & MCP, to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "Foreman Agent Safety — Connect Cursor", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectOpenCodeClick(object sender, RoutedEventArgs e)
    {
        var r = OpenCodeMcpConnector.Connect(_port, OpenCodeToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update OpenCode's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "Foreman Agent Safety — Connect OpenCode", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart OpenCode to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "Foreman Agent Safety — Connect OpenCode", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectCopilotClick(object sender, RoutedEventArgs e)
    {
        var r = CopilotMcpConnector.Connect(_port, CopilotToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update GitHub Copilot CLI's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "Foreman Agent Safety — Connect Copilot CLI", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Copilot CLI (or run /mcp) to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "Foreman Agent Safety — Connect Copilot CLI", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectGeminiClick(object sender, RoutedEventArgs e)
    {
        var r = GeminiMcpConnector.Connect(_port, GeminiToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Gemini CLI's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "Foreman Agent Safety — Connect Gemini CLI", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Gemini CLI to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "Foreman Agent Safety — Connect Gemini CLI", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectLmStudioClick(object sender, RoutedEventArgs e)
    {
        var r = LmStudioMcpConnector.Connect(_port, LmStudioToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update LM Studio's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "Foreman Agent Safety — Connect LM Studio", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nLM Studio reloads mcp.json automatically. Caveat emptor: if LM Studio ignores " +
                "the Authorization header, Foreman will reject the connection — check LM Studio's MCP panel." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "Foreman Agent Safety — Connect LM Studio", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectT3Click(object sender, RoutedEventArgs e)
    {
        // T3 Code is a control plane — it has no MCP config of its own; you point its underlying agent at
        // Foreman. So "connect automatically" copies the config + explains, rather than writing a file blind.
        Copy(T3Box.Text, "T3 Code config copied.");
        MessageBox.Show(
            "T3 Code runs an underlying agent (Claude Code, Codex, or OpenCode) and doesn't have its own MCP " +
            "config file. Connect that agent using its card above — T3 Code will use the same Foreman MCP " +
            "server, and Foreman monitors T3 Code itself as the control plane.\n\n" +
            "The config has been copied to your clipboard for whichever agent T3 Code drives.",
            "Foreman Agent Safety — Connect T3 Code", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void CopyCliClick(object sender, RoutedEventArgs e) =>
        Copy(ClaudeMcpConnector.BuildCliCommand(_port, ClaudeToken), "CLI command copied — paste it into a terminal.");

    private void CopyCursorJsonClick(object sender, RoutedEventArgs e) =>
        Copy(CursorJsonBox.Text, "Cursor JSON copied.");

    private void CopyOpenCodeJsonClick(object sender, RoutedEventArgs e) =>
        Copy(OpenCodeJsonBox.Text, "OpenCode JSON copied.");

    private void CopyCopilotJsonClick(object sender, RoutedEventArgs e) =>
        Copy(CopilotJsonBox.Text, "Copilot CLI JSON copied.");

    private void CopyGeminiJsonClick(object sender, RoutedEventArgs e) =>
        Copy(GeminiJsonBox.Text, "Gemini CLI JSON copied.");

    private void CopyLmStudioJsonClick(object sender, RoutedEventArgs e) =>
        Copy(LmStudioJsonBox.Text, "LM Studio JSON copied.");

    private void CopyT3Click(object sender, RoutedEventArgs e) =>
        Copy(T3Box.Text, "T3 Code config copied.");

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
