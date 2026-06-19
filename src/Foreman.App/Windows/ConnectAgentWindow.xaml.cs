using Foreman.Core.Events;
using Foreman.Core.Integration;
using Foreman.Core.Models;
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
    private readonly Func<string>? _beginPairing;   // begins extension pairing, returns the on-screen code
    private readonly Func<IReadOnlyCollection<string>>? _getRunningHarnessIds;   // harness ids Foreman sees running now
    private readonly Func<bool>? _isLiveWeaveConnected;   // true when the LiveWeave extension has checked in recently

    public ConnectAgentWindow(int port, string token, Func<IReadOnlyList<McpClientInfo>>? getClients,
                              Func<string, string>? mintToken = null, Func<string>? beginPairing = null,
                              Func<IReadOnlyCollection<string>>? getRunningHarnessIds = null,
                              Func<bool>? isLiveWeaveConnected = null)
    {
        _port = port;
        _token = token;
        _mint = mintToken ?? (_ => token);   // fall back to the install token if minting isn't wired
        _getClients = getClients;
        _beginPairing = beginPairing;
        _getRunningHarnessIds = getRunningHarnessIds;
        _isLiveWeaveConnected = isLiveWeaveConnected;
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

        RefreshLiveWeaveStatus();
    }

    private void RefreshLiveWeaveStatus()
    {
        if (LiveWeaveStatusText is null) return;
        var connected = _isLiveWeaveConnected?.Invoke() ?? false;
        LiveWeaveStatusText.Text = connected
            ? "● Connected — the LiveWeave builder is linked. Only the selected driver harness or operator token can drive it."
            : "○ Not connected — pair below, then choose LiveWeave mode in the browser extension options.";
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
                $"{r.Message}\n\nStart Codex in a NEW terminal to connect and load the Foreman Agent Safety " +
                "instructions (Codex reads the bearer token from the environment variable at launch)." +
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

    private void PairExtensionClick(object sender, RoutedEventArgs e) =>
        BeginPairingFlow(
            title: "Foreman Agent Safety — Pair browser extension",
            extraInstructions:
                "In the Foreman browser extension, open its Options page and paste this code within 2 minutes. " +
                "The code never leaves your machine — the extension proves it holds the code over a loopback " +
                "challenge/response.\n\n" +
                "The same code works for both the Foreman safety extension and LiveWeave — each declares which " +
                "harness it is when it pairs.");

    private void PairLiveWeaveClick(object sender, RoutedEventArgs e) =>
        BeginPairingFlow(
            title: "Foreman Agent Safety — Pair LiveWeave extension",
            extraInstructions:
                "Open the Foreman browser extension options, choose LiveWeave local page builder mode, set a driver " +
                "harness such as codex or claude-code, and enter this code within 2 minutes. The code never leaves " +
                "your machine; LiveWeave proves it holds the code over a loopback challenge/response.\n\n" +
                "Once linked, only the selected driver harness, or the operator token, can drive LiveWeave. " +
                "Empty driver means operator-only; 'any' is an explicit all-harness mode.",
            onPaired: RefreshLiveWeaveStatus);

    // Shared pairing entry point: mint an on-screen code, copy it, and explain where to type it. The pairing code
    // is harness-agnostic — the extension (safety or LiveWeave) declares its harnessId during /pair/complete — so
    // both "Pair…" buttons funnel through here with only the on-screen copy differing.
    private void BeginPairingFlow(string title, string extraInstructions, Action? onPaired = null)
    {
        if (_beginPairing is null)
        {
            MessageBox.Show(
                "Pairing isn't available yet — the MCP server is still starting. Try again in a moment.",
                title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var code = _beginPairing();
        var copied = false;
        try { Clipboard.SetText(code); copied = true; } catch { /* clipboard busy — code is still shown below */ }
        StatusText.Text = copied
            ? $"Pairing code {code} copied — enter it in the extension's Options page within 2 minutes."
            : $"Pairing code: {code} — enter it in the extension's Options page within 2 minutes.";
        MessageBox.Show(
            $"Pairing code:\n\n        {code}\n\n" +
            (copied ? "(Copied to your clipboard.) " : "") +
            extraInstructions,
            title, MessageBoxButton.OK, MessageBoxImage.Information);
        onPaired?.Invoke();
    }

    // One-click "connect everything": writes (or refreshes) the Foreman MCP entry — with a fresh scoped token —
    // for every agent Foreman sees running, that's already configured here, or that's installed on disk. This both
    // connects not-yet-wired agents AND repairs stale tokens on the configured ones (robust against a rotated
    // install secret, which silently 401s every saved token), in a single pass. Agents that are none of
    // running/configured/installed are left untouched, so Foreman never litters config for tools you don't use.
    // Logged via the bus so it lands in the event log / OS event log. Foreman writes the config; each agent opens
    // the MCP session on its NEXT start/restart — there's no way to force a running client to dial in.
    private void ConnectAllClick(object sender, RoutedEventArgs e)
    {
        var running = _getRunningHarnessIds?.Invoke();
        var results = HarnessConnectors.ConnectDetectedAndInstalled(_port, _mint, running);
        if (results.Count == 0)
        {
            MessageBox.Show(
                "No running, configured, or installed agents were found to connect. Connect one using a card below.",
                "Foreman Agent Safety — Connect all agents", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var ok = results.Where(r => r.Status != ConnectStatus.Failed).ToArray();
        var failed = results.Where(r => r.Status == ConnectStatus.Failed).ToArray();

        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Connect.All",
            $"Connect-all wrote Foreman MCP config for {ok.Length}/{results.Count} agent(s): {string.Join(", ", results.Select(r => r.HarnessId))}."));

        var msg = (ok.Length > 0
                ? $"Wrote Foreman config for: {string.Join(", ", ok.Select(r => r.DisplayName))}.\n\n" +
                  "Restart those agents (or refresh their MCP server) to connect — Foreman can't open the session for them."
                : "")
            + (failed.Length > 0
                ? $"\n\nCouldn't update: {string.Join("; ", failed.Select(f => $"{f.DisplayName} ({f.Message})"))}"
                : "");
        MessageBox.Show(msg.Trim(),
            "Foreman Agent Safety — Connect all agents",
            MessageBoxButton.OK,
            failed.Length > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
        RefreshConnected();
    }

    private void CloseClick(object sender, RoutedEventArgs e) => Close();
}
