namespace Foreman.Core.Integration;

/// <summary>One connectable harness: its id/display name plus the delegates to check and (re)write its MCP config.</summary>
public sealed record HarnessConnector(
    string HarnessId,
    string DisplayName,
    Func<int, bool> IsConfigured,
    Func<int, string, ConnectResult> Connect);

/// <summary>The outcome of re-issuing one harness's token.</summary>
public sealed record ReissueResult(string HarnessId, string DisplayName, ConnectStatus Status, string Message);

/// <summary>
/// Registry of the harnesses Foreman can write MCP config for, plus a one-shot "re-issue every configured
/// harness's token" operation — the robust fix when per-harness tokens go stale.
///
/// Per-harness tokens are HMAC'd over the install secret (<c>mcp.token</c>); if that secret is rotated (the file
/// is deleted/regenerated) every previously-written token silently 401s. Each connector's <c>Connect</c> always
/// OVERWRITES its entry with a freshly-minted token, so re-running it for each currently-configured client repairs
/// them all in one click. (T3 Code is intentionally absent — it drives an underlying agent and has no MCP config
/// of its own.)
/// </summary>
public static class HarnessConnectors
{
    public static readonly IReadOnlyList<HarnessConnector> All =
    [
        new("claude-code",    "Claude Code",        p => ClaudeMcpConnector.IsConfigured(p),    (p, t) => ClaudeMcpConnector.Connect(p, t)),
        new("codex",          "Codex CLI",          p => CodexMcpConnector.IsConfigured(p),     (p, t) => CodexMcpConnector.Connect(p, t)),
        new("cursor",         "Cursor",             p => CursorMcpConnector.IsConfigured(p),    (p, t) => CursorMcpConnector.Connect(p, t)),
        new("opencode",       "OpenCode",           p => OpenCodeMcpConnector.IsConfigured(p),  (p, t) => OpenCodeMcpConnector.Connect(p, t)),
        new("github-copilot", "GitHub Copilot CLI", p => CopilotMcpConnector.IsConfigured(p),   (p, t) => CopilotMcpConnector.Connect(p, t)),
        new("gemini-cli",     "Gemini CLI",         p => GeminiMcpConnector.IsConfigured(p),    (p, t) => GeminiMcpConnector.Connect(p, t)),
        new("lm-studio",      "LM Studio",          p => LmStudioMcpConnector.IsConfigured(p),  (p, t) => LmStudioMcpConnector.Connect(p, t)),
    ];

    /// <summary>
    /// For every harness whose config currently points at Foreman, mint a fresh per-harness token and overwrite
    /// its entry — repairing stale tokens. <paramref name="mint"/> is the running server's MintHarnessToken.
    /// Returns one result per re-issued harness (unconfigured ones are skipped). Never throws: a connector whose
    /// probe or write fails is reported as <see cref="ConnectStatus.Failed"/> rather than aborting the batch.
    /// </summary>
    public static IReadOnlyList<ReissueResult> ReissueConfigured(
        int port, Func<string, string> mint, IReadOnlyList<HarnessConnector>? connectors = null)
    {
        var results = new List<ReissueResult>();
        foreach (var c in connectors ?? All)
        {
            bool configured;
            try { configured = c.IsConfigured(port); }
            catch { continue; }                       // can't read its config → leave it alone
            if (!configured) continue;                // not pointed at Foreman → nothing to re-issue

            ConnectResult r;
            try { r = c.Connect(port, mint(c.HarnessId)); }
            catch (Exception ex) { r = new ConnectResult(ConnectStatus.Failed, ex.Message); }
            results.Add(new ReissueResult(c.HarnessId, c.DisplayName, r.Status, r.Message));
        }
        return results;
    }
}
