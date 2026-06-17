namespace Foreman.Core.Mcp;

/// <summary>
/// Heuristic classifier that flags the two highest-risk MCP capability classes an agent can be wired with:
/// <b>computer use</b> (control of mouse/keyboard/screen) and <b>browser use</b> (driving a real browser).
/// Matching is on the configured server name + target (best-effort, name-based — it can over-flag, so the
/// dashboard always names the matched server in its tooltip rather than just asserting the capability).
/// </summary>
public static class McpCapabilityClassifier
{
    // Computer-use: desktop/screen control. Kept tight to avoid false "this agent can drive your machine".
    private static readonly string[] ComputerUse =
    [
        "computer-use", "computer_use", "computeruse", "computer-control", "desktop-control",
        "cua", "scrapybara", "anthropic-computer",
    ];

    // Browser automation: anything that can drive a real browser session.
    private static readonly string[] BrowserUse =
    [
        "playwright", "puppeteer", "selenium", "webdriver", "browsermcp", "browser-use",
        "browserbase", "browserless", "chrome-devtools", "claude-in-chrome", "browser",
    ];

    public static bool IsComputerUse(McpServerEntry entry) => Matches(entry, ComputerUse);
    public static bool IsBrowserUse(McpServerEntry entry) => Matches(entry, BrowserUse);

    private static bool Matches(McpServerEntry entry, string[] needles)
    {
        var hay = ((entry.Name ?? "") + " " + (entry.Target ?? "")).ToLowerInvariant();
        foreach (var n in needles)
            if (hay.Contains(n, StringComparison.Ordinal)) return true;
        return false;
    }
}
