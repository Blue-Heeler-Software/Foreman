namespace Foreman.Core.Models;

public sealed record HarnessIntegration(
    string HarnessId,
    string DisplayName,
    string DefaultProfileName,
    string[] TrustedHookPathMarkers,
    string[] LauncherSuppressedRuleIds,
    string SetupHint,
    string McpConfigSnippet);

public static class HarnessIntegrationRegistry
{
    public static readonly IReadOnlyList<HarnessIntegration> All =
    [
        new(
            "claude-code",
            "Claude Code",
            "claude-code-default",
            [@".claude\hooks\", ".claude/hooks/"],
            ["win-002"],
            "Run: claude mcp add foreman http://localhost:{port}/mcp",
            """
            {
              "mcpServers": {
                "foreman": {
                  "type": "http",
                  "url": "http://localhost:{port}/mcp"
                }
              }
            }
            """),
        new(
            "codex",
            "Codex CLI",
            "codex-default",
            [],
            [],
            "Add Foreman's HTTP MCP endpoint to ~/.codex/config.toml, or use Foreman's Connect Agent window to write it automatically.",
            """
            [mcp_servers.foreman]
            url = "http://localhost:{port}/mcp"
            http_headers = { Authorization = "Bearer <token>" }
            enabled = true
            """),
        new(
            "t3-code",
            "T3 Code",
            "t3-code-default",
            [],
            [],
            "Add Foreman's MCP endpoint to the underlying agent configured in T3 Code; monitor T3 Code itself as the control plane.",
            """
            {
              "mcpServers": {
                "foreman": {
                  "type": "http",
                  "url": "http://localhost:{port}/mcp"
                }
              }
            }
            """),
        new(
            "opencode",
            "OpenCode",
            "opencode-default",
            [@".opencode\hooks\", ".opencode/hooks/"],
            [],
            "Add Foreman's HTTP MCP endpoint to opencode.json under the mcp object.",
            """
            {
              "$schema": "https://opencode.ai/config.json",
              "mcp": {
                "foreman": {
                  "type": "remote",
                  "url": "http://localhost:{port}/mcp",
                  "enabled": true
                }
              }
            }
            """),
    ];

    public static HarnessIntegration? Get(string harnessId) =>
        All.FirstOrDefault(h => string.Equals(h.HarnessId, harnessId, StringComparison.OrdinalIgnoreCase));

    public static string? GetDefaultProfileName(string harnessId) =>
        Get(harnessId)?.DefaultProfileName;

    public static KnownHarness? GetKnownHarness(string harnessId) =>
        KnownHarnesses.GetById(harnessId);
}
