using Foreman.App.Windows;
using Foreman.McpServer;
using System.IO;
using System.Windows;

namespace Foreman.App;

/// <summary>
/// On first launch, points users at the agent connection guide.
/// </summary>
public static class FirstRunDetector
{
    private static readonly string _flagPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Foreman", "first-run-complete.flag");

    public static void RunIfNeeded(
        int mcpPort,
        string mcpToken,
        Func<IReadOnlyList<McpClientInfo>>? getClients = null,
        Func<string, string>? mintToken = null)
    {
        if (File.Exists(_flagPath)) return;

        Directory.CreateDirectory(Path.GetDirectoryName(_flagPath)!);
        File.WriteAllText(_flagPath, DateTime.UtcNow.ToString("O"));

        var choice = MessageBox.Show(
            $"""
            Welcome to Foreman Agent Safety - a local safety monitor for AI coding agents.

            Foreman Agent Safety's MCP server is running on port {mcpPort}.

            Open the Connect Agent guide now?

            It can configure Claude Code and Codex automatically, and it shows
            copy-paste settings for other MCP-capable agents.
            """,
            "Foreman Agent Safety - First Run", MessageBoxButton.YesNo, MessageBoxImage.Question);

        if (choice == MessageBoxResult.Yes)
        {
            var connect = new ConnectAgentWindow(mcpPort, mcpToken, getClients, mintToken);
            WindowActivation.Surface(connect);
            return;
        }

        MessageBox.Show(
            $"""
            You can connect an agent later from the Foreman Agent Safety tray menu or dashboard.

            MCP URL:
              http://localhost:{mcpPort}/mcp

            The /mcp endpoint needs the bearer token in:
              %LocalAppData%\Foreman\mcp.token
            """,
            "Foreman Agent Safety - Connect Agent", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
