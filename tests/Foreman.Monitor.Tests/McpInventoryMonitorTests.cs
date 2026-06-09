using Foreman.Core.Mcp;
using Foreman.Monitor;

namespace Foreman.Monitor.Tests;

public sealed class McpInventoryMonitorTests
{
    [Theory]
    [InlineData("http://localhost:54321/mcp")]
    [InlineData("http://127.0.0.1:54321/mcp")]
    [InlineData("http://[::1]:54321/mcp")]
    [InlineData("http://localhost:54321/mcp/")]
    public void ForemanLoopbackMcpServer_IsSelfServer(string target)
    {
        var entry = new McpServerEntry("codex", "foreman", "http", target, "global", "config.toml");

        Assert.True(McpInventoryMonitor.IsForemanSelfServer(entry, 54321));
    }

    [Theory]
    [InlineData("other", "http", "http://localhost:54321/mcp")]
    [InlineData("foreman", "stdio", "node foreman-mcp.js")]
    [InlineData("foreman", "http", "https://example.com/mcp")]
    [InlineData("foreman", "http", "http://localhost:54321/other")]
    [InlineData("foreman", "http", "not-a-url")]
    [InlineData("foreman", "http", "http://localhost:9999/mcp")]   // right name, WRONG port → not self
    public void NonForemanOrRemoteServers_AreNotSelfServer(string name, string transport, string target)
    {
        var entry = new McpServerEntry("codex", name, transport, target, "global", "config.toml");

        Assert.False(McpInventoryMonitor.IsForemanSelfServer(entry, 54321));
    }
}
