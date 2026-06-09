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

    private static McpServerEntry Srv(string name, string source) =>
        new("codex", name, "stdio", $"cmd-{name}", "global", source);

    [Fact]
    public void ClassifyNewServers_FirstRun_BaselinesEverythingSilently()
    {
        var keys = new HashSet<string>();
        var sources = new HashSet<string>();

        var newOnes = McpInventoryMonitor.ClassifyNewServers(
            [Srv("a", "X"), Srv("b", "X")], keys, sources, firstRun: true);

        Assert.Empty(newOnes);
        Assert.Contains("X", sources);
        Assert.Equal(2, keys.Count);
    }

    [Fact]
    public void ClassifyNewServers_NewServerInKnownSource_Alerts()
    {
        var keys = new HashSet<string>();
        var sources = new HashSet<string>();
        McpInventoryMonitor.ClassifyNewServers([Srv("a", "X")], keys, sources, firstRun: true);

        var newOnes = McpInventoryMonitor.ClassifyNewServers(
            [Srv("a", "X"), Srv("b", "X")], keys, sources, firstRun: false);

        Assert.Single(newOnes);
        Assert.Equal("b", newOnes[0].Name);
    }

    [Fact]
    public void ClassifyNewServers_FirstSightOfNewSource_IsSilent()
    {
        var keys = new HashSet<string>();
        var sources = new HashSet<string>();
        McpInventoryMonitor.ClassifyNewServers([Srv("a", "X")], keys, sources, firstRun: true);

        // A brand-new source Y appears later, not on first run. Its servers should not flood as "new".
        var newOnes = McpInventoryMonitor.ClassifyNewServers(
            [Srv("a", "X"), Srv("c", "Y")], keys, sources, firstRun: false);

        Assert.Empty(newOnes);
        Assert.Contains("Y", sources);

        var later = McpInventoryMonitor.ClassifyNewServers(
            [Srv("a", "X"), Srv("c", "Y"), Srv("d", "Y")], keys, sources, firstRun: false);
        Assert.Single(later);
        Assert.Equal("d", later[0].Name);
    }
}
