using Foreman.Core.Integration;
using System.Text.Json.Nodes;

namespace Foreman.Core.Tests.Integration;

public sealed class CopilotMcpConnectorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public CopilotMcpConnectorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-copilot-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "mcp-config.json");
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private JsonObject Read() => (JsonObject)JsonNode.Parse(File.ReadAllText(_path))!;

    [Fact]
    public void Connect_NoFile_WritesHttpServer_WithToolsWildcard()
    {
        var r = CopilotMcpConnector.Connect(54321, "tok-abc", _path);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.True(CopilotMcpConnector.IsConfigured(54321, _path));

        var foreman = Read()["mcpServers"]!["foreman"]!;
        Assert.Equal("http", foreman["type"]!.GetValue<string>());
        Assert.Equal("http://localhost:54321/mcp", foreman["url"]!.GetValue<string>());
        Assert.Equal("Bearer tok-abc", foreman["headers"]!["Authorization"]!.GetValue<string>());
        // tools:["*"] so every Foreman tool is exposed to Copilot CLI.
        Assert.Equal("*", foreman["tools"]!.AsArray()[0]!.GetValue<string>());
    }

    [Fact]
    public void Connect_PreservesExistingServers()
    {
        File.WriteAllText(_path, """
        {
          "mcpServers": {
            "github": { "type": "http", "url": "https://api.githubcopilot.com/mcp/", "headers": { "Authorization": "Bearer x" } },
            "local-tool": { "command": "node", "args": ["server.js"] }
          }
        }
        """);

        var r = CopilotMcpConnector.Connect(54321, "tok", _path);

        Assert.Equal(ConnectStatus.Added, r.Status);
        var servers = Read()["mcpServers"]!;
        Assert.NotNull(servers["github"]);       // other remote server preserved
        Assert.NotNull(servers["local-tool"]);   // stdio server preserved
        Assert.NotNull(servers["foreman"]);       // foreman added
        Assert.True(File.Exists(_path + ".foreman-bak"));
        Assert.False(File.Exists(_path + ".tmp"), "atomic write should leave no temp file");
    }

    [Fact]
    public void Connect_ExistingForemanEntry_Updates()
    {
        CopilotMcpConnector.Connect(54321, "old", _path);
        var r = CopilotMcpConnector.Connect(54321, "new", _path);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        Assert.Equal("Bearer new", Read()["mcpServers"]!["foreman"]!["headers"]!["Authorization"]!.GetValue<string>());
    }

    [Fact]
    public void Connect_MalformedExistingFile_FailsSafely_WithoutClobbering()
    {
        File.WriteAllText(_path, "{ not valid json ");
        var r = CopilotMcpConnector.Connect(54321, "tok", _path);

        Assert.Equal(ConnectStatus.Failed, r.Status);
        Assert.Equal("{ not valid json ", File.ReadAllText(_path));   // original left intact
    }

    [Fact]
    public void BuildConfigSnippet_IsValidJson_HttpShape()
    {
        var root = (JsonObject)JsonNode.Parse(CopilotMcpConnector.BuildConfigSnippet(12345, "tok"))!;
        var foreman = root["mcpServers"]!["foreman"]!;
        Assert.Equal("http", foreman["type"]!.GetValue<string>());
        Assert.Contains("12345", foreman["url"]!.GetValue<string>());
    }
}
