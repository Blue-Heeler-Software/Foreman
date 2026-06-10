using Foreman.Core.Integration;
using System.Text.Json.Nodes;

namespace Foreman.Core.Tests.Integration;

public sealed class CursorMcpConnectorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public CursorMcpConnectorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-cursor-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "mcp.json");
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private JsonObject Read() => (JsonObject)JsonNode.Parse(File.ReadAllText(_path))!;

    [Fact]
    public void Connect_NoFile_WritesRemoteServer_NoTypeField()
    {
        var r = CursorMcpConnector.Connect(54321, "tok-abc", _path);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.True(CursorMcpConnector.IsConfigured(54321, _path));

        var foreman = Read()["mcpServers"]!["foreman"]!;
        Assert.Equal("http://localhost:54321/mcp", foreman["url"]!.GetValue<string>());
        Assert.Equal("Bearer tok-abc", foreman["headers"]!["Authorization"]!.GetValue<string>());
        // Cursor remote servers must NOT carry a "type" field (that's stdio-only) — a wrong field can break it.
        Assert.Null(foreman["type"]);
    }

    [Fact]
    public void Connect_PreservesExistingServersAndSettings()
    {
        File.WriteAllText(_path, """
        {
          "mcpServers": {
            "github": { "url": "https://api.example/mcp" },
            "local-tool": { "command": "node", "args": ["server.js"] }
          }
        }
        """);

        var r = CursorMcpConnector.Connect(54321, "tok", _path);

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
        CursorMcpConnector.Connect(54321, "old", _path);
        var r = CursorMcpConnector.Connect(54321, "new", _path);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        Assert.Equal("Bearer new", Read()["mcpServers"]!["foreman"]!["headers"]!["Authorization"]!.GetValue<string>());
    }

    [Fact]
    public void Connect_MalformedExistingFile_FailsSafely_WithoutClobbering()
    {
        File.WriteAllText(_path, "{ not valid json ");
        var r = CursorMcpConnector.Connect(54321, "tok", _path);

        Assert.Equal(ConnectStatus.Failed, r.Status);
        Assert.Equal("{ not valid json ", File.ReadAllText(_path));   // original left intact
    }

    [Fact]
    public void BuildConfigSnippet_IsValidJson_RemoteShape()
    {
        var root = (JsonObject)JsonNode.Parse(CursorMcpConnector.BuildConfigSnippet(12345, "tok"))!;
        var foreman = root["mcpServers"]!["foreman"]!;
        Assert.Contains("12345", foreman["url"]!.GetValue<string>());
        Assert.Null(foreman["type"]);
    }
}
