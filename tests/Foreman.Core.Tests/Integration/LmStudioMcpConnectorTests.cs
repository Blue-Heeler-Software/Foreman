using Foreman.Core.Integration;
using System.Linq;
using System.Text.Json.Nodes;

namespace Foreman.Core.Tests.Integration;

public sealed class LmStudioMcpConnectorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public LmStudioMcpConnectorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-lmstudio-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "mcp.json");
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private JsonObject Read() => (JsonObject)JsonNode.Parse(File.ReadAllText(_path))!;
    private static string[] Args(JsonNode entry) => ((JsonArray)entry["args"]!).Select(a => a!.GetValue<string>()).ToArray();

    [Fact]   // default = the local mcp-remote bridge (works around LM Studio #1892), with the token in an env var
    public void Connect_NoFile_WritesBridgeServer_WithToken()
    {
        var r = LmStudioMcpConnector.Connect(54321, "tok-abc", configPath: _path);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.True(LmStudioMcpConnector.IsConfigured(54321, _path));

        var foreman = Read()["mcpServers"]!["foreman"]!;
        Assert.Equal("npx", foreman["command"]!.GetValue<string>());
        var args = Args(foreman);
        Assert.Contains("mcp-remote", args);
        Assert.Contains("http://localhost:54321/mcp", args);
        Assert.Equal("Bearer tok-abc", foreman["env"]!["AUTH"]!.GetValue<string>());
        Assert.Null(foreman["url"]);   // bridge form: no remote url field
    }

    [Fact]   // explicit remote form (the spec-correct shape for once LM Studio fixes #1892)
    public void Connect_RemoteForm_WhenBridgeDisabled()
    {
        var r = LmStudioMcpConnector.Connect(54321, "tok-abc", useHeaderBridge: false, configPath: _path);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.True(LmStudioMcpConnector.IsConfigured(54321, _path));

        var foreman = Read()["mcpServers"]!["foreman"]!;
        Assert.Equal("http://localhost:54321/mcp", foreman["url"]!.GetValue<string>());
        Assert.Equal("Bearer tok-abc", foreman["headers"]!["Authorization"]!.GetValue<string>());
        Assert.Null(foreman["command"]);
    }

    [Fact]
    public void Connect_PreservesExistingServers()
    {
        File.WriteAllText(_path, """
        {
          "mcpServers": {
            "other": { "url": "https://api.example/mcp" },
            "local-tool": { "command": "node", "args": ["server.js"] }
          }
        }
        """);

        var r = LmStudioMcpConnector.Connect(54321, "tok", configPath: _path);

        Assert.Equal(ConnectStatus.Added, r.Status);
        var servers = Read()["mcpServers"]!;
        Assert.NotNull(servers["other"]);
        Assert.NotNull(servers["local-tool"]);
        Assert.NotNull(servers["foreman"]);
        Assert.True(File.Exists(_path + ".foreman-bak"));
        Assert.False(File.Exists(_path + ".tmp"), "atomic write should leave no temp file");
    }

    [Fact]
    public void Connect_ExistingForemanEntry_Updates()
    {
        LmStudioMcpConnector.Connect(54321, "old", configPath: _path);
        var r = LmStudioMcpConnector.Connect(54321, "new", configPath: _path);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        Assert.Equal("Bearer new", Read()["mcpServers"]!["foreman"]!["env"]!["AUTH"]!.GetValue<string>());
    }

    [Fact]   // the remote-form config also reads as configured (IsConfigured accepts either shape)
    public void IsConfigured_AcceptsRemoteForm()
    {
        LmStudioMcpConnector.Connect(54321, "tok", useHeaderBridge: false, configPath: _path);
        Assert.True(LmStudioMcpConnector.IsConfigured(54321, _path));
        Assert.False(LmStudioMcpConnector.IsConfigured(9999, _path));   // wrong port
    }

    [Fact]
    public void Connect_MalformedExistingFile_FailsSafely_WithoutClobbering()
    {
        File.WriteAllText(_path, "{ not valid json ");
        var r = LmStudioMcpConnector.Connect(54321, "tok", configPath: _path);

        Assert.Equal(ConnectStatus.Failed, r.Status);
        Assert.Equal("{ not valid json ", File.ReadAllText(_path));
    }

    [Fact]
    public void BuildConfigSnippet_IsValidJson_BridgeShape()
    {
        var foreman = ((JsonObject)JsonNode.Parse(LmStudioMcpConnector.BuildConfigSnippet(12345, "tok"))!)["mcpServers"]!["foreman"]!;
        Assert.Equal("npx", foreman["command"]!.GetValue<string>());
        Assert.Contains("http://localhost:12345/mcp", Args(foreman));
    }
}
