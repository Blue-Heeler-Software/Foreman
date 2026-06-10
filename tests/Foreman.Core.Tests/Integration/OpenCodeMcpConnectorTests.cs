using Foreman.Core.Integration;
using System.Text.Json.Nodes;

namespace Foreman.Core.Tests.Integration;

public sealed class OpenCodeMcpConnectorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public OpenCodeMcpConnectorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-opencode-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "opencode.json");
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private JsonObject Read() => (JsonObject)JsonNode.Parse(File.ReadAllText(_path))!;

    [Fact]
    public void Connect_NoFile_CreatesConfigWithForemanRemoteEntry()
    {
        var r = OpenCodeMcpConnector.Connect(54321, "tok-abc", _path);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.True(OpenCodeMcpConnector.IsConfigured(54321, _path));

        var foreman = Read()["mcp"]!["foreman"]!;
        Assert.Equal("remote", foreman["type"]!.GetValue<string>());
        Assert.Equal("http://localhost:54321/mcp", foreman["url"]!.GetValue<string>());
        Assert.True(foreman["enabled"]!.GetValue<bool>());
        Assert.Equal("Bearer tok-abc", foreman["headers"]!["Authorization"]!.GetValue<string>());
        Assert.Equal("https://opencode.ai/config.json", Read()["$schema"]!.GetValue<string>());
    }

    [Fact]
    public void Connect_PreservesExistingConfigAndOtherMcpServers()
    {
        File.WriteAllText(_path, """
        {
          "$schema": "https://opencode.ai/config.json",
          "theme": "dark",
          "mcp": {
            "other": { "type": "local", "command": ["foo"] }
          }
        }
        """);

        var r = OpenCodeMcpConnector.Connect(54321, "tok", _path);

        Assert.Equal(ConnectStatus.Added, r.Status);                    // foreman is new
        var root = Read();
        Assert.Equal("dark", root["theme"]!.GetValue<string>());        // unrelated setting preserved
        Assert.NotNull(root["mcp"]!["other"]);                          // sibling MCP server preserved
        Assert.NotNull(root["mcp"]!["foreman"]);                        // foreman added
        Assert.True(File.Exists(_path + ".foreman-bak"));               // original backed up
    }

    [Fact]
    public void Connect_ExistingForemanEntry_Updates()
    {
        OpenCodeMcpConnector.Connect(54321, "old", _path);
        var r = OpenCodeMcpConnector.Connect(54321, "new", _path);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        Assert.Equal("Bearer new", Read()["mcp"]!["foreman"]!["headers"]!["Authorization"]!.GetValue<string>());
    }

    [Fact]
    public void IsConfigured_FalseWhenMissingOrPortMismatch()
    {
        Assert.False(OpenCodeMcpConnector.IsConfigured(54321, _path));   // no file
        OpenCodeMcpConnector.Connect(54321, "t", _path);
        Assert.True(OpenCodeMcpConnector.IsConfigured(54321, _path));
        Assert.False(OpenCodeMcpConnector.IsConfigured(60000, _path));   // different port
    }

    [Fact]
    public void BuildConfigSnippet_IsValidJson_WithMcpForeman()
    {
        var snippet = OpenCodeMcpConnector.BuildConfigSnippet(12345, "tok");
        var root = (JsonObject)JsonNode.Parse(snippet)!;
        Assert.Equal("remote", root["mcp"]!["foreman"]!["type"]!.GetValue<string>());
        Assert.Contains("12345", root["mcp"]!["foreman"]!["url"]!.GetValue<string>());
    }
}
