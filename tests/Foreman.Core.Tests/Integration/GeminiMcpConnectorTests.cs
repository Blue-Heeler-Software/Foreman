using Foreman.Core.Integration;
using System.Text.Json.Nodes;

namespace Foreman.Core.Tests.Integration;

public sealed class GeminiMcpConnectorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public GeminiMcpConnectorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-gemini-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "settings.json");
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private JsonObject Read() => (JsonObject)JsonNode.Parse(File.ReadAllText(_path))!;

    [Fact]
    public void Connect_NoFile_WritesStreamableHttp_UsingHttpUrl_NotUrl()
    {
        var r = GeminiMcpConnector.Connect(54321, "tok-abc", _path);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.True(GeminiMcpConnector.IsConfigured(54321, _path));

        var foreman = Read()["mcpServers"]!["foreman"]!;
        // Gemini distinguishes transports by field name: httpUrl = streamable HTTP, url = SSE.
        Assert.Equal("http://localhost:54321/mcp", foreman["httpUrl"]!.GetValue<string>());
        Assert.Null(foreman["url"]);   // must NOT use "url" (that would be treated as SSE)
        Assert.Equal("Bearer tok-abc", foreman["headers"]!["Authorization"]!.GetValue<string>());
    }

    [Fact]
    public void Connect_PreservesOtherTopLevelSettings()
    {
        File.WriteAllText(_path, """
        {
          "theme": "Default",
          "selectedAuthType": "oauth-personal",
          "mcpServers": {
            "github": { "httpUrl": "https://api.example/mcp" }
          }
        }
        """);

        var r = GeminiMcpConnector.Connect(54321, "tok", _path);

        Assert.Equal(ConnectStatus.Added, r.Status);
        var root = Read();
        Assert.Equal("Default", root["theme"]!.GetValue<string>());              // unrelated setting preserved
        Assert.Equal("oauth-personal", root["selectedAuthType"]!.GetValue<string>());
        Assert.NotNull(root["mcpServers"]!["github"]);                            // other server preserved
        Assert.NotNull(root["mcpServers"]!["foreman"]);                           // foreman added
        Assert.True(File.Exists(_path + ".foreman-bak"));
        Assert.False(File.Exists(_path + ".tmp"), "atomic write should leave no temp file");
    }

    [Fact]
    public void Connect_ExistingForemanEntry_Updates()
    {
        GeminiMcpConnector.Connect(54321, "old", _path);
        var r = GeminiMcpConnector.Connect(54321, "new", _path);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        Assert.Equal("Bearer new", Read()["mcpServers"]!["foreman"]!["headers"]!["Authorization"]!.GetValue<string>());
    }

    [Fact]
    public void Connect_MalformedExistingFile_FailsSafely_WithoutClobbering()
    {
        File.WriteAllText(_path, "{ not valid json ");
        var r = GeminiMcpConnector.Connect(54321, "tok", _path);

        Assert.Equal(ConnectStatus.Failed, r.Status);
        Assert.Equal("{ not valid json ", File.ReadAllText(_path));   // original left intact
    }

    [Fact]
    public void BuildConfigSnippet_IsValidJson_HttpUrlShape()
    {
        var root = (JsonObject)JsonNode.Parse(GeminiMcpConnector.BuildConfigSnippet(12345, "tok"))!;
        var foreman = root["mcpServers"]!["foreman"]!;
        Assert.Contains("12345", foreman["httpUrl"]!.GetValue<string>());
        Assert.Null(foreman["url"]);
    }
}
