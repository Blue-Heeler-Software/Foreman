using Foreman.Core.Mcp;

namespace Foreman.Core.Tests.Mcp;

public sealed class McpInventoryScannerTests
{
    [Fact]
    public void Parses_Http_Stdio_GlobalAndProject_Servers()
    {
        const string json = """
        {
          "mcpServers": {
            "foreman": { "type": "http", "url": "http://localhost:54321/mcp" },
            "fs":       { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:/work"] }
          },
          "projects": {
            "C:\\proj": {
              "mcpServers": {
                "evil": { "url": "https://attacker.example/mcp" }
              }
            }
          }
        }
        """;

        var entries = McpInventoryScanner.ParseClaudeJson(json, "claude-code", "test.json");

        var foreman = entries.Single(e => e.Name == "foreman");
        Assert.Equal("http", foreman.Transport);
        Assert.Equal("http://localhost:54321/mcp", foreman.Target);
        Assert.Equal("global", foreman.Scope);

        var fs = entries.Single(e => e.Name == "fs");
        Assert.Equal("stdio", fs.Transport);
        Assert.Contains("server-filesystem", fs.Target);

        var evil = entries.Single(e => e.Name == "evil");
        Assert.Equal("http", evil.Transport);                 // inferred from url
        Assert.Equal("https://attacker.example/mcp", evil.Target);
        Assert.Equal(@"C:\proj", evil.Scope);                 // project-scoped
    }

    [Fact]
    public void ChangedTarget_ProducesADifferentKey()
    {
        var a = McpInventoryScanner.ParseClaudeJson(
            """{ "mcpServers": { "x": { "url": "http://a" } } }""", "claude-code", "f").Single();
        var b = McpInventoryScanner.ParseClaudeJson(
            """{ "mcpServers": { "x": { "url": "http://b" } } }""", "claude-code", "f").Single();

        Assert.NotEqual(a.Key, b.Key);   // a swapped URL re-alerts as "new"
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("""{ "mcpServers": null }""")]
    [InlineData("""{ "mcpServers": "weird" }""")]
    public void MalformedOrEmpty_ReturnsNoEntries_AndDoesNotThrow(string json)
    {
        Assert.Empty(McpInventoryScanner.ParseClaudeJson(json, "claude-code", "f"));
    }

    [Fact]
    public void Parses_Codex_Toml_HttpAndStdio_Servers()
    {
        const string toml = """
        model = "gpt-5.5"

        [mcp_servers.foreman]
        url = "http://localhost:54321/mcp"
        http_headers = { Authorization = "Bearer TOKEN" }
        enabled = true

        [mcp_servers.playwright]
        command = "npx"
        args = ["@playwright/mcp@latest"]
        enabled = false

        [mcp_servers.playwright.env]
        SHOULD = "not become a server"
        """;

        var entries = McpInventoryScanner.ParseCodexToml(toml, "codex", "config.toml");

        var foreman = entries.Single(e => e.Name == "foreman");
        Assert.Equal("codex", foreman.Harness);
        Assert.Equal("http", foreman.Transport);
        Assert.Equal("http://localhost:54321/mcp", foreman.Target);
        Assert.Equal("global", foreman.Scope);

        var playwright = entries.Single(e => e.Name == "playwright");
        Assert.Equal("stdio", playwright.Transport);
        Assert.Contains("@playwright/mcp", playwright.Target);
        Assert.DoesNotContain(entries, e => e.Name == "env");
    }

    [Fact]
    public void Codex_Toml_PreservesHashInsideQuotedValue()
    {
        // A '#' inside a quoted value must NOT be treated as a comment — otherwise the Target (and the
        // change-detection dedup key) is corrupted and the server re-alerts as "new" forever.
        const string toml = """
        [mcp_servers.frag]
        url = "http://localhost:7000/mcp#section"   # a real trailing comment
        """;

        var entry = McpInventoryScanner.ParseCodexToml(toml, "codex", "config.toml").Single();

        Assert.Equal("http://localhost:7000/mcp#section", entry.Target);
    }

    [Fact]
    public void Codex_Toml_ParsesMultiLineArgsArray()
    {
        // TOML arrays can span lines; the stdio Target must keep its args (the benign-vs-suspicious signal).
        const string toml = """
        [mcp_servers.fs]
        command = "npx"
        args = [
          "-y",
          "@modelcontextprotocol/server-filesystem",
          "C:/work"
        ]
        """;

        var entry = McpInventoryScanner.ParseCodexToml(toml, "codex", "config.toml").Single();

        Assert.Equal("stdio", entry.Transport);
        Assert.Contains("server-filesystem", entry.Target);
        Assert.Contains("-y", entry.Target);
    }

    [Fact]
    public void Codex_Toml_MalformedUnterminatedArray_DoesNotSwallowNextServer()
    {
        // A never-closed array must not eat the following [mcp_servers.*] table.
        const string toml = """
        [mcp_servers.broken]
        args = [
          "-y",

        [mcp_servers.good]
        url = "http://localhost:8080/mcp"
        """;

        var entries = McpInventoryScanner.ParseCodexToml(toml, "codex", "config.toml");

        Assert.Contains(entries, e => e.Name == "good" && e.Target == "http://localhost:8080/mcp");
    }

    [Fact]
    public void DefaultSources_IncludesCodexConfig()
    {
        var sources = McpInventoryScanner.DefaultSources().ToArray();

        Assert.Contains(sources, s => s.Harness == "codex" && s.Path.EndsWith(Path.Combine(".codex", "config.toml")));
    }
}
