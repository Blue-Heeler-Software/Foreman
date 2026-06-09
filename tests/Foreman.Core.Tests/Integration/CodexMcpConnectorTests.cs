using Foreman.Core.Integration;

namespace Foreman.Core.Tests.Integration;

public sealed class CodexMcpConnectorTests : IDisposable
{
    private readonly string _dir;
    private readonly string _cfg;

    public CodexMcpConnectorTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-codex-conn-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _cfg = Path.Combine(_dir, "config.toml");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Fact]
    public void Connect_AddsForemanSection_PreservesOtherConfig_AndBacksUp()
    {
        File.WriteAllText(_cfg, """
        model = "gpt-5.5"

        [mcp_servers.figma]
        url = "https://mcp.figma.com/mcp"
        enabled = false
        """);

        var r = CodexMcpConnector.Connect(54321, "TOKEN123", _cfg);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.True(File.Exists(_cfg + ".foreman-bak"));

        var toml = File.ReadAllText(_cfg);
        Assert.Contains("model = \"gpt-5.5\"", toml);
        Assert.Contains("[mcp_servers.figma]", toml);
        Assert.Contains("[mcp_servers.foreman]", toml);
        Assert.Contains("url = \"http://localhost:54321/mcp\"", toml);
        Assert.Contains("Authorization = \"Bearer TOKEN123\"", toml);
        Assert.True(CodexMcpConnector.IsConfigured(54321, _cfg));
    }

    [Fact]
    public void Connect_OnMissingFile_CreatesIt()
    {
        var r = CodexMcpConnector.Connect(54321, "T", _cfg);

        Assert.Equal(ConnectStatus.Added, r.Status);
        Assert.Null(r.BackupPath);
        Assert.True(CodexMcpConnector.IsConfigured(54321, _cfg));
    }

    [Fact]
    public void Connect_Twice_ReportsUpdated_AndReplacesOldToken()
    {
        CodexMcpConnector.Connect(54321, "old", _cfg);

        var r = CodexMcpConnector.Connect(54321, "new", _cfg);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        var toml = File.ReadAllText(_cfg);
        Assert.Contains("Authorization = \"Bearer new\"", toml);
        Assert.DoesNotContain("Bearer old", toml);
    }

    [Fact]
    public void Connect_ReplacesQuotedForemanSection_AndChildTables()
    {
        File.WriteAllText(_cfg, """
        [mcp_servers."foreman"]
        command = "old"

        [mcp_servers.foreman.env]
        X = "Y"

        [mcp_servers.other]
        command = "npx"
        """);

        var r = CodexMcpConnector.Connect(54321, "T", _cfg);

        Assert.Equal(ConnectStatus.Updated, r.Status);
        var toml = File.ReadAllText(_cfg);
        Assert.Contains("[mcp_servers.foreman]", toml);
        Assert.Contains("[mcp_servers.other]", toml);
        Assert.DoesNotContain("[mcp_servers.foreman.env]", toml);
        Assert.DoesNotContain("command = \"old\"", toml);
    }

    [Fact]
    public void IsConfigured_FalseForWrongPortOrNoToken()
    {
        CodexMcpConnector.Connect(54321, "T", _cfg);

        Assert.False(CodexMcpConnector.IsConfigured(9999, _cfg));
        Assert.False(CodexMcpConnector.IsConfigured(54321, Path.Combine(_dir, "missing.toml")));
    }
}
