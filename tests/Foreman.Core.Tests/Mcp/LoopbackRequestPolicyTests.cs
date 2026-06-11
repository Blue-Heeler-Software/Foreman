using Foreman.Core.Mcp;

namespace Foreman.Core.Tests.Mcp;

public sealed class LoopbackRequestPolicyTests
{
    private static readonly string[] None = [];
    private const string Ext = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

    [Theory]
    [InlineData("localhost:54321", true)]
    [InlineData("127.0.0.1:54321", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.0.0.5", true)]            // 127.0.0.0/8 is all loopback
    [InlineData("[::1]:54321", true)]
    [InlineData("[::1]", true)]
    [InlineData("LOCALHOST:54321", true)]      // case-insensitive
    [InlineData("evil.com", false)]
    [InlineData("evil.com:54321", false)]      // DNS-rebound hostname
    [InlineData("192.168.1.5:54321", false)]   // LAN, not loopback
    [InlineData("0.0.0.0:54321", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsLoopbackHost(string? host, bool expected)
        => Assert.Equal(expected, LoopbackRequestPolicy.IsLoopbackHost(host));

    [Fact]
    public void Evaluate_LoopbackHost_NoOrigin_Allowed()
        => Assert.True(LoopbackRequestPolicy.Evaluate("localhost:54321", "", None).Allowed);

    [Fact]
    public void Evaluate_LoopbackHost_LoopbackOrigin_Allowed()
        => Assert.True(LoopbackRequestPolicy.Evaluate("localhost:54321", "http://localhost:54321", None).Allowed);

    [Fact]
    public void Evaluate_ForeignOrigin_Denied()   // a drive-by cross-origin browser POST
        => Assert.False(LoopbackRequestPolicy.Evaluate("localhost:54321", "https://evil.com", None).Allowed);

    [Fact]
    public void Evaluate_NonLoopbackHost_Denied()   // the DNS-rebinding case
    {
        var v = LoopbackRequestPolicy.Evaluate("evil.com", "", None);
        Assert.False(v.Allowed);
        Assert.Contains("rebinding", v.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Evaluate_PairedExtensionOrigin_Allowed()
        => Assert.True(LoopbackRequestPolicy.Evaluate("localhost:54321", Ext, [Ext]).Allowed);

    [Fact]
    public void Evaluate_UnpairedExtensionOrigin_Denied()
        => Assert.False(LoopbackRequestPolicy.Evaluate(
            "localhost:54321", "chrome-extension://someotherunpairedextensionidhere00", [Ext]).Allowed);

    [Fact]
    public void Evaluate_NonLoopbackHost_BeatsAGoodOrigin()   // Host check is unconditional
        => Assert.False(LoopbackRequestPolicy.Evaluate("evil.com", "http://localhost:54321", None).Allowed);
}
