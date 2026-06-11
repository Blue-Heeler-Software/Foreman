using System.Text.Json;
using Foreman.Core.Ipc;
using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class DecoyAuditPolicyTests
{
    private static readonly string[] Decoys =
        [@"C:\Users\u\.aws\credentials", @"C:\Users\u\.npmrc"];
    private static readonly int[] Excluded = [1000, 1001];   // Foreman app + sidecar

    [Fact]
    public void DecoyReadByForeignProcess_IsADecoyRead() =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.aws\credentials", 4242, Decoys, Excluded));

    [Fact]
    public void ReadByForeman_IsExcluded() =>   // Foreman reads decoys during sentinel re-validation
        Assert.False(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\.aws\credentials", 1000, Decoys, Excluded));

    [Fact]
    public void ReadOfNonDecoyPath_IsNot() =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(@"C:\Users\u\project\readme.md", 4242, Decoys, Excluded));

    [Theory]
    [InlineData(@"c:\users\u\.AWS\Credentials")]        // case-insensitive
    [InlineData(@"\\?\C:\Users\u\.aws\credentials")]    // long-path prefix stripped
    [InlineData(@"C:/Users/u/.aws/credentials")]        // forward separators
    public void PathNormalisationMatches(string objectName) =>
        Assert.True(DecoyAuditPolicy.IsDecoyRead(objectName, 4242, Decoys, Excluded));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void EmptyObjectName_IsNot(string? objectName) =>
        Assert.False(DecoyAuditPolicy.IsDecoyRead(objectName, 4242, Decoys, Excluded));

    // ── Pipe protocol: Kind discriminator + back-compat ─────────────────────

    [Fact]
    public void NetworkRatesMessage_RoundTrips_AsNet()
    {
        var json = JsonSerializer.Serialize(new NetworkRatesMessage { Rates = { [7] = 99.0 } });
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("net", doc.RootElement.GetProperty("Kind").GetString());
        Assert.Equal(99.0, JsonSerializer.Deserialize<NetworkRatesMessage>(json)!.Rates[7]);
    }

    [Fact]
    public void LegacyFrameWithoutKind_DefaultsToNet()
    {
        // An older sidecar emits no Kind field; the app must still treat it as a net frame.
        const string legacy = """{ "TimestampUnixMs": 1, "Rates": { "5": 1.0 } }""";
        Assert.Equal("net", JsonSerializer.Deserialize<NetworkRatesMessage>(legacy)!.Kind);
    }

    [Fact]
    public void DecoyReadMessage_RoundTrips_AsDecoyRead()
    {
        var json = JsonSerializer.Serialize(new DecoyReadMessage { Path = @"C:\x\.aws\credentials", Pid = 42, Image = "node.exe" });
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("decoyRead", doc.RootElement.GetProperty("Kind").GetString());
        var back = JsonSerializer.Deserialize<DecoyReadMessage>(json)!;
        Assert.Equal(42, back.Pid);
        Assert.Equal("node.exe", back.Image);
    }
}
