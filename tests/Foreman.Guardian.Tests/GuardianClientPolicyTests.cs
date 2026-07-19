using Foreman.Guardian;

namespace Foreman.Guardian.Tests;

public sealed class GuardianClientPolicyTests
{
    private const string ForemanPath = @"C:\Program Files\Foreman\Foreman.exe";

    [Fact]
    public void PublisherMode_AcceptsSamePublisherAcrossPathsAndVersions()
    {
        var result = GuardianClientPolicy.Decide(
            GuardianClientPolicy.PublisherSignedMode,
            ForemanPath, null, "AABB",
            @"D:\Foreman-dev\Foreman.exe", null, "aabb");

        Assert.True(result.Trusted);
    }

    [Fact]
    public void PublisherMode_RejectsUnsignedOrDifferentPublisher()
    {
        Assert.False(GuardianClientPolicy.Decide(
            GuardianClientPolicy.PublisherSignedMode,
            ForemanPath, null, "AABB",
            ForemanPath, null, null).Trusted);
        Assert.False(GuardianClientPolicy.Decide(
            GuardianClientPolicy.PublisherSignedMode,
            ForemanPath, null, "AABB",
            ForemanPath, null, "CCDD").Trusted);
    }

    [Fact]
    public void DevelopmentMode_RequiresBothPinnedPathAndHash()
    {
        Assert.True(GuardianClientPolicy.Decide(
            GuardianClientPolicy.PathHashPinnedMode,
            ForemanPath, "0011", null,
            ForemanPath.ToUpperInvariant(), "0011", null).Trusted);
        Assert.False(GuardianClientPolicy.Decide(
            GuardianClientPolicy.PathHashPinnedMode,
            ForemanPath, "0011", null,
            @"C:\Temp\Foreman.exe", "0011", null).Trusted);
        Assert.False(GuardianClientPolicy.Decide(
            GuardianClientPolicy.PathHashPinnedMode,
            ForemanPath, "0011", null,
            ForemanPath, "2233", null).Trusted);
    }

    [Fact]
    public void UnknownMode_FailsClosed()
        => Assert.False(GuardianClientPolicy.Decide(
            "legacy_allow_all", ForemanPath, null, null, ForemanPath, null, null).Trusted);
}
