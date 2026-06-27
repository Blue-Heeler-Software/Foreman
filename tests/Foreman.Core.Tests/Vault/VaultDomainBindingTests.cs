using Foreman.Core.Vault;

namespace Foreman.Core.Tests.Vault;

public sealed class VaultDomainBindingTests
{
    private static readonly string[] GitHub = ["github.com"];

    [Fact]
    public void HostMatches_IsCaseAndDotInsensitive()
    {
        Assert.True(VaultDomainBinding.HostMatches("GitHub.com", "github.com."));
        Assert.False(VaultDomainBinding.HostMatches("github.com", "evil.com"));
        Assert.False(VaultDomainBinding.HostMatches("", "github.com"));
    }

    [Fact]
    public void ReleaseAllowed_WhenLiveTargetMatchesItemOrigin()
        => Assert.True(VaultDomainBinding.ReleaseAllowed(GitHub, "github.com", "github.com"));

    [Fact]
    public void ReleaseAllowed_False_WhenLiveTargetDiffers()   // the phishing case: agent points the page at evil.com
        => Assert.False(VaultDomainBinding.ReleaseAllowed(GitHub, "github.com", "evil.com"));

    [Fact]
    public void ReleaseAllowed_False_WhenNoLiveTarget()
        => Assert.False(VaultDomainBinding.ReleaseAllowed(GitHub, "github.com", null));

    [Fact]
    public void ReleaseAllowed_False_WhenItemDoesNotOwnRequestedOrigin()
        => Assert.False(VaultDomainBinding.ReleaseAllowed(GitHub, "gitlab.com", "gitlab.com"));

    [Fact]
    public void ReleaseAllowed_AllowsRegisteredAlias()
    {
        string[] origins = ["github.com", "www.github.com"];
        Assert.True(VaultDomainBinding.ReleaseAllowed(origins, "github.com", "www.github.com"));
    }
}
