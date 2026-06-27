using Foreman.Core.Vault;

namespace Foreman.Core.Tests.Vault;

public sealed class VaultReferenceTests
{
    [Fact]
    public void HasReference_DetectsVaultToken()
    {
        Assert.True(VaultReference.HasReference("type {{vault:github.com/password}}"));
        Assert.False(VaultReference.HasReference("type hunter2"));
        Assert.False(VaultReference.HasReference(""));
    }

    [Fact]
    public void Replace_SubstitutesEachReference()
    {
        var outp = VaultReference.Replace(
            "u={{vault:github.com/username}} p={{vault:github.com/password}}",
            (_, f) => f switch { VaultField.Username => "alice", VaultField.Password => "s3cret", _ => null });
        Assert.Equal("u=alice p=s3cret", outp);
    }

    [Fact]
    public void Replace_UnknownField_FailsClosed_ReturnsNull()
        => Assert.Null(VaultReference.Replace("{{vault:github.com/pin}}", (_, _) => "x"));   // 'pin' is not a VaultField

    [Fact]
    public void Replace_ResolverReturnsNull_FailsClosed_ReturnsNull()
        => Assert.Null(VaultReference.Replace("a {{vault:github.com/password}} b", (_, _) => null));

    [Fact]
    public void Replace_NoReference_Passthrough()
        => Assert.Equal("nothing here", VaultReference.Replace("nothing here", (_, _) => "x"));
}
