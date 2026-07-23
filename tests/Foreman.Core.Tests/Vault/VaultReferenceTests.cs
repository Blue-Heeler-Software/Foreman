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

    [Fact]
    public void SelectedCardReference_ParsesEntryAndField()
    {
        string? seenEntry = null;
        var output = VaultReference.Replace("{{vault:shop.example/abc12345/cardnumber}}", (_, entry, field) =>
        {
            seenEntry = entry;
            return field == VaultField.CardNumber ? "4111111111111111" : null;
        });
        Assert.Equal("abc12345", seenEntry);
        Assert.Equal("4111111111111111", output);
        Assert.True(VaultReference.HasPaymentCardReference("{{vault:shop.example/abc12345/cardnumber}}"));
    }

    [Fact]
    public void TrySignup_DetectsWholeSignupToken()
    {
        Assert.True(VaultReference.TrySignup("{{vault:example.com/signup}}", out var o));
        Assert.Equal("example.com", o);
        Assert.True(VaultReference.TrySignup("  {{vault:Example.com:8443/signup}}  ", out var o2));   // trims + port (origin case preserved)
        Assert.Equal("Example.com:8443", o2);
    }

    [Fact]
    public void TrySignup_RejectsMixedReadOrPartialOrMiscased()
    {
        Assert.False(VaultReference.TrySignup("u {{vault:example.com/signup}}", out _));               // not the whole value
        Assert.False(VaultReference.TrySignup("{{vault:example.com/password}}", out _));               // a read field, not signup
        Assert.False(VaultReference.TrySignup("{{vault:a.com/signup}}{{vault:b.com/signup}}", out _)); // two tokens
        Assert.False(VaultReference.TrySignup("{{vault:example.com/SIGNUP}}", out _));                 // case-sensitive: not 'signup'
        Assert.False(VaultReference.TrySignup("{{VAULT:example.com/signup}}", out _));                 // case-sensitive: not 'vault:'
        Assert.False(VaultReference.TrySignup("", out _));
    }
}
