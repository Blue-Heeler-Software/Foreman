using Foreman.Vault;

namespace Foreman.Vault.Tests;

public sealed class VaultPasswordGeneratorTests
{
    [Fact]
    public void Generate_HasRequestedLength_NoWhitespace_NoAmbiguousChars()
    {
        var p = VaultPasswordGenerator.Generate(24);
        Assert.Equal(24, p.Length);
        Assert.All(p, c => Assert.False(char.IsWhiteSpace(c)));
        Assert.DoesNotContain(p, c => c is '0' or 'O' or '1' or 'l' or 'I');   // excluded ambiguous set
    }

    [Fact]
    public void Generate_IsRandom()
        => Assert.NotEqual(VaultPasswordGenerator.Generate(32), VaultPasswordGenerator.Generate(32));
}
