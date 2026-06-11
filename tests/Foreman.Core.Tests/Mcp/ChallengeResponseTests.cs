using Foreman.Core.Mcp;

namespace Foreman.Core.Tests.Mcp;

public sealed class ChallengeResponseTests
{
    [Fact]
    public void Respond_Then_Verify_RoundTrips()
    {
        var challenge = ChallengeResponse.NewChallenge();
        var response = ChallengeResponse.Respond("pairing-key", challenge);
        Assert.True(ChallengeResponse.Verify("pairing-key", challenge, response));
    }

    [Fact]
    public void Verify_WrongKey_Fails()
    {
        var challenge = ChallengeResponse.NewChallenge();
        var response = ChallengeResponse.Respond("real-key", challenge);
        Assert.False(ChallengeResponse.Verify("attacker-key", challenge, response));
    }

    [Fact]
    public void Verify_WrongChallenge_Fails()   // defeats replay of an old response against a new nonce
    {
        var response = ChallengeResponse.Respond("k", ChallengeResponse.NewChallenge());
        Assert.False(ChallengeResponse.Verify("k", ChallengeResponse.NewChallenge(), response));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("deadbeef")]                 // wrong value/length
    public void Verify_BadResponse_Fails(string? response)
        => Assert.False(ChallengeResponse.Verify("k", "ABCD", response));

    [Fact]
    public void NewChallenge_IsUnique_AndFullLength()
    {
        var a = ChallengeResponse.NewChallenge();
        var b = ChallengeResponse.NewChallenge();
        Assert.NotEqual(a, b);
        Assert.Equal(64, a.Length);   // 32 random bytes, hex
    }
}
