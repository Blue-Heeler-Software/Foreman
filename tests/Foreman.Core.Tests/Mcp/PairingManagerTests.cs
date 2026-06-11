using Foreman.Core.Mcp;

namespace Foreman.Core.Tests.Mcp;

public sealed class PairingManagerTests
{
    private const string Ext = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

    // A controllable clock so TTL/expiry is deterministic.
    private sealed class Clock { public DateTimeOffset Now = DateTimeOffset.UnixEpoch; }

    private static (PairingManager mgr, Clock clock) New(TimeSpan? ttl = null)
    {
        var c = new Clock();
        return (new PairingManager(() => c.Now, ttl ?? TimeSpan.FromMinutes(2)), c);
    }

    [Fact]
    public void HappyPath_CorrectResponse_Pairs()
    {
        var (mgr, _) = New();
        var code = mgr.Begin();
        var challenge = mgr.IssueChallenge()!;
        var response = ChallengeResponse.Respond(code, challenge);   // what the real extension computes

        var result = mgr.Complete(Ext, response);

        Assert.True(result.Ok);
        Assert.Equal(Ext, result.Origin);
        Assert.False(mgr.IsPending);   // single-use: window closes on success
    }

    [Fact]
    public void Begin_ArmsPending_AndCodeIsTypeable()
    {
        var (mgr, _) = New();
        var code = mgr.Begin();
        Assert.True(mgr.IsPending);
        Assert.Contains('-', code);
        Assert.DoesNotContain('0', code);   // no confusable characters
        Assert.DoesNotContain('O', code);
    }

    [Fact]
    public void IssueChallenge_BeforeBegin_IsNull()
        => Assert.Null(New().mgr.IssueChallenge());

    [Fact]
    public void Complete_WrongResponse_Fails()
    {
        var (mgr, _) = New();
        mgr.Begin();
        mgr.IssueChallenge();
        Assert.False(mgr.Complete(Ext, "wrong").Ok);
    }

    [Fact]
    public void Complete_NonExtensionOrigin_Fails()
    {
        var (mgr, _) = New();
        var code = mgr.Begin();
        var ch = mgr.IssueChallenge()!;
        Assert.False(mgr.Complete("https://evil.com", ChallengeResponse.Respond(code, ch)).Ok);
    }

    [Fact]
    public void Complete_AfterExpiry_Fails()
    {
        var (mgr, clock) = New(TimeSpan.FromMinutes(2));
        var code = mgr.Begin();
        var ch = mgr.IssueChallenge()!;
        clock.Now += TimeSpan.FromMinutes(3);   // past TTL
        Assert.False(mgr.Complete(Ext, ChallengeResponse.Respond(code, ch)).Ok);
        Assert.False(mgr.IsPending);
    }

    [Fact]
    public void StaleChallenge_AfterReissue_Fails()   // replay defence
    {
        var (mgr, _) = New();
        var code = mgr.Begin();
        var first = mgr.IssueChallenge()!;
        var staleResponse = ChallengeResponse.Respond(code, first);
        mgr.IssueChallenge();   // a new nonce supersedes 'first'
        Assert.False(mgr.Complete(Ext, staleResponse).Ok);
    }

    [Fact]
    public void SecondComplete_AfterSuccess_Fails()   // single-use
    {
        var (mgr, _) = New();
        var code = mgr.Begin();
        var ch = mgr.IssueChallenge()!;
        Assert.True(mgr.Complete(Ext, ChallengeResponse.Respond(code, ch)).Ok);
        Assert.False(mgr.Complete(Ext, ChallengeResponse.Respond(code, ch)).Ok);
    }
}
