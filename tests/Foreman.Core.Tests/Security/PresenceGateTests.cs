using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class PresenceGateTests
{
    // A fake authenticator: scripted result, records how many times it was prompted.
    private sealed class FakeVerifier(PresenceResult? result = null, Exception? throws = null) : IPresenceVerifier
    {
        public int VerifyCalls { get; private set; }
        public bool IsAvailable => true;
        public Task<EnrollResult> EnrollAsync(string reason, CancellationToken ct = default) =>
            Task.FromResult(EnrollResult.Success("cred-1", "Fake"));
        public Task<PresenceResult> VerifyAsync(string credentialId, string reason, CancellationToken ct = default)
        {
            VerifyCalls++;
            if (throws is not null) throw throws;
            return Task.FromResult(result ?? PresenceResult.Ok("Fake"));
        }
    }

    private static PresenceLockSettings On(LockScope scope = LockScope.Standard, int ttl = 0) =>
        new() { Enabled = true, Scope = scope, ApprovalTtlSeconds = ttl, CredentialId = "cred-1" };

    private static (PresenceGate gate, List<PresenceDecision> log, FakeVerifier v) Make(
        PresenceLockSettings settings, PresenceResult? result = null, Exception? throws = null, Func<DateTimeOffset>? now = null)
    {
        var log = new List<PresenceDecision>();
        var v = new FakeVerifier(result, throws);
        var gate = new PresenceGate(() => settings, v, log.Add, now);
        return (gate, log, v);
    }

    [Fact]
    public async Task LockOff_Proceeds_WithoutPrompting()
    {
        var (gate, log, v) = Make(new PresenceLockSettings { Enabled = false });
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "trust 4→2"));
        Assert.Equal(0, v.VerifyCalls);   // never touched the authenticator
        Assert.Empty(log);                // not a gated decision → nothing to record
    }

    [Fact]
    public async Task GatedAction_VerifiedTap_Proceeds_AndLogsGranted()
    {
        var (gate, log, v) = Make(On(), PresenceResult.Ok("Windows Hello"));
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.DisableReadAuditing, "read-auditing on→off"));
        Assert.Equal(1, v.VerifyCalls);
        Assert.True(log.Single().Granted);
        Assert.Equal("Windows Hello", log.Single().AuthenticatorLabel);
    }

    [Fact]
    public async Task GatedAction_UserCancels_IsBlocked_FailClosed()
    {
        var (gate, log, _) = Make(On(), PresenceResult.Fail("user canceled"));
        Assert.False(await gate.AuthorizeAsync(WeakeningAction.DisableLogPersist, "persist on→off"));
        Assert.False(log.Single().Granted);
        Assert.Contains("user canceled", log.Single().Detail);
    }

    [Fact]
    public async Task GatedAction_VerifierThrows_IsBlocked_FailClosed()
    {
        var (gate, log, _) = Make(On(), throws: new InvalidOperationException("hello.dll boom"));
        Assert.False(await gate.AuthorizeAsync(WeakeningAction.MuteProtectedAlert, "mute cred-decoy-read"));
        Assert.False(log.Single().Granted);   // an error must never be read as "allowed"
    }

    [Fact]
    public async Task LockOn_ButNothingEnrolled_IsBlocked_FailClosed()
    {
        var s = On();
        s.CredentialId = null;   // misconfig: enabled without an enrolled authenticator
        var (gate, log, v) = Make(s);
        Assert.False(await gate.AuthorizeAsync(WeakeningAction.DisableMonitoring, "disable claude-code"));
        Assert.Equal(0, v.VerifyCalls);       // can't prompt — but must NOT silently pass
        Assert.False(log.Single().Granted);
    }

    [Fact]
    public async Task ExitUnderStandard_NotGated_Proceeds()  // policy: Exit gated only under Strict
    {
        var (gate, _, v) = Make(On(LockScope.Standard));
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.ExitForeman, "quit"));
        Assert.Equal(0, v.VerifyCalls);
    }

    [Fact]
    public async Task ExitUnderStrict_IsGated()
    {
        var (gate, _, v) = Make(On(LockScope.Strict), PresenceResult.Ok("key"));
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.ExitForeman, "quit"));
        Assert.Equal(1, v.VerifyCalls);       // Strict prompts on Exit
    }

    [Fact]
    public async Task ApprovalTtl_CachesRecentTap_SkipsSecondPrompt()
    {
        var t = DateTimeOffset.UnixEpoch;
        var s = On(ttl: 60);
        var (gate, log, v) = Make(s, PresenceResult.Ok("Hello"), now: () => t);

        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "first"));   // prompts
        t = t.AddSeconds(30);                                                          // within TTL
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.DisableReadAuditing, "second"));
        Assert.Equal(1, v.VerifyCalls);                                                // second used the cached approval
        Assert.True(log[1].Granted);
        Assert.Contains("within approval window", log[1].Detail);
    }

    [Fact]
    public async Task ApprovalTtl_Expired_PromptsAgain()
    {
        var t = DateTimeOffset.UnixEpoch;
        var s = On(ttl: 60);
        var (gate, _, v) = Make(s, PresenceResult.Ok("Hello"), now: () => t);

        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "first"));
        t = t.AddSeconds(90);                                                          // past TTL
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "second"));
        Assert.Equal(2, v.VerifyCalls);                                                // re-prompted
    }

    [Fact]
    public async Task DeniedTap_DoesNotPrimeTheApprovalCache()
    {
        var t = DateTimeOffset.UnixEpoch;
        var s = On(ttl: 60);
        var (gate, _, v) = Make(s, PresenceResult.Fail("canceled"), now: () => t);

        Assert.False(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "first"));   // denied
        t = t.AddSeconds(5);
        Assert.False(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "second"));  // must prompt again, not ride a cache
        Assert.Equal(2, v.VerifyCalls);
    }
}
