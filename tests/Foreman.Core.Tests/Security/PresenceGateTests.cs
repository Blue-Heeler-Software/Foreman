using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class PresenceGateTests
{
    // A fake authenticator: scripted result, records how many times it was prompted.
    private sealed class FakeVerifier(PresenceResult? result = null, Exception? throws = null) : IPresenceVerifier
    {
        public int VerifyCalls { get; private set; }
        public bool? LastRequireUv { get; private set; }   // records the UV requirement the gate asked for
        public bool IsAvailable => true;
        public Task<EnrollResult> EnrollAsync(string reason, bool requireUserVerification, CancellationToken ct = default) =>
            Task.FromResult(EnrollResult.Success("cred-1", "Fake"));
        public Task<PresenceResult> VerifyAsync(string credentialId, string reason, bool requireUserVerification, CancellationToken ct = default)
        {
            VerifyCalls++;
            LastRequireUv = requireUserVerification;
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

    [Fact]   // desktop-input-authority / panic-override actions force full UV even when the global default is touch-only
    public async Task HighStakesAction_ForcesUserVerification_EvenWhenGlobalTouchOnly()
    {
        var s = On();   // RequireUserVerification defaults false (touch-only)
        var (gate, _, v) = Make(s);
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.ResumeComputerUse, "resume", forcePresence: true, freshTap: true));
        Assert.True(v.LastRequireUv!.Value);   // forced UV for the panic-resume action despite the touch-only default
    }

    [Fact]   // ordinary weakening / vault taps follow the global touch-only default (and the opt-in)
    public async Task OrdinaryAction_FollowsGlobalUserVerificationSetting()
    {
        var touchOnly = On();   // RequireUserVerification = false
        var (g1, _, v1) = Make(touchOnly);
        Assert.True(await g1.AuthorizeAsync(WeakeningAction.LowerTrust, "trust 4→2"));
        Assert.False(v1.LastRequireUv!.Value);   // touch-only by default

        var optedIn = On(); optedIn.RequireUserVerification = true;
        var (g2, _, v2) = Make(optedIn);
        Assert.True(await g2.AuthorizeAsync(WeakeningAction.LowerTrust, "trust 4→2"));
        Assert.True(v2.LastRequireUv!.Value);   // operator opted into PIN/biometric globally
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

        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "trust 4->2"));   // prompts
        t = t.AddSeconds(30);                                                                // within TTL
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "trust 4->2"));   // SAME (action,detail) -> cached
        Assert.Equal(1, v.VerifyCalls);                                                      // second used the cached approval
        Assert.True(log[1].Granted);
        Assert.Contains("within approval window", log[1].Detail);
    }

    [Fact]
    public async Task ApprovalTtl_Expired_PromptsAgain()
    {
        var t = DateTimeOffset.UnixEpoch;
        var s = On(ttl: 60);
        var (gate, _, v) = Make(s, PresenceResult.Ok("Hello"), now: () => t);

        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "same"));
        t = t.AddSeconds(90);                                                          // past TTL
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "same"));    // same key; re-prompt due to EXPIRY
        Assert.Equal(2, v.VerifyCalls);                                                // re-prompted
    }

    [Fact]
    public async Task ApprovalTtl_ClampedToMax_ForcesReTap_NoIndefiniteReplay()  // B9 polish
    {
        var t = DateTimeOffset.UnixEpoch;
        var s = On(ttl: 86_400);   // operator (or a tampered settings file) set a day-long approval window
        var (gate, _, v) = Make(s, PresenceResult.Ok("Hello"), now: () => t);

        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "same"));
        t = t.AddSeconds(PresenceGate.MaxApprovalTtlSeconds + 1);   // past the hard ceiling, though within the configured day
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "same"));   // same key; re-tap ONLY due to the clamp
        Assert.Equal(2, v.VerifyCalls);   // the clamp forced a re-tap despite the huge configured TTL
    }

    [Fact]
    public async Task DeniedTap_DoesNotPrimeTheApprovalCache()
    {
        var t = DateTimeOffset.UnixEpoch;
        var s = On(ttl: 60);
        var (gate, _, v) = Make(s, PresenceResult.Fail("canceled"), now: () => t);

        Assert.False(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "same"));   // denied
        t = t.AddSeconds(5);
        Assert.False(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "same"));   // must prompt again, not ride a cache
        Assert.Equal(2, v.VerifyCalls);
    }

    // ── Local Agent Host L1: per-(action,detail) cache keying + forcePresence + freshTap ─────────────

    [Fact]
    public async Task CachedTap_DoesNotCoverADifferentAction()  // INV: a tap for one change never covers another
    {
        var t = DateTimeOffset.UnixEpoch;
        var (gate, _, v) = Make(On(ttl: 60), PresenceResult.Ok("Hello"), now: () => t);

        Assert.True(await gate.AuthorizeAsync(WeakeningAction.LowerTrust, "trust 4->2"));   // prompts + caches its key
        t = t.AddSeconds(5);                                                                 // well within TTL
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.DisableMonitoring, "disable claude-code"));
        Assert.Equal(2, v.VerifyCalls);   // different (action,detail) => its own tap, never the cached one
    }

    [Fact]
    public async Task ForcePresence_BlocksWhenLockOff_NoSilentProceed()  // INV-16
    {
        var (gate, _, v) = Make(new PresenceLockSettings { Enabled = false, CredentialId = "cred-1" }, PresenceResult.Ok("Hello"));
        // Lock OFF: a normal action would proceed silently, but a forced CU-sovereignty action still demands a tap.
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.BindCuWindow, "bind Notepad", forcePresence: true, freshTap: true));
        Assert.Equal(1, v.VerifyCalls);   // it actually prompted - did NOT take the lock-off shortcut
    }

    [Fact]
    public async Task ForcePresence_NoCredentialEnrolled_FailsClosed()  // INV-16: cannot ARM desktop CU without enrollment
    {
        var (gate, log, v) = Make(new PresenceLockSettings { Enabled = false, CredentialId = null });
        Assert.False(await gate.AuthorizeAsync(WeakeningAction.EnrollLocalAgentHost, "enroll local-agent-host", forcePresence: true, freshTap: true));
        Assert.Equal(0, v.VerifyCalls);   // nothing to prompt -> blocked, never a silent pass
        Assert.False(log.Single().Granted);
    }

    [Fact]
    public async Task FreshTap_BypassesCache_AndABindTapCannotSatisfyEnrollOrResume()  // closes "one tap covers bind+enroll+resume"
    {
        var t = DateTimeOffset.UnixEpoch;
        var (gate, _, v) = Make(On(ttl: 300), PresenceResult.Ok("Hello"), now: () => t);

        Assert.True(await gate.AuthorizeAsync(WeakeningAction.BindCuWindow, "bind Notepad", forcePresence: true, freshTap: true));
        t = t.AddSeconds(2);   // immediately after, well within any TTL
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.EnrollLocalAgentHost, "enroll local-agent-host", forcePresence: true, freshTap: true));
        t = t.AddSeconds(2);
        Assert.True(await gate.AuthorizeAsync(WeakeningAction.ResumeComputerUse, "resume after panic", forcePresence: true, freshTap: true));
        Assert.Equal(3, v.VerifyCalls);   // each demanded its OWN fresh tap; none rode another's approval
    }
}
