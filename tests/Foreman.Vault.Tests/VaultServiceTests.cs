using Foreman.Core.Vault;
using Foreman.Vault;

namespace Foreman.Vault.Tests;

public sealed class VaultServiceTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "foreman-vaultsvc-" + Guid.NewGuid().ToString("N"));
    public VaultServiceTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, recursive: true); } catch { /* best-effort */ } }

    // Stand-in for DPAPI so the test stays cross-platform: an XOR pad simulates user/machine binding — a different pad
    // (a "different machine") decodes the component to the wrong bytes, just as a foreign DPAPI scope would fail.
    private sealed class XorProtector(byte pad) : IVaultKeyProtector
    {
        public byte[] Protect(byte[] s) => s.Select(b => (byte)(b ^ pad)).ToArray();
        public byte[] Unprotect(byte[] b) => b.Select(x => (byte)(x ^ pad)).ToArray();
    }

    private const string Pw = "correct horse battery staple";
    private VaultService NewService(IVaultKeyProtector p) =>
        new(Path.Combine(_dir, "v.fvault"), Path.Combine(_dir, "c.bin"), p);

    private static VaultEntry GitHub() => new()
    { Name = "GitHub", Origins = { "github.com" }, Harnesses = { "claude-code" }, Password = "s3cret" };

    [Fact]
    public void Enroll_Unlock_Resolve_Lock_Lifecycle()
    {
        var svc = NewService(new XorProtector(0x5A));
        Assert.False(svc.IsEnrolled);

        svc.Enroll(Pw);
        Assert.True(svc.IsEnrolled);
        Assert.True(svc.IsUnlocked);
        svc.Upsert(GitHub());

        var ok = svc.Resolver.Resolve("{{vault:github.com/password}}", "github.com", "claude-code", isOperator: false);
        Assert.True(ok.Ok);
        Assert.Equal("s3cret", ok.Resolved);

        svc.Lock();
        Assert.False(svc.IsUnlocked);
        var locked = svc.Resolver.Resolve("{{vault:github.com/password}}", "github.com", "claude-code", false);
        Assert.False(locked.Ok);   // the stable resolver fails closed while locked
    }

    [Fact]
    public void Reopen_WithSameProtector_Unlocks()
    {
        var a = NewService(new XorProtector(0x5A));
        a.Enroll(Pw);
        a.Upsert(GitHub());
        a.Lock();

        var b = NewService(new XorProtector(0x5A));
        Assert.True(b.IsEnrolled);
        b.Unlock(Pw);
        var r = b.Resolver.Resolve("{{vault:github.com/password}}", "github.com", "claude-code", false);
        Assert.Equal("s3cret", r.Resolved);
    }

    [Fact]
    public void WrongMasterPassword_Throws()
    {
        NewService(new XorProtector(0x5A)).Enroll(Pw);
        Assert.ThrowsAny<Exception>(() => NewService(new XorProtector(0x5A)).Unlock("wrong-password"));
    }

    [Fact]
    public void DifferentMachine_WrongProtector_Throws()
    {
        NewService(new XorProtector(0x5A)).Enroll(Pw);
        // A different "machine" (pad) can't release the right component, so the composite key is wrong → open fails.
        Assert.ThrowsAny<Exception>(() => NewService(new XorProtector(0x11)).Unlock(Pw));
    }

    [Fact]
    public void EnrollTwice_Throws()
    {
        var svc = NewService(new XorProtector(0x5A));
        svc.Enroll(Pw);
        Assert.Throws<InvalidOperationException>(() => svc.Enroll(Pw));
    }

    [Fact]   // signup generates + stores a new password OPERATOR-ONLY: the creating agent can't later auto-resolve it
    public void SelfSignup_GeneratesStores_OperatorOnly()
    {
        var svc = NewService(new XorProtector(0x5A));
        svc.Enroll(Pw);

        var r = svc.SelfSignup("Example.com", "example.com", "claude-code");
        Assert.True(r.Ok);
        Assert.False(string.IsNullOrWhiteSpace(r.Value));

        // The operator can read it back and it matches the generated password.
        var asOperator = svc.Resolver.Resolve("{{vault:example.com/password}}", "example.com", harnessId: null, isOperator: true);
        Assert.True(asOperator.Ok);
        Assert.Equal(r.Value, asOperator.Resolved);

        // ...but the agent that created it is NOT on the ACL (no phishing self-grant) — it cannot resolve it.
        Assert.False(svc.Resolver.Resolve("{{vault:example.com/password}}", "example.com", "claude-code", isOperator: false).Ok);
    }

    [Fact]   // never clobber an existing login (origin collision)
    public void SelfSignup_RefusesWhenOriginExists()
    {
        var svc = NewService(new XorProtector(0x5A));
        svc.Enroll(Pw);
        svc.Upsert(GitHub());

        Assert.False(svc.SelfSignup("github.com", "github.com", "claude-code").Ok);
        Assert.Equal("s3cret", svc.Resolver.Resolve("{{vault:github.com/password}}", "github.com", "claude-code", false).Resolved);
    }

    [Fact]   // regression: no-clobber must hold even when an item's Name == host but its origins differ (the by-name Upsert trap)
    public void SelfSignup_RefusesNameCollisionEvenIfOriginDiffers()
    {
        var svc = NewService(new XorProtector(0x5A));
        svc.Enroll(Pw);
        // An operator item NAMED "solo.example" but registered to a DIFFERENT origin — FindByOrigin would miss it.
        svc.Upsert(new VaultEntry { Name = "solo.example", Origins = { "other.example" }, Password = "orig" });

        Assert.False(svc.SelfSignup("solo.example", "solo.example", "claude-code").Ok);   // name collision -> refused
        Assert.Equal("orig",                                                              // original survives, un-clobbered
            svc.Resolver.Resolve("{{vault:other.example/password}}", "other.example", harnessId: null, isOperator: true).Resolved);
    }

    [Fact]   // the requested origin must match the live target (no cross-site signup)
    public void SelfSignup_RefusesDomainMismatch()
    {
        var svc = NewService(new XorProtector(0x5A));
        svc.Enroll(Pw);
        Assert.False(svc.SelfSignup("github.com", "evil.com", "claude-code").Ok);
        Assert.False(svc.Resolver.Resolve("{{vault:github.com/password}}", "github.com", harnessId: null, isOperator: true).Ok);   // nothing stored
    }

    [Fact]
    public void SelfSignup_RefusesWhileLocked()
    {
        var svc = NewService(new XorProtector(0x5A));
        svc.Enroll(Pw);
        svc.Lock();
        Assert.False(svc.SelfSignup("example.com", "example.com", "claude-code").Ok);
    }

    [Fact]   // rate guard: a per-harness cap (3) and an overall cap (5) — SECONDARY to the operator-approval gate
    public void SelfSignup_RateGuard_PerHarnessAndOverall()
    {
        var svc = NewService(new XorProtector(0x5A));
        svc.Enroll(Pw);

        // Harness "a" is capped at 3; the 4th is blocked even though the overall window isn't full.
        for (var i = 0; i < 3; i++) Assert.True(svc.SelfSignup($"a{i}.com", $"a{i}.com", "a").Ok);
        Assert.False(svc.SelfSignup("a3.com", "a3.com", "a").Ok);

        // Harness "b" can still create until the OVERALL window (5) fills, then it too is blocked.
        Assert.True(svc.SelfSignup("b0.com", "b0.com", "b").Ok);    // overall = 4
        Assert.True(svc.SelfSignup("b1.com", "b1.com", "b").Ok);    // overall = 5
        Assert.False(svc.SelfSignup("b2.com", "b2.com", "b").Ok);   // overall cap hit
    }
}
