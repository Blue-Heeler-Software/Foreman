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
}
