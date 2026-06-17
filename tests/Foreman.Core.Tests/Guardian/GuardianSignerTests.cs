using System.Security.Cryptography;
using Foreman.Core.Events;
using Foreman.Core.Guardian;
using Foreman.Core.Ipc.Guardian;

namespace Foreman.Core.Tests.Guardian;

/// <summary>
/// Circle-back Phase A, step 5: the app-side GuardianSigner seals via the guardian but verifies locally, and a
/// slow/hung/absent guardian degrades to unsigned-this-append rather than stalling the publish path.
/// </summary>
public sealed class GuardianSignerTests
{
    // A fake guardian client: seals by signing locally with a software key (so the seal verifies), or delays / errors.
    private sealed class FakeClient : IGuardianClient
    {
        private readonly ECDsa _key;
        private readonly int _delayMs;
        private readonly bool _throw;
        public FakeClient(ECDsa key, int delayMs = 0, bool @throw = false) { _key = key; _delayMs = delayMs; _throw = @throw; }

        public bool IsAvailable => true;
        public Task<HelloResult?> HelloAsync(CancellationToken ct = default) => Task.FromResult<HelloResult?>(new HelloResult { GuardianVersion = "test", HeadKeyAvailable = true });
        public Task<string?> GetPinnedHeadKeyAsync(CancellationToken ct = default) => Task.FromResult<string?>(Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo()));
        public Task<VerifySettingsResult?> VerifySettingsAsync(string p, string? s, CancellationToken ct = default) => Task.FromResult<VerifySettingsResult?>(null);
        public Task<SealSettingsResult> SealSettingsAsync(SealSettingsArgs a, CancellationToken ct = default) => Task.FromResult(new SealSettingsResult());

        public async Task<string?> SealHeadAsync(string headHash, long recordCount, CancellationToken ct = default)
        {
            if (_throw) throw new InvalidOperationException("boom");
            if (_delayMs > 0) await Task.Delay(_delayMs, ct).ConfigureAwait(false); // honors ct → cancels on timeout
            var payload = System.Text.Encoding.UTF8.GetBytes($"{headHash}|{recordCount}");
            return Convert.ToBase64String(_key.SignData(payload, HashAlgorithmName.SHA256));
        }
    }

    [Fact]
    public void Seal_FromGuardian_VerifiesLocally()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinned = key.ExportSubjectPublicKeyInfo();
        var signer = new GuardianSigner(new FakeClient(key), pinned);

        var seal = signer.SealHead("HEAD", 5);
        Assert.NotNull(seal);
        Assert.True(signer.VerifyHead("HEAD", 5, seal));   // local verify against the pinned key
        Assert.False(signer.VerifyHead("HEAD", 6, seal));  // tampered count
    }

    [Fact]
    public void Seal_TimesOut_DegradesToNull() // hung guardian must not stall the publish path
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new GuardianSigner(new FakeClient(key, delayMs: 5000), key.ExportSubjectPublicKeyInfo(), sealTimeoutMs: 60);
        Assert.Null(signer.SealHead("HEAD", 5));
    }

    [Fact]
    public void Seal_ClientThrows_DegradesToNull()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new GuardianSigner(new FakeClient(key, @throw: true), key.ExportSubjectPublicKeyInfo());
        Assert.Null(signer.SealHead("HEAD", 5));
    }

    [Fact]
    public void Verify_IsLocal_EvenWhenClientWouldThrow() // reads never touch the pipe
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pinned = key.ExportSubjectPublicKeyInfo();
        // Seal with a healthy client, then verify with a signer whose client always throws — verify still works.
        var goodSeal = new GuardianSigner(new FakeClient(key), pinned).SealHead("HEAD", 9)!;
        var signerWithBadClient = new GuardianSigner(new FakeClient(key, @throw: true), pinned);
        Assert.True(signerWithBadClient.VerifyHead("HEAD", 9, goodSeal));
    }

    [Fact]
    public void ExpectsSeal_OnlyOncePinned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.False(new GuardianSigner(new FakeClient(key), pinnedPublicKey: null).ExpectsSeal);
        Assert.True(new GuardianSigner(new FakeClient(key), key.ExportSubjectPublicKeyInfo()).ExpectsSeal);
    }
}
