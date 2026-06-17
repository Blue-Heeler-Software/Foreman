using System.Security.Cryptography;
using Foreman.Core.Events;
using Foreman.Guardian;

namespace Foreman.Guardian.Tests;

/// <summary>
/// Circle-back Phase A, step 4: the guardian's authority signs the event-log head with its (SYSTEM-held in prod)
/// key, and the signature verifies against the public key it hands the app to pin. Exercised with a software key
/// standing in for the TPM/PCP key — production only differs in WHERE the private half lives. This is the durable,
/// net10-based proof behind the cross-process smoke test (PS 5.1 can't verify SPKI; this can).
/// </summary>
public sealed class GuardianAuthorityTests
{
    private sealed class SoftwareKey : IHeadSealKey, IDisposable
    {
        private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public byte[] PublicKey => _ecdsa.ExportSubjectPublicKeyInfo();
        public byte[] Sign(byte[] payload) => _ecdsa.SignData(payload, HashAlgorithmName.SHA256);
        public void Dispose() => _ecdsa.Dispose();
    }

    [Fact]
    public void SealHead_VerifiesAgainst_PinnedKey()
    {
        using var key = new SoftwareKey();
        using var authority = new GuardianAuthority(key);

        Assert.True(authority.HeadKeyAvailable);
        var seal = authority.SealHead("ABC", 7);
        Assert.NotNull(seal);

        // The app pins what GetPinnedHeadKey returns and verifies offline with SignedHeadSigner.
        var pinned = Convert.FromBase64String(authority.GetPinnedHeadKey()!);
        var verifier = new SignedHeadSigner(key: null, pinnedPublicKey: pinned); // verify-only
        Assert.True(verifier.VerifyHead("ABC", 7, seal));
        Assert.False(verifier.VerifyHead("ABC", 8, seal)); // truncation/edit changes the signed payload
        Assert.False(verifier.VerifyHead("XYZ", 7, seal));
    }

    [Fact]
    public void NoKey_DegradesGracefully() // no-TPM box: HeadKeyAvailable false, SealHead null, no pinned key
    {
        using var authority = new GuardianAuthority(headKey: null);
        Assert.False(authority.HeadKeyAvailable);
        Assert.Null(authority.SealHead("ABC", 7));
        Assert.Null(authority.GetPinnedHeadKey());
        Assert.False(authority.Hello().HeadKeyAvailable);
    }

    [Fact]
    public void Hello_ReportsVersionAndKeyAvailability()
    {
        using var key = new SoftwareKey();
        using var authority = new GuardianAuthority(key);
        var hello = authority.Hello();
        Assert.Equal(GuardianAuthority.Version, hello.GuardianVersion);
        Assert.True(hello.HeadKeyAvailable);
    }

    [Fact]
    public void TwoAuthorities_DifferentKeys_DoNotCrossVerify() // a swapped/forged key can't pass another's pin
    {
        using var keyA = new SoftwareKey();
        using var keyB = new SoftwareKey();
        using var authA = new GuardianAuthority(keyA);
        using var authB = new GuardianAuthority(keyB);

        var sealA = authA.SealHead("ABC", 7)!;
        var pinnedB = Convert.FromBase64String(authB.GetPinnedHeadKey()!);
        Assert.False(new SignedHeadSigner(null, pinnedB).VerifyHead("ABC", 7, sealA));
    }
}
