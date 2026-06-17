using System.Security.Cryptography;
using Foreman.Core.Events;

namespace Foreman.Core.Tests.Events;

/// <summary>
/// Circle-back Phase B: the chain head is signed (retiring NullHeadSigner) and verified against a PINNED public
/// key, so a swapped/forged key fails rather than passing. Exercised with a software ECDSA key standing in for the
/// TPM/PCP key (the production key only differs in WHERE the private half lives — the sign/verify/pin logic here is
/// identical).
/// </summary>
public sealed class SignedHeadSignerTests
{
    // Test double for IHeadSealKey — a software ECDSA P-256 key. Production uses a non-exportable TPM/PCP key.
    private sealed class SoftwareKey : IHeadSealKey, IDisposable
    {
        private readonly ECDsa _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public byte[] PublicKey => _ecdsa.ExportSubjectPublicKeyInfo();
        public byte[] Sign(byte[] payload) => _ecdsa.SignData(payload, HashAlgorithmName.SHA256);
        public void Dispose() => _ecdsa.Dispose();
    }

    [Fact]
    public void SealThenVerify_RoundTrips()
    {
        using var key = new SoftwareKey();
        var signer = new SignedHeadSigner(key, key.PublicKey);
        var seal = signer.SealHead("HEAD123", 7);
        Assert.NotNull(seal);
        Assert.True(signer.VerifyHead("HEAD123", 7, seal));
    }

    [Fact]
    public void Verify_FailsWhenHeadOrCountChanged() // truncation/edit changes the signed payload
    {
        using var key = new SoftwareKey();
        var signer = new SignedHeadSigner(key, key.PublicKey);
        var seal = signer.SealHead("HEAD123", 7);
        Assert.False(signer.VerifyHead("HEAD123", 6, seal));   // count tampered
        Assert.False(signer.VerifyHead("OTHER", 7, seal));     // head tampered
    }

    [Fact]
    public void Verify_FailsWhenPinnedToADifferentKey() // attacker re-keyed / swapped in their own key
    {
        using var signingKey = new SoftwareKey();
        using var otherKey = new SoftwareKey();
        var signer = new SignedHeadSigner(signingKey, otherKey.PublicKey); // pinned != signing key
        var seal = signer.SealHead("HEAD123", 7);
        Assert.False(signer.VerifyHead("HEAD123", 7, seal));
    }

    [Fact]
    public void ExpectsSeal_OnlyOncePinned() // TOFU: no false tamper alarm before a key is pinned
    {
        using var key = new SoftwareKey();
        Assert.False(new SignedHeadSigner(key, null).ExpectsSeal);
        Assert.False(new SignedHeadSigner(key, Array.Empty<byte>()).ExpectsSeal);
        Assert.True(new SignedHeadSigner(key, key.PublicKey).ExpectsSeal);
    }

    [Fact]
    public void Verify_TrueWhenNotPinned() // not pinned yet → nothing to verify against
    {
        using var key = new SoftwareKey();
        var signer = new SignedHeadSigner(key, null);
        Assert.True(signer.VerifyHead("anything", 1, "anyseal"));
        Assert.True(signer.VerifyHead("anything", 1, null));
    }

    [Fact]
    public void Verify_FalseWhenPinnedButSealMissing()
    {
        using var key = new SoftwareKey();
        var signer = new SignedHeadSigner(key, key.PublicKey);
        Assert.False(signer.VerifyHead("HEAD123", 7, null));
        Assert.False(signer.VerifyHead("HEAD123", 7, ""));
    }

    [Fact]
    public void SealHead_NullWhenNoPrivateKey() // verify-only signer (non-TPM box / guardian offline)
    {
        using var key = new SoftwareKey();
        var verifyOnly = new SignedHeadSigner(key: null, pinnedPublicKey: key.PublicKey);
        Assert.Null(verifyOnly.SealHead("HEAD123", 7));
        Assert.True(verifyOnly.ExpectsSeal); // still expects a seal (pinned) → a missing one surfaces at Verify
    }

    [Fact]
    public void Verify_RejectsGarbageSeal()
    {
        using var key = new SoftwareKey();
        var signer = new SignedHeadSigner(key, key.PublicKey);
        Assert.False(signer.VerifyHead("HEAD123", 7, "not-base64!!"));
    }
}
