using System.Security.Cryptography;
using System.Text;

namespace Foreman.Core.Events;

/// <summary>
/// A signing key for the event-log chain head. The PRIVATE half lives behind this abstraction (a TPM/Platform
/// Crypto Provider key on Windows, a software key in tests); only the PUBLIC half (SubjectPublicKeyInfo) ever
/// leaves it, so verification is asymmetric — a future auditor or the elevated guardian can verify a seal without
/// ever holding the signing key.
/// </summary>
public interface IHeadSealKey
{
    /// <summary>The public key as a SubjectPublicKeyInfo (DER) blob — pinned in settings and used to verify.</summary>
    byte[] PublicKey { get; }

    /// <summary>Signs <paramref name="payload"/> with the private key (ECDSA/SHA-256). Returns the raw signature.</summary>
    byte[] Sign(byte[] payload);
}

/// <summary>
/// An <see cref="ILogHeadSigner"/> backed by an asymmetric key (<see cref="IHeadSealKey"/>) and a PINNED public
/// key. This retires <see cref="NullHeadSigner"/>: the chain head is signed, not left unsealed, and verification
/// runs against the pinned public key — so a swapped key (re-key / TPM clear / an attacker substituting their own
/// key) fails verification rather than silently passing.
///
/// HONEST THREAT MODEL (the same-user boundary still applies in Phase B):
///  - A TPM/PCP key created under the user's profile is NON-EXPORTABLE — it can't be copied off the box or
///    forged offline, and there is no readable seal secret at rest (unlike an HMAC keyed by a file). That removes
///    the "steal the secret, forge elsewhere" path and makes verification asymmetric.
///  - It does NOT, on its own, stop a same-user agent from USING the named key to produce a valid seal (CNG has
///    no per-process ACL at one SID). True unforgeability arrives only when the elevated guardian (the next phase)
///    creates and holds this key under a DIFFERENT principal (LocalSystem), out of the medium-IL agent's reach.
///    This type is exactly the seam the guardian will own — the crypto and pinning logic don't change, only WHO
///    holds the private key.
///
/// TOFU adoption: <see cref="ExpectsSeal"/> is true only once a public key has been pinned. On the very first run
/// after enabling sealing, nothing is pinned yet, so a pre-existing unsealed log is NOT reported as tampered; the
/// host pins the key after the first seal is written, and every subsequent run verifies against it.
/// </summary>
public sealed class SignedHeadSigner : ILogHeadSigner
{
    private readonly IHeadSealKey? _key;            // null = verify-only (no private key available this run)
    private readonly byte[]? _pinnedPublicKey;       // the SPKI we trust; verify against THIS, not the live key

    public SignedHeadSigner(IHeadSealKey? key, byte[]? pinnedPublicKey)
    {
        _key = key;
        _pinnedPublicKey = pinnedPublicKey is { Length: > 0 } ? pinnedPublicKey : null;
    }

    /// <summary>We only expect (and therefore require) a seal once a public key has been pinned — clean TOFU upgrade.</summary>
    public bool ExpectsSeal => _pinnedPublicKey is not null;

    public string? SealHead(string headHash, long recordCount)
    {
        if (_key is null) return null;   // no private key this run (non-TPM box / guardian offline) → unsealed, surfaced at Verify
        try { return Convert.ToBase64String(_key.Sign(Payload(headHash, recordCount))); }
        catch { return null; }
    }

    public bool VerifyHead(string headHash, long recordCount, string? seal)
    {
        if (_pinnedPublicKey is null) return true;          // nothing pinned yet (TOFU) — nothing to verify against
        if (string.IsNullOrEmpty(seal)) return false;       // pinned but no seal present = unsealed/dropped
        try
        {
            var sig = Convert.FromBase64String(seal);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(_pinnedPublicKey, out _);
            return ecdsa.VerifyData(Payload(headHash, recordCount), sig, HashAlgorithmName.SHA256);
        }
        catch { return false; }
    }

    /// <summary>Canonical signed payload: the head hash bound to the record count (so truncation changes it).</summary>
    private static byte[] Payload(string headHash, long recordCount) =>
        Encoding.UTF8.GetBytes($"{headHash}|{recordCount}");
}
