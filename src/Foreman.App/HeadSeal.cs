using System.Runtime.Versioning;
using System.Security.Cryptography;
using Foreman.Core.Events;
using Foreman.Core.Settings;

namespace Foreman.App;

/// <summary>
/// Windows TPM-backed head-seal key (circle-back Phase B). The private key is created in the Microsoft Platform
/// Crypto Provider (the TPM) as a NON-EXPORTABLE ECDSA P-256 key — its private half can never leave the chip, so
/// there is no seal secret at rest and it can't be forged off the box. Only the public half is exported (for the
/// pinned verifier). See <see cref="SignedHeadSigner"/> for the honest same-user caveat: a per-user PCP key is
/// still USABLE (not extractable) by a same-user process; true unforgeability arrives when the elevated guardian
/// creates this key under LocalSystem (Phase A) — same code, different key owner.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class TpmHeadSealKey : IHeadSealKey, IDisposable
{
    private const string ProviderName = "Microsoft Platform Crypto Provider";
    private readonly CngKey _key;
    private readonly ECDsaCng _ecdsa;

    private TpmHeadSealKey(CngKey key)
    {
        _key = key;
        _ecdsa = new ECDsaCng(key);
    }

    public byte[] PublicKey => _ecdsa.ExportSubjectPublicKeyInfo();
    public byte[] Sign(byte[] payload) => _ecdsa.SignData(payload, HashAlgorithmName.SHA256);

    public void Dispose()
    {
        _ecdsa.Dispose();
        _key.Dispose();
    }

    /// <summary>
    /// Opens the named PCP key, creating a non-exportable one if absent. Returns null when no usable Platform
    /// Crypto Provider / TPM is present (older box, vTPM disabled, policy blocked) — the caller then falls back to
    /// the unsigned (no-op) signer, so sealing is best-effort and never a hard requirement.
    /// </summary>
    public static TpmHeadSealKey? OpenOrCreate(string keyName)
    {
        try
        {
            var provider = new CngProvider(ProviderName);
            var key = CngKey.Exists(keyName, provider)
                ? CngKey.Open(keyName, provider)
                : CngKey.Create(CngAlgorithm.ECDsaP256, keyName, new CngKeyCreationParameters
                {
                    Provider = provider,
                    ExportPolicy = CngExportPolicies.None,   // non-exportable: the private key never leaves the TPM
                });
            return new TpmHeadSealKey(key);
        }
        catch
        {
            return null;   // no TPM / PCP unavailable → unsigned fallback (NullHeadSigner)
        }
    }
}

/// <summary>Result of building the head signer: the signer plus an optional operator notice to publish.</summary>
internal readonly record struct HeadSealBuild(ILogHeadSigner Signer, string? Notice, bool NoticeIsHigh, IDisposable? Owns);

/// <summary>
/// Builds the event-log head signer from settings, handling the TPM-or-fallback choice and trust-on-first-use
/// pinning of the public key. Pure-ish: it may persist the pinned key via <paramref name="saveSettings"/> on first
/// run, and returns a notice for the host to publish (kept out of here so this stays UI-free).
/// </summary>
internal static class HeadSealFactory
{
    public static HeadSealBuild Build(ForemanSettings settings, Action<ForemanSettings> saveSettings)
    {
        var integrity = settings.LogIntegrity;
        if (!integrity.SealHeadEnabled)
            return new HeadSealBuild(new NullHeadSigner(), null, false, null);

        var key = TpmHeadSealKey.OpenOrCreate(integrity.HeadKeyName);
        if (key is null)
            // No usable TPM/PCP — keep the hash chain (still tamper-evident) but don't claim a seal we can't make.
            return new HeadSealBuild(new NullHeadSigner(), null, false, null);

        var livePub = key.PublicKey;
        var livePubB64 = Convert.ToBase64String(livePub);
        var pinned = integrity.PinnedHeadPublicKeyB64;

        if (string.IsNullOrEmpty(pinned))
        {
            // Trust-on-first-use: pin the key's public half so future runs verify against it. Re-seals settings (B4).
            integrity.PinnedHeadPublicKeyB64 = livePubB64;
            try { saveSettings(settings); } catch { /* best-effort; an unpinned run just won't verify yet */ }
            return new HeadSealBuild(new SignedHeadSigner(key, livePub), null, false, key);
        }

        if (!string.Equals(pinned, livePubB64, StringComparison.Ordinal))
        {
            // The live TPM key no longer matches the pinned public key — a TPM clear / profile move, or an attacker
            // substituting their own key. Verify against the PINNED key (so the new key's seals fail → loud) and
            // raise a High notice. Re-pinning to re-establish trust will be presence-gated in the guardian phase.
            var pinnedBytes = SafeFromBase64(pinned);
            return new HeadSealBuild(
                new SignedHeadSigner(key, pinnedBytes),
                "Event-log seal key CHANGED: the TPM head-seal key no longer matches the pinned public key. This is " +
                "expected after a TPM reset or moving the profile to a new machine — but it is also what an attacker " +
                "substituting their own key looks like. New seals will fail verification until the key is re-pinned. " +
                "Investigate if you didn't reset the TPM; re-pin from Settings to restore trust.",
                true, key);
        }

        return new HeadSealBuild(new SignedHeadSigner(key, SafeFromBase64(pinned)), null, false, key);
    }

    private static byte[]? SafeFromBase64(string? s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        try { return Convert.FromBase64String(s); }
        catch { return null; }
    }
}
