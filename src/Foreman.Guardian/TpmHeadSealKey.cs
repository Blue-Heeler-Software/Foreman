using System.Runtime.Versioning;
using System.Security.Cryptography;
using Foreman.Core.Events;

namespace Foreman.Guardian;

/// <summary>
/// Windows TPM-backed head-seal key for the guardian. Identical in logic to the App's
/// <c>Foreman.App.TpmHeadSealKey</c> (Phase B) — a non-exportable ECDSA P-256 key in the Microsoft Platform
/// Crypto Provider — but created in the GUARDIAN's process context. When the guardian runs as the LocalSystem
/// service, CNG scopes the key to the SYSTEM SID, so the medium-IL agent can neither extract NOR use it: that is
/// the privilege boundary that finally makes the seal unforgeable, not just tamper-evident.
///
/// Deliberately duplicated (not shared) because the App is a WPF assembly the guardian must not reference, and
/// Foreman.Core is cross-platform (Codex's Linux port references it) so Windows-only CngKey cannot live there.
/// CONSOLIDATE the two copies into a shared Windows platform assembly once Codex's Foreman.Platform(.Windows)
/// refactor lands. The class is tiny and stable (PCP key open/create), so the drift risk is low until then.
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
    /// Crypto Provider / TPM is present (older box, vTPM disabled, policy blocked) — the guardian then reports
    /// HeadKeyAvailable=false and the app keeps its tamper-EVIDENT hash chain (degrade, never hard-fail).
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
            return null;   // no TPM / PCP unavailable → caller degrades to the unsigned hash chain
        }
    }
}
