using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Foreman.Core.Settings;

/// <summary>The result of checking settings.json's security subset against its sidecar seal.</summary>
public enum SettingsSealVerdict
{
    /// <summary>Seal present and matches — the security posture is exactly what Foreman last wrote.</summary>
    Sealed,
    /// <summary>Seal present but does NOT match — settings were edited by something other than Foreman.</summary>
    Tampered,
    /// <summary>No seal yet (first run / freshly upgraded) — adopt + seal, don't treat as tamper.</summary>
    Unsealed,
    /// <summary>
    /// A guardian-scheme seal was present but the guardian (the SYSTEM authority that holds the key) was
    /// unreachable, so the seal could be neither confirmed nor refuted. NOT a clean Sealed — the security
    /// posture is unverified this launch. The app surfaces this as a notice rather than blocking load.
    /// </summary>
    Unverified,
}

/// <summary>
/// Tamper-DETECTION for the security-significant subset of settings.json.
///
/// Against the primary adversary — a monitored agent running as the SAME user — tampering cannot be PREVENTED:
/// there is no privilege boundary, so the agent can read the install secret and recompute any seal. What IS
/// achievable, and what this provides, is DETECTION. Foreman re-seals on every save (<see cref="Compute"/>), so
/// any edit it did not make — another principal, accidental corruption, or a naive agent that flips a flag
/// without re-sealing — is caught at load (<see cref="Verify"/>) and can be reverted + alerted. Combined with the
/// external OS-event-log anchor and a SACL write-audit on settings.json, even a sophisticated same-user agent
/// that deletes/recomputes the seal trips a loud, externally-recorded signal rather than silently weakening
/// Foreman. The seal is keyed by the install secret (the same one minting MCP tokens), so it also blocks
/// cross-user / offline tampering outright.
/// </summary>
public static class SettingsSeal
{
    /// <summary>
    /// Deterministic projection of the fields whose silent change weakens Foreman's posture (the presence lock,
    /// log persistence/integrity, elevation, decoy auditing, MCP peer binding, disabled harnesses, emergency rule
    /// set, per-harness Trust, and mutes). Order-independent so re-serialization can't cause false tamper.
    /// </summary>
    public static string SecurityProjection(ForemanSettings s)
    {
        var projection = new
        {
            presenceEnabled = s.PresenceLock.Enabled,
            presenceScope   = (int)s.PresenceLock.Scope,
            presenceCred    = s.PresenceLock.CredentialId ?? "",
            eventLogPersist = s.EventLogPersist,
            hashChain       = s.LogIntegrity.HashChainEnabled,
            runElevated     = s.RunElevated,
            scanMcpTools    = s.ScanMcpTools,
            monitorAll      = s.MonitorAllProcesses,
            peerBinding     = s.McpPeerBindingEnforce,
            autoExtPair     = s.AllowAutoExtensionPairing,   // re-enabling code-less extension auto-pair is a weakening
            decoyEnabled    = s.DecoyCredentials.Enabled,
            decoyReadAudit  = s.DecoyCredentials.EnableReadAuditing,
            osEventLog      = s.OsEventLog.Enabled,
            // Desktop CU + Local Agent Host: a silent edit here grants desktop input authority or redirects which exe
            // Foreman launches as the agent - seal them so any change flips the verdict to Tampered (revert + alert).
            cuDesktop       = s.CuDesktopEnabled,
            cuDriverHost    = s.CuDriverHostEnabled,
            cuAutoGrant     = s.CuDesktopAutoGrant,
            cuDriver        = s.CuDriver ?? "",
            cuAgentCommand  = s.CuAgentCommand ?? "",
            cuAgentArgs     = s.CuAgentArguments ?? "",
            cuAgentWorkDir  = s.CuAgentWorkingDir ?? "",
            disabled        = s.DisabledHarnesses.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            emergency       = s.EmergencyRuleIds.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            trust           = s.HarnessTrust.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                            .Select(kv => $"{kv.Key.ToLowerInvariant()}={kv.Value}").ToArray(),
            capabilities    = s.HarnessCapabilityRestrictions.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                            .Select(kv => $"{kv.Key.ToLowerInvariant()}={(int)kv.Value.ComputerUse}:{(int)kv.Value.BrowserUse}").ToArray(),
            mutes           = s.Mutes.OrderBy(MuteKey, StringComparer.Ordinal).Select(MuteKey).ToArray(),
        };
        return JsonSerializer.Serialize(projection);
    }

    private static string MuteKey(Models.MuteEntry m) => $"{m.Scope}|{m.Value}|{m.Until:O}";

    /// <summary>
    /// Prefix marking a seal computed behind the SYSTEM boundary by the guardian (circle-back Phase A, step 7). It
    /// lets the local verify path recognise a guardian-scheme seal it CAN'T check (e.g. after opting out) and treat
    /// it as Unsealed → adopt + re-seal locally, rather than crying false tamper.
    /// </summary>
    public const string GuardianScheme = "g1:";

    /// <summary>HMAC-SHA256(secret, projection), base64 — the raw MAC, shared by the local path and the guardian.</summary>
    public static string ComputeMac(string projection, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(projection)));
    }

    /// <summary>Constant-time compare of a candidate MAC to the stored one.</summary>
    public static bool MacEquals(string computedMac, string storedMac)
    {
        var a = Encoding.UTF8.GetBytes(computedMac);
        var b = Encoding.UTF8.GetBytes(storedMac);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>HMAC-SHA256(install secret, security projection), base64. The seal written next to settings.json.</summary>
    public static string Compute(ForemanSettings s, string secret) => ComputeMac(SecurityProjection(s), secret);

    /// <summary>
    /// Compares the loaded settings' security subset to the stored seal (constant-time). A seal carrying the
    /// guardian scheme prefix is NOT verifiable with the local secret, so it reads as Unsealed (adopt + re-seal),
    /// never Tampered — that's the graceful opt-out path when the guardian is no longer present.
    /// </summary>
    public static SettingsSealVerdict Verify(ForemanSettings loaded, string? storedSeal, string secret)
    {
        if (string.IsNullOrEmpty(storedSeal)) return SettingsSealVerdict.Unsealed;
        if (storedSeal.StartsWith(GuardianScheme, StringComparison.Ordinal)) return SettingsSealVerdict.Unsealed;
        return MacEquals(Compute(loaded, secret), storedSeal)
            ? SettingsSealVerdict.Sealed
            : SettingsSealVerdict.Tampered;
    }
}

/// <summary>
/// Seam for WHO computes/verifies the settings seal (circle-back Phase A, step 7). The default local path keys it
/// by the install secret; the guardian-backed implementation keeps the secret behind the SYSTEM boundary so a
/// same-user agent can't read it to forge the seal. <see cref="SettingsStore"/> uses this when set, else its local
/// secret path.
/// </summary>
public interface ISettingsSealer
{
    /// <summary>Computes the seal string (including any scheme prefix) to write next to settings.json; null if unavailable.</summary>
    string? Compute(ForemanSettings settings);

    /// <summary>Verifies the stored seal against the loaded settings.</summary>
    SettingsSealVerdict Verify(ForemanSettings settings, string? storedSeal);
}
