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
            decoyEnabled    = s.DecoyCredentials.Enabled,
            decoyReadAudit  = s.DecoyCredentials.EnableReadAuditing,
            osEventLog      = s.OsEventLog.Enabled,
            disabled        = s.DisabledHarnesses.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            emergency       = s.EmergencyRuleIds.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
            trust           = s.HarnessTrust.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                                            .Select(kv => $"{kv.Key.ToLowerInvariant()}={kv.Value}").ToArray(),
            mutes           = s.Mutes.OrderBy(MuteKey, StringComparer.Ordinal).Select(MuteKey).ToArray(),
        };
        return JsonSerializer.Serialize(projection);
    }

    private static string MuteKey(Models.MuteEntry m) => $"{m.Scope}|{m.Value}|{m.Until:O}";

    /// <summary>HMAC-SHA256(install secret, security projection), base64. The seal written next to settings.json.</summary>
    public static string Compute(ForemanSettings s, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(SecurityProjection(s))));
    }

    /// <summary>Compares the loaded settings' security subset to the stored seal (constant-time).</summary>
    public static SettingsSealVerdict Verify(ForemanSettings loaded, string? storedSeal, string secret)
    {
        if (string.IsNullOrEmpty(storedSeal)) return SettingsSealVerdict.Unsealed;
        var expected = Encoding.UTF8.GetBytes(Compute(loaded, secret));
        var actual   = Encoding.UTF8.GetBytes(storedSeal);
        return actual.Length == expected.Length && CryptographicOperations.FixedTimeEquals(actual, expected)
            ? SettingsSealVerdict.Sealed
            : SettingsSealVerdict.Tampered;
    }
}
