using System.Text.Json;

namespace Foreman.Core.Ipc.Guardian;

/// <summary>
/// Wire contract for the opt-in guardian control pipe (circle-back Phase A). Unlike the one-way sidecar sensor
/// pipe (<see cref="SidecarFrame"/>), this is a DUPLEX request/response channel: the medium-IL app asks the
/// LocalSystem guardian to perform the operations whose authority now lives behind the SYSTEM boundary (signing
/// the event-log head, computing/verifying the settings seal) so a same-user agent can no longer forge them.
///
/// Kept in Foreman.Core (cross-platform, pure DTOs) so both the Windows guardian and the app share ONE contract —
/// no app↔guardian project reference, and nothing Windows-only leaks into Core. Each frame is a single line of
/// JSON; every request carries a <see cref="GuardianRequest.RequestId"/> so responses can be paired even if they
/// interleave on the shared pipe.
/// </summary>
public static class GuardianRpc
{
    public const string Hello = "hello";                 // liveness + capability probe
    public const string SealHead = "sealHead";           // sign (headHash|count) with the SYSTEM-held key
    public const string GetPinnedHeadKey = "getPinnedHeadKey"; // SPKI of the SYSTEM head-seal key, for the app to pin
    public const string VerifySettings = "verifySettings";     // verify a settings seal with the SYSTEM-held secret
    public const string SealSettings = "sealSettings";   // (re-)seal settings; presence-gated for weakening actions
}

/// <summary>Request envelope (one JSON line). <see cref="Payload"/> is the serialized inner args DTO, or null.</summary>
public sealed class GuardianRequest
{
    public string RequestId { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public string? Payload { get; set; }
}

/// <summary>Response envelope (one JSON line), echoing the request's <see cref="RequestId"/> and <see cref="Kind"/>.</summary>
public sealed class GuardianResponse
{
    public string RequestId { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public bool Ok { get; set; }
    public string? Payload { get; set; }
    public string? Error { get; set; }
}

// ── Inner payload DTOs ───────────────────────────────────────────────────────────────────────────────────────

/// <summary>Hello response: guardian version + whether it has a usable SYSTEM head-seal key (no-TPM box ⇒ false).</summary>
public sealed class HelloResult
{
    public string GuardianVersion { get; set; } = string.Empty;
    public bool HeadKeyAvailable { get; set; }
}

public sealed class SealHeadArgs
{
    public string HeadHash { get; set; } = string.Empty;
    public long RecordCount { get; set; }
}

public sealed class SealHeadResult
{
    /// <summary>Base64 signature, or null when the guardian has no signing key (caller degrades to unsigned).</summary>
    public string? Seal { get; set; }
}

public sealed class PinnedHeadKeyResult
{
    /// <summary>Base64 SubjectPublicKeyInfo of the SYSTEM head-seal key; null when unavailable.</summary>
    public string? HeadPublicKeyB64 { get; set; }
}

public sealed class VerifySettingsArgs
{
    public string SecurityProjection { get; set; } = string.Empty;
    public string? StoredSeal { get; set; }
}

public sealed class VerifySettingsResult
{
    /// <summary>"Sealed" | "Tampered" | "Unsealed" — mirrors SettingsSealVerdict, computed with the SYSTEM secret.</summary>
    public string Verdict { get; set; } = "Unsealed";
}

public sealed class SealSettingsArgs
{
    public string SecurityProjection { get; set; } = string.Empty;
    /// <summary>The weakening action being attempted (for the server-side presence gate); empty if none.</summary>
    public string Action { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    /// <summary>A fresh presence proof for a weakening action; null otherwise.</summary>
    public string? PresenceToken { get; set; }
}

public sealed class SealSettingsResult
{
    /// <summary>The new seal, or null if denied/unavailable.</summary>
    public string? Seal { get; set; }
    /// <summary>True when the guardian refused (e.g. a weakening action without a valid presence proof).</summary>
    public bool Denied { get; set; }
    public string? Reason { get; set; }
}

/// <summary>Shared JSON options + envelope payload helpers, so client and server encode identically.</summary>
public static class GuardianFrameJson
{
    public static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    public static string Encode<T>(T dto) => JsonSerializer.Serialize(dto, Options);
    public static T? Decode<T>(string? payload) =>
        string.IsNullOrEmpty(payload) ? default : JsonSerializer.Deserialize<T>(payload, Options);

    public static string Line(object frame) => JsonSerializer.Serialize(frame, Options);
}
