using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// Wire contract between the App's <c>DesktopCuController</c> and the medium-IL <c>Foreman.CuSidecar</c> over the
/// duplex owner-only control pipe. Capture frames travel on a SEPARATE pipe (Slice 5). Per spec INV-5, every
/// sidecar response is HMAC'd with the session nonce so the App can authenticate the return channel, and the App
/// also cross-checks results against independent OS state before trusting them.
/// </summary>
public enum DesktopCuKind { Hello, BindWindow, ExecuteAction, SetCursorSkin, Heartbeat }

/// <summary>App -> sidecar request. <see cref="PayloadB64"/> is a base64 UTF-8 JSON body specific to the Kind.</summary>
public sealed record DesktopCuRequest(string RequestId, DesktopCuKind Kind, string? PayloadB64 = null);

/// <summary>Sidecar -> App response. <see cref="Hmac"/> = HMAC(nonce, RequestId + Kind + PayloadB64) so the App can
/// verify the response actually came from the handshaked sidecar (INV-5), not an injected frame.</summary>
public sealed record DesktopCuResponse(string RequestId, DesktopCuKind Kind, bool Ok,
    string? PayloadB64 = null, string? Error = null, string? Hmac = null);

/// <summary>ExecuteAction payload. BoundHwnd is cross-checked against the shared MMF by the sidecar (INV-2);
/// the App verifies the result independently (INV-5). DryRun runs the resolve+confine path without injecting.</summary>
public sealed record ExecuteActionArgs(string ActionId, string Verb, IReadOnlyDictionary<string, string> Args,
    long BoundHwnd, bool DryRun = false);

/// <summary>ExecuteAction result. The App re-checks FinalHwnd/CursorX/CursorY against GetForegroundWindow/GetCursorPos
/// and HaltedMidStream against the panic epoch before trusting it (INV-5).</summary>
public sealed record ExecuteActionResult(bool Ok, string? Error = null,
    long FinalHwnd = 0, int CursorX = 0, int CursorY = 0, bool HaltedMidStream = false);

/// <summary>Shared HMAC for the handshake (challenge-response) and response authentication. The nonce (a per-launch
/// secret passed to the sidecar) is the key; a scraped nonce replayed on a NEW connection still fails because the
/// App also pins the connecting PID to the one it launched.</summary>
public static class CuHandshake
{
    public static string Hmac(string nonce, string message)
    {
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(nonce ?? string.Empty));
        return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(message ?? string.Empty)));
    }

    /// <summary>Constant-time compare so a wrong response can't be probed byte by byte.</summary>
    public static bool Verify(string nonce, string message, string? presented) =>
        !string.IsNullOrEmpty(presented) &&
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(Hmac(nonce, message)), Encoding.ASCII.GetBytes(presented));
}

/// <summary>Shared serializer settings so the App and sidecar marshal the same bytes (string-named Kinds for
/// forward compatibility and readable frames). Both sides MUST use these, never the defaults.</summary>
public static class CuJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>The canonical string an HMAC is computed over for a response (binds id+kind+payload together).</summary>
    public static string ResponseMac(DesktopCuKind kind, string requestId, string? payloadB64) =>
        $"{requestId}|{kind}|{payloadB64 ?? string.Empty}";
}
