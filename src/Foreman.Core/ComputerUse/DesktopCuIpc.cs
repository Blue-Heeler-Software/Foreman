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

/// <summary>ExecuteAction result. The App independently verifies a claimed success against the AUTHORITATIVE bound
/// window (GetForegroundWindow == bound AND FinalHwnd == bound) and cross-checks the cursor (INV-5); HaltedMidStream is
/// surfaced as an honored-halt signal. Full result-vs-panic-epoch reconciliation is a Slice-4b-3 item (the App does not
/// yet stamp a per-gesture epoch); the hard floor (TerminateProcess + BlockInput) is the actual halt-race protection.</summary>
public sealed record ExecuteActionResult(bool Ok, string? Error = null,
    long FinalHwnd = 0, int CursorX = 0, int CursorY = 0, bool HaltedMidStream = false);

/// <summary>Hello payload (App -> sidecar): hands the sidecar the read-only DUPLICATED handle of the shared panic/bind
/// memory map (valid in the SIDECAR's handle table) so it can map and read panic/boundHwnd itself before every input
/// (INV-2/INV-3) - never trusting either from the pipe payload alone. The map is unnamed, so no other same-user
/// process can open it; the sidecar's handle is read-only, so it cannot forge the halt or move the bound window.</summary>
public sealed record HelloArgs(long PanicMapHandle, int MapCapacity);

/// <summary>What the sidecar reports it actually read from the shared MMF (in Hello/Heartbeat results), so the App can
/// confirm the sidecar sees the SAME panic/bind state the App wrote (INV-5 cross-check). Panic is 0/1.</summary>
public sealed record PanicSnapshot(int Panic, long BoundHwnd, long Epoch);

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

    /// <summary>Domain-separated message for the connection handshake, so the nonce-keyed HMAC used to prove the
    /// sidecar holds the nonce can never be confused with the per-response MAC (which is tagged "resp|").</summary>
    public static string HandshakeMessage(string? challenge) => "cu-handshake-v1|" + (challenge ?? string.Empty);
}

/// <summary>Shared serializer settings so the App and sidecar marshal the same bytes (string-named Kinds for
/// forward compatibility and readable frames). Both sides MUST use these, never the defaults.</summary>
public static class CuJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>The canonical string a response HMAC is computed over. Binds id + kind + the Ok/Error DECISION bits
    /// + payload (so a pipe peer cannot flip Ok/Error without breaking the MAC - Slice 4 trusts the Ok bit and the
    /// self-reported result fields), and is domain-separated from the handshake MAC by the leading "resp|" tag.</summary>
    public static string ResponseMac(DesktopCuKind kind, string requestId, bool ok, string? error, string? payloadB64) =>
        $"resp|{requestId}|{kind}|{ok}|{error ?? string.Empty}|{payloadB64 ?? string.Empty}";
}
