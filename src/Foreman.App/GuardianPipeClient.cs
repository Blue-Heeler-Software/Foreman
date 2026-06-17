using System.IO;
using System.IO.Pipes;
using Foreman.Core.Guardian;
using Foreman.Core.Ipc.Guardian;

namespace Foreman.App;

/// <summary>
/// The app's <see cref="IGuardianClient"/> over the guardian's duplex control pipe (circle-back Phase A). One
/// connection per RPC (matching the guardian's one-request-per-connection server), fully async + cancellation-
/// bound so a slow/hung guardian releases the calling thread on timeout. Every failure path returns the "absent"
/// sentinel (null / non-denied) so the app degrades to its local logic — never blocks, never throws.
/// </summary>
internal sealed class GuardianPipeClient : IGuardianClient
{
    private readonly int _connectTimeoutMs;

    public GuardianPipeClient(int connectTimeoutMs = 250) => _connectTimeoutMs = connectTimeoutMs;

    // Constructed only when GuardianDiscovery found the service registered; an unreachable pipe still degrades per-call.
    public bool IsAvailable => true;

    public async Task<HelloResult?> HelloAsync(CancellationToken ct = default) =>
        GuardianFrameJson.Decode<HelloResult>(await RpcAsync(GuardianRpc.Hello, null, ct).ConfigureAwait(false));

    public async Task<string?> SealHeadAsync(string headHash, long recordCount, CancellationToken ct = default)
    {
        var payload = GuardianFrameJson.Encode(new SealHeadArgs { HeadHash = headHash, RecordCount = recordCount });
        var resp = await RpcAsync(GuardianRpc.SealHead, payload, ct).ConfigureAwait(false);
        return GuardianFrameJson.Decode<SealHeadResult>(resp)?.Seal;
    }

    public async Task<string?> GetPinnedHeadKeyAsync(CancellationToken ct = default)
    {
        var resp = await RpcAsync(GuardianRpc.GetPinnedHeadKey, null, ct).ConfigureAwait(false);
        return GuardianFrameJson.Decode<PinnedHeadKeyResult>(resp)?.HeadPublicKeyB64;
    }

    public async Task<VerifySettingsResult?> VerifySettingsAsync(string securityProjection, string? storedSeal, CancellationToken ct = default)
    {
        var payload = GuardianFrameJson.Encode(new VerifySettingsArgs { SecurityProjection = securityProjection, StoredSeal = storedSeal });
        var resp = await RpcAsync(GuardianRpc.VerifySettings, payload, ct).ConfigureAwait(false);
        return GuardianFrameJson.Decode<VerifySettingsResult>(resp);
    }

    public async Task<SealSettingsResult> SealSettingsAsync(SealSettingsArgs args, CancellationToken ct = default)
    {
        var resp = await RpcAsync(GuardianRpc.SealSettings, GuardianFrameJson.Encode(args), ct).ConfigureAwait(false);
        return GuardianFrameJson.Decode<SealSettingsResult>(resp)
               ?? new SealSettingsResult { Denied = false, Reason = "guardian-unreachable" };
    }

    /// <summary>One request → one response on a fresh connection. Returns the response payload, or null on any failure.</summary>
    private async Task<string?> RpcAsync(string kind, string? payload, CancellationToken ct)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", GuardianPipe.Name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(_connectTimeoutMs, ct).ConfigureAwait(false);

            using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, leaveOpen: true);

            var req = new GuardianRequest { RequestId = Guid.NewGuid().ToString("N"), Kind = kind, Payload = payload };
            await writer.WriteLineAsync(GuardianFrameJson.Line(req).AsMemory(), ct).ConfigureAwait(false);

            var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            var resp = GuardianFrameJson.Decode<GuardianResponse>(line);
            return resp is { Ok: true } ? resp.Payload : null;
        }
        catch
        {
            return null;   // timeout / not running / pipe error → absent; caller falls back to local logic
        }
    }
}
