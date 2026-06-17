using System.IO.Pipes;
using Foreman.Core.Ipc.Guardian;

namespace Foreman.Guardian;

/// <summary>
/// Hosts the guardian's duplex control pipe and dispatches one request → one response per connection, pairing by
/// <see cref="GuardianRequest.RequestId"/>. Transport only — all decisions live in <see cref="GuardianAuthority"/>.
///
/// STEP 3 (scaffold): a plain owner-default pipe that answers <see cref="GuardianRpc.Hello"/>. The hardened ACL
/// (server owner = LocalSystem, interactive-user SID granted read/write) and the mutual-auth handshake (the app
/// verifies the server is the genuine SYSTEM guardian; the guardian verifies the client's Authenticode) arrive
/// with the SYSTEM key custody + install steps. Unknown kinds return a not-implemented response, never throw.
/// </summary>
public sealed class GuardianPipeServer
{
    public const string PipeName = "foreman-guardian";

    private readonly GuardianAuthority _authority;

    public GuardianPipeServer(GuardianAuthority authority) => _authority = authority;

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(
                    PipeName, PipeDirection.InOut, maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                await HandleConnectionAsync(server, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch { /* a broken/abandoned connection must never kill the host — accept the next one */ }
        }
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        using var reader = new StreamReader(server, leaveOpen: true);
        using var writer = new StreamWriter(server, leaveOpen: true) { AutoFlush = true };

        var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line)) return;

        var req = GuardianFrameJson.Decode<GuardianRequest>(line);
        if (req is null) return;

        var res = Dispatch(req);
        await writer.WriteLineAsync(GuardianFrameJson.Line(res).AsMemory(), ct).ConfigureAwait(false);
    }

    private GuardianResponse Dispatch(GuardianRequest req) => req.Kind switch
    {
        GuardianRpc.Hello => Ok(req, GuardianFrameJson.Encode(_authority.Hello())),
        _ => new GuardianResponse
        {
            RequestId = req.RequestId,
            Kind = req.Kind,
            Ok = false,
            Error = "not implemented (guardian scaffold)",
        },
    };

    private static GuardianResponse Ok(GuardianRequest req, string payload) =>
        new() { RequestId = req.RequestId, Kind = req.Kind, Ok = true, Payload = payload };
}
