using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Foreman.Core.Ipc.Guardian;

namespace Foreman.Guardian;

/// <summary>
/// Hosts the guardian's duplex control pipe and dispatches one request → one response per connection, paired by
/// <see cref="GuardianRequest.RequestId"/>. Transport only — decisions live in <see cref="GuardianAuthority"/>.
///
/// SECURITY: the pipe is created with an explicit ACL (LocalSystem + Administrators full; Authenticated Users
/// read/write so the medium-IL app can reach a SYSTEM-owned service pipe), and EVERY connection is
/// Authenticode-authenticated (<see cref="GuardianIntegrity.VerifyClient"/>): the guardian signs the event-log
/// head ONLY for a caller signed by the same publisher as itself. Without this, any same-user process could ask
/// the guardian to sign a forged chain head and defeat the whole prevention tier. On an unsigned dev build the
/// check allows (no trust anchor), matching the sidecar's documented dev-vs-release posture.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GuardianPipeServer
{
    /// <summary>Shared with the app client via the Core contract, so the two can never drift.</summary>
    public const string PipeName = GuardianPipe.Name;

    private readonly GuardianAuthority _authority;
    private readonly Action<string>? _log;

    public GuardianPipeServer(GuardianAuthority authority, Action<string>? log = null)
    {
        _authority = authority;
        _log = log;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var server = CreateServer();
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                await HandleConnectionAsync(server, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch { /* a broken/abandoned connection must never kill the host — accept the next one */ }
        }
    }

    private static NamedPipeServerStream CreateServer()
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        // Authenticated users may CONNECT (read/write) and READ THE OWNER (ReadPermissions) — the latter lets the
        // app confirm this pipe is owned by SYSTEM (anti pipe-name-squatting) before trusting it. The per-connection
        // Authenticode check below still decides who is actually answered.
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.ReadPermissions, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            PipeName, PipeDirection.InOut, maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
            inBufferSize: 0, outBufferSize: 0, pipeSecurity: sec);
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        // Client auth FIRST: only sign for a caller signed by the same publisher as this guardian.
        var clientPath = PipeClientIdentity.GetClientImagePath(server);
        var (trusted, reason) = GuardianIntegrity.VerifyClient(clientPath);
        if (!trusted)
        {
            _log?.Invoke($"guardian: rejected pipe client '{clientPath ?? "<unknown>"}' — {reason}");
            return; // drop the connection without processing
        }

        using var reader = new StreamReader(server, leaveOpen: true);
        using var writer = new StreamWriter(server, leaveOpen: true) { AutoFlush = true };

        var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line)) return;

        var req = GuardianFrameJson.Decode<GuardianRequest>(line);
        if (req is null) return;

        var res = Dispatch(req);
        await writer.WriteLineAsync(GuardianFrameJson.Line(res).AsMemory(), ct).ConfigureAwait(false);
    }

    private GuardianResponse Dispatch(GuardianRequest req)
    {
        switch (req.Kind)
        {
            case GuardianRpc.Hello:
                return Ok(req, GuardianFrameJson.Encode(_authority.Hello()));

            case GuardianRpc.SealHead:
            {
                var args = GuardianFrameJson.Decode<SealHeadArgs>(req.Payload);
                if (args is null) return Bad(req, "missing SealHead args");
                var seal = _authority.SealHead(args.HeadHash, args.RecordCount);
                return Ok(req, GuardianFrameJson.Encode(new SealHeadResult { Seal = seal }));
            }

            case GuardianRpc.GetPinnedHeadKey:
                return Ok(req, GuardianFrameJson.Encode(new PinnedHeadKeyResult { HeadPublicKeyB64 = _authority.GetPinnedHeadKey() }));

            default:
                return Bad(req, "not implemented (guardian scaffold)");
        }
    }

    private static GuardianResponse Ok(GuardianRequest req, string payload) =>
        new() { RequestId = req.RequestId, Kind = req.Kind, Ok = true, Payload = payload };

    private static GuardianResponse Bad(GuardianRequest req, string error) =>
        new() { RequestId = req.RequestId, Kind = req.Kind, Ok = false, Error = error };
}
