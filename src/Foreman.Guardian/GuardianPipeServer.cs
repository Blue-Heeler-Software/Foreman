using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
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
    private readonly GuardianClientPolicy _clientPolicy;
    private readonly Action<string>? _log;
    private const int MaxRequestChars = 128 * 1024;

    public GuardianPipeServer(GuardianAuthority authority, GuardianClientPolicy clientPolicy, Action<string>? log = null)
    {
        _authority = authority;
        _clientPolicy = clientPolicy;
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
        var (trusted, reason) = _clientPolicy.VerifyClient(clientPath);
        if (!trusted)
        {
            _log?.Invoke($"guardian: rejected pipe client '{clientPath ?? "<unknown>"}' — {reason}");
            return; // drop the connection without processing
        }

        using var reader = new StreamReader(server, leaveOpen: true);
        using var writer = new StreamWriter(server, leaveOpen: true) { AutoFlush = true };

        var line = await ReadBoundedLineAsync(reader, MaxRequestChars, ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line)) return;

        var req = GuardianFrameJson.Decode<GuardianRequest>(line);
        if (req is null || req.RequestId.Length is < 1 or > 64 || req.Kind.Length is < 1 or > 64)
            return;

        var res = Dispatch(req);
        await writer.WriteLineAsync(GuardianFrameJson.Line(res).AsMemory(), ct).ConfigureAwait(false);
    }

    private GuardianResponse Dispatch(GuardianRequest req)
    {
        switch (req.Kind)
        {
            case GuardianRpc.Hello:
            {
                var hello = _authority.Hello();
                hello.TrustMode = _clientPolicy.Mode;
                hello.PublisherAuthenticated = _clientPolicy.PublisherAuthenticated;
                return Ok(req, GuardianFrameJson.Encode(hello));
            }

            case GuardianRpc.SealHead:
            {
                var args = GuardianFrameJson.Decode<SealHeadArgs>(req.Payload);
                if (args is null) return Bad(req, "missing SealHead args");
                if (args.HeadHash.Length is < 1 or > 256 || args.RecordCount < 0)
                    return Bad(req, "invalid SealHead args");
                var seal = _authority.SealHead(args.HeadHash, args.RecordCount);
                return Ok(req, GuardianFrameJson.Encode(new SealHeadResult { Seal = seal }));
            }

            case GuardianRpc.GetPinnedHeadKey:
                return Ok(req, GuardianFrameJson.Encode(new PinnedHeadKeyResult { HeadPublicKeyB64 = _authority.GetPinnedHeadKey() }));

            case GuardianRpc.VerifySettings:
            {
                var args = GuardianFrameJson.Decode<VerifySettingsArgs>(req.Payload);
                if (args is null) return Bad(req, "missing VerifySettings args");
                if (args.SecurityProjection.Length > 64 * 1024 || args.StoredSeal?.Length > 4 * 1024)
                    return Bad(req, "VerifySettings args exceed limits");
                var verdict = _authority.VerifySettings(args.SecurityProjection, args.StoredSeal);
                return Ok(req, GuardianFrameJson.Encode(new VerifySettingsResult { Verdict = verdict.ToString() }));
            }

            case GuardianRpc.SealSettings:
            {
                var args = GuardianFrameJson.Decode<SealSettingsArgs>(req.Payload);
                if (args is null) return Bad(req, "missing SealSettings args");
                if (args.SecurityProjection.Length > 64 * 1024 ||
                    args.Action.Length > 256 || args.Detail.Length > 4 * 1024 ||
                    args.PresenceToken?.Length > 4 * 1024)
                    return Bad(req, "SealSettings args exceed limits");
                // Client auth already proved this is the genuine Foreman; server-side presence enforcement of a
                // weakening action is a noted future refinement. Seal the supplied projection.
                return Ok(req, GuardianFrameJson.Encode(new SealSettingsResult { Seal = _authority.SealSettings(args.SecurityProjection) }));
            }

            default:
                return Bad(req, "not implemented (guardian scaffold)");
        }
    }

    private static GuardianResponse Ok(GuardianRequest req, string payload) =>
        new() { RequestId = req.RequestId, Kind = req.Kind, Ok = true, Payload = payload };

    private static GuardianResponse Bad(GuardianRequest req, string error) =>
        new() { RequestId = req.RequestId, Kind = req.Kind, Ok = false, Error = error };

    internal static async Task<string?> ReadBoundedLineAsync(StreamReader reader, int maxChars, CancellationToken ct)
    {
        var result = new StringBuilder(Math.Min(maxChars, 4096));
        var buffer = new char[4096];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
            if (read == 0) return result.Length == 0 ? null : result.ToString();
            var newline = Array.IndexOf(buffer, '\n', 0, read);
            var count = newline >= 0 ? newline : read;
            if (result.Length + count > maxChars)
                throw new InvalidDataException("Guardian request exceeded the maximum frame size.");
            result.Append(buffer, 0, count);
            if (newline >= 0)
            {
                if (result.Length > 0 && result[^1] == '\r') result.Length--;
                return result.ToString();
            }
        }
    }
}
