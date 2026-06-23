using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Foreman.Core.ComputerUse;

// Foreman desktop computer-use sidecar (Slice 3: handshake + idle only - capture-free, input-free).
//   Usage: Foreman.CuSidecar --pipe <name> --nonce <secret> --parent <pid>
// It connects to the App's duplex owner-only control pipe, proves it holds the launch nonce via a
// challenge-response (the App sends a random challenge; we return HMAC(nonce, challenge) so the nonce
// itself never travels the wire and a scraped nonce replayed on a new connection is useless because the
// App also pins our PID), then services Hello/Heartbeat frames - authenticating every reply with the
// nonce. Input injection (SendInput) and screen capture arrive in Slices 4-5. It exits the moment the
// parent dies or the pipe breaks, so nothing lingers.

return Run(args);

static int Run(string[] args)
{
    string? pipeName = null, nonce = null;
    var parentPid = 0;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--pipe":   pipeName = Next(args, ref i); break;
            case "--nonce":  nonce = Next(args, ref i); break;
            case "--parent": _ = int.TryParse(Next(args, ref i), out parentPid); break;
        }
    }

    if (string.IsNullOrEmpty(pipeName) || string.IsNullOrEmpty(nonce)) return 2;   // bad args

    try
    {
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
        try { pipe.Connect(5000); }
        catch { return 4; }

        using var reader = new StreamReader(pipe, new UTF8Encoding(false));
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };

        // Handshake: read the App's random challenge, return HMAC(nonce, challenge). We never echo the nonce.
        var challenge = reader.ReadLine();
        if (string.IsNullOrEmpty(challenge)) return 5;
        try { writer.WriteLine(CuHandshake.Hmac(nonce, challenge)); }
        catch { return 5; }

        var parent = SafeGetProcess(parentPid);

        // Serviced loop. ReadLine blocks; the App closing the pipe returns null, and a dead parent is caught
        // both by that and by the explicit HasExited check (covers a wedged/half-open pipe).
        while (true)
        {
            if (parent is { HasExited: true }) return 0;

            string? line;
            try { line = reader.ReadLine(); }
            catch { break; }
            if (line is null) break;   // App closed the pipe

            DesktopCuRequest? req;
            try { req = JsonSerializer.Deserialize<DesktopCuRequest>(line, CuJson.Options); }
            catch { continue; }        // skip one malformed frame
            if (req is null) continue;

            var resp = Handle(req);
            try { writer.WriteLine(JsonSerializer.Serialize(Sign(resp, nonce), CuJson.Options)); }
            catch { break; }           // pipe gone
        }

        return 0;
    }
    catch { return 1; }
}

// Slice 3 services only the liveness frames. Input/capture/bind kinds are accepted by the contract but
// not yet implemented here - they fail closed (Ok=false) rather than silently appearing to succeed.
static DesktopCuResponse Handle(DesktopCuRequest req) => req.Kind switch
{
    DesktopCuKind.Hello     => new DesktopCuResponse(req.RequestId, req.Kind, Ok: true, PayloadB64: B64("slice3-ready")),
    DesktopCuKind.Heartbeat => new DesktopCuResponse(req.RequestId, req.Kind, Ok: true),
    _ => new DesktopCuResponse(req.RequestId, req.Kind, Ok: false,
            Error: "Not implemented in Slice 3 (input/capture land in Slices 4-5)."),
};

// Authenticate the reply with the session nonce so the App can reject any frame it did not get from us.
static DesktopCuResponse Sign(DesktopCuResponse r, string nonce) =>
    r with { Hmac = CuHandshake.Hmac(nonce, CuJson.ResponseMac(r.Kind, r.RequestId, r.PayloadB64)) };

static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

static Process? SafeGetProcess(int pid)
{
    if (pid <= 0) return null;
    try { return Process.GetProcessById(pid); }
    catch { return null; }
}

static string? Next(string[] a, ref int i) => i + 1 < a.Length ? a[++i] : null;
