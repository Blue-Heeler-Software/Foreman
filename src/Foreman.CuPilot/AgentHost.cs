using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Foreman.Core.ComputerUse;

/// <summary>
/// HOP B host (L4) inside the Pilot shim. Foreman (via the App over HOP A) tells the shim to start the operator's
/// agent; the shim LAUNCHES it, hands it the HOP B pipe name + a per-session secret via the agent's STDIN (an
/// inherited handle - never argv, never a file), hosts an owner-only duplex pipe the agent connects to, and accepts it
/// only if it is the LAUNCHED PID (launch-bound, same gate class as HOP A) AND answers the secret challenge-response.
/// It then queues the agent's DriverSubmit PROPOSALS for the App to poll over HOP A. The agent can only PROPOSE; it
/// never reaches the App except as a relayed, App-rebuilt CuAction (INV-12), and never touches the broker channel.
/// </summary>
internal static class AgentHost
{
    private static readonly ConcurrentQueue<DriverSubmit> _queue = new();
    private static readonly object _lock = new();
    private static Process? _agent;
    private static bool _started;

    /// <summary>Launch the agent + host HOP B (idempotent: a second call while running is refused). Never throws.</summary>
    public static bool Start(StartAgentArgs args, out string error)
    {
        error = string.Empty;
        lock (_lock)
        {
            if (_started) { error = "agent already started"; return false; }
            if (string.IsNullOrWhiteSpace(args.Command)) { error = "no agent command configured"; return false; }

            var pipeName = "foreman-agent-" + Guid.NewGuid().ToString("N");
            var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

            NamedPipeServerStream server;
            try { server = CreateOwnerOnlyDuplexPipe(pipeName); }
            catch (Exception ex) { error = "could not host HOP B pipe: " + ex.Message; return false; }

            Process agent;
            try
            {
                var psi = new ProcessStartInfo(args.Command)
                {
                    Arguments = args.Arguments ?? string.Empty,
                    WorkingDirectory = string.IsNullOrWhiteSpace(args.WorkingDir) ? string.Empty : args.WorkingDir!,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardInput = true,
                };
                agent = Process.Start(psi) ?? throw new InvalidOperationException("Process.Start returned null");
            }
            catch (Exception ex) { try { server.Dispose(); } catch { } error = "could not launch agent: " + ex.Message; return false; }

            // Hand the agent its HOP B pipe name + the session secret via STDIN (an inherited handle). Two lines, then
            // close - the agent reads them, connects to HOP B, and answers the challenge with the secret.
            try
            {
                agent.StandardInput.WriteLine(pipeName);
                agent.StandardInput.WriteLine(secret);
                agent.StandardInput.Flush();
                agent.StandardInput.Close();
            }
            catch { /* if the agent never reads it, the accept/verify below fails closed */ }

            _agent = agent;
            _started = true;
            var agentPid = agent.Id;

            var t = new Thread(() => ServeAgent(server, agentPid, secret)) { IsBackground = true, Name = "cu-agent-hopb" };
            t.Start();
            return true;
        }
    }

    private static void ServeAgent(NamedPipeServerStream server, int agentPid, string secret)
    {
        try
        {
            using (server)
            {
                using (var acceptCts = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
                {
                    try { server.WaitForConnectionAsync(acceptCts.Token).GetAwaiter().GetResult(); }
                    catch { return; }   // agent never connected in time
                }

                // launch-PID-pin: the connecting client MUST be the agent we launched (a same-user process that learned
                // the pipe name cannot be it). The secret challenge below is the second factor.
                if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out var pid) || (int)pid != agentPid)
                    return;

                using var reader = new StreamReader(server, new UTF8Encoding(false));
                using var writer = new StreamWriter(server, new UTF8Encoding(false)) { AutoFlush = true };

                // Secret challenge-response: the agent proves it read the stdin secret without it crossing the pipe.
                var challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                writer.WriteLine(challenge);
                var presented = reader.ReadLine();
                if (!CuHandshake.Verify(secret, CuHandshake.HandshakeMessage(challenge), presented)) return;

                // Queue the agent's proposals until it/the pipe closes. These are PROPOSALS only - the App rebuilds the
                // trusted CuAction and audits it; the shim never interprets or acts on them.
                while (server.IsConnected)
                {
                    string? line;
                    try { line = reader.ReadLine(); }
                    catch { break; }
                    if (line is null) break;
                    DriverSubmit? sub;
                    try { sub = JsonSerializer.Deserialize<DriverSubmit>(line, CuJson.Options); }
                    catch { continue; }
                    if (sub is not null) _queue.Enqueue(sub);
                }
            }
        }
        catch { /* HOP B failure just means no proposals flow; HOP A + the App stay healthy */ }
    }

    /// <summary>Drain the queued agent proposals for the App's poll.</summary>
    public static DriverSubmitBatch Drain()
    {
        var list = new List<DriverSubmit>();
        while (_queue.TryDequeue(out var s)) list.Add(s);
        return new DriverSubmitBatch(list);
    }

    /// <summary>Kill the agent (on shim shutdown / parent death). Never throws.</summary>
    public static void Stop()
    {
        lock (_lock)
        {
            try { if (_agent is { HasExited: false }) _agent.Kill(); } catch { }
        }
    }

    private static NamedPipeServerStream CreateOwnerOnlyDuplexPipe(string name)
    {
        var me = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("No current Windows user SID.");
        var security = new PipeSecurity();
        security.SetOwner(me);
        security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            name, PipeDirection.InOut, maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, inBufferSize: 0, outBufferSize: 0, security);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);
}
