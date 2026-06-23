using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Foreman.Core.ComputerUse;
using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Launches and supervises the medium-IL desktop computer-use sidecar (<c>Foreman.CuSidecar.exe</c>) and owns the
/// duplex control pipe to it. Unlike the elevated ETW sidecar, this one runs at the SAME integrity as Foreman - CU
/// needs isolation (one auditable input source), never elevation.
///
/// Trust rebuild (spec INV-6): because the sidecar is same-user / same-IL, the elevation test that guards the ETW
/// pipe does not apply. Instead the connecting client must clear THREE gates before any frame is trusted:
///   1. Integrity:   the exe carries Foreman's Authenticode signature, verified under a write/delete-denying handle
///                   held across verify -> launch (TOCTOU close), and re-verified against the connected image.
///   2. Identity:    the pipe's client PID equals the PID we launched, its parent is us, and its image is that exe.
///   3. Knowledge:   challenge-response - we send a random challenge, it returns HMAC(nonce, challenge). A nonce
///                   scraped from our command line is useless on a new connection because gate 2 pins the PID.
/// Off by default; the App starts it only when <c>CuDesktopEnabled</c> is set. Slice 3 is capture-free / input-free.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DesktopCuController : IDisposable
{
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private NamedPipeServerStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private readonly SemaphoreSlim _io = new(1, 1);
    private volatile bool _connected;
    private string _nonce = string.Empty;

    public bool IsRunning { get; private set; }
    public bool IsConnected => _connected;

    /// <summary>Raised High when a process tried to impersonate the sidecar or the integrity check failed.</summary>
    public Action<ForemanSeverity, string>? OnSecurityNotice { get; set; }

    public void Start()
    {
        lock (_gate)
        {
            if (IsRunning) return;
            IsRunning = true;
            _cts = new CancellationTokenSource();
            var cts = _cts;
            _ = Task.Run(() => RunAsync(cts));
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            if (!IsRunning) return;
            IsRunning = false;
            _connected = false;
            _cts?.Cancel();
            try { _pipe?.Dispose(); } catch { }
            _pipe = null;
        }
    }

    private async Task RunAsync(CancellationTokenSource cts)
    {
        var ct = cts.Token;
        var pipeName = "foreman-cu-" + Guid.NewGuid().ToString("N");
        _nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        // Hold a write/delete-denying handle on the exe across verify -> launch so it cannot be swapped under us.
        FileStream? exeLock = null;
        try
        {
            var exe = Path.Combine(AppContext.BaseDirectory, "cu-sidecar", "Foreman.CuSidecar.exe");
            if (!File.Exists(exe)) { Notice(ForemanSeverity.Low, "Desktop CU sidecar is not installed."); return; }

            try { exeLock = new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.Read); }
            catch { Notice(ForemanSeverity.High, "Could not lock the desktop CU sidecar for launch (in use?)."); return; }

            var (trusted, reason) = SidecarIntegrity.Verify(exe);
            if (!trusted)
            {
                Notice(ForemanSeverity.High,
                    $"Refused to launch the desktop CU sidecar - {reason} The binary may have been tampered with.");
                return;
            }

            using var server = CreateOwnerOnlyDuplexPipe(pipeName);
            _pipe = server;

            var child = LaunchSidecar(exe, pipeName, _nonce);
            if (child is null) { Notice(ForemanSeverity.Low, "Desktop CU sidecar failed to start."); return; }

            await server.WaitForConnectionAsync(ct).ConfigureAwait(false);

            if (!VerifyClientIdentity(server, child, exe, out var idReason))
            {
                Notice(ForemanSeverity.High, $"Rejected a process impersonating the desktop CU sidecar ({idReason}).");
                try { child.Kill(); } catch { }
                return;
            }

            var reader = new StreamReader(server, new UTF8Encoding(false));
            var writer = new StreamWriter(server, new UTF8Encoding(false)) { AutoFlush = true };

            // Challenge-response: prove the client holds the nonce without it ever crossing the wire.
            var challenge = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            await writer.WriteLineAsync(challenge.AsMemory(), ct).ConfigureAwait(false);
            var presented = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (!CuHandshake.Verify(_nonce, challenge, presented))
            {
                Notice(ForemanSeverity.High, "Desktop CU sidecar failed the nonce challenge-response - dropped.");
                try { child.Kill(); } catch { }
                return;
            }

            _reader = reader;
            _writer = writer;
            _connected = true;

            // Slice 3: confirm the channel is alive, then idle. Input/capture loops arrive in Slices 4-5.
            var hello = await SendAsync(new DesktopCuRequest(NewId(), DesktopCuKind.Hello), ct).ConfigureAwait(false);
            if (hello is not { Ok: true })
                Notice(ForemanSeverity.Low, "Desktop CU sidecar connected but did not acknowledge Hello.");

            while (!ct.IsCancellationRequested && server.IsConnected)
            {
                await Task.Delay(2000, ct).ConfigureAwait(false);
                var beat = await SendAsync(new DesktopCuRequest(NewId(), DesktopCuKind.Heartbeat), ct).ConfigureAwait(false);
                if (beat is not { Ok: true }) break;   // sidecar gone / unauthenticated
            }
        }
        catch (OperationCanceledException) { }
        catch { /* pipe/launch failure -> desktop CU simply stays unavailable */ }
        finally
        {
            _connected = false;
            try { exeLock?.Dispose(); } catch { }
            lock (_gate) { if (ReferenceEquals(_cts, cts)) IsRunning = false; }
        }
    }

    /// <summary>Send one request and return the sidecar's authenticated response (null on any failure).</summary>
    public async Task<DesktopCuResponse?> SendAsync(DesktopCuRequest req, CancellationToken ct = default)
    {
        var reader = _reader;
        var writer = _writer;
        if (reader is null || writer is null) return null;

        await _io.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(req, CuJson.Options).AsMemory(), ct).ConfigureAwait(false);
            var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (line is null) return null;

            var resp = JsonSerializer.Deserialize<DesktopCuResponse>(line, CuJson.Options);
            if (resp is null) return null;

            // INV-5: authenticate the return channel - a frame whose HMAC does not verify is not from our sidecar.
            var expectMac = CuJson.ResponseMac(resp.Kind, resp.RequestId, resp.PayloadB64);
            if (resp.RequestId != req.RequestId || !CuHandshake.Verify(_nonce, expectMac, resp.Hmac))
            {
                Notice(ForemanSeverity.High, "Discarded an unauthenticated desktop CU response frame.");
                return null;
            }
            return resp;
        }
        catch { return null; }
        finally { _io.Release(); }
    }

    // Identity gate (INV-6 #2): the connected client must BE the child we launched, parented to us, from our exe.
    private bool VerifyClientIdentity(NamedPipeServerStream server, Process child, string exe, out string reason)
    {
        reason = string.Empty;
        if (!GetNamedPipeClientProcessId(server.SafePipeHandle.DangerousGetHandle(), out var clientPid) || clientPid == 0)
        { reason = "no client PID"; return false; }

        if ((int)clientPid != child.Id) { reason = $"client PID {clientPid} != launched {child.Id}"; return false; }

        try
        {
            using var p = Process.GetProcessById((int)clientPid);
            var img = p.MainModule?.FileName;
            if (string.IsNullOrEmpty(img) || !string.Equals(Path.GetFullPath(img), Path.GetFullPath(exe), StringComparison.OrdinalIgnoreCase))
            { reason = "client image is not the verified sidecar"; return false; }

            // Re-verify the running image's backing file (belt-and-suspenders against a swap between launch and connect).
            var (trusted, why) = SidecarIntegrity.Verify(img);
            if (!trusted) { reason = $"connected image failed integrity: {why}"; return false; }
        }
        catch (Exception ex) { reason = "could not inspect client image: " + ex.Message; return false; }

        return true;
    }

    private static NamedPipeServerStream CreateOwnerOnlyDuplexPipe(string name)
    {
        var me = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("No current Windows user SID.");
        var security = new PipeSecurity();
        security.SetOwner(me);
        security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            name, PipeDirection.InOut, maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
            inBufferSize: 0, outBufferSize: 0, security);
    }

    private Process? LaunchSidecar(string exe, string pipeName, string nonce)
    {
        try
        {
            // asInvoker manifest -> UseShellExecute=false (no UAC), and we get the real PID for the identity pin.
            var psi = new ProcessStartInfo(exe)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(exe) ?? AppContext.BaseDirectory,
            };
            psi.ArgumentList.Add("--pipe");   psi.ArgumentList.Add(pipeName);
            psi.ArgumentList.Add("--nonce");  psi.ArgumentList.Add(nonce);
            psi.ArgumentList.Add("--parent"); psi.ArgumentList.Add(Environment.ProcessId.ToString());
            return Process.Start(psi);
        }
        catch { return null; }
    }

    private void Notice(ForemanSeverity sev, string message)
    {
        try { OnSecurityNotice?.Invoke(sev, message); } catch { }
        try
        {
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, sev, "Foreman.CuSidecar", message));
        }
        catch { }
    }

    private static string NewId() => Guid.NewGuid().ToString("N");

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    public void Dispose() { Stop(); _io.Dispose(); }
}
