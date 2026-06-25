using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Foreman.Core.Events;
using Foreman.Core.Ipc;
using Foreman.Core.Models;
using Foreman.Core.Power;

namespace Foreman.App;

/// <summary>
/// Launches and supervises the elevated ETW network sidecar and exposes the per-PID network rates
/// it streams. The sidecar is the ONLY elevated component — this controller and the rest of the app
/// (including the MCP server and the kill UI) stay at medium integrity.
///
/// Transport: the app hosts a current-user-only named pipe; the elevated sidecar connects to it and
/// proves itself with a one-time nonce before any data is accepted. The sidecar exits on its own when
/// the pipe breaks or the app exits, so nothing privileged lingers.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ElevatedSidecarController : IDisposable
{
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private volatile Dictionary<int, double> _rates = new();
    private volatile WakeRequestSnapshot _wakeRequests = WakeRequestSnapshot.Unavailable("Elevated sidecar is not connected.");
    private volatile bool _connected;
    private bool _captureNet = true;
    private bool _captureWakeRequests = true;
    private IReadOnlyList<string> _decoyPaths = [];
    private string? _decoyPathsFile;

    /// <summary>
    /// Sets what the next launch does: per-PID network capture and/or SACL read-auditing of the given decoy
    /// paths. Call before <see cref="Start"/> / <see cref="Restart"/>.
    /// </summary>
    public void Configure(bool captureNet, IReadOnlyList<string>? decoyPaths, bool captureWakeRequests = true)
    {
        _captureNet = captureNet;
        _captureWakeRequests = captureWakeRequests;
        _decoyPaths = decoyPaths ?? [];
    }

    /// <summary>Stop and start with the current configuration (re-prompts UAC if elevated).</summary>
    public void Restart() { Stop(); Start(); }

    public bool IsRunning { get; private set; }
    public bool IsConnected => _connected;

    /// <summary>Raised when the elevated sidecar reports a SACL-audited read of a decoy credential file.</summary>
    public Action<DecoyReadMessage>? OnDecoyRead { get; set; }

    /// <summary>Latest network bytes/sec for a PID, or null when the sidecar isn't feeding it.</summary>
    public double? GetRate(int pid) =>
        _connected && _rates.TryGetValue(pid, out var rate) ? rate : null;

    public WakeRequestSnapshot GetWakeRequests() =>
        _connected ? _wakeRequests : WakeRequestSnapshot.Unavailable("Elevated sidecar is not connected.");

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
            _rates = new();
            _wakeRequests = WakeRequestSnapshot.Unavailable("Elevated sidecar is not connected.");
        }
    }

    private async Task RunAsync(CancellationTokenSource cts)
    {
        var ct = cts.Token;
        var pipeName = "foreman-etw-" + Guid.NewGuid().ToString("N");
        var nonce    = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

        try
        {
            using var server = CreateOwnerOnlyPipe(pipeName);
            if (!LaunchSidecar(pipeName, nonce)) return;   // exe missing or UAC declined

            await server.WaitForConnectionAsync(ct).ConfigureAwait(false);

            // Reject a non-elevated racer: the cmdline nonce is readable by same-user processes, so a medium-IL
            // agent could scrape it and connect first. The genuine sidecar runs elevated — anything that isn't is
            // an impersonator, dropped before any frame is trusted (the nonce check below is the second factor).
            if (PipeClientGuard.ConnectedClientIsNotElevated(server.SafePipeHandle, out var notElevatedReason))
            {
                EventBus.Instance.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Sidecar",
                    $"Rejected a process impersonating the elevated sidecar over its pipe ({notElevatedReason})."));
                return;
            }

            using var reader = new StreamReader(server, new UTF8Encoding(false));

            // Handshake: the first line must be our nonce, else it isn't the sidecar we launched.
            var presented = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (!string.Equals(presented, nonce, StringComparison.Ordinal)) return;

            _connected = true;
            while (!ct.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (line is null) break;   // sidecar closed the pipe
                try { HandleFrame(line); }
                catch { /* skip one malformed frame */ }
            }
        }
        catch (OperationCanceledException) { }
        catch { /* pipe/launch failure — features simply stay n/a */ }
        finally
        {
            _connected = false;
            CleanupDecoyPathsFile();
            // Clear IsRunning so a later Start() can relaunch a dead/failed sidecar — but only if a newer
            // Start() hasn't already replaced our CTS (else we'd stomp the live run's flag).
            lock (_gate) { if (ReferenceEquals(_cts, cts)) IsRunning = false; }
        }
    }

    // Each pipe line is self-describing via a "Kind" field; route net frames to the rate table and
    // decoy-read frames to the callback. A line without Kind is a legacy net frame.
    private void HandleFrame(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var kind = doc.RootElement.TryGetProperty("Kind", out var k) ? k.GetString() : SidecarFrame.Net;
        if (kind == SidecarFrame.DecoyRead)
        {
            if (JsonSerializer.Deserialize<DecoyReadMessage>(line) is { } d) OnDecoyRead?.Invoke(d);
        }
        else if (kind == SidecarFrame.WakeRequests)
        {
            if (JsonSerializer.Deserialize<WakeRequestsMessage>(line) is { } msg)
                _wakeRequests = new WakeRequestSnapshot(msg.Available, msg.Requests, msg.Error);
        }
        else if (JsonSerializer.Deserialize<NetworkRatesMessage>(line) is { } msg)
        {
            _rates = msg.Rates;
        }
    }

    private static NamedPipeServerStream CreateOwnerOnlyPipe(string name)
    {
        var me = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("No current Windows user SID.");
        var security = new PipeSecurity();
        security.SetOwner(me);
        security.AddAccessRule(new PipeAccessRule(me, PipeAccessRights.FullControl, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(
            name, PipeDirection.In, maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
            inBufferSize: 0, outBufferSize: 0, security);
    }

    /// <summary>The staged elevated ETW sidecar path.</summary>
    public static string SidecarPath() => Path.Combine(AppContext.BaseDirectory, "sidecar", "Foreman.EtwSidecar.exe");

    /// <summary>
    /// Hold a write/delete-denying handle on the elevated sidecar for the App's WHOLE lifetime so a same-user process
    /// cannot swap it AT REST. This is CRITICAL here because the sidecar is launched with requireAdministrator (UAC), so
    /// a swapped-in binary would turn Foreman's branded admin prompt into a privilege-escalation primitive. On
    /// unsigned/dev builds (where <see cref="SidecarIntegrity"/> waives the signer match) this at-rest lock — not
    /// Authenticode — IS the integrity safeguard; on signed builds it is defense-in-depth that also closes the
    /// verify->launch TOCTOU. Mirrors the desktop-CU helpers' pin. Call ONCE at startup regardless of the Run-Elevated
    /// toggle (the at-rest window is exactly when the feature is off) and hold the handle until exit. Returns null if the
    /// sidecar isn't installed (or is already locked by a prior instance).
    /// </summary>
    public static FileStream? PinBinaryAtRest()
    {
        try
        {
            var exe = SidecarPath();
            return File.Exists(exe) ? new FileStream(exe, FileMode.Open, FileAccess.Read, FileShare.Read) : null;
        }
        catch { return null; }
    }

    private bool LaunchSidecar(string pipeName, string nonce)
    {
        var exe = SidecarPath();
        if (!File.Exists(exe)) return false;

        // Never launch an UNTRUSTED binary with administrator rights. The sidecar sits in a same-user-writable
        // dir and forces requireAdministrator, so an overwritten sidecar would turn Foreman's branded UAC prompt
        // into a privilege-escalation primitive. Require it to carry the same Authenticode signature as Foreman.
        var (trusted, reason) = SidecarIntegrity.Verify(exe);
        if (!trusted)
        {
            EventBus.Instance.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Sidecar",
                $"Refused to launch the elevated sidecar — {reason} This can mean the sidecar binary was tampered " +
                "with to hijack Foreman's administrator prompt. Reinstall Foreman from a trusted source."));
            return false;
        }

        var args = $"--pipe {pipeName} --nonce {nonce} --parent {Environment.ProcessId}";
        if (_captureNet) args += " --capture-net";
        if (_captureWakeRequests) args += " --wake-requests";

        _decoyPathsFile = null;
        if (_decoyPaths.Count > 0)
        {
            try
            {
                // The decoy paths (not secret) are passed via a temp file rather than a long arg list.
                _decoyPathsFile = Path.Combine(Path.GetTempPath(), "foreman-decoys-" + Guid.NewGuid().ToString("N") + ".txt");
                File.WriteAllLines(_decoyPathsFile, _decoyPaths);
                args += $" --audit-decoys \"{_decoyPathsFile}\"";
            }
            catch { _decoyPathsFile = null; }
        }

        try
        {
            // UseShellExecute=true is required for the sidecar's requireAdministrator manifest to
            // raise the UAC prompt. If the user declines, Process.Start throws (1223) — features stay n/a.
            Process.Start(new ProcessStartInfo(exe) { Arguments = args, UseShellExecute = true });
            return true;
        }
        catch { return false; }
    }

    private void CleanupDecoyPathsFile()
    {
        if (_decoyPathsFile is null) return;
        try { if (File.Exists(_decoyPathsFile)) File.Delete(_decoyPathsFile); } catch { }
        _decoyPathsFile = null;
    }

    public void Dispose() => Stop();
}
