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
    private volatile bool _connected;
    private bool _captureNet = true;
    private IReadOnlyList<string> _decoyPaths = [];
    private string? _decoyPathsFile;

    /// <summary>
    /// Sets what the next launch does: per-PID network capture and/or SACL read-auditing of the given decoy
    /// paths. Call before <see cref="Start"/> / <see cref="Restart"/>.
    /// </summary>
    public void Configure(bool captureNet, IReadOnlyList<string>? decoyPaths)
    {
        _captureNet = captureNet;
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

    private bool LaunchSidecar(string pipeName, string nonce)
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "sidecar", "Foreman.EtwSidecar.exe");
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
