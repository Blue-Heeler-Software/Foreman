using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Foreman.Core.Ipc;

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
            _ = Task.Run(() => RunAsync(_cts.Token));
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

    private async Task RunAsync(CancellationToken ct)
    {
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
        catch { /* pipe/launch failure — Net simply stays n/a */ }
        finally { _connected = false; }
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

    private static bool LaunchSidecar(string pipeName, string nonce)
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "sidecar", "Foreman.EtwSidecar.exe");
        if (!File.Exists(exe)) return false;
        try
        {
            // UseShellExecute=true is required for the sidecar's requireAdministrator manifest to
            // raise the UAC prompt. If the user declines, Process.Start throws (1223) — Net stays n/a.
            Process.Start(new ProcessStartInfo(exe)
            {
                Arguments = $"--pipe {pipeName} --nonce {nonce} --parent {Environment.ProcessId}",
                UseShellExecute = true,
            });
            return true;
        }
        catch { return false; }
    }

    public void Dispose() => Stop();
}
