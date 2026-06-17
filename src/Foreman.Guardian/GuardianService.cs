using System.Runtime.Versioning;
using System.ServiceProcess;

namespace Foreman.Guardian;

/// <summary>
/// Windows Service host for the guardian (circle-back Phase A). The Service Control Manager launches it as
/// LocalSystem, so the head-seal key it opens is SYSTEM-scoped — unusable by the medium-IL agent. OnStart spins the
/// authenticated control pipe on a background task; OnStop cancels it. Reached only via <c>--service</c> (SCM); the
/// plain console run uses the same authority + pipe for smoke tests.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class GuardianService : ServiceBase
{
    private CancellationTokenSource? _cts;
    private GuardianAuthority? _authority;
    private Task? _loop;

    public GuardianService() => ServiceName = GuardianInstaller.ServiceName;

    protected override void OnStart(string[] args)
    {
        _cts = new CancellationTokenSource();
        _authority = GuardianAuthority.CreateWithTpmKey();
        GuardianLog.Write($"started; headKey={(_authority.HeadKeyAvailable ? "available" : "unavailable (no TPM)")}");
        var server = new GuardianPipeServer(_authority, m => GuardianLog.Write(m));
        _loop = Task.Run(() => server.RunAsync(_cts.Token));
    }

    protected override void OnStop()
    {
        GuardianLog.Write("stopping");
        _cts?.Cancel();
        try { _loop?.Wait(TimeSpan.FromSeconds(3)); } catch { /* shutting down */ }
        _authority?.Dispose();
    }
}
