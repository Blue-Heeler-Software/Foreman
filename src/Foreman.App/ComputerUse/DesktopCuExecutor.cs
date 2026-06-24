using System.Runtime.Versioning;
using Foreman.Core.ComputerUse;

namespace Foreman.App.ComputerUse;

/// <summary>
/// The desktop <see cref="ICuExecutor"/>: runs an APPROVED desktop <see cref="CuBrokerItem"/> through the verified
/// medium-IL sidecar injector via <see cref="DesktopCuController.ExecuteAsync"/>. The controller independently verifies
/// the result against the bound window (INV-5) and hard-kills + halts on any mismatch, so this executor's returned
/// CuExecResult is the controller's already-verified outcome. <see cref="IsReady"/> tracks the sidecar handshake.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DesktopCuExecutor : ICuExecutor
{
    private readonly DesktopCuController _controller;
    private readonly Func<long> _boundHwnd;   // the authoritative MMF bound HWND (PanicFlag.BoundHwnd)

    public DesktopCuExecutor(DesktopCuController controller, Func<long> boundHwnd)
    {
        _controller = controller;
        _boundHwnd = boundHwnd;
    }

    public CuModality Modality => CuModality.Desktop;
    public bool IsReady => _controller.IsConnected;

    public async Task<CuExecResult> ExecuteAsync(CuBrokerItem item, CancellationToken ct = default)
    {
        var a = item.Action;
        var args = new ExecuteActionArgs(item.ActionId, a.Verb, a.Args, _boundHwnd());
        var r = await _controller.ExecuteAsync(args, ct).ConfigureAwait(false);
        if (r is null) return new CuExecResult(false, null, "desktop executor unavailable (sidecar killed / timed out)");
        return new CuExecResult(r.Ok, new { r.FinalHwnd, r.CursorX, r.CursorY, r.HaltedMidStream }, r.Error);
    }
}
