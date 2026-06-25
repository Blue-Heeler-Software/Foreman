using System.Runtime.Versioning;
using System.Windows.Automation;
using Foreman.Core.ComputerUse;
using Foreman.Core.Events;
using Foreman.Core.Models;

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
        // Bind to the window this action was APPROVED against - the broker stamps "hwnd" onto the action at Claim - NOT
        // the live MMF. So if the operator re-binds between Claim and execute, args.BoundHwnd no longer matches the live
        // bound window and the controller refuses (below) rather than redirecting the action into the new window (INV-2).
        var boundHwnd = long.TryParse(a.Arg("hwnd"), out var h) ? h : _boundHwnd();
        var args = new ExecuteActionArgs(item.ActionId, a.Verb, a.Args, boundHwnd);
        var r = await _controller.ExecuteAsync(args, ct).ConfigureAwait(false);
        if (r is null) return new CuExecResult(false, null, "desktop executor unavailable (sidecar killed / timed out)");

        // Best-effort fidelity check (warn-only): the controller's INV-5 already proved the input landed in the BOUND
        // window, but a receiver with an async text pipeline (e.g. the Win11 Notepad island) can still RENDER typed text
        // garbled. Read the target back and flag a mismatch so the operator/agent knows the text may not be faithful. No
        // auto-retry: re-typing would duplicate/compound a substitution-garble, and a wrong-window type is already an
        // INV-5 failure above.
        if (r.Ok && string.Equals(a.Verb?.Trim(), "type", StringComparison.OrdinalIgnoreCase)
            && a.Arg("text") is { Length: > 0 } expected)
        {
            var got = TryReadText((IntPtr)boundHwnd);
            if (got is not null && !got.Contains(expected, StringComparison.Ordinal))
                Publish(ForemanSeverity.Low,
                    "Typed text did not verify against the target window - the receiver may have dropped or altered " +
                    "characters (the input WAS delivered to the bound window, INV-5-verified; only the rendered text differs).");
        }

        // Record which monitor the action ran on, so the pump/audit/log is monitor-aware.
        var monitor = MonitorProbe.ForWindow((IntPtr)boundHwnd)?.Summary;
        return new CuExecResult(r.Ok, new { r.FinalHwnd, r.CursorX, r.CursorY, r.HaltedMidStream, Monitor = monitor }, r.Error);
    }

    private static void Publish(ForemanSeverity sev, string message)
    {
        try { EventBus.Instance.Publish(new MonitoringNoticeEvent(DateTimeOffset.UtcNow, sev, "Foreman.ComputerUse", message)); }
        catch { /* fidelity note is best-effort */ }
    }

    // Best-effort UIA readback of the bound window's text (Document/Edit TextPattern, ValuePattern fallback). Null if it
    // can't be read - then we simply don't warn (can't-verify != failed).
    private static string? TryReadText(IntPtr hwnd)
    {
        try
        {
            if (hwnd == IntPtr.Zero) return null;
            var root = AutomationElement.FromHandle(hwnd);
            if (root is null) return null;
            var doc = root.FindFirst(TreeScope.Subtree, new OrCondition(
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Document),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit))) ?? root;
            if (doc.TryGetCurrentPattern(TextPattern.Pattern, out var tp))
                return ((TextPattern)tp).DocumentRange.GetText(-1);
            if (doc.TryGetCurrentPattern(ValuePattern.Pattern, out var vp))
                return ((ValuePattern)vp).Current.Value;
            return null;
        }
        catch { return null; }
    }
}
