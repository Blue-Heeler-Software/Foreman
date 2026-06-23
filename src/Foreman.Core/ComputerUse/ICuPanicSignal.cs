namespace Foreman.Core.ComputerUse;

/// <summary>
/// The shared panic + bound-window signal the desktop sidecar reads before every input (Slice 4) and the App writes.
/// Backed (Slice 4a impl) by an UNNAMED memory-mapped file the App owns read-write; the sidecar gets a read-only
/// DUPLICATED handle, so per spec INV-2/INV-3 it cannot clear the halt or move the bound window. The App mirrors
/// <c>CuPanicState.Changed</c> into this. (A cross-process auto-reset WAKE event is a Slice-4b optimisation - the
/// hard floor is the App killing the sidecar, not the sidecar noticing the byte.)
/// </summary>
public interface ICuPanicSignal
{
    /// <summary>True while computer use is halted (panic). The sidecar refuses to inject while set.</summary>
    bool IsHalted { get; }

    /// <summary>The bound CU window handle the sidecar must confine input to (0 = none).</summary>
    long BoundHwnd { get; }

    /// <summary>Monotonic epoch bumped on every halt or (re)bind, so a stale read is detectable.</summary>
    long Epoch { get; }

    /// <summary>App-only: set/clear the halt; the sidecar observes it on its next pre-input read (Slice 4b also adds the
    /// App-side TerminateProcess + BlockInput hard floor, which does not depend on the sidecar noticing this byte).</summary>
    void SetHalted(bool halted);

    /// <summary>App-only: publish the bound window (and bump the epoch) for the sidecar to confine to.</summary>
    void SetBound(long hwnd);
}
