namespace Foreman.Core.ComputerUse;

/// <summary>
/// The shared panic + bound-window signal the desktop sidecar reads before every input (Slice 4) and the App writes.
/// Backed by a named memory-mapped file plus an auto-reset event (the App-side impl, Slice 3). Per spec INV-2/INV-3
/// the sidecar must NOT be able to clear the halt or move the bound window — that read-only-to-sidecar guarantee is
/// completed in Slice 4 by handing the sidecar a read-only duplicated handle (a same-user named DACL alone cannot
/// distinguish two processes of the same user). The App mirrors <c>CuPanicState.Changed</c> into this.
/// </summary>
public interface ICuPanicSignal
{
    /// <summary>True while computer use is halted (panic). The sidecar refuses to inject while set.</summary>
    bool IsHalted { get; }

    /// <summary>The bound CU window handle the sidecar must confine input to (0 = none).</summary>
    long BoundHwnd { get; }

    /// <summary>Monotonic epoch bumped on every halt or (re)bind, so a stale read is detectable.</summary>
    long Epoch { get; }

    /// <summary>App-only: set/clear the halt and pulse the wake event so the sidecar reacts immediately.</summary>
    void SetHalted(bool halted);

    /// <summary>App-only: publish the bound window (and bump the epoch) for the sidecar to confine to.</summary>
    void SetBound(long hwnd);
}
