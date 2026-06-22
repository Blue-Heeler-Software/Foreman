using System;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// Keeps user32 out of Foreman.Core: the App supplies the real Win32 desktop-window probe; tests supply a fake.
/// Used by the broker/executor to bind, liveness-check, and resolve desktop windows for one-window confinement.
/// </summary>
public interface IDesktopWindowProbe
{
    /// <summary>The current foreground window as a <see cref="CuWindowRef"/> (Epoch left 0 — the broker assigns the
    /// monotonic Epoch on bind), or null if none/foreground couldn't be resolved.</summary>
    CuWindowRef? CaptureForeground();

    /// <summary>True if the window still exists with the SAME owning pid (recycled-handle defense).</summary>
    bool IsAlive(CuWindowRef w);

    /// <summary>The root owner of an HWND, so a child/popup resolves to its top-level owner window.</summary>
    IntPtr RootOwner(IntPtr hwnd);
}
