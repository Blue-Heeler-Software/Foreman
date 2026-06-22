using System;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// An operator-bound desktop window identity for one-window-at-a-time confinement. It carries the exact handle AND
/// the owning pid AND a broker-assigned monotonic <see cref="Epoch"/>, so a recycled HWND or a re-bind (which bumps
/// the Epoch) is detectable at delivery (spec INV-2). user32 stays OUT of Foreman.Core: an
/// <see cref="IDesktopWindowProbe"/> captures and liveness-checks these refs; the broker only reasons over the data.
/// </summary>
public sealed record CuWindowRef(IntPtr Hwnd, int OwnerPid, string ProcessName, string TitleAtBind, long Epoch)
{
    /// <summary>True only if BOTH the handle and the owning pid match (handle-reuse defense; callers also check
    /// <see cref="Epoch"/> and <see cref="IDesktopWindowProbe.IsAlive"/>).</summary>
    public bool Matches(IntPtr candidate, int candidatePid) => candidate == Hwnd && candidatePid == OwnerPid;
}
