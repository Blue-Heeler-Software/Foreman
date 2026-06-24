using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Foreman.App.ComputerUse;

/// <summary>How long since the operator last touched the keyboard/mouse (GetLastInputInfo). Wired into
/// <see cref="Foreman.Core.ComputerUse.CuBroker.OperatorIdle"/> so a bounded auto-grant pauses while the operator is
/// away (INV-15). System-wide last input across all sessions/input desktops on this station.</summary>
[SupportedOSPlatform("windows")]
public static class OperatorActivity
{
    public static TimeSpan IdleTime()
    {
        var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        if (!GetLastInputInfo(ref lii)) return TimeSpan.Zero;   // unknown -> treat as active (don't falsely pause)
        // Unsigned tick subtraction handles the ~49-day TickCount wrap correctly for short idle spans.
        var idleMs = unchecked((uint)Environment.TickCount - lii.dwTime);
        return TimeSpan.FromMilliseconds(idleMs);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
}
