using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Which physical monitor a window is on, so desktop CU is monitor-aware: the HUD positions itself on the bound
/// window's monitor, and the bound-window descriptor records it. All coordinates are PHYSICAL pixels (so callers can
/// SetWindowPos directly without DIP/per-monitor-DPI conversion).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class MonitorProbe
{
    public readonly record struct MonInfo(
        int Index, bool Primary,
        int Left, int Top, int Width, int Height,             // full monitor rect (physical px)
        int WorkLeft, int WorkTop, int WorkWidth, int WorkHeight)   // work area (excludes taskbar)
    {
        public string Summary => $"monitor {Index}{(Primary ? " (primary)" : "")} {Width}x{Height} @ ({Left},{Top})";
    }

    public static MonInfo? ForWindow(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero) return null;
        var hMon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        if (hMon == IntPtr.Zero) return null;
        var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
        if (!GetMonitorInfo(hMon, ref mi)) return null;
        var primary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0;
        return new MonInfo(IndexOf(hMon), primary,
            mi.rcMonitor.Left, mi.rcMonitor.Top, mi.rcMonitor.Right - mi.rcMonitor.Left, mi.rcMonitor.Bottom - mi.rcMonitor.Top,
            mi.rcWork.Left, mi.rcWork.Top, mi.rcWork.Right - mi.rcWork.Left, mi.rcWork.Bottom - mi.rcWork.Top);
    }

    public static MonInfo? ForForeground() => ForWindow(GetForegroundWindow());

    // 1-based index in EnumDisplayMonitors order (stable enough for a human-readable "monitor N").
    private static int IndexOf(IntPtr hMon)
    {
        var i = 0; var found = 0;
        EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (h, _, _, _) => { i++; if (h == hMon) found = i; return true; }, IntPtr.Zero);
        return found > 0 ? found : 1;
    }

    private const uint MONITOR_DEFAULTTONEAREST = 2;
    private const uint MONITORINFOF_PRIMARY = 1;

    [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] private struct MONITORINFO { public int cbSize; public RECT rcMonitor; public RECT rcWork; public uint dwFlags; }

    private delegate bool MonitorEnumProc(IntPtr hMon, IntPtr hdc, IntPtr lprc, IntPtr data);

    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetMonitorInfo(IntPtr hMon, ref MONITORINFO mi);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr clip, MonitorEnumProc cb, IntPtr data);
}
