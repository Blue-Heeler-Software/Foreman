using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Foreman.Core.ComputerUse;

namespace Foreman.App.ComputerUse;

/// <summary>
/// The App-side user32 implementation of <see cref="IDesktopWindowProbe"/> (kept out of Foreman.Core). Captures the
/// foreground window for binding, liveness-checks a bound window (recycled-handle defense, spec INV-2), and resolves a
/// child/popup to its root owner. The broker reasons only over the returned <see cref="CuWindowRef"/> data.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class Win32WindowProbe : IDesktopWindowProbe
{
    public CuWindowRef? CaptureForeground()
    {
        var fg = GetForegroundWindow();
        if (fg == IntPtr.Zero) return null;
        var root = RootOwner(fg);
        if (!GetWindowThreadProcessId(root, out var pid) || pid == 0) return null;

        string proc = string.Empty;
        try { using var p = Process.GetProcessById(pid); proc = p.ProcessName; } catch { /* gone/denied -> empty */ }
        // Epoch 0: the broker assigns the monotonic Epoch on bind (SetActiveWindow).
        return new CuWindowRef(root, pid, proc, GetTitle(root), Epoch: 0);
    }

    public bool IsAlive(CuWindowRef w)
    {
        if (w.Hwnd == IntPtr.Zero || !IsWindow(w.Hwnd)) return false;
        // Same handle AND same owning pid: a recycled HWND (reassigned to a new process) fails the pid check.
        return GetWindowThreadProcessId(w.Hwnd, out var pid) && pid == w.OwnerPid;
    }

    public IntPtr RootOwner(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero) return IntPtr.Zero;
        var r = GetAncestor(hwnd, GA_ROOTOWNER);
        return r == IntPtr.Zero ? hwnd : r;
    }

    private static string GetTitle(IntPtr hwnd)
    {
        var len = GetWindowTextLength(hwnd);
        if (len <= 0) return string.Empty;
        var sb = new StringBuilder(len + 1);
        return GetWindowText(hwnd, sb, sb.Capacity) > 0 ? sb.ToString() : string.Empty;
    }

    private const uint GA_ROOTOWNER = 3;

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowThreadProcessId(IntPtr hWnd, out int pid);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder sb, int max);
}
