using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Interop;
using System.Windows.Threading;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Operator HUD overlay: a small, topmost, CLICK-THROUGH banner that screams "an AI is piloting" so even an
/// inattentive human can't miss it. On each takeover it runs a LOCALISED attention animation — a border-glow pulse
/// at ~2 Hz (far below the 12-30 Hz photosensitive danger band) plus a brief shake — then settles, and auto-hides
/// after a few idle seconds. It is click-through (WS_EX_TRANSPARENT) and never activates (WS_EX_NOACTIVATE) so it
/// can't steal focus or be driven into. Sizing/frequency are safe defaults today; operator config comes later.
/// </summary>
public partial class CuOverlayWindow : Window, Foreman.Core.ComputerUse.IHudAck
{
    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_TRANSPARENT = 0x20;
    private const int WS_EX_NOACTIVATE = 0x08000000;
    private const int WS_EX_TOPMOST = 0x00000008;
    private const uint GW_HWNDPREV = 3;                 // walks UP the z-order (toward the top)
    private const int DWMWA_CLOAKED = 14;
    private static readonly uint OurPid = (uint)Environment.ProcessId;

    private IntPtr _hwnd;   // cached so ConfirmVisible can run OFF the UI thread (the pump calls it from its loop)

    [DllImport("user32.dll")] private static extern int GetWindowLong(IntPtr hwnd, int index);
    [DllImport("user32.dll")] private static extern int SetWindowLong(IntPtr hwnd, int index, int newStyle);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetWindowRect(IntPtr hwnd, out RECT rc);
    [DllImport("user32.dll")] private static extern IntPtr GetWindow(IntPtr hwnd, uint cmd);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(IntPtr hwnd, int attr, out int value, int size);
    [DllImport("shell32.dll")] private static extern int SHQueryUserNotificationState(out int state);

    private const int QUNS_BUSY = 2, QUNS_RUNNING_D3D_FULL_SCREEN = 3, QUNS_PRESENTATION_MODE = 4;

    [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left, Top, Right, Bottom; }

    private readonly DispatcherTimer _hide;
    private static readonly TimeSpan AnnounceFor = TimeSpan.FromSeconds(4);   // 3-7s "fireworks" window
    private static readonly TimeSpan HideAfter = TimeSpan.FromSeconds(6);

    public CuOverlayWindow()
    {
        InitializeComponent();
        _hide = new DispatcherTimer { Interval = HideAfter };
        _hide.Tick += (_, _) => { _hide.Stop(); Hide(); };
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        // Click-through + never-activate, so the HUD floats over everything without intercepting input or focus.
        var h = new WindowInteropHelper(this).Handle;
        _hwnd = h;   // cache for the off-UI-thread ConfirmVisible occlusion test
        SetWindowLong(h, GWL_EXSTYLE, GetWindowLong(h, GWL_EXSTYLE) | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
    }

    /// <summary>Announce that the AI is piloting <paramref name="target"/>: show the banner top-centre, run the
    /// localised pulse + shake, and (re)arm the idle auto-hide. Safe to call repeatedly; each call re-announces.</summary>
    public void ShowDriving(string? target)
    {
        Label.Text = string.IsNullOrWhiteSpace(target)
            ? "CLAUDE DRIVING THRU FOREMAN"
            : $"CLAUDE DRIVING THRU FOREMAN — {target}";

        if (!IsVisible) Show();
        Reposition();
        Animate();
        _hide.Stop();
        _hide.Start();
    }

    private void Reposition()
    {
        // Top-centre of the primary work area. SizeToContent has measured the banner by now.
        Left = Math.Max(0, (SystemParameters.WorkArea.Width - ActualWidth) / 2);
        Top = SystemParameters.WorkArea.Top + 8;
    }

    private void Animate()
    {
        // LOCALISED glow pulse on the banner border only: 0.5s period = 2 Hz, repeated across the announce window.
        var pulses = Math.Max(1, (int)(AnnounceFor.TotalSeconds / 0.5));
        var glow = new DoubleAnimation(1.0, 0.25, new Duration(TimeSpan.FromSeconds(0.25)))
        {
            AutoReverse = true,
            RepeatBehavior = new RepeatBehavior(pulses),
        };
        GlowBrush.BeginAnimation(SolidColorBrush.OpacityProperty, glow);

        // Brief shake (motion, not flash — no photosensitive concern): +/-5px, ~8 Hz, for the announce window.
        var shakes = Math.Max(1, (int)(AnnounceFor.TotalSeconds / 0.125));
        var shake = new DoubleAnimation(-5, 5, new Duration(TimeSpan.FromSeconds(0.0625)))
        {
            AutoReverse = true,
            RepeatBehavior = new RepeatBehavior(shakes),
        };
        Shake.BeginAnimation(TranslateTransform.XProperty, shake);
    }

    // ── IHudAck (spec INV-8 / INV-18) ──────────────────────────────────────────────────────────────────

    /// <summary>Raise/keep the piloting banner up (sticky). The pump calls this every tick while there is approved work,
    /// so the idle auto-hide only fires once piloting stops. Marshals to the UI thread; animates only on first appearance.</summary>
    public void EnsureShown()
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(new Action(EnsureShown)); return; }
        if (string.IsNullOrWhiteSpace(Label.Text) || !IsVisible) Label.Text = "AI AGENT DRIVING THRU FOREMAN";
        Topmost = true;
        if (!IsVisible) { Show(); Animate(); }
        Reposition();
        _hide.Stop();
        _hide.Start();   // re-arm idle hide; re-called every pump tick while piloting, so it stays up
    }

    /// <summary>Adversarial occlusion test (INV-18), safe off the UI thread (uses only the cached HWND + thread-safe
    /// user32/DWM). True ONLY if the banner is visible, topmost, NOT DWM-cloaked, and NO other window above it in the
    /// z-order overlaps its rectangle. The HUD is click-through (WS_EX_TRANSPARENT) so WindowFromPoint would skip it -
    /// we enumerate windows ABOVE it in z-order instead (the spec's sanctioned method). Fail closed on any doubt.</summary>
    public bool ConfirmVisible()
    {
        var h = _hwnd;
        if (h == IntPtr.Zero || !IsWindowVisible(h)) return false;
        if (IsCloaked(h)) return false;
        if ((GetWindowLong(h, GWL_EXSTYLE) & WS_EX_TOPMOST) == 0) return false;

        // INV-18 forced handoff: a full-screen-exclusive (D3D) / presentation app can paint over everything WITHOUT
        // being a normal window above us in the z-order, so the walk below can't see it - the shell's notification state
        // does. Treat any full-screen/presentation/busy state as "HUD cannot be trusted visible" and fail closed.
        if (SHQueryUserNotificationState(out var quns) == 0 &&
            (quns == QUNS_BUSY || quns == QUNS_RUNNING_D3D_FULL_SCREEN || quns == QUNS_PRESENTATION_MODE))
            return false;

        if (!GetWindowRect(h, out var hud) || hud.Right <= hud.Left || hud.Bottom <= hud.Top) return false;

        // Any VISIBLE, non-cloaked, non-own window higher in the z-order whose rect overlaps the banner = occlusion.
        for (var w = GetWindow(h, GW_HWNDPREV); w != IntPtr.Zero; w = GetWindow(w, GW_HWNDPREV))
        {
            if (!IsWindowVisible(w) || IsCloaked(w)) continue;
            GetWindowThreadProcessId(w, out var pid);
            if (pid == OurPid) continue;   // Foreman's own windows aren't an adversarial occluder
            if (GetWindowRect(w, out var wr) && Overlaps(wr, hud)) return false;
        }
        return true;
    }

    private static bool IsCloaked(IntPtr h) =>
        DwmGetWindowAttribute(h, DWMWA_CLOAKED, out var cloaked, sizeof(int)) == 0 && cloaked != 0;

    private static bool Overlaps(RECT a, RECT b) =>
        a.Left < b.Right && a.Right > b.Left && a.Top < b.Bottom && a.Bottom > b.Top;
}
