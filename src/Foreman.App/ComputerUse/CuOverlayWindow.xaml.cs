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
public partial class CuOverlayWindow : Window
{
    private const int GWL_EXSTYLE = -20;
    private const int WS_EX_TRANSPARENT = 0x20;
    private const int WS_EX_NOACTIVATE = 0x08000000;

    [DllImport("user32.dll")] private static extern int GetWindowLong(IntPtr hwnd, int index);
    [DllImport("user32.dll")] private static extern int SetWindowLong(IntPtr hwnd, int index, int newStyle);

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
}
