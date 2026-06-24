#if DEBUG
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Windows;
using System.Windows.Automation;
using Foreman.Core.ComputerUse;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Developer on-device smoke test for the desktop CU injector spine (run via <c>Foreman.exe --cu-smoketest</c>).
/// It drives the REAL path - launch Notepad, bind its window, start + handshake the medium-IL sidecar, then
/// <see cref="DesktopCuController.ExecuteAsync"/> a "type" gesture (the controller independently verifies, INV-5, that
/// the input landed in the bound foreground window) - and then a PANIC test: it sets the shared halt byte and confirms
/// a second type is refused. Results go to a temp log file (this is a WinExe, no console). NOT a production path; it
/// bypasses the broker/audit/operator-approval chain on purpose to isolate the on-device injector + panic byte.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class CuSmokeTest
{
    public const string Flag = "--cu-smoketest";
    public static string LogPath => Path.Combine(Path.GetTempPath(), "foreman-cu-smoketest.log");

    public static void RunToFileAndExit(Application app)
    {
        _ = Task.Run(async () =>
        {
            int code; string report;
            try { (code, report) = await RunAsync().ConfigureAwait(false); }
            catch (Exception ex) { code = 99; report = "smoketest threw:\n" + ex; }
            try { File.WriteAllText(LogPath, report); } catch { }
            try { app.Dispatcher.Invoke(() => app.Shutdown(code)); } catch { }
        });
    }

    private static async Task<(int code, string report)> RunAsync()
    {
        var sb = new StringBuilder();
        void Log(string m) => sb.AppendLine(m);
        Log("=== Foreman desktop-CU injector smoke test ===");
        Log($"time(utc-ish via Stopwatch only); pid={Environment.ProcessId}; baseDir={AppContext.BaseDirectory}");
        Log($"sidecar path: {DesktopCuController.SidecarPath()} (exists={File.Exists(DesktopCuController.SidecarPath())})");
        Log("");

        Process? np = null;
        var notepadPid = 0;
        DesktopCuController? ctl = null;
        CuSharedPanicFlag? flag = null;
        try
        {
            // 1. Launch Notepad and find its top-level window. On Win11 notepad.exe is a packaged app, so the launched
            //    Process's MainWindowHandle never populates (the window belongs to a different PID) - enumerate windows
            //    by title instead, which is PID-agnostic.
            np = Process.Start(new ProcessStartInfo("notepad.exe") { UseShellExecute = true });
            IntPtr hwnd = IntPtr.Zero;
            for (var i = 0; i < 60 && hwnd == IntPtr.Zero; i++)
            {
                hwnd = FindWindowByTitle("Notepad");
                if (hwnd == IntPtr.Zero) await Task.Delay(200).ConfigureAwait(false);
            }
            if (hwnd == IntPtr.Zero) return (2, sb + "\nFAIL: Notepad window never appeared");
            GetWindowThreadProcessId(hwnd, out notepadPid);
            Log($"notepad window hwnd={hwnd.ToInt64()} ownerPid={notepadPid}");
            await EnsureForeground(hwnd).ConfigureAwait(false);

            // 2. Bind the window in the shared panic/bind map and start + handshake the sidecar.
            flag = new CuSharedPanicFlag();
            flag.SetBound(hwnd.ToInt64());
            var verifFailed = false;
            ctl = new DesktopCuController { PanicFlag = flag };
            ctl.OnSecurityNotice = (sev, m) => Log($"  [sidecar notice {sev}] {m}");
            ctl.OnVerificationFailure = () => verifFailed = true;
            ctl.Start();
            for (var i = 0; i < 75 && !ctl.IsConnected; i++) await Task.Delay(200).ConfigureAwait(false);
            if (!ctl.IsConnected) return (3, sb + "\nFAIL: sidecar never connected/handshaked");
            Log("sidecar launched + 3-gate handshake OK + shared panic map mapped");

            var fgOk = await EnsureForeground(hwnd).ConfigureAwait(false);
            Log($"foreground == bound Notepad: {fgOk} (fg={GetForegroundWindow().ToInt64()}, bound={hwnd.ToInt64()})");

            // 3. The real injection: type into the bound Notepad window. The controller verifies (INV-5) that the
            //    foreground the APP itself reads == the bound window == the sidecar's self-reported FinalHwnd.
            const string msg = "Hello from Foreman";   // <=120 inputs/gesture (the injector caps long gestures; split upstream)
            var r1 = await ctl.ExecuteAsync(new ExecuteActionArgs(
                Guid.NewGuid().ToString("N"), "type",
                new Dictionary<string, string> { ["text"] = msg }, hwnd.ToInt64())).ConfigureAwait(false);
            await Task.Delay(400).ConfigureAwait(false);
            Log($"type result: Ok={r1?.Ok} finalHwnd={r1?.FinalHwnd} err={r1?.Error}");
            var readback = TryReadText(hwnd);
            Log($"readback (UIA): {(readback is null ? "<unavailable>" : "\"" + readback.Replace("\r", " ").Replace("\n", " ").Trim() + "\"")}");

            // 4. PANIC: set the shared halt byte, then attempt a second type that MUST be refused.
            flag.SetHalted(true);
            await Task.Delay(150).ConfigureAwait(false);
            var r2 = await ctl.ExecuteAsync(new ExecuteActionArgs(
                Guid.NewGuid().ToString("N"), "type",
                new Dictionary<string, string> { ["text"] = " THIS-MUST-NOT-APPEAR-AFTER-PANIC" }, hwnd.ToInt64())).ConfigureAwait(false);
            await Task.Delay(300).ConfigureAwait(false);
            Log($"post-panic type result: Ok={r2?.Ok} halted={r2?.HaltedMidStream} err={r2?.Error}");
            var readback2 = TryReadText(hwnd);
            flag.SetHalted(false);

            // Verdicts.
            var injected = r1 is { Ok: true } && !verifFailed;
            var textPresent = readback?.Contains("Hello from Foreman", StringComparison.Ordinal) == true;
            var panicRefused = r2 is null || r2.Ok == false;
            var noLeak = readback2 is null || !readback2.Contains("THIS-MUST-NOT-APPEAR", StringComparison.Ordinal);

            Log("");
            Log($"[{(injected ? "PASS" : "FAIL")}] injection executed + INV-5 independently verified into the bound window");
            Log($"[{(textPresent ? "PASS" : readback is null ? "N/A " : "FAIL")}] typed text read back from Notepad" +
                (readback is null ? " (UIA readback unavailable; relied on INV-5)" : ""));
            Log($"[{(panicRefused ? "PASS" : "FAIL")}] second type REFUSED after panic halt");
            Log($"[{(noLeak ? "PASS" : "FAIL")}] no post-panic text leaked into Notepad");

            var overall = injected && panicRefused && noLeak;
            Log("");
            Log($"OVERALL: {(overall ? "PASS" : "FAIL")}");
            return (overall ? 0 : 10, sb.ToString());
        }
        finally
        {
            try { ctl?.Stop(); } catch { }
            try { flag?.Dispose(); } catch { }
            try { if (notepadPid != 0) Process.GetProcessById(notepadPid).Kill(); } catch { }   // discard unsaved Notepad
            try { if (np is { HasExited: false }) np.Kill(); } catch { }
        }
    }

    // Find the first visible top-level window whose title contains <paramref name="needle"/> (PID-agnostic, so it works
    // with Win11's packaged Notepad whose window belongs to a different process than the launched one).
    private static IntPtr FindWindowByTitle(string needle)
    {
        var found = IntPtr.Zero;
        EnumWindows((h, _) =>
        {
            if (!IsWindowVisible(h)) return true;
            var len = GetWindowTextLength(h);
            if (len <= 0) return true;
            var sb = new StringBuilder(len + 1);
            GetWindowText(h, sb, sb.Capacity);
            if (sb.ToString().Contains(needle, StringComparison.OrdinalIgnoreCase)) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    // Best-effort readback via UI Automation (works across classic + Win11 Notepad's document control). Null if the
    // text can't be read - the test then relies on the controller's INV-5 verification of the injection.
    private static string? TryReadText(IntPtr hwnd)
    {
        try
        {
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

    // Force a window genuinely foreground despite Windows' foreground-stealing lock (a process not itself in the
    // foreground normally cannot SetForegroundWindow). Clears the lock timeout, then does the AttachThreadInput dance.
    // Test-harness only - the production injector NEVER forces foreground; it REFUSES off-window input.
    private static async Task<bool> EnsureForeground(IntPtr hwnd)
    {
        for (var i = 0; i < 12; i++)
        {
            try
            {
                SystemParametersInfo(SPI_SETFOREGROUNDLOCKTIMEOUT, 0, IntPtr.Zero, SPIF_SENDCHANGE);
                ShowWindow(hwnd, SW_RESTORE);
                var fg = GetForegroundWindow();
                var ourTid = GetCurrentThreadId();
                var fgTid = GetWindowThreadProcessId(fg, out _);
                var tgtTid = GetWindowThreadProcessId(hwnd, out _);
                AttachThreadInput(ourTid, fgTid, true);
                AttachThreadInput(ourTid, tgtTid, true);
                BringWindowToTop(hwnd);
                SetForegroundWindow(hwnd);
                AttachThreadInput(ourTid, tgtTid, false);
                AttachThreadInput(ourTid, fgTid, false);
            }
            catch { }
            await Task.Delay(150).ConfigureAwait(false);
            if (GetForegroundWindow() == hwnd) return true;
        }
        return GetForegroundWindow() == hwnd;
    }

    private const uint SPI_SETFOREGROUNDLOCKTIMEOUT = 0x2001;
    private const uint SPIF_SENDCHANGE = 0x0002;
    private const int SW_RESTORE = 9;

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BringWindowToTop(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, [MarshalAs(UnmanagedType.Bool)] bool fAttach);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SystemParametersInfo(uint uiAction, uint uiParam, IntPtr pvParam, uint fWinIni);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder sb, int max);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int pid);
}
#endif
