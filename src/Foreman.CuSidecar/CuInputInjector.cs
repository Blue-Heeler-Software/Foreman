using System.Runtime.InteropServices;
using System.Text;
using Foreman.Core.ComputerUse;

/// <summary>
/// The Slice 4b-2 input injector (sidecar side). Executes ONE atomic gesture as a sequence of SINGLE INPUTs, and
/// before EVERY INPUT re-checks the hard invariants - so a panic, a confinement break, or a bound-window change can
/// never be crossed mid-gesture:
///   - panic: read the shared MMF (seqlock) via <paramref name="panicNow"/>; panic=1 => abort with HaltedMidStream.
///   - INV-2: the action's BoundHwnd must equal the AUTHORITATIVE MMF boundHwnd (never trust the pipe payload alone).
///   - confinement (INV-9 + foreground): the foreground window must BE the bound window, never Foreman's own UI, never
///     shell chrome; verified immediately before AND after each single INPUT. No bare absolute move - a move resolves
///     to the bound window's client rect or is refused.
///   - one-INPUT-per-batch: every SendInput call carries exactly ONE INPUT (nInputs=1), so panic interleaves between
///     each. dwExtraInfo is stamped with Foreman's magic (INV-4 sub-classifies our injection).
/// Refuses (Ok=false) rather than injecting blind on any failed gate.
/// </summary>
internal static class CuInputInjector
{
    public const ulong Magic = 0x464F5245;   // "FORE"

    public static ExecuteActionResult Execute(ExecuteActionArgs args, Func<PanicSnapshot> panicNow, int foremanPid)
    {
        var bound = (IntPtr)args.BoundHwnd;
        if (bound == IntPtr.Zero) return Fail("no bound window");

        var snap0 = panicNow();
        if (snap0.Panic != 0) return Halted();
        if (snap0.BoundHwnd != args.BoundHwnd) return Fail("BoundHwnd != authoritative MMF boundHwnd (INV-2)");

        // Build the atomic INPUT steps for the verb up front (pure), then gate + inject each one.
        var steps = BuildSteps(args, bound, out var buildErr);
        if (steps is null) return Fail(buildErr);

        // Best-effort bring the bound window forward; the per-step confine check is what actually gates (no blind inject).
        try { SetForegroundWindow(bound); } catch { }

        foreach (var step in steps)
        {
            var snap = panicNow();
            if (snap.Panic != 0) return Halted();
            if (snap.BoundHwnd != args.BoundHwnd) return Fail("bound window changed mid-gesture (INV-2)");
            if (!Confined(bound, foremanPid, out var why)) return Fail("not confined: " + why);

            if (!args.DryRun)
            {
                var one = new[] { step };
                if (SendInput(1, one, Marshal.SizeOf<INPUT>()) != 1) return Fail("SendInput rejected");
            }

            if (!Confined(bound, foremanPid, out var why2)) return Fail("foreground changed during input: " + why2);
        }

        GetCursorPos(out var pt);
        var finalFg = GetForegroundWindow();
        return new ExecuteActionResult(Ok: true, Error: null, FinalHwnd: finalFg.ToInt64(), CursorX: pt.X, CursorY: pt.Y, HaltedMidStream: false);
    }

    // Foreground confinement + INV-9. The foreground must be exactly the bound window; reject Foreman's own windows and
    // shell chrome outright. (Owned-popup / menu-class relaxation for read-only verbs is a later refinement - 4b-2 is strict.)
    private static bool Confined(IntPtr bound, int foremanPid, out string why)
    {
        why = string.Empty;
        var fg = GetForegroundWindow();
        if (fg == IntPtr.Zero) { why = "no foreground window"; return false; }
        GetWindowThreadProcessId(fg, out var fgPid);
        if ((int)fgPid == foremanPid) { why = "foreground is Foreman's own UI (INV-9)"; return false; }
        var cls = ClassOf(fg);
        if (cls is "Shell_TrayWnd" or "NotifyIconOverflowWindow" or "Progman" or "WorkerW")
        { why = $"foreground is shell chrome ({cls})"; return false; }
        if (fg != bound) { why = "foreground is not the bound window"; return false; }
        return true;
    }

    private static List<INPUT>? BuildSteps(ExecuteActionArgs args, IntPtr bound, out string err)
    {
        err = string.Empty;
        var verb = (args.Verb ?? string.Empty).Trim().ToLowerInvariant();
        switch (verb)
        {
            case "move":
                return TryClientPoint(args, bound, out var mp, out err) ? new() { MouseMove(mp) } : null;
            case "left_click":
                return TryClientPoint(args, bound, out var lp, out err)
                    ? new() { MouseMove(lp), MouseBtn(MOUSEEVENTF_LEFTDOWN), MouseBtn(MOUSEEVENTF_LEFTUP) } : null;
            case "right_click":
                return TryClientPoint(args, bound, out var rp, out err)
                    ? new() { MouseMove(rp), MouseBtn(MOUSEEVENTF_RIGHTDOWN), MouseBtn(MOUSEEVENTF_RIGHTUP) } : null;
            case "middle_click":
                return TryClientPoint(args, bound, out var cp, out err)
                    ? new() { MouseMove(cp), MouseBtn(MOUSEEVENTF_MIDDLEDOWN), MouseBtn(MOUSEEVENTF_MIDDLEUP) } : null;
            case "scroll":
            {
                if (!int.TryParse(Arg(args, "amount"), out var amt)) { err = "scroll needs an integer 'amount'"; return null; }
                return new() { Wheel(amt) };
            }
            case "key":
            {
                if (!ushort.TryParse(Arg(args, "vk"), out var vk)) { err = "key needs a numeric 'vk'"; return null; }
                return new() { KeyVk(vk, down: true), KeyVk(vk, down: false) };
            }
            case "type":
            {
                var text = Arg(args, "text");
                if (string.IsNullOrEmpty(text)) { err = "type needs non-empty 'text'"; return null; }
                var steps = new List<INPUT>();
                foreach (var ch in text) { steps.Add(KeyUnicode(ch, down: true)); steps.Add(KeyUnicode(ch, down: false)); }
                return steps;
            }
            default:
                err = $"unsupported verb '{verb}'";
                return null;
        }
    }

    // A move/click point is the bound window's CLIENT coordinates; it must lie inside the client rect (no bare absolute
    // moves anywhere on screen), then maps to a virtual-desktop-normalised absolute coordinate.
    private static bool TryClientPoint(ExecuteActionArgs args, IntPtr bound, out POINT screenAbs, out string err)
    {
        screenAbs = default; err = string.Empty;
        if (!int.TryParse(Arg(args, "x"), out var cx) || !int.TryParse(Arg(args, "y"), out var cy))
        { err = "move/click needs integer client 'x'/'y'"; return false; }
        if (!GetClientRect(bound, out var rc)) { err = "could not read bound client rect"; return false; }
        if (cx < 0 || cy < 0 || cx > rc.Right || cy > rc.Bottom) { err = "point is outside the bound client rect"; return false; }
        var p = new POINT { X = cx, Y = cy };
        if (!ClientToScreen(bound, ref p)) { err = "ClientToScreen failed"; return false; }
        screenAbs = p;
        return true;
    }

    private static string Arg(ExecuteActionArgs a, string k) => a.Args.TryGetValue(k, out var v) ? v : string.Empty;

    // ── INPUT builders ───────────────────────────────────────────────────────────────────────────────
    private static INPUT MouseMove(POINT screen)
    {
        // Normalise to the VIRTUAL desktop 0..65535 and use ABSOLUTE | VIRTUALDESK so multi-monitor maps correctly.
        var vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        var vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        var vw = Math.Max(1, GetSystemMetrics(SM_CXVIRTUALSCREEN));
        var vh = Math.Max(1, GetSystemMetrics(SM_CYVIRTUALSCREEN));
        var nx = (int)Math.Round((screen.X - vx) * 65535.0 / vw);
        var ny = (int)Math.Round((screen.Y - vy) * 65535.0 / vh);
        return Mouse(nx, ny, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK);
    }

    private static INPUT MouseBtn(uint flags) => Mouse(0, 0, 0, flags);
    private static INPUT Wheel(int amount) => Mouse(0, 0, (uint)amount, MOUSEEVENTF_WHEEL);

    private static INPUT Mouse(int dx, int dy, uint data, uint flags) => new()
    {
        type = INPUT_MOUSE,
        U = new InputUnion { mi = new MOUSEINPUT { dx = dx, dy = dy, mouseData = data, dwFlags = flags, dwExtraInfo = (IntPtr)Magic } },
    };

    private static INPUT KeyVk(ushort vk, bool down) => new()
    {
        type = INPUT_KEYBOARD,
        U = new InputUnion { ki = new KEYBDINPUT { wVk = vk, dwFlags = down ? 0 : KEYEVENTF_KEYUP, dwExtraInfo = (IntPtr)Magic } },
    };

    private static INPUT KeyUnicode(char ch, bool down) => new()
    {
        type = INPUT_KEYBOARD,
        U = new InputUnion { ki = new KEYBDINPUT { wScan = ch, dwFlags = KEYEVENTF_UNICODE | (down ? 0u : KEYEVENTF_KEYUP), dwExtraInfo = (IntPtr)Magic } },
    };

    private static ExecuteActionResult Fail(string err) => new(false, err);
    private static ExecuteActionResult Halted() => new(false, "halted", HaltedMidStream: true);

    private static string ClassOf(IntPtr hwnd)
    {
        var sb = new StringBuilder(256);
        return GetClassName(hwnd, sb, sb.Capacity) > 0 ? sb.ToString() : string.Empty;
    }

    // ── Win32 ────────────────────────────────────────────────────────────────────────────────────────
    private const uint INPUT_MOUSE = 0, INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_KEYUP = 0x0002, KEYEVENTF_UNICODE = 0x0004;
    private const uint MOUSEEVENTF_MOVE = 0x0001, MOUSEEVENTF_ABSOLUTE = 0x8000, MOUSEEVENTF_VIRTUALDESK = 0x4000, MOUSEEVENTF_WHEEL = 0x0800;
    private const uint MOUSEEVENTF_LEFTDOWN = 0x0002, MOUSEEVENTF_LEFTUP = 0x0004;
    private const uint MOUSEEVENTF_RIGHTDOWN = 0x0008, MOUSEEVENTF_RIGHTUP = 0x0010;
    private const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020, MOUSEEVENTF_MIDDLEUP = 0x0040;
    private const int SM_XVIRTUALSCREEN = 76, SM_YVIRTUALSCREEN = 77, SM_CXVIRTUALSCREEN = 78, SM_CYVIRTUALSCREEN = 79;

    [StructLayout(LayoutKind.Sequential)] private struct INPUT { public uint type; public InputUnion U; }
    [StructLayout(LayoutKind.Explicit)] private struct InputUnion { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] private struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] private struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] private struct POINT { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint n, INPUT[] inputs, int cb);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr hWnd, StringBuilder buf, int max);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetClientRect(IntPtr hWnd, out RECT rc);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ClientToScreen(IntPtr hWnd, ref POINT pt);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetCursorPos(out POINT pt);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
}
