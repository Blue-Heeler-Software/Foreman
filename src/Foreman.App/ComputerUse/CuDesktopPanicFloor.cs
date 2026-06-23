using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Foreman.App.ComputerUse;

/// <summary>
/// The ACTIVE half of the desktop computer-use panic floor (spec INV-3, Codex amendment #5). The shared MMF panic byte
/// is only the fast in-sidecar abort; THIS is the hard floor and it does NOT depend on the (forgeable-by-an-in-process
/// attacker) byte. On a halt it, in order:
///   1. arms an INDEPENDENT watchdog that will unconditionally <c>BlockInput(false)</c> after a short ceiling - so a
///      hang or throw in the body can NEVER leave the operator locked out (panic must never cause a worse failure);
///   2. <c>BlockInput(true)</c> as a bounded shield so nothing lands while we tear down (the calling thread's own
///      injected events still go through, which is how the release-all below works under the shield);
///   3. synthesises key-up / mouse-up for the modifiers and buttons so a half-held drag or chord cannot complete;
///   4. hard-kills the injector sidecar (<c>TerminateProcess</c> via the supplied delegate);
///   5. <c>BlockInput(false)</c> and cancels the watchdog.
/// Medium-IL, same-desktop, no special privilege (BlockInput + SendInput are all bounded per the spec).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class CuDesktopPanicFloor
{
    /// <summary>Foreman's injection marker stamped into dwExtraInfo so our own release-all is recognisable as ours
    /// (INV-4 sub-classifies OUR injection; the kernel LLMHF_INJECTED flag is the primary human-vs-injected test).</summary>
    public const ulong ForemanMagic = 0x464F5245;   // "FORE"

    private static readonly TimeSpan ShieldCeiling = TimeSpan.FromMilliseconds(750);

    private readonly Func<bool> _killSidecar;   // hard-kill the injector; returns true if something was killed
    private readonly object _gate = new();

    public CuDesktopPanicFloor(Func<bool> killSidecar) => _killSidecar = killSidecar;

    /// <summary>Invoke on panic (halt). Idempotent and safe to call when no sidecar is running. Never throws.</summary>
    public void Trigger()
    {
        lock (_gate)
        {
            // (1) Independent watchdog FIRST: even if everything below throws or wedges, input is restored.
            var done = new CancellationTokenSource();
            _ = Task.Run(async () =>
            {
                try { await Task.Delay(ShieldCeiling, done.Token).ConfigureAwait(false); } catch { /* cancelled = clean path won */ }
                try { BlockInput(false); } catch { }
            });

            try
            {
                try { BlockInput(true); } catch { }   // (2) bounded shield
                ReleaseHeldInput();                    // (3) drop modifiers + buttons
                try { _killSidecar(); } catch { }      // (4) hard kill the injector
            }
            finally
            {
                try { BlockInput(false); } catch { }   // (5) primary un-shield (watchdog is the backstop)
                try { done.Cancel(); } catch { }
            }
        }
    }

    // Synthesise key-up for the modifier keys and mouse-up for the three buttons, so nothing the injector left "down"
    // can keep acting after the kill. We release the dangerous chord/drag keys rather than enumerating every VK so we
    // do not fight the operator's own physically-held keys more than necessary.
    private static void ReleaseHeldInput()
    {
        ushort[] modifiers = { VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN };
        var inputs = new List<INPUT>();
        foreach (var vk in modifiers) inputs.Add(KeyUp(vk));
        inputs.Add(MouseUp(MOUSEEVENTF_LEFTUP));
        inputs.Add(MouseUp(MOUSEEVENTF_RIGHTUP));
        inputs.Add(MouseUp(MOUSEEVENTF_MIDDLEUP));
        try { SendInput((uint)inputs.Count, inputs.ToArray(), Marshal.SizeOf<INPUT>()); } catch { }
    }

    private static INPUT KeyUp(ushort vk) => new()
    {
        type = INPUT_KEYBOARD,
        U = new InputUnion { ki = new KEYBDINPUT { wVk = vk, dwFlags = KEYEVENTF_KEYUP, dwExtraInfo = (IntPtr)ForemanMagic } },
    };

    private static INPUT MouseUp(uint flag) => new()
    {
        type = INPUT_MOUSE,
        U = new InputUnion { mi = new MOUSEINPUT { dwFlags = flag, dwExtraInfo = (IntPtr)ForemanMagic } },
    };

    // ── Win32 interop ────────────────────────────────────────────────────────────────────────────────
    private const ushort VK_SHIFT = 0x10, VK_CONTROL = 0x11, VK_MENU = 0x12, VK_LWIN = 0x5B, VK_RWIN = 0x5C;
    private const uint INPUT_MOUSE = 0, INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const uint MOUSEEVENTF_LEFTUP = 0x0004, MOUSEEVENTF_RIGHTUP = 0x0010, MOUSEEVENTF_MIDDLEUP = 0x0040;

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT { public uint type; public InputUnion U; }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public IntPtr dwExtraInfo; }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BlockInput([MarshalAs(UnmanagedType.Bool)] bool fBlockIt);
}
