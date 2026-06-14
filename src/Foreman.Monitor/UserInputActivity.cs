using System.Runtime.InteropServices;

namespace Foreman.Monitor;

/// <summary>
/// Minutes since the human last touched keyboard or mouse on this session. Reads only the IDLE DURATION — never
/// what was typed (this is not keylogging; it is the same signal a screensaver uses to decide when to kick in).
/// Used to context-scale the hang/idle timeout: an agent sitting quiet while nobody is at the machine is the
/// expected parked state, not a stall.
/// </summary>
public interface IUserInputProvider
{
    /// <summary>Whole minutes since the last keyboard/mouse input, system-wide. 0 = active right now (or unknown).</summary>
    int MinutesSinceLastInput { get; }
}

/// <summary>Win32 <c>GetLastInputInfo</c>-backed implementation (Windows-only).</summary>
public sealed class Win32UserInputProvider : IUserInputProvider
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    public int MinutesSinceLastInput
    {
        get
        {
            var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };

            // Fail SAFE: if the call fails, report "active now" (0) so we never relax the threshold on bad data.
            if (!GetLastInputInfo(ref lii)) return 0;

            // dwTime is a GetTickCount() sample; Environment.TickCount is that same millisecond clock. Unsigned
            // subtraction makes the ~49.7-day tick wrap harmless. Clamp negatives (clock skew) to 0.
            var idleMs = unchecked((uint)Environment.TickCount - lii.dwTime);
            return (int)(idleMs / 60_000u);
        }
    }
}
