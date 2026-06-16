using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Foreman.App;

/// <summary>
/// Verifies that whoever connected to the elevated-sidecar pipe is actually running ELEVATED.
///
/// The sidecar's one-time nonce travels on its command line, which a same-user process can read (WMI
/// CommandLine / the process env). A medium-IL agent could therefore scrape the nonce and race to connect to
/// the pipe first, impersonating the sidecar. But the GENUINE sidecar runs as administrator (its manifest forces
/// it), so the connecting client's elevation is a discriminator the agent can't forge without already being
/// admin. We reject a connector we can POSITIVELY determine is non-elevated; if elevation can't be queried we
/// stay quiet (the nonce still gates), so the legitimate handshake is never broken.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class PipeClientGuard
{
    /// <summary>True ONLY when the connected pipe client is positively NOT elevated (a medium-IL racer).</summary>
    public static bool ConnectedClientIsNotElevated(SafePipeHandle pipe, out string reason)
    {
        reason = "";
        try
        {
            if (!GetNamedPipeClientProcessId(pipe.DangerousGetHandle(), out var pid) || pid == 0)
                return false;   // can't identify the client — inconclusive, defer to the nonce

            var process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (process == IntPtr.Zero) return false;   // can't open (inconclusive)
            try
            {
                if (!OpenProcessToken(process, TOKEN_QUERY, out var token)) return false;
                try
                {
                    var elevation = default(TOKEN_ELEVATION);
                    if (!GetTokenInformation(token, TokenElevation, ref elevation,
                            (uint)Marshal.SizeOf<TOKEN_ELEVATION>(), out _))
                        return false;   // inconclusive

                    if (elevation.TokenIsElevated == 0)
                    {
                        reason = $"connecting pid {pid} is not elevated";
                        return true;    // a non-elevated connector is NOT our admin sidecar — reject
                    }
                    return false;       // elevated — the genuine sidecar
                }
                finally { CloseHandle(token); }
            }
            finally { CloseHandle(process); }
        }
        catch { return false; }   // any interop fault → inconclusive, never break the legit handshake
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, TOKEN_QUERY = 0x0008;
    private const int TokenElevation = 20;   // TOKEN_INFORMATION_CLASS.TokenElevation

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_ELEVATION { public uint TokenIsElevated; }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint pid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr token, int tokenInfoClass, ref TOKEN_ELEVATION info, uint length, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
