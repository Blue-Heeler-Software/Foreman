using System;
using System.IO;

namespace Foreman.App;

/// <summary>
/// Best-effort fault log at %LocalAppData%\Foreman\crash.log. A watchdog must survive transient UI faults
/// (the tray Shell_NotifyIcon API is flaky across Explorer restarts) and RECORD them, not crash. Never throws.
/// </summary>
internal static class CrashLog
{
    public static void Note(string context, Exception ex)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Foreman");
            Directory.CreateDirectory(dir);
            // Redact before persisting: an exception's Message/stack can echo secret-bearing input (a URL with
            // userinfo, KEY=token, a tool argument). crash.log sits in a same-user-readable dir, and the OS-event-log
            // copy of the same crash is already redacted — keep parity so the local copy isn't the leak.
            File.AppendAllText(
                Path.Combine(dir, "crash.log"),
                Foreman.Core.Security.SecretRedactor.Redact($"[{DateTimeOffset.UtcNow:O}] {context}: {ex}") + "\n\n");
        }
        catch { /* logging must never throw */ }
    }
}
