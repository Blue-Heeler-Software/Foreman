using System.Diagnostics;
using System.Runtime.Versioning;
using Foreman.Core.Notifications;

namespace Foreman.Guardian;

/// <summary>
/// Best-effort logging for the guardian. As a LocalSystem service it has no console, so significant events go to
/// the Windows Event Log under the shared "Foreman Agent Safety" source (the same blackbox-handoff channel the app
/// uses). Also echoes to the console for the direct/smoke run. Never throws.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class GuardianLog
{
    public static void Write(string message, EventLogEntryType type = EventLogEntryType.Information)
    {
        try { Console.WriteLine(message); } catch { /* no console (service) */ }
        try
        {
            if (EventLog.SourceExists(OsEventLogNames.SourceName))
                EventLog.WriteEntry(OsEventLogNames.SourceName, $"[Guardian] {message}", type);
        }
        catch { /* source not registered yet / no rights — best-effort */ }
    }
}
