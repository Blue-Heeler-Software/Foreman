using System.Diagnostics;
using Foreman.Core.Models;
using Foreman.Core.Notifications;

namespace Foreman.App;

/// <summary>
/// Windows implementation of <see cref="IOsEventLogSink"/>: writes to the Application event log under the
/// "Foreman Agent Safety" source so Foreman's lifecycle + significant events appear in Event Viewer
/// (Defender-style) and survive the app being killed. Registering the source needs admin ONCE — done by the
/// elevated sidecar (<c>Run Elevated</c>); until then this reports unavailable and Foreman keeps logging to disk.
/// Every write is best-effort and never throws — an OS-log problem must never disturb the watchdog.
/// </summary>
public sealed class WindowsEventLogSink : IOsEventLogSink
{
    private const string SourceName = OsEventLogNames.SourceName;
    private const string LogName = OsEventLogNames.LogName;

    private readonly bool _available;
    private readonly string? _reason;

    public WindowsEventLogSink()
    {
        try
        {
            if (EventLog.SourceExists(SourceName))
            {
                _available = true;
                return;
            }

            // Not registered yet. Creating a source needs admin; try anyway (succeeds if we happen to be elevated),
            // otherwise degrade gracefully — the elevated sidecar registers it on the next Run-Elevated launch.
            try
            {
                EventLog.CreateEventSource(new EventSourceCreationData(SourceName, LogName));
                _available = true;
            }
            catch
            {
                _available = false;
                _reason = "Windows Event Log source not registered — enable Run Elevated once (Settings) to register it. Logging to disk meanwhile.";
            }
        }
        catch (Exception ex)
        {
            _available = false;
            _reason = $"Windows Event Log unavailable: {ex.Message}";
        }
    }

    public bool IsAvailable => _available;
    public string? UnavailableReason => _reason;

    public void Write(int eventId, OsEventCategory category, ForemanSeverity severity, string message)
    {
        if (!_available) return;
        try
        {
            EventLog.WriteEntry(SourceName, Trim(message), MapType(severity), eventId, (short)category);
        }
        catch
        {
            // Transient Event Log failures (service churn, quota) must never propagate into the watchdog.
        }
    }

    private static EventLogEntryType MapType(ForemanSeverity s) => s switch
    {
        ForemanSeverity.Critical or ForemanSeverity.High => EventLogEntryType.Error,
        ForemanSeverity.Medium                           => EventLogEntryType.Warning,
        _                                                => EventLogEntryType.Information,
    };

    // A single Event Log entry is capped near 32 KB; keep entries compact and well under it.
    private static string Trim(string m) => m.Length <= 16_000 ? m : m[..16_000] + "…";
}
