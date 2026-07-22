using Foreman.Core.Models;

namespace Foreman.Core.Notifications;

/// <summary>
/// Windows Event Log identifiers, shared by the app (the non-elevated writer) and the elevated sidecar (the
/// one-time registrar) so they can never drift apart.
/// </summary>
public static class OsEventLogNames
{
    public const string SourceName = "Foreman Agent Safety";
    public const string LogName = "Application";
}

/// <summary>Broad grouping for an OS-event-log entry (maps to a system-log category/facility).</summary>
public enum OsEventCategory { Lifecycle = 1, Health = 2, Security = 3 }

/// <summary>Config for the OS-event-log blackbox handoff.</summary>
public sealed class OsEventLogSettings
{
    /// <summary>
    /// Mirror lifecycle + security-significant events to the host OS event log (Windows Event Log / journald) as
    /// a durable external record. The on-disk JSONL log is unaffected either way. On Windows this needs a one-time
    /// elevated registration of the event source (it piggybacks the Run-Elevated sidecar); until then it degrades
    /// silently to disk-only.
    /// </summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// Stable numeric event IDs for the OS event log — a PUBLISHED CONTRACT so operators and SIEMs can filter and
/// alert on them. Do not renumber. Cross-platform: Windows uses them as the Event ID; Linux emits them as a
/// structured journald field (e.g. FOREMAN_EVENT_ID=...).
/// </summary>
public static class OsEventIds
{
    // 1000–1099 — lifecycle
    public const int Started = 1000;
    public const int StoppedClean = 1001;
    public const int CrashHandled = 1002;        // dispatcher exception; app survived
    public const int CrashFatal = 1003;          // AppDomain unhandled; app dying
    public const int CrashUnobservedTask = 1004;
    public const int SecondInstanceBlocked = 1005;
    public const int LogChainAnchor = 1006;      // external rollback witness for the on-disk audit chain head
    public const int AbnormalTermination = 1007; // prior instance was killed (dangling run) — watchdog-of-the-watchdog
    public const int SettingsSealEstablished = 1008; // durable witness that this install has left first-run state

    // 2000–2099 — health / state
    public const int MonitoringDegraded = 2000;
    public const int McpServerStateChanged = 2010;
    public const int MonitoringRecovered = 2001;  // reserved — recovery is an InfoEvent today; wired when promoted
    public const int ElevationChanged = 2002;     // reserved — emit when the Run-Elevated toggle path is wired

    // 3000–3099 — security-significant
    public const int EscalationAlarm = 3000;
    public const int EscalationEmergency = 3001;
    public const int CommandAlert = 3002;
    public const int PermissionViolation = 3003;
    public const int DecoyTripwire = 3004;
    public const int SecuritySignificant = 3099;  // other High+ security event
    public const int ProtectiveAction = 3005;     // reserved — emit when kill/disable paths publish an event
}

/// <summary>
/// Cross-platform sink that writes Foreman's lifecycle and significant events to the HOST OS event log — a
/// durable, external, standard record that survives Foreman being killed, crashing, or having its own files
/// tampered (the "blackbox handoff", in the spirit of how Windows Defender logs to its Operational channel).
///
/// Windows → the Windows Event Log (Application-log source "Foreman Agent Safety").
/// Linux   → journald / syslog (implemented in Foreman.Platform.Linux).
///
/// ALWAYS best-effort: every write is wrapped so an OS-log problem can never block a monitoring callback or
/// crash the watchdog. The on-disk JSONL hash-chain log remains the primary record; this is the out-of-band
/// external mirror. Callers MUST pass already-secret-redacted text (see <see cref="OsEventLogForwarder"/>).
/// </summary>
public interface IOsEventLogSink
{
    /// <summary>False when the OS log isn't writable (e.g. the event source isn't registered yet). Callers keep logging to disk regardless.</summary>
    bool IsAvailable { get; }

    /// <summary>Why the sink is unavailable (surfaced in /health and the doctor view); null when available.</summary>
    string? UnavailableReason { get; }

    /// <summary>Best-effort write of one entry. NEVER throws. <paramref name="message"/> is assumed already redacted.</summary>
    void Write(int eventId, OsEventCategory category, ForemanSeverity severity, string message);

    /// <summary>
    /// Reads back up to <paramref name="maxEntries"/> of THIS source's own recent entries, NEWEST FIRST, so the
    /// app can recover the last log-chain anchor (offline-rollback detection) and the last lifecycle run-marker
    /// (kill detection) from the durable external record on launch. Best-effort: returns empty when the platform
    /// can't read its log or the source isn't registered. Default is empty so platforms that can only write
    /// (or the no-op sink) need not implement it. NEVER throws.
    /// </summary>
    IReadOnlyList<OsEventRecord> ReadOwnRecent(int maxEntries) => [];
}

/// <summary>One entry read back from the OS event log: the numeric event id and its (already-redacted) message.</summary>
public sealed record OsEventRecord(int EventId, string Message);

/// <summary>No-op sink: the default, and what unsupported platforms / a disabled feature resolve to. Always unavailable.</summary>
public sealed class NullOsEventLogSink : IOsEventLogSink
{
    public static readonly NullOsEventLogSink Instance = new();
    public bool IsAvailable => false;
    public string? UnavailableReason => "OS event log sink is not configured.";
    public void Write(int eventId, OsEventCategory category, ForemanSeverity severity, string message) { }
}
