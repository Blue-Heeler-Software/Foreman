namespace Foreman.Core.Models;

/// <summary>
/// An operator-set rule to quiet a class of alert's <b>tray notification</b>. A mute never stops
/// detection: the event is still recorded in the log, still counts on the dashboard, and still feeds
/// escalation — it only suppresses the popup. <see cref="Until"/> null means "until manually cleared"
/// and is only permitted for non-protected alerts (see <see cref="MutePolicy"/>).
/// </summary>
public sealed class MuteEntry
{
    /// <summary>"rule" (a heuristic rule id), "category" (cred/net/hang/…), or "source" (event source).</summary>
    public string Scope { get; set; } = "rule";

    /// <summary>The rule id / category / source this mute matches.</summary>
    public string Value { get; set; } = "";

    /// <summary>Expiry. Null = until manually cleared (non-protected only).</summary>
    public DateTimeOffset? Until { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Human-readable description for the UI (e.g. "rule net-001", "hang events").</summary>
    public string Label { get; set; } = "";
}
