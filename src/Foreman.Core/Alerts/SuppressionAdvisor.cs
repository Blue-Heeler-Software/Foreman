namespace Foreman.Core.Alerts;

/// <summary>The quieting a repeated-dismissal pattern suggests.</summary>
public enum SuppressionSuggestionKind { RaiseHangThreshold, MuteClass }

/// <summary>A surfaced suggestion to quiet an operational alert class the operator keeps dismissing.</summary>
public sealed record SuppressionSuggestion(
    string ClassKey, string HarnessId, string AlertType, int AckCount, SuppressionSuggestionKind Kind, string Rationale);

/// <summary>Per-class tally of how often the OPERATOR dismissed it (persisted in settings).</summary>
public sealed class AckPattern
{
    public string ClassKey { get; set; } = "";
    public string HarnessId { get; set; } = "";
    public string AlertType { get; set; } = "";
    public int AckCount { get; set; }
    public DateTimeOffset LastAck { get; set; }
    public bool Suggested { get; set; }   // suggestion already surfaced once — don't re-nag (the advisor must not itself become noise)
}

/// <summary>Adaptive-alert config + the learned ack tallies. Persisted with the rest of ForemanSettings.</summary>
public sealed class AdaptiveAlertSettings
{
    /// <summary>Learn from operator dismissals and surface quieting suggestions. Only ever SUGGESTS — never auto-relaxes.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>How many operator dismissals of one class before a quieting suggestion is offered.</summary>
    public int SuggestAfterAcks { get; set; } = 5;

    /// <summary>Per-class ack history, keyed by "{harnessId}|{alertType}".</summary>
    public Dictionary<string, AckPattern> Patterns { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Adaptive noise reduction that is SAFE for a watchdog. It learns from the OPERATOR's dismissals (UI acks),
/// never from the monitored agent's behaviour — so a rogue/prompt-injected harness can't train the watchdog to
/// ignore it (the classic anomaly-detection poisoning attack). It only ever SUGGESTS quieting (the human
/// confirms; nothing auto-relaxes), and only for OPERATIONAL alert classes (hang/orphan/idle/nonzero-exit).
/// The security set — command/escalation/decoy/credential, i.e. anything in the always-escalate floor — is
/// NEVER eligible. And the raw event is always logged regardless; this only quiets the popup, never the record.
///
/// Pure + static (no I/O, decisions only) so it is fully unit-testable. The App records operator acks and
/// surfaces the returned suggestion; applying it (raise threshold / mute the class) stays a human action.
/// </summary>
public static class SuppressionAdvisor
{
    // The ONLY alert types this may ever quiet. Everything else (security/behavioural) is off-limits by design.
    private static readonly HashSet<string> EligibleTypes =
        new(StringComparer.OrdinalIgnoreCase) { "hang", "orphan", "idle", "nonzero-exit" };

    public static bool IsEligible(string? alertType) => alertType is not null && EligibleTypes.Contains(alertType);

    /// <summary>
    /// Record one OPERATOR dismissal of (harness, operational alert type) and return a quieting suggestion if the
    /// class has now crossed the threshold — once. Returns null when adaptive alerts are off, the type is a
    /// security/ineligible class, the threshold isn't met, or a suggestion was already surfaced for this class.
    /// Mutates <paramref name="settings"/> (caller persists). Callers MUST only invoke this for human/UI acks,
    /// never for an agent's MCP self-ack.
    /// </summary>
    public static SuppressionSuggestion? RecordOperatorAck(
        AdaptiveAlertSettings settings, string harnessId, string alertType, DateTimeOffset now)
    {
        if (!settings.Enabled || !IsEligible(alertType)) return null;
        if (string.IsNullOrWhiteSpace(harnessId)) harnessId = "(unattributed)";

        var key = $"{harnessId}|{alertType}".ToLowerInvariant();
        if (!settings.Patterns.TryGetValue(key, out var p))
            settings.Patterns[key] = p = new AckPattern { ClassKey = key, HarnessId = harnessId, AlertType = alertType };

        p.AckCount++;
        p.LastAck = now;
        return Evaluate(p, settings);
    }

    /// <summary>Pure decision: does this class's ack history warrant a one-time quieting suggestion?</summary>
    public static SuppressionSuggestion? Evaluate(AckPattern p, AdaptiveAlertSettings settings)
    {
        if (!settings.Enabled || !IsEligible(p.AlertType)) return null;   // never suggest quieting a security class
        if (p.Suggested || p.AckCount < settings.SuggestAfterAcks) return null;

        p.Suggested = true;   // surface once; further acks don't re-nag
        var kind = p.AlertType.Equals("hang", StringComparison.OrdinalIgnoreCase)
            ? SuppressionSuggestionKind.RaiseHangThreshold
            : SuppressionSuggestionKind.MuteClass;
        return new SuppressionSuggestion(p.ClassKey, p.HarnessId, p.AlertType, p.AckCount, kind,
            $"You've dismissed '{p.HarnessId} · {p.AlertType}' {p.AckCount} times — it looks like routine noise for this harness.");
    }
}
