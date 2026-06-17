using Foreman.Core.Models;
using Foreman.Core.Settings;

namespace Foreman.Core.Alerts;

/// <summary>
/// Selects a cross-harness auditor for Send for Audit: configured preferences first, then any other
/// available harness when nothing targets the offender yet.
/// </summary>
public static class AuditRouteResolver
{
    public sealed record Candidate(
        string AuditorId,
        string AuditorType,
        string DisplayName,
        int Priority,
        bool Available,
        int RunningHarnessCount,
        bool McpConnected,
        string? ApiEndpoint,
        string? Model,
        bool IsFallback);

    public sealed record Selection(
        Candidate? Selected,
        IReadOnlyList<Candidate> Candidates,
        string Reason,
        bool UsedFallback);

    public static bool HasConfiguredAuditor(
        LlmTriageSettings settings,
        string? targetHarnessId,
        ForemanSeverity severity)
    {
        if (!settings.Enabled || string.IsNullOrWhiteSpace(targetHarnessId))
            return false;

        return FindConfiguredCandidates(settings, targetHarnessId, severity, [], connectedHarnessIds: null, honorSeverity: true).Count > 0;
    }

    public static Selection Resolve(
        LlmTriageSettings settings,
        string? targetHarnessId,
        ForemanSeverity severity,
        IReadOnlyList<ProcessRecord> snapshot,
        IReadOnlySet<string>? connectedHarnessIds = null)
    {
        if (settings is null)
            return new(null, [], "No LLM triage settings are available.", false);

        if (!settings.Enabled)
            return new(null, [], "LLM triage routing is disabled in settings.", false);

        var configured = FindConfiguredCandidates(settings, targetHarnessId, severity, snapshot, connectedHarnessIds, honorSeverity: true);
        if (configured.Count > 0)
        {
            return new(
                configured[0],
                configured,
                "Auditor selected from user preference list.",
                UsedFallback: false);
        }

        var fallback = FindFallbackCandidates(settings, targetHarnessId, snapshot, connectedHarnessIds);
        if (fallback.Count > 0)
        {
            return new(
                fallback[0],
                fallback,
                $"No auditor preference configured for {Blank(targetHarnessId, "this harness")} — using another available harness.",
                UsedFallback: true);
        }

        return new(
            null,
            [],
            string.IsNullOrWhiteSpace(targetHarnessId)
                ? "No auditor preference matched this severity."
                : $"No auditor preference matched {targetHarnessId} at this severity, and no other harness is running or connected.",
            UsedFallback: false);
    }

    public static List<Candidate> FindConfiguredCandidates(
        LlmTriageSettings settings,
        string? targetHarnessId,
        ForemanSeverity severity,
        IReadOnlyList<ProcessRecord> snapshot,
        IReadOnlySet<string>? connectedHarnessIds,
        bool honorSeverity)
    {
        var targetKnown = !string.IsNullOrWhiteSpace(targetHarnessId);
        var severityRank = (int)severity;

        return settings.AuditorPreferences
            .Where(p => p.Enabled)
            .Where(p => !targetKnown || TargetMatches(p.TargetHarnessIds, targetHarnessId!))
            .Where(p => !targetKnown ||
                        !settings.PreventSelfAudit ||
                        !string.Equals(p.AuditorId, targetHarnessId, StringComparison.OrdinalIgnoreCase))
            .Where(p => !honorSeverity || HandlesSeverity(p.MinimumSeverities, severityRank))
            .Select(p => ToCandidate(p, snapshot, connectedHarnessIds))
            .OrderByDescending(c => c.Available)
            .ThenByDescending(c => c.McpConnected)
            .ThenByDescending(c => c.Priority)
            .ThenBy(c => c.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static List<Candidate> FindFallbackCandidates(
        LlmTriageSettings settings,
        string? targetHarnessId,
        IReadOnlyList<ProcessRecord> snapshot,
        IReadOnlySet<string>? connectedHarnessIds)
    {
        connectedHarnessIds ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var runningCounts = snapshot
            .Where(p => !string.IsNullOrWhiteSpace(p.HarnessType))
            .GroupBy(p => p.HarnessType!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        var harnessIds = new HashSet<string>(runningCounts.Keys, StringComparer.OrdinalIgnoreCase);
        foreach (var id in connectedHarnessIds)
            harnessIds.Add(id);

        return harnessIds
            .Where(id => string.IsNullOrWhiteSpace(targetHarnessId) ||
                         !settings.PreventSelfAudit ||
                         !string.Equals(id, targetHarnessId, StringComparison.OrdinalIgnoreCase))
            .Select(id =>
            {
                runningCounts.TryGetValue(id, out var runningCount);
                var connected = connectedHarnessIds.Contains(id);
                var known = KnownHarnesses.GetById(id);
                return new Candidate(
                    id,
                    "harness",
                    known?.DisplayName ?? id,
                    Priority: 0,
                    Available: runningCount > 0 || connected,
                    runningCount,
                    connected,
                    ApiEndpoint: null,
                    Model: null,
                    IsFallback: true);
            })
            .OrderByDescending(c => c.McpConnected)
            .ThenByDescending(c => c.Available)
            .ThenByDescending(c => c.RunningHarnessCount)
            .ThenBy(c => c.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static Candidate ToCandidate(
        AuditorPreference preference,
        IReadOnlyList<ProcessRecord>? snapshot,
        IReadOnlySet<string>? connectedHarnessIds)
    {
        var isApi = preference.AuditorType.Equals("api", StringComparison.OrdinalIgnoreCase);
        var runningCount = isApi || snapshot is null
            ? 0
            : snapshot.Count(p => string.Equals(p.HarnessType, preference.AuditorId, StringComparison.OrdinalIgnoreCase));
        var connected = !isApi &&
                        connectedHarnessIds?.Contains(preference.AuditorId) == true;
        var available = isApi
            ? !string.IsNullOrWhiteSpace(preference.ApiEndpoint)
            : runningCount > 0 || connected;

        return new Candidate(
            preference.AuditorId,
            preference.AuditorType,
            string.IsNullOrWhiteSpace(preference.DisplayName) ? preference.AuditorId : preference.DisplayName,
            preference.Priority,
            available,
            runningCount,
            connected,
            preference.ApiEndpoint,
            preference.Model,
            IsFallback: false);
    }

    private static bool TargetMatches(string[] targets, string targetHarnessId) =>
        targets.Length == 0 ||
        targets.Any(t => t == "*" || string.Equals(t, targetHarnessId, StringComparison.OrdinalIgnoreCase));

    private static bool HandlesSeverity(string[] minimumSeverities, int severityRank)
    {
        if (minimumSeverities.Length == 0) return true;
        return minimumSeverities
            .Select(s => Enum.TryParse<ForemanSeverity>(s, true, out var parsed) ? (int)parsed : -1)
            .Where(r => r >= 0)
            .Any(min => severityRank >= min);
    }

    private static string Blank(string? value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value;
}
