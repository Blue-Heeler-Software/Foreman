using Foreman.Core.Models;
using Foreman.Core.Profiles;

namespace Foreman.Core.Heuristics;

/// <summary>
/// Suppresses known-safe matches to reduce noise.
/// </summary>
public static class FalsePositiveFilter
{
    // Process names whose OWN command lines are low-signal noise: Foreman itself and dev test runners.
    // NOTE: a basename is NOT an identity — a monitored agent runs as the same user and can name its dropper
    // anything. So this set is only ever consulted to drop sub-Medium NOISE (see IsSuppressed); it can never
    // silence a security-significant rule, which is what made name-spoofing a total-bypass before.
    private static readonly HashSet<string> _suppressedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "Foreman.App",
        "Foreman.App.exe",
        "Foreman",
        "Foreman.exe",
        "dotnet",         // test runners
        "xunit.console",
        "pytest",
        "vstest.console",
    };

    public static bool IsSuppressed(
        PatternRule rule,
        string commandLine,
        string? processName,
        HarnessProfile? profile = null)
    {
        // CRITICAL: process-name suppression must NEVER silence a security-significant rule. The adversary is a
        // same-user agent that can name its process "Foreman.exe"/"dotnet"/"pytest"; if name-suppression covered
        // all rules, copying a dropper to such a name would disable the entire command heuristic engine (rm -rf,
        // mimikatz, curl|bash, the decoy sentinel). Credential/exec/destruction/decoy rules are all Medium+, so
        // gating name-suppression to sub-Medium rules makes them fire regardless of what the agent calls itself,
        // while still dropping genuine low-signal noise from Foreman's own process / test runners.
        if (processName is not null
            && rule.ParsedSeverity < ForemanSeverity.Medium
            && _suppressedProcesses.Contains(processName))
            return true;

        if (IsLauncherHygieneSuppressed(rule, commandLine, profile))
            return true;

        return false;
    }

    private static bool IsLauncherHygieneSuppressed(
        PatternRule rule,
        string commandLine,
        HarnessProfile? profile)
    {
        var profileRules = profile?.Alerts.LauncherSuppressedRuleIds ?? [];
        var profileMarkers = profile?.Alerts.TrustedHookPathMarkers ?? [];
        if (profileRules.Contains(rule.Id, StringComparer.OrdinalIgnoreCase) &&
            ContainsAnyMarker(commandLine, profileMarkers))
        {
            return true;
        }

        foreach (var integration in HarnessIntegrationRegistry.All)
        {
            if (!integration.LauncherSuppressedRuleIds.Contains(rule.Id, StringComparer.OrdinalIgnoreCase))
                continue;
            if (ContainsAnyMarker(commandLine, integration.TrustedHookPathMarkers))
                return true;
        }

        return false;
    }

    private static bool ContainsAnyMarker(string commandLine, IEnumerable<string> markers)
    {
        foreach (var marker in markers)
            if (commandLine.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
