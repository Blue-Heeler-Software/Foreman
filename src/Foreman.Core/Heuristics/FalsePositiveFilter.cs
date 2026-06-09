using Foreman.Core.Models;
using Foreman.Core.Profiles;

namespace Foreman.Core.Heuristics;

/// <summary>
/// Suppresses known-safe matches to reduce noise.
/// </summary>
public static class FalsePositiveFilter
{
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
        if (processName is not null && _suppressedProcesses.Contains(processName))
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
