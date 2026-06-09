using Foreman.Core.Models;
using Foreman.Core.Profiles;
using System.Text.RegularExpressions;

namespace Foreman.Core.Heuristics;

public sealed class CommandAnalyzer
{
    public static CommandAnalyzer Instance { get; } = new();

    private static readonly Regex _harnessEnvironmentSnapshot = new(
        @"(?is)\bGet-ChildItem\s+Env:(?!\w).*_SHELL_ENV_DELIMITER_",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        TimeSpan.FromMilliseconds(50));

    private CommandAnalyzer() { }

    /// <summary>
    /// Evaluates a command line against all loaded rules.
    /// Returns null if no rule matches or the match is suppressed.
    /// Call from any thread — thread-safe after PatternLibrary.Initialize().
    /// </summary>
    public RuleMatch? Analyze(string commandLine, string? processName = null, HarnessProfile? profile = null)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;

        if (AnalyzeKnownHarnessCommand(commandLine, profile) is { } knownHarnessMatch)
            return knownHarnessMatch;

        foreach (var (rule, regex) in PatternLibrary.Instance.Rules)
        {
            try
            {
                var m = regex.Match(commandLine);
                if (!m.Success) continue;

                if (FalsePositiveFilter.IsSuppressed(rule, commandLine, processName, profile)) continue;

                return new RuleMatch(
                    rule.Id,
                    rule.Name,
                    rule.Description,
                    rule.Guidance,
                    rule.ParsedSeverity,
                    rule.Id.Split('-')[0],
                    m.Value
                );
            }
            catch (RegexMatchTimeoutException)
            {
                // regex timed out — move on, don't hang
            }
        }

        return null;
    }

    private static RuleMatch? AnalyzeKnownHarnessCommand(string commandLine, HarnessProfile? profile)
    {
        if (profile is null) return null;

        try
        {
            if (!_harnessEnvironmentSnapshot.IsMatch(commandLine)) return null;
        }
        catch (RegexMatchTimeoutException)
        {
            return null;
        }

        return new RuleMatch(
            "cred-013-harness",
            "Harness environment snapshot",
            "A known AI harness shell setup command enumerated environment variables. This can be expected client plumbing, but it is still worth noticing because environment variables often contain tokens and API keys.",
            "1. If this was spawned by the harness shell bridge during startup or command setup, no action is usually required.\n2. Avoid storing long-lived secrets in process environment variables when running AI coding agents.\n3. If an ordinary task deliberately requested environment variables, review the output and rotate any exposed secrets.",
            ForemanSeverity.Low,
            "cred",
            "Get-ChildItem Env:");
    }
}
