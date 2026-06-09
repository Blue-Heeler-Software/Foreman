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

        // PatternLibrary sorts rules severity-descending, so the first non-suppressed match is the
        // MOST severe one. We never short-circuit this loop on a harness heuristic.
        RuleMatch? match = null;
        foreach (var (rule, regex) in PatternLibrary.Instance.Rules)
        {
            try
            {
                var m = regex.Match(commandLine);
                if (!m.Success) continue;

                if (FalsePositiveFilter.IsSuppressed(rule, commandLine, processName, profile)) continue;

                match = new RuleMatch(
                    rule.Id,
                    rule.Name,
                    rule.Description,
                    rule.Guidance,
                    rule.ParsedSeverity,
                    rule.Id.Split('-')[0],
                    m.Value
                );
                break;
            }
            catch (RegexMatchTimeoutException)
            {
                // regex timed out — move on, don't hang
            }
        }

        // Codex's shell bridge runs `Get-ChildItem Env: … _SHELL_ENV_DELIMITER_` at startup, which trips
        // the env-var credential-search rule (cred-013) as a false positive. Downgrade to a Low notice —
        // but ONLY when cred-013 is the most-severe match (the rule loop already ran, so a command that
        // also trips a higher rule like curl|bash or iex-from-web reports THAT instead) AND the process
        // is the Codex harness. This is a scoped reclassification, never a pre-loop bypass.
        if (match is { RuleId: "cred-013" }
            && IsCodexHarness(profile)
            && IsHarnessEnvironmentSnapshot(commandLine))
        {
            return HarnessEnvironmentSnapshotNotice();
        }

        return match;
    }

    private static bool IsCodexHarness(HarnessProfile? profile) =>
        profile?.Name is { Length: > 0 } name &&
        name.Contains("codex", StringComparison.OrdinalIgnoreCase);

    private static bool IsHarnessEnvironmentSnapshot(string commandLine)
    {
        try { return _harnessEnvironmentSnapshot.IsMatch(commandLine); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static RuleMatch HarnessEnvironmentSnapshotNotice() => new(
        "cred-013-harness",
        "Harness environment snapshot",
        "A known AI harness shell setup command enumerated environment variables. This can be expected client plumbing, but it is still worth noticing because environment variables often contain tokens and API keys.",
        "1. If this was spawned by the harness shell bridge during startup or command setup, no action is usually required.\n2. Avoid storing long-lived secrets in process environment variables when running AI coding agents.\n3. If an ordinary task deliberately requested environment variables, review the output and rotate any exposed secrets.",
        ForemanSeverity.Low,
        "cred",
        "Get-ChildItem Env:");
}
