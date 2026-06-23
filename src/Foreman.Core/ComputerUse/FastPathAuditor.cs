using Foreman.Core.Heuristics;
using Foreman.Core.Models;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// The always-on LOCAL auditor. Projects a <see cref="CuAction"/> to text and runs it through the existing
/// <see cref="CommandAnalyzer"/> — so the WHOLE pattern library (IOC C2 domains, credential rules, the per-install
/// decoy sentinel) applies to the action stream — plus <see cref="CuHeuristics"/> for CU-specific threats.
/// Synchronous, sub-millisecond, offline, free. Maps the most-severe finding to a decision: Critical -> Block,
/// High -> Hold, a sub-High library hit -> Allow but with LOW confidence (so the pipeline may escalate), nothing
/// -> Allow.
/// </summary>
public sealed class FastPathAuditor : IAuditor
{
    private const string Src = "fast-path";

    public Task<CuVerdict> JudgeAsync(CuAction action, CuContext context, CancellationToken ct = default)
        => Task.FromResult(Judge(action, context));

    public static CuVerdict Judge(CuAction action, CuContext context)
    {
        // CU-specific concern (always Hold/Block or null).
        CuVerdict? best = CuHeuristics.Evaluate(action);

        // Reuse the full command pattern library against the projected action text.
        var libMatch = CommandAnalyzer.Instance.Analyze(Project(action), processName: null, profile: context.Profile);
        if (libMatch is not null)
        {
            var decision = libMatch.Severity >= ForemanSeverity.Critical ? CuDecision.Block
                : libMatch.Severity >= ForemanSeverity.High ? CuDecision.Hold
                : CuDecision.Allow;
            // A sub-High library hit allows but flags uncertainty, so the pipeline escalates it to the deep judge.
            var confidence = decision == CuDecision.Allow ? 0.5 : 1.0;
            var lib = new CuVerdict(decision, $"{libMatch.RuleName}: {Trim(libMatch.MatchedText)}",
                Src, libMatch.Severity, confidence);
            if (best is null || lib.Severity > best.Severity) best = lib;
        }

        return best ?? CuVerdict.Allow(Src);
    }

    /// <summary>Project the structured action to a single line the command pattern library can match. Includes the
    /// resolved DESKTOP target (label + role + window title) so a coordinate-only click is no longer projected to an
    /// empty string (the review's empty-projection bug) — the library + heuristics judge what is being clicked, not
    /// "". No synthetic prefix, so the projection can't itself trip a command rule.</summary>
    public static string Project(CuAction a) =>
        ($"{a.Arg("url")} {a.Arg("text")} {a.Arg("selector")} {a.Arg("key")} " +
         $"{a.Arg("targetLabel")} {a.Arg("targetRole")} {a.Arg("windowTitle")}").Trim();

    private static string Trim(string s) => s.Length <= 120 ? s : s[..120] + "…";
}
