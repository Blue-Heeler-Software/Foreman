using Foreman.Core.Models;

namespace Foreman.Core.ComputerUse;

/// <summary>An auditor's ruling on a <see cref="CuAction"/> — the allow/escalate/block vocabulary of
/// report_suspicious_command, applied to computer use. Hold = do not execute; surface to the operator (or escalate).</summary>
public enum CuDecision { Allow, Hold, Block }

/// <summary>
/// A judged verdict for a <see cref="CuAction"/>. <see cref="Source"/> names who ruled ("fast-path", "cloud",
/// "operator"); <see cref="Confidence"/> is 0..1 and lets the pipeline escalate a LOW-confidence Allow to the deep
/// judge. <see cref="Severity"/> carries the underlying signal severity (for logging + worst-of comparison).
/// </summary>
public sealed record CuVerdict(
    CuDecision Decision,
    string Reason,
    string Source,
    ForemanSeverity Severity,
    double Confidence)
{
    public static CuVerdict Allow(string source, string reason = "no policy concern", double confidence = 1.0)
        => new(CuDecision.Allow, reason, source, ForemanSeverity.Info, confidence);

    public static CuVerdict Hold(string source, string reason, ForemanSeverity severity = ForemanSeverity.High)
        => new(CuDecision.Hold, reason, source, severity, 1.0);

    public static CuVerdict Block(string source, string reason, ForemanSeverity severity = ForemanSeverity.Critical)
        => new(CuDecision.Block, reason, source, severity, 1.0);
}
