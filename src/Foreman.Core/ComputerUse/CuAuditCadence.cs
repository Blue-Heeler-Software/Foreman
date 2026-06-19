using Foreman.Core.Models;

namespace Foreman.Core.ComputerUse;

/// <summary>How often the EXPENSIVE deep/cloud judge is consulted for gray-area actions.</summary>
public enum CadenceMode
{
    /// <summary>Never call the cloud judge — local fast-path only (cloud effectively off).</summary>
    Off,
    /// <summary>Review every reviewable (ambiguous, state-changing) action.</summary>
    Always,
    /// <summary>Review one in every N reviewable actions (plus always the at/above-threshold ones).</summary>
    EveryNth,
    /// <summary>Review only actions whose fast-path severity is at or above the threshold.</summary>
    RiskBased,
}

/// <summary>
/// Token-economy control for the cloud deep judge: which gray-area actions actually get a (paid) cloud opinion. The
/// FREE local fast-path runs on EVERY action regardless — this only throttles cloud calls, and it can never clear a
/// Block or downgrade a Hold by skipping (a skipped Hold stays a Hold; a skipped low-confidence Allow proceeds, the
/// operator's chosen risk). To keep throttling from hiding the riskier gray cases, anything at or above
/// <see cref="AlwaysReviewAtOrAbove"/> is always reviewed (unless the mode is <see cref="CadenceMode.Off"/>).
/// </summary>
public sealed record CuAuditCadence(
    CadenceMode Mode = CadenceMode.Always,
    int EveryN = 5,
    ForemanSeverity AlwaysReviewAtOrAbove = ForemanSeverity.High)
{
    /// <summary>Should THIS reviewable action get the deep judge? <paramref name="reviewableIndex"/> is a 1-based
    /// running count of reviewable actions (so EveryNth can sample).</summary>
    public bool ShouldReview(CuVerdict fastVerdict, long reviewableIndex)
    {
        if (Mode == CadenceMode.Off) return false;                                   // cloud fully off
        if (fastVerdict.Severity >= AlwaysReviewAtOrAbove) return true;              // never skip the riskier gray cases
        return Mode switch
        {
            CadenceMode.Always => true,
            CadenceMode.EveryNth => reviewableIndex % Math.Max(1, EveryN) == 0,
            CadenceMode.RiskBased => false,                                          // only the at/above case (handled above)
            _ => true,
        };
    }
}
