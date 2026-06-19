namespace Foreman.Core.ComputerUse;

/// <summary>Latency / escalation knobs for the audit pipeline.</summary>
public sealed record CuAuditOptions(double AmbiguityThreshold = 0.75, TimeSpan? MaxHoldOverride = null)
{
    /// <summary>Hard ceiling on how long an action may HOLD waiting for the deep judge before failing closed.</summary>
    public TimeSpan MaxHold => MaxHoldOverride ?? TimeSpan.FromSeconds(5);
}

/// <summary>
/// The two-tier hybrid auditor. The synchronous LOCAL fast-path runs on EVERY action (the common path, never
/// blocks). Only an AMBIGUOUS, state-changing action escalates to the optional deep judge (a frontier model),
/// under a hard hold timeout. Invariants:
///  - a fast-path BLOCK is final and never calls out (obvious-bad is stopped offline + free);
///  - read-only verbs and confident allows never escalate;
///  - the deep judge timing out or failing falls CLOSED to an operator Hold, never an auto-Allow.
/// Itself an <see cref="IAuditor"/>, so it composes (and the broker depends on just one interface).
/// </summary>
public sealed class AuditPipeline : IAuditor
{
    private readonly IAuditor _fastPath;
    private readonly IAuditor? _deepJudge;
    private readonly CuAuditOptions _opts;

    public AuditPipeline(IAuditor fastPath, IAuditor? deepJudge = null, CuAuditOptions? opts = null)
    {
        _fastPath = fastPath ?? throw new ArgumentNullException(nameof(fastPath));
        _deepJudge = deepJudge;
        _opts = opts ?? new CuAuditOptions();
    }

    public async Task<CuVerdict> JudgeAsync(CuAction action, CuContext context, CancellationToken ct = default)
    {
        var fast = await _fastPath.JudgeAsync(action, context, ct).ConfigureAwait(false);
        if (fast.Decision == CuDecision.Block) return fast;   // obvious-bad: blocked offline, no deep judge

        var ambiguous = fast.Decision == CuDecision.Hold
            || (fast.Decision == CuDecision.Allow && fast.Confidence < _opts.AmbiguityThreshold);

        // Confident allow, a read-only verb, or no deep judge configured -> the fast path's verdict stands
        // (a fast-path Hold with no deep judge correctly becomes an operator Hold).
        if (!ambiguous || !CuVerbs.IsStateChanging(action.Verb) || _deepJudge is null)
            return fast;

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(_opts.MaxHold);
            return await _deepJudge.JudgeAsync(action, context, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return CuVerdict.Hold("cloud", "deep judge timed out; held for operator");
        }
        catch
        {
            return CuVerdict.Hold("cloud", "deep judge unavailable; held for operator");
        }
    }
}
