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
    private readonly CuAuditCadence _cadence;
    private long _reviewable;   // running count of reviewable actions, for EveryNth sampling

    public AuditPipeline(IAuditor fastPath, IAuditor? deepJudge = null, CuAuditOptions? opts = null,
        CuAuditCadence? cadence = null)
    {
        _fastPath = fastPath ?? throw new ArgumentNullException(nameof(fastPath));
        _deepJudge = deepJudge;
        _opts = opts ?? new CuAuditOptions();
        _cadence = cadence ?? new CuAuditCadence();   // default: review every reviewable action
    }

    public async Task<CuVerdict> JudgeAsync(CuAction action, CuContext context, CancellationToken ct = default)
    {
        var fast = await _fastPath.JudgeAsync(action, context, ct).ConfigureAwait(false);
        if (fast.Decision == CuDecision.Block) return fast;   // obvious-bad: blocked offline, no deep judge
        // A FINAL hold is a deterministic policy decision (e.g. an agent self-signup vault WRITE) the operator must
        // approve in person — never escalate it to the advisory deep judge, which could otherwise auto-Allow it.
        if (fast.Decision == CuDecision.Hold && fast.Final) return fast;

        var ambiguous = fast.Decision == CuDecision.Hold
            || (fast.Decision == CuDecision.Allow && fast.Confidence < _opts.AmbiguityThreshold);

        // Confident allow, a read-only verb, or no deep judge configured -> the fast path's verdict stands
        // (a fast-path Hold with no deep judge correctly becomes an operator Hold).
        if (!ambiguous || !CuVerbs.IsStateChanging(action.Verb) || _deepJudge is null)
            return fast;

        // Token economy: sample the (paid) deep judge per the operator's cadence. Skipping leaves the fast-path
        // verdict standing (a Hold stays a Hold; a low-confidence Allow proceeds) — it never clears a Block.
        // DESKTOP CU never sample-skips a risky target (Slice 2 / Medium #7): only confirmed read-only no-ops may be
        // skipped, and those already returned above. Browser ambiguous actions still sample per the operator cadence.
        if (action.Modality != CuModality.Desktop
            && !_cadence.ShouldReview(fast, Interlocked.Increment(ref _reviewable)))
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
