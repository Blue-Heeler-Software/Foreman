using System.Collections.Concurrent;

namespace Foreman.Core.ComputerUse;

/// <summary>Lifecycle of a brokered computer-use action. The executor only ever runs APPROVED actions, so nothing
/// touches the machine until the auditor (and, for a Held action, the operator) clears it.</summary>
public enum CuActionState
{
    Auditing,   // submitted; the auditor is judging it
    Held,       // auditor said Hold — awaiting an operator approve/reject
    Approved,   // cleared to execute (auditor Allow, or operator approved a Held action)
    Rejected,   // operator rejected a Held action
    Blocked,    // auditor Block, or submitted while halted — never executes
    Executing,  // claimed by the executor (extension / sidecar)
    Completed,
    Failed,
}

/// <summary>One action moving through the broker.</summary>
public sealed record CuBrokerItem(
    string ActionId,
    CuAction Action,
    CuActionState State,
    CuVerdict? Verdict,
    DateTimeOffset CreatedAt,
    object? Result = null,
    string? Error = null,
    DateTimeOffset? UpdatedAt = null,
    // True once the OPERATOR has explicitly approved this action out of Held. The delivery-time focus re-gate
    // skips operator-approved items so an excursion the operator already OK'd isn't re-held into a loop.
    bool OperatorApproved = false);

/// <summary>
/// The mediated computer-use command broker — the Phase 0.5 replacement for LiveWeave's immediate command queue.
/// Where LiveWeave was Pending -> Delivered -> Completed (accepted commands ran at once), every action here passes
/// an AUDIT gate first and the executor only ever claims APPROVED actions:
///
///   Submit -> Auditing -> (Approved | Held | Blocked)
///   Held   -> [operator] -> Approved | Rejected
///   Approved -> Claim -> Executing -> Completed | Failed
///
/// The panic kill plugs straight in: while halted, Submit is Blocked and Claim delivers nothing, so the executor
/// goes quiet instantly. The auditor is the Phase 2 <see cref="AuditPipeline"/> (fast-path + optional cloud judge);
/// an auditor error fails CLOSED to Held (operator decides), never to a silent Allow.
/// </summary>
public sealed class CuBroker
{
    private readonly ConcurrentDictionary<string, CuBrokerItem> _items = new();
    private readonly IAuditor _auditor;
    private readonly Func<bool> _isHalted;
    private const int MaxItems = 200;

    // Operator-chosen driver SET: empty = operator only, ["*"] = any harness, else the specific harness ids that
    // may drive. Volatile reference; SetDrivers swaps the whole array atomically. (Was a single string; now a set
    // so the operator can authorize e.g. {claude-code, codex} without opening it to every harness.)
    private volatile string[] _drivers = [];
    private const string OperatorMarker = "operator";

    // Operator's pinned shared-attention tab (browser): the locked focus the extension reports when the operator
    // presses the pinned icon. Null = no pin. Drives the excursion gate in SubmitAsync.
    private volatile string? _attentionTab;

    public CuBroker(IAuditor auditor, Func<bool>? isHalted = null)
    {
        _auditor = auditor ?? throw new ArgumentNullException(nameof(auditor));
        _isHalted = isHalted ?? (() => false);
    }

    // ── Submit + audit ─────────────────────────────────────────────────────────

    /// <summary>Submit an action. Audits it (fail-closed to Held on error) and lands it in Approved/Held/Blocked.
    /// Returns the resulting item. While the panic halt is on, the action is Blocked without auditing.</summary>
    public async Task<CuBrokerItem> SubmitAsync(CuAction action, CuContext context, CancellationToken ct = default)
    {
        var id = string.IsNullOrEmpty(action.ActionId) ? Guid.NewGuid().ToString("N")[..12] : action.ActionId!;

        if (_isHalted())
        {
            var halted = new CuBrokerItem(id, action, CuActionState.Blocked,
                CuVerdict.Block("broker", "computer use is halted (panic)"), DateTimeOffset.UtcNow,
                Error: "Computer use is halted.", UpdatedAt: DateTimeOffset.UtcNow);
            _items[id] = halted;
            return halted;
        }

        _items[id] = new CuBrokerItem(id, action, CuActionState.Auditing, null, DateTimeOffset.UtcNow);

        CuVerdict verdict;
        try { verdict = await _auditor.JudgeAsync(action, context, ct).ConfigureAwait(false); }
        catch { verdict = CuVerdict.Hold("broker", "auditor error; held for operator"); }   // fail closed

        var state = verdict.Decision switch
        {
            CuDecision.Allow => CuActionState.Approved,
            CuDecision.Block => CuActionState.Blocked,
            _                => CuActionState.Held,   // Hold (and any unknown) -> operator decides
        };

        // Pinned-focus excursion gate (browser): when the operator has pinned a shared-attention tab, an action
        // that leaves it (a different explicit tabId, or 'navigate' which opens a NEW tab) is an "excursion".
        // Read-only excursions proceed (the peek is surfaced); STATE-CHANGING excursions are held for the operator
        // even when the auditor allowed them, so the driver can never silently leave the agreed tab. Only ever
        // downgrades Allow -> Held; never relaxes a Block/Held.
        if (state == CuActionState.Approved && EvaluateExcursion(action, "for operator") is { } exVerdict)
        {
            verdict = exVerdict;
            if (exVerdict.Decision != CuDecision.Allow) state = CuActionState.Held;
        }

        var item = new CuBrokerItem(id, action, state, verdict, DateTimeOffset.UtcNow, UpdatedAt: DateTimeOffset.UtcNow);
        _items[id] = item;
        Prune();
        return item;
    }

    // ── Operator decisions on Held actions ───────────────────────────────────────

    public (bool Ok, string Reason) ApproveHeld(string actionId)
    {
        if (!_items.TryGetValue(actionId, out var item)) return (false, "Unknown action id.");
        if (item.State != CuActionState.Held) return (false, $"Action is {item.State}, not Held.");
        // OperatorApproved=true so the delivery-time focus re-gate (Claim) won't re-hold this excursion.
        _items[actionId] = item with { State = CuActionState.Approved, OperatorApproved = true, UpdatedAt = DateTimeOffset.UtcNow };
        return (true, "Approved.");
    }

    public (bool Ok, string Reason) RejectHeld(string actionId, string? reason = null)
    {
        if (!_items.TryGetValue(actionId, out var item)) return (false, "Unknown action id.");
        if (item.State != CuActionState.Held) return (false, $"Action is {item.State}, not Held.");
        _items[actionId] = item with
        {
            State = CuActionState.Rejected,
            Error = string.IsNullOrWhiteSpace(reason) ? "Rejected by operator." : reason!.Trim(),
            UpdatedAt = DateTimeOffset.UtcNow,
        };
        return (true, "Rejected.");
    }

    // ── Executor: claim Approved actions, then complete them ─────────────────────

    /// <summary>The executor claims up to <paramref name="limit"/> APPROVED actions, moving them to Executing.
    /// Returns nothing while halted; re-checks the driver at delivery (rejects actions no longer authorized).</summary>
    public IReadOnlyList<CuBrokerItem> Claim(int limit)
    {
        if (_isHalted()) return [];
        var n = Math.Clamp(limit, 1, 10);
        var batch = new List<CuBrokerItem>(n);
        foreach (var item in _items.Values
                     .Where(i => i.State == CuActionState.Approved)
                     .OrderBy(i => i.CreatedAt))
        {
            if (batch.Count >= n) break;
            if (!CanDrive(item.Action.ByHarness, isOperator: false))
            {
                _items[item.ActionId] = item with
                {
                    State = CuActionState.Rejected,
                    Error = "Driver no longer authorized for this action.",
                    UpdatedAt = DateTimeOffset.UtcNow,
                };
                continue;
            }

            // Re-evaluate the pinned-focus gate against the LIVE pin at DELIVERY, not just at submit (unless the
            // operator already approved this out of Held). Closes the submit-before-pin / move-pin-after-approve
            // TOCTOU: an action that became an off-focus state change since it was approved is re-held here. An
            // operator-opted-in override with a justification still passes (EvaluateExcursion returns Allow).
            if (!item.OperatorApproved && EvaluateExcursion(item.Action, "at delivery") is { } exV
                && exV.Decision != CuDecision.Allow)
            {
                _items[item.ActionId] = item with
                {
                    State = CuActionState.Held,
                    Verdict = exV,
                    UpdatedAt = DateTimeOffset.UtcNow,
                };
                continue;
            }

            // On-focus state change with NO explicit tab: STAMP the live pin into the action the executor receives,
            // so the executor cannot fall back to the (possibly different) active tab. The broker is authoritative
            // for the target; a stale extension-side pin can no longer divert a no-tabId action off the focus.
            var deliver = item;
            if (_attentionTab is { Length: > 0 } pin
                && CuVerbs.IsStateChanging(item.Action.Verb)
                && !string.Equals(item.Action.Verb, "navigate", StringComparison.OrdinalIgnoreCase)
                && string.IsNullOrEmpty(item.Action.Arg("tabId")))
            {
                var stamped = new Dictionary<string, string>(item.Action.Args, StringComparer.Ordinal) { ["tabId"] = pin };
                deliver = item with { Action = item.Action with { Args = stamped } };
            }

            var executing = deliver with { State = CuActionState.Executing, UpdatedAt = DateTimeOffset.UtcNow };
            if (_items.TryUpdate(item.ActionId, executing, item))   // CAS against the original Approved item
            {
                batch.Add(executing);
                try { OnExecuting?.Invoke(executing); } catch { /* HUD is best-effort; never break delivery */ }
            }
        }
        return batch;
    }

    public (bool Ok, string Reason) Complete(string actionId, bool ok, object? result, string? error)
    {
        if (!_items.TryGetValue(actionId, out var item)) return (false, "Unknown action id.");
        if (item.State is CuActionState.Completed or CuActionState.Failed) return (false, "Already completed.");
        _items[actionId] = item with
        {
            State = ok ? CuActionState.Completed : CuActionState.Failed,
            Result = result,
            Error = string.IsNullOrWhiteSpace(error) ? null : error!.Trim(),
            UpdatedAt = DateTimeOffset.UtcNow,
        };
        return (true, ok ? "Completed." : "Failed.");
    }

    // ── Queries ──────────────────────────────────────────────────────────────────

    public CuBrokerItem? Get(string actionId) => _items.TryGetValue(actionId, out var i) ? i : null;

    public IReadOnlyList<CuBrokerItem> ListHeld() =>
        _items.Values.Where(i => i.State == CuActionState.Held).OrderBy(i => i.CreatedAt).ToList();

    // ── Driver gating (ported from LiveWeaveBroker) ──────────────────────────────

    /// <summary>The authorized driver set, normalized: empty = operator-only, ["*"] = any harness, else harness ids.</summary>
    public IReadOnlyList<string> Drivers => _drivers;

    /// <summary>Back-compat single-string view: null = operator-only, "*" = any, else the ids joined by commas.</summary>
    public string? Driver => _drivers.Length == 0 ? null : string.Join(",", _drivers);

    /// <summary>Optional sink invoked whenever the driver set changes, so the host can persist it across restarts.
    /// Receives the NORMALIZED <see cref="Driver"/> string ("*" = any, null = operator-only, else comma-joined ids).
    /// Wire it AFTER the startup seed (call <see cref="SetDriver"/> with the saved value first) so restoring doesn't re-save.</summary>
    public Action<string?>? DriverPersister { get; set; }

    /// <summary>Back-compat single setter: accepts one id, "any", blank (operator-only), OR a comma-separated list
    /// (so a persisted "a,b" round-trips). Delegates to <see cref="SetDrivers"/>.</summary>
    public void SetDriver(string? harnessId) =>
        SetDrivers(string.IsNullOrWhiteSpace(harnessId)
            ? null
            : harnessId.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    /// <summary>Sets the full authorized driver set. Each id is normalized (trim/lower-case, "any" -> "*"); if "*"
    /// is present it supersedes the specifics and collapses to ["*"] (any harness). Empty -> operator-only.</summary>
    public void SetDrivers(IEnumerable<string>? harnessIds)
    {
        var set = (harnessIds ?? [])
            .Select(h => (h ?? string.Empty).Trim().ToLowerInvariant())
            .Where(h => h.Length > 0)
            .Select(h => string.Equals(h, "any", StringComparison.OrdinalIgnoreCase) ? "*" : h)
            .Distinct()
            .ToArray();
        _drivers = set.Contains("*") ? ["*"] : set;
        DriverPersister?.Invoke(Driver);
    }

    public bool CanDrive(string? harnessId, bool isOperator)
    {
        if (isOperator || string.Equals(harnessId, OperatorMarker, StringComparison.OrdinalIgnoreCase)) return true;
        var d = _drivers;
        if (d.Length == 0) return false;
        if (d.Contains("*")) return true;
        return harnessId is not null && d.Contains(harnessId.Trim().ToLowerInvariant());
    }

    // ── Pinned shared-attention (focus-lock) ─────────────────────────────────────

    /// <summary>The operator's pinned shared-attention tab (the locked focus), or null when nothing is pinned.</summary>
    public string? AttentionTab => _attentionTab;

    /// <summary>Sets the pinned attention tab (the executor reports the operator's pinned-icon choice). Blank clears it.</summary>
    public void SetAttention(string? tabId) => _attentionTab = string.IsNullOrWhiteSpace(tabId) ? null : tabId.Trim();

    // True when a pin is set AND the action leaves it: either an explicit args["tabId"] != pin, or a 'navigate'
    // (which opens a NEW tab, always off the pinned focus). No pin set -> never an excursion. No explicit tabId on a
    // tab-acting verb -> the executor runs it IN the pinned tab, so that is on-focus, not an excursion.
    private bool IsOffPinExcursion(CuAction action, out string? target, out string? justification)
    {
        justification = action.Arg("justification") is { Length: > 0 } j ? j : null;
        target = action.Arg("tabId") is { Length: > 0 } t ? t : null;
        if (string.IsNullOrEmpty(_attentionTab)) return false;
        // 'navigate' opens a NEW tab, which always leaves the pinned focus.
        if (string.Equals(action.Verb?.Trim(), "navigate", StringComparison.OrdinalIgnoreCase)) { target ??= "a new tab"; return true; }
        if (string.IsNullOrEmpty(target)) return false;   // no explicit tab -> runs in the pinned tab (stamped at delivery)
        return !TabsMatch(target, _attentionTab);
    }

    // Canonical integer compare for tab ids: parse both sides so "042"/" 42 " match "42", and a NON-integer tabId
    // (which the executor resolves differently, or rejects) is treated as off-focus (conservative). The verb
    // classifier is the shared CuVerbs.IsStateChanging so the pin gate and the audit pipeline never diverge.
    private static bool TabsMatch(string? a, string? b) =>
        long.TryParse(a, out var ai) && long.TryParse(b, out var bi) && ai == bi;

    private CuVerdict ExcursionHold(string? target, string? justification, string when) =>
        CuVerdict.Hold("broker",
            $"Off-focus change held {when} (pinned tab {_attentionTab}; action targets {target})" +
            (string.IsNullOrWhiteSpace(justification) ? " — no justification given." : $": {justification}"));

    /// <summary>Operator opt-in (from settings.CuTabOverride): when true, an off-focus state change may PROCEED
    /// instead of being held — but ONLY if it carries a justification. Default false (off-focus changes are held).</summary>
    public bool AllowTabOverride { get; set; }

    /// <summary>Fired when an action is handed to the executor (moves to Executing). The App raises the operator
    /// HUD overlay ("CLAUDE DRIVING THRU FOREMAN") from it. Invoked on the poll thread — marshal to the UI thread.</summary>
    public Action<CuBrokerItem>? OnExecuting { get; set; }

    // The off-focus verdict for a state-changing action, or null when there is no excursion (on-focus / read-only /
    // no pin). With tab-override opted in AND a justification present -> Allow (proceeds, surfaced); otherwise Hold.
    // A justification is mandatory to ever proceed off-focus, so the implicit-auth assumption is always explained.
    private CuVerdict? EvaluateExcursion(CuAction action, string when)
    {
        if (!CuVerbs.IsStateChanging(action.Verb)) return null;
        if (!IsOffPinExcursion(action, out var target, out var just)) return null;
        if (AllowTabOverride && !string.IsNullOrWhiteSpace(just))
            return CuVerdict.Allow("broker", $"Off-focus override (operator opt-in) {when} (targets {target}): {just}");
        return ExcursionHold(target, just, AllowTabOverride ? $"{when} — override needs a justification" : when);
    }

    private void Prune()
    {
        if (_items.Count <= MaxItems) return;
        var terminal = _items.Values
            .Where(i => i.State is CuActionState.Completed or CuActionState.Failed
                or CuActionState.Rejected or CuActionState.Blocked)
            .OrderBy(i => i.UpdatedAt ?? i.CreatedAt)
            .Take(_items.Count - MaxItems)
            .Select(i => i.ActionId)
            .ToList();
        foreach (var id in terminal) _items.TryRemove(id, out _);
    }
}
