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
    DateTimeOffset? UpdatedAt = null);

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
        if (state == CuActionState.Approved
            && IsOffPinExcursion(action, out var excTarget, out var justification)
            && IsStateChanging(action.Verb))
        {
            state = CuActionState.Held;
            verdict = CuVerdict.Hold("broker",
                $"Off-focus change held for operator (pinned tab {_attentionTab}; action targets {excTarget})" +
                (string.IsNullOrWhiteSpace(justification) ? " — no justification given." : $": {justification}"));
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
        _items[actionId] = item with { State = CuActionState.Approved, UpdatedAt = DateTimeOffset.UtcNow };
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
            var executing = item with { State = CuActionState.Executing, UpdatedAt = DateTimeOffset.UtcNow };
            if (_items.TryUpdate(item.ActionId, executing, item))   // CAS guards against a double-claim
                batch.Add(executing);
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
        justification = action.Args.TryGetValue("justification", out var j) ? j?.Trim() : null;
        target = action.Args.TryGetValue("tabId", out var t) ? t?.Trim() : null;
        if (string.IsNullOrEmpty(_attentionTab)) return false;
        if (string.Equals(action.Verb, "navigate", StringComparison.OrdinalIgnoreCase)) { target ??= "a new tab"; return true; }
        return !string.IsNullOrEmpty(target) && !string.Equals(_attentionTab, target, StringComparison.OrdinalIgnoreCase);
    }

    // Read-only verbs never change page/desktop state, so off-focus reads are allowed (and surfaced). Everything
    // else (navigate/goto/click/type/scroll/back/forward/...) is a state change that must be held when off-focus.
    private static bool IsStateChanging(string verb) =>
        verb is not ("read" or "list_tabs" or "tabs" or "status");

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
