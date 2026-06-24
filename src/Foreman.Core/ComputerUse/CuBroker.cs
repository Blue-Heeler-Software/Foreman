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
    bool OperatorApproved = false,
    // Desktop one-window confinement: the active-window Epoch this item was bound at (null for browser), and the
    // panic epoch at submit. Claim re-checks both, so a window switch/rebind or a panic since approval invalidates it.
    long? BoundEpoch = null,
    long PanicEpoch = 0);

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

    // Desktop one-window-at-a-time confinement (parallel to the browser pin; modality-scoped). The operator binds a
    // single target window; _windowEpoch bumps on every (re)bind so an action approved against an old binding is
    // caught at delivery; _panicEpoch bumps on each halt so actions queued before a panic are invalidated.
    private volatile CuWindowRef? _activeWindow;
    private long _windowEpoch;
    private long _panicEpoch;

    // Per-harness action rate limit (token bucket): a burst faster than a human could plausibly pilot is Held, not
    // run (Slice 2 -- approval-fatigue + auditor-flood defense). The operator's own manual actions are exempt.
    private readonly object _rateLock = new();
    private readonly Dictionary<string, (double Tokens, long Ticks)> _rate = new();
    private const double RateBurst = 12;
    private const double RatePerSecond = 6;

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

        // Desktop verb allowlist (INV-12 structural): reject an unknown/over-length verb before the auditor or the
        // injector ever sees it, so a crafted verb from a relayed proposal cannot smuggle through.
        if (action.Modality == CuModality.Desktop && !CuVerbs.IsKnownDesktop(action.Verb))
        {
            var bad = new CuBrokerItem(id, action, CuActionState.Blocked,
                CuVerdict.Block("broker", "unsupported desktop verb"), DateTimeOffset.UtcNow,
                Error: "Unsupported desktop verb.", UpdatedAt: DateTimeOffset.UtcNow);
            _items[id] = bad;
            return bad;
        }

        // Desktop driver authorization (INV-14): a Desktop action must come from an explicitly enrolled driver id (or
        // the operator); the "*" wildcard never authorizes Desktop. Blocked early, before audit. (Browser is unaffected
        // - it keeps the existing Claim-time CanDrive gate.)
        if (action.Modality == CuModality.Desktop
            && !CanDriveModality(action.ByHarness, isOperator: false, CuModality.Desktop))
        {
            var denied = new CuBrokerItem(id, action, CuActionState.Blocked,
                CuVerdict.Block("broker", "driver not authorized for desktop computer use (enroll the id; '*' does not count)"),
                DateTimeOffset.UtcNow, Error: "Driver not authorized for desktop.", UpdatedAt: DateTimeOffset.UtcNow);
            _items[id] = denied;
            return denied;
        }

        // Rate limit (Slice 2): a non-operator harness flooding actions faster than a human could pilot is Held
        // without even auditing -- defeats approval-fatigue + auditor-flood. The operator's manual actions are exempt.
        if (!string.Equals(action.ByHarness, OperatorMarker, StringComparison.OrdinalIgnoreCase)
            && !RateLimitOk(action.ByHarness ?? "?"))
        {
            var throttled = new CuBrokerItem(id, action, CuActionState.Held,
                CuVerdict.Hold("broker", "action rate exceeds plausible pilot speed — held for operator"),
                DateTimeOffset.UtcNow, UpdatedAt: DateTimeOffset.UtcNow,
                BoundEpoch: action.Modality == CuModality.Desktop ? _activeWindow?.Epoch : null,
                PanicEpoch: Interlocked.Read(ref _panicEpoch));
            _items[id] = throttled;
            return throttled;
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

        // Excursion gate, MODALITY-SCOPED so the browser pin and the desktop one-window gate never cross-fire:
        //  - Browser: pinned-tab excursion (off-tab state changes held; read-only peeks proceed).
        //  - Desktop: one-window excursion (off-window state/cursor-move held; no bound window -> held).
        // Only ever downgrades Allow -> Held; never relaxes a Block/Held.
        if (state == CuActionState.Approved && EvaluateModalityExcursion(action, "for operator") is { } exVerdict)
        {
            verdict = exVerdict;
            if (exVerdict.Decision != CuDecision.Allow) state = CuActionState.Held;
        }

        // INV-15 (propose-not-act default): a Desktop action from a driver lands HELD for the operator even on an
        // auditor Allow (DesktopAutoGrant OFF by default), so a compromised channel cannot act without a human in the
        // loop. The operator's own actions, and an explicitly opted-in auto-grant, skip this.
        if (action.Modality == CuModality.Desktop && state == CuActionState.Approved && !DesktopAutoGrant
            && !string.Equals(action.ByHarness, OperatorMarker, StringComparison.OrdinalIgnoreCase))
        {
            state = CuActionState.Held;
            verdict = CuVerdict.Hold("broker", "desktop action held for operator approval (auto-grant off)");
        }

        var item = new CuBrokerItem(id, action, state, verdict, DateTimeOffset.UtcNow, UpdatedAt: DateTimeOffset.UtcNow,
            BoundEpoch: action.Modality == CuModality.Desktop ? _activeWindow?.Epoch : null,
            PanicEpoch: Interlocked.Read(ref _panicEpoch));
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
            if (!CanDriveModality(item.Action.ByHarness, isOperator: false, item.Action.Modality))   // INV-14 at delivery
            {
                _items[item.ActionId] = item with
                {
                    State = CuActionState.Rejected,
                    Error = "Driver no longer authorized for this action.",
                    UpdatedAt = DateTimeOffset.UtcNow,
                };
                continue;
            }

            // Stale across a panic: an item approved before the latest halt is invalidated, never delivered.
            if (item.PanicEpoch < Interlocked.Read(ref _panicEpoch))
            {
                _items[item.ActionId] = item with
                {
                    State = CuActionState.Rejected,
                    Error = "Computer use was halted (panic) after this was approved — re-submit.",
                    UpdatedAt = DateTimeOffset.UtcNow,
                };
                continue;
            }

            var deliver = item;
            if (item.Action.Modality == CuModality.Desktop)
            {
                // Desktop one-window confinement re-gate at DELIVERY — NO OperatorApproved skip (spec INV-2): even an
                // operator-approved item re-validates the bound window, so a switch/rebind/recycle since approval is caught.
                if (EvaluateWindowExcursion(item.Action, "at delivery") is { } wv && wv.Decision != CuDecision.Allow)
                {
                    _items[item.ActionId] = item with { State = CuActionState.Held, Verdict = wv, UpdatedAt = DateTimeOffset.UtcNow };
                    continue;
                }
                var aw = _activeWindow;
                if (item.BoundEpoch is long be && aw is not null && be != aw.Epoch)   // window switched/rebound since approval
                {
                    _items[item.ActionId] = item with { State = CuActionState.Held,
                        Verdict = CuVerdict.Hold("broker", "Bound window switched since approval — re-bind + re-submit."),
                        UpdatedAt = DateTimeOffset.UtcNow };
                    continue;
                }
                if (aw is not null && WindowProbe is { } probe && !probe.IsAlive(aw))   // recycled-handle / window gone
                {
                    _items[item.ActionId] = item with { State = CuActionState.Held,
                        Verdict = CuVerdict.Hold("broker", "Bound window is no longer alive — re-bind + re-submit."),
                        UpdatedAt = DateTimeOffset.UtcNow };
                    continue;
                }
                // On-window with no explicit hwnd: STAMP the bound hwnd + epoch so the executor can't pick another window.
                if (aw is not null && (CuVerbs.IsStateChanging(item.Action.Verb) || CuVerbs.IsCursorMoving(item.Action.Verb))
                    && string.IsNullOrEmpty(item.Action.Arg("hwnd")))
                {
                    var stamped = new Dictionary<string, string>(item.Action.Args, StringComparer.Ordinal)
                    {
                        ["hwnd"] = aw.Hwnd.ToInt64().ToString(),
                        ["epoch"] = aw.Epoch.ToString(),
                    };
                    deliver = item with { Action = item.Action with { Args = stamped } };
                }
            }
            else
            {
                // Browser: re-evaluate the pinned-tab gate at delivery (operator-approved excursions pass), then stamp
                // the live pin into a no-tabId state change so the executor cannot divert to the active tab.
                if (!item.OperatorApproved && EvaluateExcursion(item.Action, "at delivery") is { } exV
                    && exV.Decision != CuDecision.Allow)
                {
                    _items[item.ActionId] = item with { State = CuActionState.Held, Verdict = exV, UpdatedAt = DateTimeOffset.UtcNow };
                    continue;
                }
                if (_attentionTab is { Length: > 0 } pin
                    && CuVerbs.IsStateChanging(item.Action.Verb)
                    && !string.Equals(item.Action.Verb, "navigate", StringComparison.OrdinalIgnoreCase)
                    && string.IsNullOrEmpty(item.Action.Arg("tabId")))
                {
                    var stamped = new Dictionary<string, string>(item.Action.Args, StringComparer.Ordinal) { ["tabId"] = pin };
                    deliver = item with { Action = item.Action with { Args = stamped } };
                }
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

    /// <summary>Enroll an explicit DESKTOP driver id (e.g. "local-agent-host") additively, PRESERVING any existing
    /// browser "*" - the set can become ["*", "local-agent-host"], i.e. browser=any but desktop=only this enrolled id
    /// (INV-14: "*" never authorizes Desktop, so the wildcard is harmless here and the explicit id is required). This is
    /// a DERIVED in-memory enrollment, NOT persisted - the App re-applies it each startup from the sealed
    /// CuDriverHostEnabled flag (which is itself presence-gated to arm), so it can't be turned on by a settings edit
    /// alone. Does NOT collapse "*" (unlike SetDrivers) and does NOT call the persister.</summary>
    public void EnrollDesktopDriver(string id)
    {
        var norm = (id ?? string.Empty).Trim().ToLowerInvariant();
        if (norm.Length == 0 || norm == "*") return;
        var d = _drivers;
        if (d.Contains(norm)) return;
        _drivers = [.. d, norm];
    }

    public bool CanDrive(string? harnessId, bool isOperator)
    {
        if (isOperator || string.Equals(harnessId, OperatorMarker, StringComparison.OrdinalIgnoreCase)) return true;
        var d = _drivers;
        if (d.Length == 0) return false;
        if (d.Contains("*")) return true;
        return harnessId is not null && d.Contains(harnessId.Trim().ToLowerInvariant());
    }

    /// <summary>Modality-aware driver gate (spec INV-14): the "*" wildcard NEVER authorizes the Desktop modality - a
    /// desktop driver must be an EXPLICITLY enumerated, operator-enrolled id (e.g. "local-agent-host"). The operator /
    /// Hello root always passes. Browser keeps the existing wildcard behaviour.</summary>
    public bool CanDriveModality(string? harnessId, bool isOperator, CuModality modality)
    {
        if (isOperator || string.Equals(harnessId, OperatorMarker, StringComparison.OrdinalIgnoreCase)) return true;
        var d = _drivers;
        if (d.Length == 0) return false;
        var id = harnessId?.Trim().ToLowerInvariant();
        if (modality == CuModality.Desktop)
            return id is not null && d.Contains(id);   // explicit enrolled id only - NOT "*"
        if (d.Contains("*")) return true;
        return id is not null && d.Contains(id);
    }

    /// <summary>Opt-in: let a desktop action that audits to Allow proceed without operator approval. Default OFF, so a
    /// desktop action from a driver is always Held for the operator (INV-15). The App wires this from settings.</summary>
    public bool DesktopAutoGrant { get; set; }

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

    // Modality-scoped dispatch: browser actions hit the pinned-tab gate, desktop actions the one-window gate.
    private CuVerdict? EvaluateModalityExcursion(CuAction a, string when) =>
        a.Modality == CuModality.Desktop ? EvaluateWindowExcursion(a, when) : EvaluateExcursion(a, when);

    // ── Desktop one-window confinement (parallel to the pin; modality-scoped) ────

    /// <summary>The operator-bound active CU window (desktop), or null. Switching is explicit and Epoch-bumped.</summary>
    public CuWindowRef? ActiveWindow => _activeWindow;

    /// <summary>App-supplied probe for liveness checks at delivery (recycled-handle defense); null in tests/headless.</summary>
    public IDesktopWindowProbe? WindowProbe { get; set; }

    /// <summary>App-wired one-time bind-token validator (spec INV-17). When set, a desktop BIND must present a token
    /// the validator accepts - one the presence gate minted on a real operator BindCuWindow tap and consumes once - so
    /// a caller cannot fabricate a CuWindowRef for an attacker-owned window and bind it. Null in tests/headless means
    /// no token is required (the App wires this when the local agent host is enabled).</summary>
    public Func<string?, bool>? BindTokenValidator { get; set; }

    /// <summary>Fired when the bound CU window changes (old, new) — the App announces it via the HUD + audit log.</summary>
    public Action<CuWindowRef?, CuWindowRef?>? OnWindowSwitch { get; set; }

    /// <summary>Fired when desktop cursor ownership changes (for the Shared-Monopilot cursor in a later slice).</summary>
    public Action<CuBrokerItem, bool>? OnHandoff { get; set; }

    /// <summary>Binds (or clears, with null) the single active CU window. REFUSES Foreman's own windows. Bumps the
    /// Epoch so any action approved against a prior binding is re-held at delivery. The caller presence-gates the bind.</summary>
    public (bool Ok, string Reason) SetActiveWindow(CuWindowRef? w, string? bindToken = null)
    {
        if (w is not null)
        {
            if (w.OwnerPid == Environment.ProcessId)
                return (false, "Refused: cannot bind Foreman's own window as a CU target.");
            // INV-17: a bind must carry a live one-time token the presence gate minted on a real operator tap, so a
            // caller cannot hand the broker a fabricated CuWindowRef for a window the operator never chose.
            if (BindTokenValidator is { } validate && !validate(bindToken))
                return (false, "Refused: bind not authorized by a live presence tap (missing/invalid bind token).");
        }
        var old = _activeWindow;
        _activeWindow = w is null ? null : w with { Epoch = Interlocked.Increment(ref _windowEpoch) };
        try { OnWindowSwitch?.Invoke(old, _activeWindow); } catch { /* best-effort announce */ }
        return (true, w is null ? "Cleared the bound CU window." : $"Bound CU window '{w.TitleAtBind}' (pid {w.OwnerPid}).");
    }

    /// <summary>Called on a panic HALT: invalidate the desktop queue. Every non-terminal Desktop item is Rejected and
    /// the panic epoch is bumped, so any in-flight/after Claim refuses items approved before the halt (spec Slice 1).</summary>
    public void OnPanicHalt()
    {
        Interlocked.Increment(ref _panicEpoch);
        foreach (var item in _items.Values)
        {
            if (item.Action.Modality != CuModality.Desktop) continue;
            if (item.State is CuActionState.Auditing or CuActionState.Held or CuActionState.Approved or CuActionState.Executing)
                _items[item.ActionId] = item with
                {
                    State = CuActionState.Rejected,
                    Error = "Computer use was halted (panic) — re-submit.",
                    OperatorApproved = false,
                    UpdatedAt = DateTimeOffset.UtcNow,
                };
        }
    }

    // Desktop one-window gate. Gated verbs = state-changing OR cursor-moving (a move/scroll leaves confinement too).
    // No window bound -> a gated verb is Held. Bound + the action targets a DIFFERENT hwnd -> Held (off-window). On
    // the bound window (matching hwnd, or no explicit hwnd -> runs in it) -> null (proceeds; hwnd stamped at delivery).
    private CuVerdict? EvaluateWindowExcursion(CuAction action, string when)
    {
        if (!CuVerbs.IsStateChanging(action.Verb) && !CuVerbs.IsCursorMoving(action.Verb)) return null;
        var just = action.Arg("justification") is { Length: > 0 } j ? j : null;
        var target = action.Arg("hwnd") is { Length: > 0 } t ? t : null;
        var aw = _activeWindow;
        if (aw is null)
            return CuVerdict.Hold("broker", $"Desktop action held {when}: no CU window is bound — the operator must bind a target window first.");
        if (!string.IsNullOrEmpty(target) && !HwndMatches(target, aw.Hwnd))
            return CuVerdict.Hold("broker",
                $"Off-window change held {when} (bound HWND {aw.Hwnd} '{aw.TitleAtBind}'; action targets {target})" +
                (string.IsNullOrWhiteSpace(just) ? "." : $": {just}"));
        return null;
    }

    private static bool HwndMatches(string? a, IntPtr b) => long.TryParse(a, out var ai) && ai == b.ToInt64();

    // Token-bucket rate limit per harness: refill RatePerSecond up to RateBurst; consume 1 per submit. Empty -> false
    // (the submit is Held). Locked because submit is not a hot path and correctness beats lock-free here.
    private bool RateLimitOk(string harness)
    {
        lock (_rateLock)
        {
            var now = DateTimeOffset.UtcNow.Ticks;
            if (!_rate.TryGetValue(harness, out var cur)) { _rate[harness] = (RateBurst - 1, now); return true; }
            var elapsedSec = (now - cur.Ticks) / (double)TimeSpan.TicksPerSecond;
            var tokens = Math.Min(RateBurst, cur.Tokens + elapsedSec * RatePerSecond);
            if (tokens >= 1) { _rate[harness] = (tokens - 1, now); return true; }
            _rate[harness] = (tokens, now);
            return false;
        }
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
