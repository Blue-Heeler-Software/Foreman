using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;

namespace Foreman.Monitor;

/// <summary>
/// "Idle Harness self-cleanup": watches each harness's process tree and, when it looks
/// abandoned (everything I/O-silent past the threshold), asks the harness over MCP to pack
/// up cleanly — checkpoint work, stop leftover children, release resources — via the
/// Ask-Harness mailbox plus a live push when the harness has an MCP session.
///
/// Two triggers: automatic (opt-in via <see cref="ForemanSettings.IdleCleanupEnabled"/>,
/// driven by a 60s timer) and manual (<see cref="TriggerCleanup"/>, wired to the Process
/// Monitor's per-harness context menu — always available regardless of the setting).
///
/// All decisions live in <see cref="IdleCleanupPolicy"/> (pure, tested). The MCP pieces are
/// injected by the App composition root, because Monitor must not reference McpServer.
/// </summary>
public sealed class IdleHarnessDetector : IDisposable
{
    private readonly EventBus _bus;
    private readonly ForemanSettings _settings;
    private readonly ProcessTreeTracker _tree;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();
    private readonly Dictionary<string, CleanupState> _state = new(StringComparer.OrdinalIgnoreCase);
    private Task? _task;

    private sealed class CleanupState
    {
        public DateTimeOffset RequestedAt;
        public string RequestId = "";
        public bool Escalated;
    }

    /// <summary>(harnessId, alertId, systemPrompt, userPrompt, pid, processName) → mailbox requestId, or null if unavailable. Wired by App.</summary>
    public Func<string, string, string, string, int?, string?, string?>? CreateCleanupRequest { get; set; }

    /// <summary>(harnessId, systemPrompt, userPrompt, requestId) → best-effort live delivery to the harness's MCP session. Wired by App.</summary>
    public Func<string, string, string, string, Task>? PushToOffender { get; set; }

    /// <summary>requestId → is the mailbox request still unanswered. Wired by App.</summary>
    public Func<string, bool>? IsRequestPending { get; set; }

    public IdleHarnessDetector(EventBus bus, ForemanSettings settings, ProcessTreeTracker tree)
    {
        _bus = bus;
        _settings = settings;
        _tree = tree;
    }

    public void Start() => _task = RunAsync(_cts.Token);

    private async Task RunAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(60));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try { CheckNow(); }
            catch { /* a single bad sweep must not kill the loop */ }
        }
    }

    /// <summary>One detection sweep. Public (with injectable clock) so tests drive it directly.</summary>
    public void CheckNow(DateTimeOffset? nowOverride = null)
    {
        var now = nowOverride ?? DateTimeOffset.UtcNow;

        var types = _tree.GetAll()
            .Where(r => r.IsHarness && r.HarnessType is not null && r.State != ProcessState.Terminated)
            .Select(r => r.HarnessType!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var type in types)
        {
            if (_settings.DisabledHarnesses.Contains(type)) continue;

            var tree = _tree.GetTreeByHarnessType(type)
                .Where(r => r.State != ProcessState.Terminated)
                .ToList();
            var idle = IdleCleanupPolicy.IsTreeIdle(tree, _settings.IdleCleanupAfterMinutes, now);

            CleanupState? st;
            lock (_gate) _state.TryGetValue(type, out st);

            // 1) Unanswered earlier request + still idle → visible notice (once per request).
            if (st is not null &&
                IdleCleanupPolicy.ShouldEscalate(
                    st.RequestedAt,
                    stillPending: IsRequestPending?.Invoke(st.RequestId) == true,
                    stillIdle: idle,
                    alreadyEscalated: st.Escalated,
                    _settings.IdleCleanupGraceMinutes, now))
            {
                st.Escalated = true;
                var ago = (int)(now - st.RequestedAt).TotalMinutes;
                _bus.Publish(new MonitoringNoticeEvent(
                    now, ForemanSeverity.Low, "Foreman.IdleCleanup",
                    $"'{type}' hasn't answered the self-cleanup request from {ago} minute(s) ago and is still idle — " +
                    "check on it, or use Dashboard → Behavior / Process Monitor to kill the harness tree."));
            }

            // 2) Auto-request (opt-in), once per cooldown window.
            if (_settings.IdleCleanupEnabled && idle &&
                IdleCleanupPolicy.ShouldAutoRequest(st?.RequestedAt, _settings.IdleCleanupCooldownMinutes, now))
            {
                TriggerCleanupCore(type, tree, manual: false, now);
            }
        }
    }

    /// <summary>
    /// Manual trigger (Process Monitor context menu). Always allowed — no idle/enabled gating —
    /// but shares the same state so the auto path won't immediately re-ask.
    /// </summary>
    public (bool Ok, string Message) TriggerCleanup(string harnessType, bool manual = true)
    {
        var tree = _tree.GetTreeByHarnessType(harnessType)
            .Where(r => r.State != ProcessState.Terminated)
            .ToList();
        if (tree.Count == 0)
            return (false, $"No running processes found for '{harnessType}'.");

        return TriggerCleanupCore(harnessType, tree, manual, DateTimeOffset.UtcNow);
    }

    private (bool Ok, string Message) TriggerCleanupCore(
        string harnessType, IReadOnlyList<ProcessRecord> tree, bool manual, DateTimeOffset now)
    {
        var create = CreateCleanupRequest;
        if (create is null)
            return (false, "The MCP mailbox isn't wired up yet — try again in a moment.");

        var root = tree.Where(r => r.IsHarness).OrderBy(r => r.StartTime).FirstOrDefault() ?? tree[0];
        var idleMinutes = IdleCleanupPolicy.TreeIdleMinutes(tree, now);
        var childNames = tree.Where(r => !r.IsHarness).Select(r => r.Name).ToList();
        var (system, user) = IdleCleanupPolicy.BuildPrompts(harnessType, idleMinutes, childNames, manual);

        // Log entry first; its id becomes the mailbox request's alertId so the two stay linked.
        var evt = new InfoEvent(
            now, "Foreman.IdleCleanup",
            $"Self-cleanup requested for '{harnessType}' ({(manual ? "manual" : $"idle {idleMinutes}m")}) — " +
            "asked to checkpoint work, stop leftover children, and reply or exit.");
        _bus.Publish(evt);

        var requestId = create(harnessType, evt.Id, system, user, root.Pid, root.Name);
        if (requestId is null)
            return (false, "Could not queue the cleanup request on the MCP mailbox.");

        lock (_gate)
            _state[harnessType] = new CleanupState { RequestedAt = now, RequestId = requestId };

        // Best-effort live delivery; the mailbox copy survives either way.
        if (PushToOffender is { } push)
            _ = SafePush(push, harnessType, system, user, requestId);

        return (true,
            $"Cleanup request {requestId} queued for '{harnessType}'. It's delivered live if the agent is " +
            "connected to Foreman's MCP, and waits in the mailbox (ListAskHarnessRequests) either way.");
    }

    private static async Task SafePush(
        Func<string, string, string, string, Task> push,
        string harnessType, string system, string user, string requestId)
    {
        try { await push(harnessType, system, user, requestId).ConfigureAwait(false); }
        catch { /* delivery is best-effort; the mailbox request remains */ }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _task?.GetAwaiter().GetResult(); }
        catch (OperationCanceledException) { /* normal shutdown */ }
        _cts.Dispose();
    }
}
