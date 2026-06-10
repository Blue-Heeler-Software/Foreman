namespace Foreman.Core.Models;

/// <summary>
/// Pure decision logic for "Idle Harness self-cleanup": when a harness process tree looks
/// abandoned, Foreman asks the harness over MCP to pack up cleanly (checkpoint work, stop
/// leftover children, release resources) instead of silently burning CPU/tokens. The
/// orchestration (timer, mailbox, MCP push) lives in Foreman.Monitor/App; everything here
/// is side-effect-free and unit-testable.
///
/// This is a housekeeping nudge, not an enforcement action: the harness decides what to do,
/// and an unanswered request only escalates to a visible notice suggesting the operator act.
/// </summary>
public static class IdleCleanupPolicy
{
    /// <summary>
    /// True when the harness tree looks abandoned: every judgeable (readable-counters,
    /// not-terminated) process has been I/O-silent for at least <paramref name="idleAfterMinutes"/>,
    /// AND nothing in the tree was spawned more recently than that (a fresh child is activity),
    /// AND at least one process is judgeable at all. Records with unavailable I/O counters
    /// (elevated children) can't veto idleness, but their spawn time still counts as activity.
    /// </summary>
    public static bool IsTreeIdle(IReadOnlyList<ProcessRecord> tree, int idleAfterMinutes, DateTimeOffset now)
    {
        var threshold = TimeSpan.FromMinutes(Math.Max(1, idleAfterMinutes));
        var live = tree.Where(r => r.State != ProcessState.Terminated).ToList();
        if (live.Count == 0) return false;

        var judgeable = live.Where(r => !r.IoCountersUnavailable).ToList();
        if (judgeable.Count == 0) return false;                       // can't tell — never nag blind

        if (live.Any(r => now - r.StartTime < threshold)) return false;          // recent spawn = activity
        return judgeable.All(r => now - r.LastIoChangeTime >= threshold);
    }

    /// <summary>Minutes since the tree last did anything — min silent time across judgeable processes.</summary>
    public static int TreeIdleMinutes(IReadOnlyList<ProcessRecord> tree, DateTimeOffset now)
    {
        var judgeable = tree
            .Where(r => r.State != ProcessState.Terminated && !r.IoCountersUnavailable)
            .ToList();
        if (judgeable.Count == 0) return 0;
        return (int)judgeable.Min(r => (now - r.LastIoChangeTime).TotalMinutes);
    }

    /// <summary>Whether an automatic request may fire — once per harness per cooldown window.</summary>
    public static bool ShouldAutoRequest(DateTimeOffset? lastRequestAt, int cooldownMinutes, DateTimeOffset now)
        => lastRequestAt is null
        || now - lastRequestAt.Value >= TimeSpan.FromMinutes(Math.Max(1, cooldownMinutes));

    /// <summary>
    /// Whether an unanswered cleanup request should escalate to a visible notice. Fires at most
    /// once per request, only while the request is still pending AND the tree is still idle —
    /// if the harness woke up or replied, there is nothing to escalate.
    /// </summary>
    public static bool ShouldEscalate(
        DateTimeOffset requestedAt, bool stillPending, bool stillIdle, bool alreadyEscalated,
        int graceMinutes, DateTimeOffset now)
        => !alreadyEscalated
        && stillPending
        && stillIdle
        && now - requestedAt >= TimeSpan.FromMinutes(Math.Max(1, graceMinutes));

    /// <summary>
    /// Builds the system/user prompts delivered to the harness (via the Ask-Harness mailbox and,
    /// when a session is live, the sampling/notification push). The request id is not embedded —
    /// agents see it alongside the prompt in ListAskHarnessRequests, and pushes carry it separately.
    /// </summary>
    public static (string System, string User) BuildPrompts(
        string harnessId, int idleMinutes, IReadOnlyList<string> childNames, bool manual)
    {
        var system =
            $"You are the '{harnessId}' coding agent. Foreman Agent Safety, the local watchdog on this machine, " +
            "is asking you to wrap up an apparently idle session. This is routine housekeeping, not an accusation — " +
            "if you are mid-task or waiting on the user, just say so.";

        var trigger = manual
            ? "The operator asked Foreman to request a session cleanup from you."
            : $"Your process tree has shown no I/O activity for about {idleMinutes} minute(s) and looks abandoned.";

        var children = childNames.Count > 0
            ? $" Your tracked child processes: {string.Join(", ", childNames.Distinct(StringComparer.OrdinalIgnoreCase).Take(8))}."
            : "";

        var user =
            $"{trigger}{children}\n" +
            "Please pack up cleanly:\n" +
            "1. Finish or checkpoint your current work (save files; commit only if your own instructions allow it).\n" +
            "2. Stop any leftover child processes you spawned (builds, dev servers, file watchers, shells).\n" +
            "3. Release file locks and clean up temp resources you own.\n" +
            $"4. Reply via ReplyToAskHarnessRequest(requestId, response, actionTaken, harnessId: \"{harnessId}\") " +
            "— the requestId is shown by ListAskHarnessRequests.\n" +
            "5. If this session is still needed (mid-task, waiting for the user), reply saying so and Foreman will leave you alone.";

        return (system, user);
    }
}
