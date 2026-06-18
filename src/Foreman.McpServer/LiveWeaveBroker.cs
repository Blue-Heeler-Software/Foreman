using System.Collections.Concurrent;

namespace Foreman.McpServer;

public enum LiveWeaveCommandStatus
{
    Pending,
    Delivered,
    Completed,
    Failed,
}

public sealed record LiveWeaveCommand(
    string CommandId,
    string Action,
    IReadOnlyDictionary<string, object?> Parameters,
    DateTimeOffset CreatedAt,
    LiveWeaveCommandStatus Status,
    object? Result = null,
    string? Error = null,
    DateTimeOffset? CompletedAt = null,
    string? ByHarness = null);   // which harness enqueued it — gated against the chosen driver

public sealed class LiveWeavePresence
{
    public DateTimeOffset LastSeen { get; set; }
    public object? TabInfo { get; set; }
    public string? NanoStatus { get; set; }
}

/// <summary>
/// Command queue between Foreman MCP (agents) and the LiveWeave Chrome extension.
/// Agents enqueue; the extension polls and completes.
/// </summary>
public sealed class LiveWeaveBroker
{
    private readonly ConcurrentDictionary<string, LiveWeaveCommand> _commands = new();
    private readonly ConcurrentQueue<string> _pending = new();
    private readonly object _presenceLock = new();
    private LiveWeavePresence _presence = new();
    private const int MaxCommands = 100;
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(10);
    private volatile string? _driver;   // the chosen harness allowed to drive LiveWeave; null/empty = any

    /// <summary>"operator" marker recorded for commands enqueued by the unscoped install token — always allowed.</summary>
    private const string OperatorMarker = "operator";

    /// <summary>The harness the operator chose (via the LiveWeave extension) to let drive the builder; null = any.</summary>
    public string? Driver => _driver;

    /// <summary>Set by the LiveWeave extension (the thing being driven) to the one harness it accepts commands
    /// from. "" / null clears it back to "any harness".</summary>
    public void SetDriver(string? harnessId)
        => _driver = string.IsNullOrWhiteSpace(harnessId) ? null : harnessId.Trim().ToLowerInvariant();

    /// <summary>May commands from <paramref name="harnessId"/> drive LiveWeave? The operator always may; an
    /// operator-enqueued command always may; a harness only when it is the chosen driver (or none is set = any).</summary>
    public bool CanDrive(string? harnessId, bool isOperator)
    {
        if (isOperator || string.Equals(harnessId, OperatorMarker, StringComparison.OrdinalIgnoreCase)) return true;
        var d = _driver;
        if (string.IsNullOrEmpty(d)) return true;
        return harnessId is not null && string.Equals(harnessId, d, StringComparison.OrdinalIgnoreCase);
    }

    public string Enqueue(string action, IReadOnlyDictionary<string, object?>? parameters = null, string? byHarness = null)
    {
        var id = Guid.NewGuid().ToString("N")[..12];
        var cmd = new LiveWeaveCommand(
            id,
            action.Trim().ToLowerInvariant(),
            parameters ?? new Dictionary<string, object?>(),
            DateTimeOffset.UtcNow,
            LiveWeaveCommandStatus.Pending,
            ByHarness: string.IsNullOrWhiteSpace(byHarness) ? null : byHarness.Trim().ToLowerInvariant());

        _commands[id] = cmd;
        _pending.Enqueue(id);
        Prune();
        return id;
    }

    public IReadOnlyList<LiveWeaveCommand> Poll(int limit)
    {
        var n = Math.Clamp(limit, 1, 10);
        var batch = new List<LiveWeaveCommand>(n);
        while (batch.Count < n && _pending.TryDequeue(out var id))
        {
            if (!_commands.TryGetValue(id, out var cmd)) continue;
            if (cmd.Status != LiveWeaveCommandStatus.Pending) continue;
            // Re-check the driver at delivery: the operator may have changed the chosen harness since this was
            // queued, so fail (don't deliver) anything no longer from the current driver instead of executing it.
            if (!CanDrive(cmd.ByHarness, isOperator: false))
            {
                _commands[id] = cmd with
                {
                    Status = LiveWeaveCommandStatus.Failed,
                    Error = $"Rejected: LiveWeave is set to accept commands only from '{_driver}', not '{cmd.ByHarness ?? "unknown"}'.",
                    CompletedAt = DateTimeOffset.UtcNow,
                };
                continue;
            }
            var delivered = cmd with { Status = LiveWeaveCommandStatus.Delivered };
            _commands[id] = delivered;
            batch.Add(delivered);
        }
        TouchPresence();
        return batch;
    }

    public (bool Ok, string Reason) Complete(string commandId, bool ok, object? result, string? error)
    {
        if (!_commands.TryGetValue(commandId, out var cmd))
            return (false, "Unknown command id.");

        if (cmd.Status is LiveWeaveCommandStatus.Completed or LiveWeaveCommandStatus.Failed)
            return (false, "Command already completed.");

        var done = cmd with
        {
            Status = ok ? LiveWeaveCommandStatus.Completed : LiveWeaveCommandStatus.Failed,
            Result = result,
            Error = string.IsNullOrWhiteSpace(error) ? null : error.Trim(),
            CompletedAt = DateTimeOffset.UtcNow,
        };
        _commands[commandId] = done;
        TouchPresence();
        return (true, ok ? "Completed." : "Failed.");
    }

    public LiveWeaveCommand? GetCommand(string commandId) =>
        _commands.TryGetValue(commandId, out var c) ? c : null;

    public void UpdatePresence(object? tabInfo, string? nanoStatus)
    {
        lock (_presenceLock)
        {
            _presence.LastSeen = DateTimeOffset.UtcNow;
            if (tabInfo is not null) _presence.TabInfo = tabInfo;
            if (!string.IsNullOrWhiteSpace(nanoStatus)) _presence.NanoStatus = nanoStatus;
        }
    }

    /// <summary>
    /// True when the LiveWeave extension has polled/checked in within the last 30 seconds — the same
    /// presence window <see cref="DescribeStatus"/> reports. Lets the Connect-Agent UI show live link state
    /// without depending on MCP session bookkeeping (the extension polls, it holds no persistent session).
    /// </summary>
    public bool IsConnected
    {
        get
        {
            lock (_presenceLock)
                return DateTimeOffset.UtcNow - _presence.LastSeen < TimeSpan.FromSeconds(30);
        }
    }

    public object DescribeStatus()
    {
        lock (_presenceLock)
        {
            var age = DateTimeOffset.UtcNow - _presence.LastSeen;
            var connected = age < TimeSpan.FromSeconds(30);
            var pending = _commands.Values.Count(c => c.Status == LiveWeaveCommandStatus.Pending);
            var delivered = _commands.Values.Count(c => c.Status == LiveWeaveCommandStatus.Delivered);

            return new
            {
                connected,
                lastSeenSecondsAgo = connected ? (int)age.TotalSeconds : (int?)null,
                nanoStatus = _presence.NanoStatus,
                tab = _presence.TabInfo,
                pendingCommands = pending,
                inFlightCommands = delivered,
                driverHarness = _driver,   // null = accepting commands from any harness; else only this one
                hint = connected
                    ? "LiveWeave extension is linked. Use liveweave_command to control the builder."
                    : "LiveWeave extension not connected — open LiveWeave in Chrome and pair with Foreman (Connect agent → Pair browser extension, choose LiveWeave harness).",
            };
        }
    }

    private void TouchPresence() => UpdatePresence(null, null);

    private void Prune()
    {
        if (_commands.Count <= MaxCommands) return;
        var victims = _commands.Values
            .Where(c => c.Status is LiveWeaveCommandStatus.Completed or LiveWeaveCommandStatus.Failed)
            .OrderBy(c => c.CompletedAt ?? c.CreatedAt)
            .Take(_commands.Count - MaxCommands)
            .Select(c => c.CommandId)
            .ToList();
        foreach (var id in victims) _commands.TryRemove(id, out _);
    }
}
