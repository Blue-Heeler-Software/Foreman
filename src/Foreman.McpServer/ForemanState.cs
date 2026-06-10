using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Mcp;
using Foreman.Core.Models;
using Foreman.Core.Profiles;
using Foreman.Core.Security;
using Foreman.Core.Settings;
using System.Collections.Concurrent;

namespace Foreman.McpServer;

/// <summary>
/// Shared in-process state bag threadsafely accessed by MCP tools and the alert dispatcher.
/// </summary>
public sealed class ForemanState : IEventSink
{
    private readonly ConcurrentQueue<ForemanEvent> _eventLog = new();
    private readonly ConcurrentDictionary<string, ForemanEvent> _alertById = new();
    private readonly ConcurrentDictionary<string, AskHarnessRequest> _askRequests = new();
    private const int MaxEvents = 1000;
    private const int MaxAlerts = 1000;
    private const int MaxAskHarnessRequests = 200;

    public DateTimeOffset StartTime { get; } = DateTimeOffset.UtcNow;
    public int McpPort { get; set; } = 54321;
    public LlmTriageSettings LlmTriage { get; set; } = new();

    // injected from MonitorService / BehaviorTracker after construction
    public Func<IEnumerable<ProcessRecord>>?       GetProcessSnapshot  { get; set; }
    public Func<IEnumerable<BehaviorProfile>>?     GetBehaviorProfiles { get; set; }
    public Func<string, HarnessProfile?>?          GetProfileByName    { get; set; }
    public Func<string, string?>?                  GetDefaultProfileNameByHarnessId { get; set; }
    public Func<int, ProcessRecord?>?              FindHarnessAncestorByPid { get; set; }
    public Func<int>?                              GetMcpSessionCount { get; set; }
    public Func<IReadOnlyList<McpClientInfo>>?      GetMcpClients { get; set; }
    public Func<IEnumerable<McpServerEntry>>?      GetMcpInventory    { get; set; }
    public Func<(IReadOnlyList<McpToolFinding> Findings, string Summary)>? GetMcpToolScan { get; set; }

    /// <summary>Resets behavioral metrics for a specific harness ID. Returns false if not found.</summary>
    public Action<string>? ResetBehaviorProfile { get; set; }

    public int ActiveAlerts => _alertById.Values.Count(e => !e.Acknowledged);
    public bool HasCritical => _alertById.Values.Any(e => !e.Acknowledged && e.Severity >= ForemanSeverity.High);
    public int ProcessCount => GetProcessSnapshot?.Invoke().Count() ?? 0;
    public int McpSessionCount => GetMcpSessionCount?.Invoke() ?? 0;
    public int PendingAskHarnessCount => _askRequests.Values.Count(static r => r.Status == "pending");

    void IEventSink.OnEvent(ForemanEvent evt)
    {
        if (evt.Severity > ForemanSeverity.Info)
        {
            _alertById[evt.Id] = evt;

            // Bound the alert store like the event queue — a connected agent can mint events,
            // so an uncapped dictionary is attacker-inflatable memory + count poisoning.
            // Evict acknowledged first, then oldest, so live signal survives the longest.
            if (_alertById.Count > MaxAlerts)
            {
                foreach (var stale in _alertById.Values
                    .OrderBy(static a => a.Acknowledged ? 0 : 1)
                    .ThenBy(static a => a.Timestamp)
                    .Take(_alertById.Count - MaxAlerts)
                    .ToList())
                {
                    _alertById.TryRemove(stale.Id, out _);
                }
            }
        }
        _eventLog.Enqueue(evt);

        // prune old events
        while (_eventLog.Count > MaxEvents)
            _eventLog.TryDequeue(out _);
    }

    public void AddEvent(ForemanEvent evt) => ((IEventSink)this).OnEvent(evt);

    public bool AcknowledgeAlert(string alertId)
    {
        if (!_alertById.TryGetValue(alertId, out var evt)) return false;
        evt.Acknowledged = true;
        return true;
    }

    /// <summary>Returns the tracked alert with the given id, or null. Used to gate ack by severity.</summary>
    public ForemanEvent? GetAlert(string alertId) =>
        _alertById.TryGetValue(alertId, out var evt) ? evt : null;

    /// <summary>Current escalation level for a harness, or null if it has no profile yet.</summary>
    public EscalationLevel? GetEscalationLevel(string harnessId) =>
        GetBehaviorProfiles?.Invoke()
            .FirstOrDefault(p => string.Equals(p.HarnessId, harnessId, StringComparison.OrdinalIgnoreCase))
            ?.CurrentLevel;

    public IEnumerable<ProcessRecord> GetProcesses(bool includeChildren) =>
        GetProcessSnapshot?.Invoke()
            .Where(p => includeChildren || p.IsHarness) ?? [];

    public ProcessRecord? GetProcess(int pid) =>
        GetProcessSnapshot?.Invoke().FirstOrDefault(p => p.Pid == pid);

    public IEnumerable<ProcessRecord> GetProcessesForHarness(string harnessId, bool includeChildren)
    {
        var snapshot = GetProcessSnapshot?.Invoke().ToList() ?? [];
        if (!includeChildren)
        {
            return snapshot.Where(p =>
                string.Equals(p.HarnessType, harnessId, StringComparison.OrdinalIgnoreCase));
        }

        return snapshot.Where(p =>
            string.Equals(p.HarnessType, harnessId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(FindHarnessAncestorByPid?.Invoke(p.Pid)?.HarnessType, harnessId, StringComparison.OrdinalIgnoreCase));
    }

    public HarnessProfile? ResolveProfile(string? profileName, string? harnessId, int? processId)
    {
        if (!string.IsNullOrWhiteSpace(profileName) && GetProfileByName?.Invoke(profileName) is { } explicitProfile)
            return explicitProfile;

        if (processId is int pid)
        {
            var proc = GetProcess(pid);
            if (proc?.ProfileName is not null && GetProfileByName?.Invoke(proc.ProfileName) is { } processProfile)
                return processProfile;

            var ancestor = FindHarnessAncestorByPid?.Invoke(pid);
            if (ancestor?.ProfileName is not null && GetProfileByName?.Invoke(ancestor.ProfileName) is { } ancestorProfile)
                return ancestorProfile;
        }

        if (!string.IsNullOrWhiteSpace(harnessId) &&
            GetDefaultProfileNameByHarnessId?.Invoke(harnessId) is { } defaultProfileName)
        {
            return GetProfileByName?.Invoke(defaultProfileName);
        }

        return null;
    }

    public string? ResolveHarnessId(string? harnessId, int? processId)
    {
        if (!string.IsNullOrWhiteSpace(harnessId)) return harnessId;

        if (processId is int pid)
        {
            var proc = GetProcess(pid);
            if (proc?.HarnessType is not null) return proc.HarnessType;
            var ancestor = FindHarnessAncestorByPid?.Invoke(pid);
            if (ancestor?.HarnessType is not null) return ancestor.HarnessType;
        }

        return null;
    }

    public IEnumerable<object> GetEvents(int limit, ForemanSeverity? minSeverity)
    {
        return _eventLog
            .Where(e => minSeverity is null || e.Severity >= minSeverity)
            .TakeLast(limit)
            .Select(e => new
            {
                id        = e.Id,
                timestamp = e.Timestamp,
                severity  = e.Severity.ToString(),
                source    = e.Source,
                message   = SecretRedactor.Redact(e.Message),   // egress to a connected agent — mask secrets
                acked     = e.Acknowledged,
            });
    }

    public AskHarnessRequest CreateAskHarnessRequest(
        string harnessId,
        string systemPrompt,
        string prompt,
        string alertId,
        int? processId,
        string? processName)
    {
        var request = new AskHarnessRequest(
            Guid.NewGuid().ToString("N")[..12],
            DateTimeOffset.UtcNow,
            alertId,
            harnessId,
            processId,
            processName,
            systemPrompt,
            prompt,
            "pending");

        _askRequests[request.RequestId] = request;
        PruneAskHarnessRequests();
        return request;
    }

    public IReadOnlyList<AskHarnessRequest> ListAskHarnessRequests(
        string? harnessId,
        int? processId,
        bool includeAnswered,
        int limit)
    {
        var resolvedHarness = ResolveHarnessId(harnessId, processId);
        var query = _askRequests.Values.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(resolvedHarness))
        {
            query = query.Where(r =>
                string.Equals(r.HarnessId, resolvedHarness, StringComparison.OrdinalIgnoreCase));
        }

        if (!includeAnswered)
            query = query.Where(static r => r.Status == "pending");

        return query
            .OrderByDescending(static r => r.CreatedAt)
            .Take(Math.Clamp(limit, 1, 50))
            .ToList();
    }

    public AskHarnessRequest? GetAskHarnessRequest(string requestId) =>
        _askRequests.TryGetValue(requestId, out var request) ? request : null;

    public (bool Ok, string Reason, AskHarnessRequest? Request) ReplyToAskHarnessRequest(
        string requestId,
        string replyText,
        string? actionTaken,
        string? harnessId,
        int? processId)
    {
        if (!_askRequests.TryGetValue(requestId, out var request))
            return (false, "No Ask Harness request exists with that id.", null);

        // Identity is required: an anonymous reply (no harnessId/processId) previously
        // short-circuited the ownership check, letting any connected client answer any
        // harness's request — including forging "I cleaned up" for idle-cleanup asks.
        var resolvedHarness = ResolveHarnessId(harnessId, processId);
        if (string.IsNullOrWhiteSpace(resolvedHarness))
        {
            return (false,
                $"Identify yourself to reply: pass harnessId (\"{request.HarnessId}\") or a processId belonging to it.",
                request);
        }

        if (!string.Equals(request.HarnessId, resolvedHarness, StringComparison.OrdinalIgnoreCase))
        {
            return (false,
                $"Request {requestId} belongs to '{request.HarnessId}', not '{resolvedHarness}'.",
                request);
        }

        var updated = request with
        {
            Status = "answered",
            RepliedAt = DateTimeOffset.UtcNow,
            ReplyText = replyText,
            ActionTaken = string.IsNullOrWhiteSpace(actionTaken) ? null : actionTaken.Trim(),
        };
        _askRequests[requestId] = updated;
        return (true, "Reply recorded.", updated);
    }

    public int CountAskHarnessRequests(string? harnessId = null, bool includeAnswered = false)
    {
        var query = _askRequests.Values.AsEnumerable();
        if (!string.IsNullOrWhiteSpace(harnessId))
            query = query.Where(r => string.Equals(r.HarnessId, harnessId, StringComparison.OrdinalIgnoreCase));
        if (!includeAnswered)
            query = query.Where(static r => r.Status == "pending");
        return query.Count();
    }

    private void PruneAskHarnessRequests()
    {
        var toRemove = _askRequests.Values
            .OrderByDescending(static r => r.CreatedAt)
            .Skip(MaxAskHarnessRequests)
            .Select(static r => r.RequestId)
            .ToList();

        foreach (var id in toRemove)
            _askRequests.TryRemove(id, out _);
    }
}
