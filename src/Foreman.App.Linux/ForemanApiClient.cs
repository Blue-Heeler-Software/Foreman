using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Foreman.Platform.Linux;

namespace Foreman.App.Linux;

public sealed class ForemanApiClient : IDisposable
{
    private readonly HttpClient _http;

    public string ConfigDirectory { get; }
    public string StateDirectory { get; }
    public int Port { get; }

    public ForemanApiClient()
    {
        var paths = LinuxXdgPaths.FromCurrentEnvironment();
        ConfigDirectory = paths.ConfigDir;
        StateDirectory = paths.StateDir;
        Port = ReadPort(Path.Combine(paths.ConfigDir, "settings.json"));
        var tokenPath = Path.Combine(paths.StateDir, "mcp.token");
        var token = File.Exists(tokenPath) ? File.ReadAllText(tokenPath).Trim() : "";
        _http = new HttpClient
        {
            BaseAddress = new Uri($"http://127.0.0.1:{Port}/"),
            Timeout = TimeSpan.FromSeconds(3),
        };
        if (token.Length > 0)
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    public Task<ServiceStatus?> GetStatusAsync(CancellationToken ct) => GetAsync<ServiceStatus>("api/status", ct);
    public Task<List<ProcessInfo>?> GetProcessesAsync(CancellationToken ct) => GetAsync<List<ProcessInfo>>("api/processes", ct);
    public Task<List<AlertInfo>?> GetAlertsAsync(CancellationToken ct) => GetAsync<List<AlertInfo>>("api/alerts?limit=300", ct);
    public Task<List<EventInfo>?> GetEventsAsync(CancellationToken ct) => GetAsync<List<EventInfo>>("api/events?limit=400", ct);
    public Task<List<BehaviorInfo>?> GetBehaviorAsync(CancellationToken ct) => GetAsync<List<BehaviorInfo>>("api/behavior", ct);
    public Task<List<McpEntry>?> GetMcpInventoryAsync(CancellationToken ct) => GetAsync<List<McpEntry>>("api/mcp-inventory", ct);
    public Task<SettingsInfo?> GetSettingsAsync(CancellationToken ct) => GetAsync<SettingsInfo>("api/settings", ct);

    public async Task<bool> AcknowledgeAsync(string id, CancellationToken ct) =>
        (await _http.PostAsync($"api/alerts/{Uri.EscapeDataString(id)}/ack", null, ct)).IsSuccessStatusCode;

    public async Task<(bool Ok, string Reason)> KillAsync(int pid, CancellationToken ct)
    {
        using var response = await _http.PostAsync($"api/processes/{pid}/kill", null, ct);
        var result = await response.Content.ReadFromJsonAsync<ActionResult>(cancellationToken: ct);
        return (response.IsSuccessStatusCode && result?.Ok == true, result?.Reason ?? response.ReasonPhrase ?? "Unknown result");
    }

    public async Task<bool> ResetBehaviorAsync(string harnessId, CancellationToken ct) =>
        (await _http.PostAsync($"api/behavior/{Uri.EscapeDataString(harnessId)}/reset", null, ct)).IsSuccessStatusCode;

    private async Task<T?> GetAsync<T>(string path, CancellationToken ct)
    {
        using var response = await _http.GetAsync(path, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<T>(cancellationToken: ct);
    }

    private static int ReadPort(string path)
    {
        try
        {
            if (!File.Exists(path)) return 54321;
            using var json = JsonDocument.Parse(File.ReadAllText(path));
            foreach (var property in json.RootElement.EnumerateObject())
                if (property.Name.Equals("McpPort", StringComparison.OrdinalIgnoreCase) && property.Value.TryGetInt32(out var port))
                    return port;
        }
        catch { }
        return 54321;
    }

    public void Dispose() => _http.Dispose();

    private sealed record ActionResult([property: JsonPropertyName("ok")] bool Ok, [property: JsonPropertyName("reason")] string? Reason);
}

public sealed record ServiceStatus(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("startedAt")] DateTimeOffset StartedAt,
    [property: JsonPropertyName("uptimeSeconds")] long UptimeSeconds,
    [property: JsonPropertyName("activeAlerts")] int ActiveAlerts,
    [property: JsonPropertyName("hasCritical")] bool HasCritical,
    [property: JsonPropertyName("processCount")] int ProcessCount,
    [property: JsonPropertyName("harnessCount")] int HarnessCount,
    [property: JsonPropertyName("mcpSessions")] int McpSessions,
    [property: JsonPropertyName("pendingAskHarness")] int PendingAskHarness,
    [property: JsonPropertyName("mcpPort")] int McpPort)
{
    public string Uptime => TimeSpan.FromSeconds(UptimeSeconds) is var value
        ? value.TotalDays >= 1 ? $"{(int)value.TotalDays}d {value.Hours}h" : $"{value.Hours}h {value.Minutes}m"
        : "—";
}

public sealed record ProcessInfo(
    [property: JsonPropertyName("pid")] int Pid,
    [property: JsonPropertyName("parentPid")] int ParentPid,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("commandLine")] string CommandLine,
    [property: JsonPropertyName("executablePath")] string ExecutablePath,
    [property: JsonPropertyName("startTime")] DateTimeOffset StartTime,
    [property: JsonPropertyName("uptimeMinutes")] int UptimeMinutes,
    [property: JsonPropertyName("silentMinutes")] int SilentMinutes,
    [property: JsonPropertyName("isHarness")] bool IsHarness,
    [property: JsonPropertyName("harnessType")] string? HarnessType,
    [property: JsonPropertyName("profileName")] string? ProfileName,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("ioCountersUnavailable")] bool IoCountersUnavailable);

public sealed record AlertInfo(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("acknowledged")] bool Acknowledged,
    [property: JsonPropertyName("autoResolved")] bool AutoResolved,
    [property: JsonPropertyName("resolvedReason")] string? ResolvedReason,
    [property: JsonPropertyName("processId")] int? ProcessId)
{
    public string Time => Timestamp.ToLocalTime().ToString("g");
    public string State => Acknowledged ? "Acknowledged" : AutoResolved ? "Resolved" : "Active";
}

public sealed record EventInfo(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("acked")] bool Acknowledged)
{
    public string Time => Timestamp.ToLocalTime().ToString("g");
}

public sealed record BehaviorInfo(
    [property: JsonPropertyName("harnessId")] string HarnessId,
    [property: JsonPropertyName("displayName")] string DisplayName,
    [property: JsonPropertyName("level")] string Level,
    [property: JsonPropertyName("totalAlerts")] int TotalAlerts,
    [property: JsonPropertyName("uniqueRules")] int UniqueRules,
    [property: JsonPropertyName("categories")] List<string> Categories,
    [property: JsonPropertyName("lastAlertTime")] DateTimeOffset LastAlertTime)
{
    public string CategoryText => Categories.Count == 0 ? "—" : string.Join(", ", Categories);
}

public sealed record McpEntry(
    [property: JsonPropertyName("harness")] string Harness,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("transport")] string Transport,
    [property: JsonPropertyName("target")] string Target,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("sourceFile")] string SourceFile);

public sealed record SettingsInfo(
    [property: JsonPropertyName("mcpPort")] int McpPort,
    [property: JsonPropertyName("monitorAllProcesses")] bool MonitorAllProcesses,
    [property: JsonPropertyName("hangThresholdMinutes")] int HangThresholdMinutes,
    [property: JsonPropertyName("hookJamThresholdMinutes")] int HookJamThresholdMinutes,
    [property: JsonPropertyName("ioPollerIntervalSeconds")] int IoPollerIntervalSeconds,
    [property: JsonPropertyName("eventLogPersist")] bool EventLogPersist,
    [property: JsonPropertyName("scanMcpTools")] bool ScanMcpTools,
    [property: JsonPropertyName("idleCleanupEnabled")] bool IdleCleanupEnabled,
    [property: JsonPropertyName("idleCleanupAfterMinutes")] int IdleCleanupAfterMinutes,
    [property: JsonPropertyName("mcpPeerBindingEnforce")] bool McpPeerBindingEnforce);
