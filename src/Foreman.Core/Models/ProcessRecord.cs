namespace Foreman.Core.Models;

public enum ProcessState
{
    Active,
    Hanging,
    Orphaned,
    Terminated,
}

public sealed class ProcessRecord
{
    public int Pid { get; init; }
    public DateTimeOffset StartTime { get; init; }
    public string Name { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public string ExecutablePath { get; init; } = string.Empty;
    public int ParentPid { get; init; }
    public bool IsHarness { get; set; }
    public string? HarnessType { get; set; }
    public string? ProfileName { get; set; }
    public ProcessState State { get; set; } = ProcessState.Active;

    public ulong LastReadOps { get; set; }
    public ulong LastWriteOps { get; set; }
    public DateTimeOffset LastIoChangeTime { get; set; }
    public bool IoCountersUnavailable { get; set; }

    public int UptimeMinutes => (int)(DateTimeOffset.UtcNow - StartTime).TotalMinutes;
    public int SilentMinutes => (int)(DateTimeOffset.UtcNow - LastIoChangeTime).TotalMinutes;

    // stable key: pid + start tick avoids reuse confusion
    public string Key => $"{Pid}:{StartTime.ToUnixTimeMilliseconds()}";

    /// <summary>
    /// A copy with the command line replaced — used to redact secrets at MCP egress without mutating
    /// the live record the local UI, detector, and kill path rely on. All other fields (incl. computed
    /// Uptime/Silent/Key) are preserved, so the serialized shape is identical.
    /// </summary>
    public ProcessRecord WithCommandLine(string commandLine) => new()
    {
        Pid = Pid,
        StartTime = StartTime,
        Name = Name,
        CommandLine = commandLine,
        ExecutablePath = ExecutablePath,
        ParentPid = ParentPid,
        IsHarness = IsHarness,
        HarnessType = HarnessType,
        ProfileName = ProfileName,
        State = State,
        LastReadOps = LastReadOps,
        LastWriteOps = LastWriteOps,
        LastIoChangeTime = LastIoChangeTime,
        IoCountersUnavailable = IoCountersUnavailable,
    };
}
