namespace Foreman.Platform.Linux;

public sealed record LinuxProcStat(
    int Pid,
    string Name,
    int ParentPid,
    ulong StartTicks,
    DateTimeOffset StartTime);
