using Foreman.Core.Models;
using Foreman.Platform;

namespace Foreman.Platform.Linux;

public sealed class LinuxProcProcessSnapshotProvider : IProcessSnapshotProvider
{
    private readonly string _procRoot;
    private readonly long _clockTicksPerSecond;

    public LinuxProcProcessSnapshotProvider(string procRoot = "/proc", long clockTicksPerSecond = 100)
    {
        _procRoot = procRoot;
        _clockTicksPerSecond = clockTicksPerSecond;
    }

    public IReadOnlyList<ProcessRecord> Snapshot()
    {
        var bootTime = ReadBootTime();
        if (bootTime is null) return [];

        var now = DateTimeOffset.UtcNow;
        var records = new List<ProcessRecord>();
        foreach (var dir in Directory.EnumerateDirectories(_procRoot))
        {
            var name = Path.GetFileName(dir);
            if (!int.TryParse(name, out var pid))
                continue;

            if (!TryBuildRecord(pid, dir, bootTime.Value, now, out var record))
                continue;

            records.Add(record);
        }

        return records;
    }

    private bool TryBuildRecord(
        int pid,
        string procDir,
        long bootTimeUnixSeconds,
        DateTimeOffset observedAt,
        out ProcessRecord record)
    {
        record = default!;
        try
        {
            var statText = File.ReadAllText(Path.Combine(procDir, "stat"));
            if (!LinuxProcParser.TryParseStat(pid, statText, bootTimeUnixSeconds, _clockTicksPerSecond, out var stat))
                return false;

            var cmdlinePath = Path.Combine(procDir, "cmdline");
            var commandLine = File.Exists(cmdlinePath)
                ? LinuxProcParser.ParseCmdline(File.ReadAllBytes(cmdlinePath))
                : "";

            record = new ProcessRecord
            {
                Pid = stat.Pid,
                ParentPid = stat.ParentPid,
                Name = stat.Name,
                CommandLine = commandLine,
                ExecutablePath = ReadLinkTarget(Path.Combine(procDir, "exe")) ?? "",
                StartTime = stat.StartTime,
                LastIoChangeTime = observedAt,
            };
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private long? ReadBootTime()
    {
        try
        {
            var stat = File.ReadAllText(Path.Combine(_procRoot, "stat"));
            return LinuxProcParser.TryParseBootTime(stat, out var bootTime) ? bootTime : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadLinkTarget(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.LinkTarget;
        }
        catch
        {
            return null;
        }
    }
}
