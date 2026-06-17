using System.Text;

namespace Foreman.Platform.Linux;

public static class LinuxProcParser
{
    public static bool TryParseStat(
        int expectedPid,
        string stat,
        long bootTimeUnixSeconds,
        long clockTicksPerSecond,
        out LinuxProcStat parsed)
    {
        parsed = default!;
        if (string.IsNullOrWhiteSpace(stat) || clockTicksPerSecond <= 0)
            return false;

        var open = stat.IndexOf('(');
        var close = stat.LastIndexOf(')');
        if (open <= 0 || close <= open)
            return false;

        if (!int.TryParse(stat[..open].Trim(), out var pid) || pid != expectedPid)
            return false;

        var name = stat[(open + 1)..close];
        var rest = stat[(close + 1)..].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // rest[0] is field 3 (state), rest[1] is field 4 (ppid), rest[19] is field 22 (starttime).
        if (rest.Length <= 19 ||
            !int.TryParse(rest[1], out var parentPid) ||
            !ulong.TryParse(rest[19], out var startTicks))
        {
            return false;
        }

        var startMs = checked((bootTimeUnixSeconds * 1000) + ((long)startTicks * 1000 / clockTicksPerSecond));
        parsed = new LinuxProcStat(
            pid,
            name,
            parentPid,
            startTicks,
            DateTimeOffset.FromUnixTimeMilliseconds(startMs));
        return true;
    }

    public static string ParseCmdline(byte[] bytes)
    {
        if (bytes.Length == 0) return "";
        var text = Encoding.UTF8.GetString(bytes);
        return text.Replace('\0', ' ').Trim();
    }

    public static bool TryParseBootTime(string procStat, out long bootTimeUnixSeconds)
    {
        bootTimeUnixSeconds = 0;
        foreach (var line in procStat.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!line.StartsWith("btime ", StringComparison.Ordinal))
                continue;
            return long.TryParse(line["btime ".Length..].Trim(), out bootTimeUnixSeconds);
        }
        return false;
    }

    public static bool TryParseIo(string ioText, out ulong readOps, out ulong writeOps)
    {
        readOps = 0;
        writeOps = 0;
        var sawRead = false;
        var sawWrite = false;

        foreach (var line in ioText.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var sep = line.IndexOf(':');
            if (sep <= 0) continue;

            var key = line[..sep].Trim();
            var raw = line[(sep + 1)..].Trim();
            if (!ulong.TryParse(raw, out var value))
                continue;

            if (key == "syscr")
            {
                readOps = value;
                sawRead = true;
            }
            else if (key == "syscw")
            {
                writeOps = value;
                sawWrite = true;
            }
        }

        return sawRead && sawWrite;
    }
}
