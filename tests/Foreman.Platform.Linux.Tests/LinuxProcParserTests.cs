using Foreman.Platform.Linux;

namespace Foreman.Platform.Linux.Tests;

public sealed class LinuxProcParserTests
{
    [Fact]
    public void TryParseStat_HandlesProcessNamesWithSpacesAndParentheses()
    {
        var stat = "4242 (agent worker (dev)) S 100 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 987654 12 18446744073709551615";

        var ok = LinuxProcParser.TryParseStat(
            4242,
            stat,
            bootTimeUnixSeconds: 1_700_000_000,
            clockTicksPerSecond: 100,
            out var parsed);

        Assert.True(ok);
        Assert.Equal(4242, parsed.Pid);
        Assert.Equal("agent worker (dev)", parsed.Name);
        Assert.Equal(100, parsed.ParentPid);
        Assert.Equal((ulong)12345, parsed.StartTicks);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1_700_000_000_000 + 123_450), parsed.StartTime);
    }

    [Fact]
    public void ParseCmdline_ReplacesNulSeparators()
    {
        var bytes = new byte[] { (byte)'n', (byte)'o', (byte)'d', (byte)'e', 0, (byte)'a', (byte)'p', (byte)'p', (byte)'.', (byte)'j', (byte)'s', 0 };

        var parsed = LinuxProcParser.ParseCmdline(bytes);

        Assert.Equal("node app.js", parsed);
    }

    [Fact]
    public void TryParseBootTime_ReadsBtimeLine()
    {
        var ok = LinuxProcParser.TryParseBootTime("cpu  1 2 3\nbtime 1710000000\nintr 1\n", out var boot);

        Assert.True(ok);
        Assert.Equal(1_710_000_000, boot);
    }

    [Fact]
    public void TryParseIo_ReadsSyscallCounters()
    {
        var io = """
                 rchar: 10
                 wchar: 20
                 syscr: 30
                 syscw: 40
                 read_bytes: 50
                 write_bytes: 60
                 """;

        var ok = LinuxProcParser.TryParseIo(io, out var readOps, out var writeOps);

        Assert.True(ok);
        Assert.Equal((ulong)30, readOps);
        Assert.Equal((ulong)40, writeOps);
    }
}
