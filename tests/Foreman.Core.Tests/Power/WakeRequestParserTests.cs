using Foreman.Core.Power;

namespace Foreman.Core.Tests.Power;

public sealed class WakeRequestParserTests
{
    [Fact]
    public void ParsePowercfgRequests_ReturnsProcessRequestsWithDetails()
    {
        var parsed = WakeRequestParser.ParsePowercfgRequests("""
            DISPLAY:
            None.

            SYSTEM:
            [PROCESS] C:\Tools\agent\node.exe
            An active timer is keeping the system awake.

            AWAYMODE:
            None.

            EXECUTION:
            [PROCESS] \Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
            Power Request Context: test
            """);

        Assert.True(parsed.Available);
        Assert.Equal(2, parsed.Requests.Count);
        Assert.Equal("SYSTEM", parsed.Requests[0].Category);
        Assert.Equal("PROCESS", parsed.Requests[0].RequesterType);
        Assert.Equal(@"C:\Tools\agent\node.exe", parsed.Requests[0].Image);
        Assert.Contains("active timer", parsed.Requests[0].Detail);
        Assert.Equal("EXECUTION", parsed.Requests[1].Category);
        Assert.Contains("Power Request Context", parsed.Requests[1].Detail);
    }
}
