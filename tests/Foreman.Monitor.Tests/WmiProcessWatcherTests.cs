using Foreman.Core.Events;
using Foreman.Core.Settings;
using Foreman.Monitor;
using Foreman.Monitor.Wmi;
using System.Reflection;

namespace Foreman.Monitor.Tests;

public sealed class WmiProcessWatcherTests
{
    [Fact]
    public void ParseDmtfDate_PreservesWmiUtcOffset()
    {
        var method = typeof(WmiProcessWatcher).GetMethod(
            "ParseDmtfDate",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var parsed = (DateTimeOffset)method!.Invoke(null, ["20260608205253.127537+570"])!;

        Assert.Equal(TimeSpan.FromMinutes(570), parsed.Offset);
        Assert.Equal(2026, parsed.Year);
        Assert.Equal(6, parsed.Month);
        Assert.Equal(8, parsed.Day);
        Assert.Equal(20, parsed.Hour);
        Assert.Equal(52, parsed.Minute);
        Assert.Equal(53, parsed.Second);
        Assert.Equal(
            new DateTimeOffset(2026, 6, 8, 11, 22, 53, 127, TimeSpan.Zero).AddTicks(5370),
            parsed.ToUniversalTime());
    }

    [Fact]
    public void IoPoller_DisposeAfterStart_DoesNotThrowOnCancellation()
    {
        var tree = new ProcessTreeTracker();
        var hang = new HangDetector(new EventBus(), new ForemanSettings(), tree);
        var poller = new IoPoller(
            tree,
            hang,
            new ForemanSettings { IoPollerIntervalSeconds = 60 });

        poller.Start();
        poller.Dispose();
    }
}
