using Foreman.Core.Models;
using Foreman.Platform;
using Foreman.Platform.Linux;

namespace Foreman.Platform.Linux.Tests;

public sealed class LinuxPollingProcessEventSourceTests
{
    [Fact]
    public void PollNow_EmitsStartedAndExitedFromSnapshotDiff()
    {
        var provider = new ScriptedSnapshotProvider(
            [
                [Record(1, 1000), Record(2, 1000)],
                [Record(2, 1000), Record(3, 1000)],
            ]);
        using var source = new LinuxPollingProcessEventSource(provider, TimeSpan.FromHours(1));
        var started = new List<int>();
        var exited = new List<int>();
        source.ProcessStarted += p => started.Add(p.Pid);
        source.ProcessExited += (pid, _) => exited.Add(pid);

        source.Start();
        source.PollNow();

        Assert.Equal([3], started);
        Assert.Equal([1], exited);
    }

    private static ProcessRecord Record(int pid, long startMs) => new()
    {
        Pid = pid,
        ParentPid = 0,
        Name = $"p{pid}",
        StartTime = DateTimeOffset.FromUnixTimeMilliseconds(startMs),
        LastIoChangeTime = DateTimeOffset.UtcNow,
    };

    private sealed class ScriptedSnapshotProvider : IProcessSnapshotProvider
    {
        private readonly Queue<IReadOnlyList<ProcessRecord>> _snapshots;

        public ScriptedSnapshotProvider(IEnumerable<IReadOnlyList<ProcessRecord>> snapshots)
        {
            _snapshots = new Queue<IReadOnlyList<ProcessRecord>>(snapshots);
        }

        public IReadOnlyList<ProcessRecord> Snapshot() =>
            _snapshots.Count > 0 ? _snapshots.Dequeue() : [];
    }
}
