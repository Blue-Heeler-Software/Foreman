using Foreman.Core.Models;

namespace Foreman.Platform;

public interface IProcessSnapshotProvider
{
    IReadOnlyList<ProcessRecord> Snapshot();
}

public interface IProcessEventSource : IDisposable
{
    event Action<ProcessRecord>? ProcessStarted;
    event Action<int, DateTimeOffset?>? ProcessExited;
    void Start();
}

public interface IProcessIoReader
{
    bool TryReadIo(int pid, out ulong readOps, out ulong writeOps, out string? unavailableReason);
}
