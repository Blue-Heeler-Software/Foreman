using Foreman.Core.Models;
using Foreman.Platform;

namespace Foreman.Platform.Linux;

public sealed class LinuxPollingProcessEventSource : IProcessEventSource
{
    private readonly IProcessSnapshotProvider _snapshotProvider;
    private readonly TimeSpan _interval;
    private readonly object _gate = new();
    private Dictionary<string, ProcessRecord> _last = new(StringComparer.Ordinal);
    private Timer? _timer;
    private bool _started;

    public event Action<ProcessRecord>? ProcessStarted;
    public event Action<int, DateTimeOffset?>? ProcessExited;

    public LinuxPollingProcessEventSource(IProcessSnapshotProvider snapshotProvider, TimeSpan? interval = null)
    {
        _snapshotProvider = snapshotProvider;
        _interval = interval ?? TimeSpan.FromSeconds(1);
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_started) return;
            _started = true;
            _last = SnapshotByKey();
            _timer = new Timer(_ => Poll(), null, _interval, _interval);
        }
    }

    public void PollNow() => Poll();

    private void Poll()
    {
        Dictionary<string, ProcessRecord> current;
        Dictionary<string, ProcessRecord> previous;

        lock (_gate)
        {
            if (!_started) return;
            current = SnapshotByKey();
            previous = _last;
            _last = current;
        }

        foreach (var pair in current)
        {
            if (!previous.ContainsKey(pair.Key))
                ProcessStarted?.Invoke(pair.Value);
        }

        foreach (var pair in previous)
        {
            if (!current.ContainsKey(pair.Key))
                ProcessExited?.Invoke(pair.Value.Pid, pair.Value.StartTime);
        }
    }

    private Dictionary<string, ProcessRecord> SnapshotByKey() =>
        _snapshotProvider.Snapshot().ToDictionary(static p => p.Key, StringComparer.Ordinal);

    public void Dispose()
    {
        _timer?.Dispose();
    }
}
