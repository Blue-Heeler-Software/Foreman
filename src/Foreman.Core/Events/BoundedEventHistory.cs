using Foreman.Core.Models;

namespace Foreman.Core.Events;

/// <summary>
/// Thread-safe bounded event history that sheds acknowledged and lower-severity noise before unresolved High or
/// Critical evidence. Ordering of retained items remains chronological.
/// </summary>
public sealed class BoundedEventHistory
{
    private readonly object _gate = new();
    private readonly List<ForemanEvent> _events = [];
    private readonly int _capacity;

    public BoundedEventHistory(int capacity)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
    }

    public void Add(ForemanEvent evt)
    {
        lock (_gate)
        {
            _events.Add(evt);
            if (_events.Count <= _capacity) return;

            var victim = _events
                .Select(static (candidate, index) => new { candidate, index })
                .OrderBy(static x => x.candidate.Acknowledged ? 0 : 1)
                .ThenBy(static x => x.candidate.Severity)
                .ThenBy(static x => x.candidate.Timestamp)
                .First();
            _events.RemoveAt(victim.index);
        }
    }

    public IReadOnlyList<ForemanEvent> Snapshot()
    {
        lock (_gate) return _events.ToArray();
    }
}
