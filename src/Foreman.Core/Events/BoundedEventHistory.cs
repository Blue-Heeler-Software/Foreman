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
    private readonly int _agentQuota;

    public BoundedEventHistory(int capacity)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
        _agentQuota = Math.Max(1, capacity / 4);
    }

    public void Add(ForemanEvent evt)
    {
        lock (_gate)
        {
            _events.Add(evt);
            foreach (var victim in EventRetentionPolicy.SelectAgentQuotaVictims(_events, _agentQuota))
                _events.Remove(victim);

            if (_events.Count <= _capacity) return;
            var protectArrival = !EventRetentionPolicy.IsAgentReported(evt) && evt.Severity >= ForemanSeverity.High
                ? evt.Id
                : null;
            foreach (var victim in EventRetentionPolicy.SelectVictims(
                         _events, _events.Count - _capacity, protectArrival))
                _events.Remove(victim);
        }
    }

    public IReadOnlyList<ForemanEvent> Snapshot()
    {
        lock (_gate) return _events.ToArray();
    }
}
