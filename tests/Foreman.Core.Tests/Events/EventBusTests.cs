using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Events;

public sealed class EventBusTests
{
    [Fact]
    public void Unsubscribe_HandlerStopsReceivingEvents()
    {
        var bus = new EventBus();   // isolated — not the shared Instance
        var count = 0;
        void Handler(ForemanEvent _) => count++;

        bus.Subscribe(Handler);
        bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "test", "before"));
        bus.Unsubscribe(Handler);
        bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "test", "after"));

        Assert.Equal(1, count);
    }

    [Fact]
    public void BoundedHistory_RetainsUnacknowledgedCriticalAheadOfNewNoise()
    {
        var history = new BoundedEventHistory(3);
        var critical = new MonitoringNoticeEvent(
            DateTimeOffset.UnixEpoch, ForemanSeverity.Critical, "test", "do not lose me");
        history.Add(critical);
        history.Add(new InfoEvent(DateTimeOffset.UnixEpoch.AddSeconds(1), "test", "noise 1"));
        history.Add(new InfoEvent(DateTimeOffset.UnixEpoch.AddSeconds(2), "test", "noise 2"));
        history.Add(new InfoEvent(DateTimeOffset.UnixEpoch.AddSeconds(3), "test", "noise 3"));

        Assert.Contains(history.Snapshot(), e => e.Id == critical.Id);
        Assert.Equal(3, history.Snapshot().Count);
    }

    [Fact]
    public void BoundedHistory_EvictsAcknowledgedCriticalBeforeActiveNoise()
    {
        var history = new BoundedEventHistory(2);
        var acknowledged = new MonitoringNoticeEvent(
            DateTimeOffset.UnixEpoch, ForemanSeverity.Critical, "test", "resolved") { Acknowledged = true };
        history.Add(acknowledged);
        history.Add(new MonitoringNoticeEvent(
            DateTimeOffset.UnixEpoch.AddSeconds(1), ForemanSeverity.Medium, "test", "active"));
        history.Add(new MonitoringNoticeEvent(
            DateTimeOffset.UnixEpoch.AddSeconds(2), ForemanSeverity.Medium, "test", "new"));

        Assert.DoesNotContain(history.Snapshot(), e => e.Id == acknowledged.Id);
    }
}
