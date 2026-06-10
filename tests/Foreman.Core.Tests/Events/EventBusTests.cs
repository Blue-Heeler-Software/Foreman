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
}
