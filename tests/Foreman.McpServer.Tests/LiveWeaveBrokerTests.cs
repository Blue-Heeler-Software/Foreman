using Foreman.McpServer;

namespace Foreman.McpServer.Tests;

public sealed class LiveWeaveBrokerTests
{
    [Fact]
    public void Enqueue_Poll_Complete_RoundTrip()
    {
        var broker = new LiveWeaveBroker();
        var id = broker.Enqueue("apply_page", new Dictionary<string, object?> { ["html"] = "<main>x</main>" });

        var batch = broker.Poll(5);
        Assert.Single(batch);
        Assert.Equal(id, batch[0].CommandId);
        Assert.Equal("apply_page", batch[0].Action);

        var done = broker.Complete(id, true, new { ok = true }, null);
        Assert.True(done.Ok);

        var cmd = broker.GetCommand(id);
        Assert.NotNull(cmd);
        Assert.Equal(LiveWeaveCommandStatus.Completed, cmd!.Status);
    }

    [Fact]
    public void Poll_Is_Empty_When_No_Pending()
    {
        var broker = new LiveWeaveBroker();
        Assert.Empty(broker.Poll(3));
    }
}
