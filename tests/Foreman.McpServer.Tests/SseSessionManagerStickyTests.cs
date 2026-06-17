using Foreman.McpServer;

namespace Foreman.McpServer.Tests;

public sealed class SseSessionManagerStickyTests
{
    [Fact]
    public void MarkSeen_AppearsInRecent_WithinTtl()
    {
        var m = new SseSessionManager();
        m.MarkSeen("claude-code");
        m.MarkSeen("codex");

        var recent = m.RecentlyActiveHarnessIds(TimeSpan.FromMinutes(5));

        Assert.Contains("claude-code", recent);
        Assert.Contains("codex", recent);
    }

    [Fact]
    public void RecentlyActive_PrunesEntriesOlderThanTtl()
    {
        var m = new SseSessionManager();
        m.MarkSeen("codex");

        // A negative TTL puts the cutoff in the future, so the just-recorded entry is "older" → pruned.
        Assert.Empty(m.RecentlyActiveHarnessIds(TimeSpan.FromMilliseconds(-1)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void MarkSeen_NullOrBlank_IsIgnored(string? id)
    {
        var m = new SseSessionManager();
        m.MarkSeen(id);
        Assert.Empty(m.RecentlyActiveHarnessIds(TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public void MarkSeen_IsCaseInsensitive_AndDeduplicates()
    {
        var m = new SseSessionManager();
        m.MarkSeen("Claude-Code");
        m.MarkSeen("claude-code");
        Assert.Single(m.RecentlyActiveHarnessIds(TimeSpan.FromMinutes(5)));
    }
}
