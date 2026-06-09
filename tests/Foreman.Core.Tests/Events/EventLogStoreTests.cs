using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Events;

public sealed class EventLogStoreTests : IDisposable
{
    private readonly string _dir;

    public EventLogStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-eventlog-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private static readonly DateTimeOffset T = DateTimeOffset.UnixEpoch;

    public static IEnumerable<object[]> AllEventTypes() => new[]
    {
        new object[] { new CommandAlertEvent(T, ForemanSeverity.Critical, "src", "msg", "curl x|bash", "net-001", "pipe", "desc", "guide", 4321) },
        new object[] { new HangDetectedEvent(T, "src", "hung", 12, "bash", 60, 30, 9, "node.exe", 9, "claude-code", "node.exe") },
        new object[] { new OrphanDetectedEvent(T, "src", "orphan", 12, "bash", 34, "node", 90) },
        new object[] { new PermissionViolationEvent(T, "src", "violation", 12, "profile", "write", "C:/Windows") },
        new object[] { new NonzeroExitEvent(T, "src", "exit", 12, "node", 1, 9) },
        new object[] { new InfoEvent(T, "src", "info msg") },
        new object[] { new MonitoringNoticeEvent(T, ForemanSeverity.Medium, "Foreman.McpInventory", "new server") },
        new object[] { new EscalationEvent(T, EscalationLevel.Alarm, EscalationLevel.Watch, "codex", "Codex CLI", "reason", 5, 3, 2, ["net", "cred"], "net-001", "pipe") },
    };

    [Theory]
    [MemberData(nameof(AllEventTypes))]
    public void RoundTrips_EveryEventSubtype(ForemanEvent evt)
    {
        var store = new EventLogStore(_dir);
        store.Append(evt);

        var loaded = store.Load();

        var e = Assert.Single(loaded);
        Assert.Equal(evt.GetType(), e.GetType());      // polymorphic type preserved
        Assert.Equal(evt.Id, e.Id);
        Assert.Equal(evt.Severity, e.Severity);
        Assert.Equal(evt.Source, e.Source);
        Assert.Equal(evt.Message, e.Message);
        Assert.Equal(evt.Timestamp, e.Timestamp);
    }

    [Fact]
    public void EscalationEvent_PreservesDerivedFields()
    {
        var store = new EventLogStore(_dir);
        store.Append(new EscalationEvent(T, EscalationLevel.Emergency, EscalationLevel.Alarm,
            "claude-code", "Claude Code", "too many", 10, 6, 4, ["net", "cred", "priv"], "cred-005", "lsass"));

        var e = Assert.IsType<EscalationEvent>(Assert.Single(store.Load()));
        Assert.Equal(EscalationLevel.Emergency, e.NewLevel);
        Assert.Equal("claude-code", e.HarnessId);
        Assert.Equal(ForemanSeverity.Critical, e.Severity);   // computed-in-ctor value survives
        Assert.Equal(["net", "cred", "priv"], e.CategoryList);
    }

    [Fact]
    public void Append_IsDurableAcrossStoreInstances()
    {
        new EventLogStore(_dir).Append(new InfoEvent(T, "a", "one"));
        new EventLogStore(_dir).Append(new InfoEvent(T, "b", "two"));

        var loaded = new EventLogStore(_dir).Load();   // a fresh instance = "after restart"
        Assert.Equal(2, loaded.Count);
        Assert.Equal("one", loaded[0].Message);
        Assert.Equal("two", loaded[1].Message);
    }

    [Fact]
    public void Load_TrimsToMaxEntries()
    {
        var store = new EventLogStore(_dir, maxEntries: 10);
        for (var i = 0; i < 25; i++)
            store.Append(new InfoEvent(T, "src", $"e{i}"));

        var loaded = store.Load();
        Assert.Equal(10, loaded.Count);
        Assert.Equal("e15", loaded[0].Message);     // kept the most recent 10
        Assert.Equal("e24", loaded[^1].Message);
    }

    [Fact]
    public void Load_SkipsCorruptLines_DoesNotThrow()
    {
        var store = new EventLogStore(_dir);
        store.Append(new InfoEvent(T, "src", "good"));
        File.AppendAllText(store.FilePath, "{ this is not valid json\n\n");
        store.Append(new InfoEvent(T, "src", "also good"));

        var loaded = store.Load();
        Assert.Equal(2, loaded.Count);
    }

    [Fact]
    public void Load_MissingFile_ReturnsEmpty()
        => Assert.Empty(new EventLogStore(_dir).Load());
}
