using System.Text.Json;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Settings;

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

    // ── P1: tamper-evident hash chain ───────────────────────────────────────

    private string[] Raw(EventLogStore s) => File.ReadAllLines(s.FilePath);
    private void WriteRaw(EventLogStore s, IEnumerable<string> lines)
        => File.WriteAllText(s.FilePath, string.Join("\n", lines) + "\n");
    private static ForemanEvent De(string line) => JsonSerializer.Deserialize<ForemanEvent>(line)!;

    /// <summary>A deterministic stand-in for the P3 TPM signer so the head-seal path is testable without hardware.</summary>
    private sealed class StubSigner : ILogHeadSigner
    {
        public bool ExpectsSeal => true;
        public string? SealHead(string headHash, long recordCount) => $"{headHash}|{recordCount}|SIG";
        public bool VerifyHead(string headHash, long recordCount, string? seal) => seal == $"{headHash}|{recordCount}|SIG";
    }

    [Fact]
    public void Append_PopulatesPrevHashAndHash()
    {
        var store = new EventLogStore(_dir);
        store.Append(new InfoEvent(T, "src", "one"));
        store.Append(new InfoEvent(T, "src", "two"));

        var lines = Raw(store);
        var e0 = De(lines[0]);
        var e1 = De(lines[1]);
        Assert.Equal("", e0.PrevHash);                     // genesis
        Assert.False(string.IsNullOrEmpty(e0.Hash));
        Assert.Equal(e0.Hash, e1.PrevHash);                // chained
    }

    [Fact]
    public void Verify_CleanChain_ReturnsValid()
    {
        var store = new EventLogStore(_dir);
        for (var i = 0; i < 5; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));

        var vr = store.Verify();
        Assert.Equal(VerifyStatus.Valid, vr.Status);
        Assert.Equal(5, vr.Count);
    }

    [Fact]
    public void Verify_EditedMiddleRecord_DetectsBrokenLink()
    {
        var store = new EventLogStore(_dir);
        for (var i = 0; i < 3; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));

        var lines = Raw(store);
        lines[1] = lines[1].Replace("e1", "TAMPERED");     // edit content, leave the (now-stale) hash
        WriteRaw(store, lines);

        var vr = new EventLogStore(_dir).Verify();
        Assert.Equal(VerifyStatus.BrokenLink, vr.Status);
        Assert.Equal(1, vr.Index);
    }

    [Fact]
    public void Verify_DroppedRecord_DetectsBrokenLink()
    {
        var store = new EventLogStore(_dir);
        for (var i = 0; i < 3; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));

        var lines = Raw(store);
        WriteRaw(store, new[] { lines[0], lines[2] });     // drop the middle record

        var vr = new EventLogStore(_dir).Verify();
        Assert.Equal(VerifyStatus.BrokenLink, vr.Status);
        Assert.Equal(1, vr.Index);
    }

    [Fact]
    public void Verify_ReorderedRecords_DetectsBrokenLink()
    {
        var store = new EventLogStore(_dir);
        for (var i = 0; i < 3; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));

        var lines = Raw(store);
        WriteRaw(store, new[] { lines[0], lines[2], lines[1] });   // swap 1 and 2

        var vr = new EventLogStore(_dir).Verify();
        Assert.Equal(VerifyStatus.BrokenLink, vr.Status);
    }

    [Fact]
    public void Verify_TornLastLine_ReturnsUnverifiedTail()   // crash mid-append is benign, not tamper
    {
        var store = new EventLogStore(_dir);
        store.Append(new InfoEvent(T, "src", "one"));
        store.Append(new InfoEvent(T, "src", "two"));
        File.AppendAllText(store.FilePath, "{ partial torn line");

        Assert.Equal(VerifyStatus.UnverifiedTail, store.Verify().Status);
    }

    [Fact]
    public void Verify_TornMiddleLine_ReturnsCorrupt()
    {
        var store = new EventLogStore(_dir);
        for (var i = 0; i < 3; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));

        var lines = Raw(store);
        WriteRaw(store, new[] { lines[0], "{ partial torn line", lines[1], lines[2] });

        var vr = new EventLogStore(_dir).Verify();
        Assert.Equal(VerifyStatus.Corrupt, vr.Status);
        Assert.Equal(1, vr.Index);
    }

    [Fact]
    public void Trim_ReanchorsChain_AndRemainsVerifiable()   // regression: trimming must not break the chain
    {
        var store = new EventLogStore(_dir, maxEntries: 10);
        for (var i = 0; i < 25; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));
        store.Load();   // triggers trim + re-anchoring Rewrite

        var vr = new EventLogStore(_dir, maxEntries: 10).Verify();
        Assert.Equal(VerifyStatus.Valid, vr.Status);
        Assert.Equal(10, vr.Count);
    }

    [Fact]
    public void Verify_SealedChain_ReturnsValid()
    {
        var store = new EventLogStore(_dir, signer: new StubSigner());
        for (var i = 0; i < 5; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));

        var vr = store.Verify();
        Assert.Equal(VerifyStatus.Valid, vr.Status);
        Assert.Equal(5, vr.Count);
    }

    [Fact]
    public void Verify_DroppedTailAfterSeal_DetectsHeadMismatch()   // count in the seal defeats truncation
    {
        var store = new EventLogStore(_dir, signer: new StubSigner());
        for (var i = 0; i < 5; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));   // head sealed at count 5

        WriteRaw(store, Raw(store).Take(3));   // drop the last 2 records; head file still says 5

        Assert.Equal(VerifyStatus.HeadMismatch, store.Verify().Status);
    }

    [Fact]
    public void Verify_ForgedHeadSeal_DetectsHeadUnsealed()
    {
        var store = new EventLogStore(_dir, signer: new StubSigner());
        for (var i = 0; i < 3; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));

        File.WriteAllText(store.FilePath + ".head", "{\"HeadHash\":\"x\",\"Count\":3,\"Seal\":\"garbage\"}");

        Assert.Equal(VerifyStatus.HeadUnsealed, store.Verify().Status);
    }

    [Fact]
    public void Verify_LegacyPrefix_IsNotTamper()   // enabling the chain over an existing un-chained log is graceful
    {
        var legacy = new EventLogStore(_dir, integrity: new LogIntegritySettings { HashChainEnabled = false });
        legacy.Append(new InfoEvent(T, "src", "old1"));
        legacy.Append(new InfoEvent(T, "src", "old2"));

        var chained = new EventLogStore(_dir, integrity: new LogIntegritySettings { HashChainEnabled = true });
        chained.Append(new InfoEvent(T, "src", "new1"));
        chained.Append(new InfoEvent(T, "src", "new2"));

        var vr = chained.Verify();
        Assert.Equal(VerifyStatus.Valid, vr.Status);
        Assert.Equal(2, vr.Count);   // only the chained records counted; the legacy prefix is skipped
    }
}
