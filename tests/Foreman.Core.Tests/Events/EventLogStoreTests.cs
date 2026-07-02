using System.Text.Json;
using System.Text.Json.Nodes;
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

    private sealed class TestClock : ITemporalClock
    {
        public string SessionId { get; init; } = "session-a";
        public DateTimeOffset UtcNow { get; set; } = T;
        public long MonotonicTicks { get; set; }
        public long MonotonicFrequency { get; init; } = 1_000;
    }

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
    public void Load_TrimRewrite_RaisesChainRewritten_SoASupersedingAnchorCanBePublished()
    {
        var store = new EventLogStore(_dir, maxEntries: 5);
        for (var i = 0; i < 12; i++)
            store.Append(new InfoEvent(T, "src", $"e{i}"));
        // What a prior launch (or clean stop) would have witnessed externally, BEFORE the trim.
        var preTrimWitness = LogHeadReader.CurrentAnchor(store.FilePath);

        LogAnchor? raised = null;
        store.ChainRewritten += a => raised = a;
        store.Load();

        // The rewrite re-anchored the chain: the old witness is gone from the file (this is exactly the false
        // rollback the event exists to prevent)...
        var onDisk = LogHeadReader.ReadChainedHashes(store.FilePath);
        Assert.Equal(AnchorVerdict.Rolledback, AnchorPolicy.Check(onDisk, preTrimWitness));
        // ...and the raised anchor is the REWRITTEN head, which reads clean as the superseding witness.
        Assert.NotNull(raised);
        Assert.Equal(5, raised!.Count);
        Assert.Equal(LogHeadReader.CurrentAnchor(store.FilePath).HeadHash, raised.HeadHash);
        Assert.Equal(AnchorVerdict.Match, AnchorPolicy.Check(onDisk, raised));
    }

    [Fact]
    public void Load_UnderTheCap_DoesNotRaiseChainRewritten()
    {
        var store = new EventLogStore(_dir, maxEntries: 10);
        for (var i = 0; i < 3; i++)
            store.Append(new InfoEvent(T, "src", $"e{i}"));

        var raised = false;
        store.ChainRewritten += _ => raised = true;
        store.Load();

        Assert.False(raised);
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
    private static JsonObject Obj(ForemanEvent evt) => JsonSerializer.SerializeToNode<ForemanEvent>(evt)!.AsObject();

    private static string HistoricalCanonical(JsonObject stored)
    {
        var canonical = JsonNode.Parse(stored.ToJsonString())!.AsObject();
        canonical[nameof(ForemanEvent.Hash)] = null;
        canonical[nameof(ForemanEvent.PrevHash)] = null;
        return canonical.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
    }

    private static string StoreHistorical(JsonObject stored, string prevHash)
    {
        stored[nameof(ForemanEvent.PrevHash)] = prevHash;
        stored[nameof(ForemanEvent.Hash)] = LogChain.ComputeHash(prevHash, HistoricalCanonical(stored));
        return stored.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
    }

    /// <summary>A deterministic stand-in for the P3 TPM signer so the head-seal path is testable without hardware.</summary>
    private sealed class StubSigner : ILogHeadSigner
    {
        public bool ExpectsSeal => true;
        public string? SealHead(string headHash, long recordCount) => $"{headHash}|{recordCount}|SIG";
        public bool VerifyHead(string headHash, long recordCount, string? seal) => seal == $"{headHash}|{recordCount}|SIG";
    }

    private sealed class StubTimeAnchor : ILogTimeAnchor
    {
        public bool ExpectsAnchor => true;
        public string? AnchorHead(string headHash, long recordCount, TemporalCheckpoint checkpoint) =>
            $"{headHash}|{recordCount}|{checkpoint.SessionId}|{checkpoint.Sequence}|TIME";

        public bool VerifyAnchor(string headHash, long recordCount, TemporalCheckpoint? checkpoint, string? anchor) =>
            checkpoint is not null &&
            anchor == $"{headHash}|{recordCount}|{checkpoint.SessionId}|{checkpoint.Sequence}|TIME";
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
    public void Append_PopulatesTemporalOrderingMetadata()
    {
        var clock = new TestClock { SessionId = "temporal-test", UtcNow = T.AddSeconds(10), MonotonicTicks = 100 };
        var store = new EventLogStore(_dir, clock: clock);

        store.Append(new InfoEvent(T, "src", "one"));

        var e = Assert.Single(store.Load());
        Assert.Equal("temporal-test", e.TemporalSessionId);
        Assert.Equal(1, e.Sequence);
        Assert.Equal(T.AddSeconds(10), e.RecordedAtUtc);
        Assert.Equal(100, e.MonotonicTicks);
        Assert.Equal(1_000, e.MonotonicFrequency);
        Assert.Empty(e.TemporalAnomalies);
    }

    [Fact]
    public void Append_SequenceContinuesAcrossStoreInstances()
    {
        new EventLogStore(_dir, clock: new TestClock { SessionId = "a", MonotonicTicks = 10 })
            .Append(new InfoEvent(T, "src", "one"));
        new EventLogStore(_dir, clock: new TestClock { SessionId = "b", MonotonicTicks = 20 })
            .Append(new InfoEvent(T, "src", "two"));

        var loaded = new EventLogStore(_dir).Load();
        Assert.Equal([1L, 2L], loaded.Select(e => e.Sequence!.Value).ToArray());
        Assert.Equal(["a", "b"], loaded.Select(e => e.TemporalSessionId!).ToArray());
    }

    [Fact]
    public void Append_FlagsWallClockRollback()
    {
        var clock = new TestClock { UtcNow = T.AddMinutes(10), MonotonicTicks = 100 };
        var store = new EventLogStore(_dir, clock: clock);
        store.Append(new InfoEvent(T, "src", "one"));

        clock.UtcNow = T.AddMinutes(5);
        clock.MonotonicTicks = 200;
        store.Append(new InfoEvent(T, "src", "two"));

        Assert.Contains("wall-clock-moved-backward", store.Load()[1].TemporalAnomalies);
    }

    [Fact]
    public void Append_FlagsWallMonotonicDivergence()
    {
        var clock = new TestClock { UtcNow = T, MonotonicTicks = 0, MonotonicFrequency = 1_000 };
        var store = new EventLogStore(_dir, clock: clock);
        store.Append(new InfoEvent(T, "src", "one"));

        clock.UtcNow = T.AddHours(1);
        clock.MonotonicTicks = 1_000; // one monotonic second
        store.Append(new InfoEvent(T, "src", "two"));

        Assert.Contains("wall-monotonic-divergence", store.Load()[1].TemporalAnomalies);
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
    public void RotateAndReseal_ArchivesOldChain_AndStartsFreshVerifiableChain()
    {
        var store = new EventLogStore(_dir);
        for (var i = 0; i < 3; i++) store.Append(new InfoEvent(T, "src", $"e{i}"));

        var result = store.RotateAndReseal("test rotate", DateTimeOffset.UnixEpoch);

        // 3 appended + the closing "rotated" record = 4 in the archived chain.
        Assert.Equal(4, result.PriorCount);
        Assert.True(File.Exists(result.ArchivePath));               // evidence preserved (JSONL)
        // (the .head seal is archived too, but only exists under a real signer — none in this default store)

        // Fresh chain verifies clean and no longer contains the old records.
        Assert.Equal(VerifyStatus.Valid, store.Verify().Status);
        var loaded = store.Load();
        Assert.DoesNotContain(loaded, e => e.Message.Contains("e0"));
        Assert.Contains(loaded, e => e.Message.Contains("Fresh event-log chain established"));

        // KEY: the new anchor's head IS present in the fresh chain, so the anti-rollback check MATCHES.
        // A naive archive would leave the stale anchor's head absent -> AnchorVerdict.Rolledback.
        var freshHashes = LogHeadReader.ReadChainedHashes(store.FilePath);
        Assert.Equal(AnchorVerdict.Match, AnchorPolicy.Check(freshHashes, result.NewAnchor));
    }

    [Fact]
    public void RotateAndReseal_FreshChainVerifies_AfterReopen()
    {
        var store = new EventLogStore(_dir);
        store.Append(new InfoEvent(T, "src", "before"));
        store.RotateAndReseal("test", DateTimeOffset.UnixEpoch);

        // A new store instance over the same dir continues the rotated chain and verifies clean.
        Assert.Equal(VerifyStatus.Valid, new EventLogStore(_dir).Verify().Status);
    }

    [Fact]
    public void RotateAndReseal_FailureMidRotate_DoesNotCorruptChain()
    {
        var store = new EventLogStore(_dir);
        store.Append(new InfoEvent(T, "src", "a"));
        store.Append(new InfoEvent(T, "src", "b"));

        // Force the archive move to fail: pre-create a DIRECTORY at the predicted archive path (File.Move onto an
        // existing directory throws). 'now' is fixed so the path is deterministic.
        var now = DateTimeOffset.UnixEpoch;
        Directory.CreateDirectory($"{store.FilePath}.{now.ToUnixTimeSeconds()}.archived");

        Assert.ThrowsAny<Exception>(() => store.RotateAndReseal("boom", now));

        // Crash-consistency: the store stays usable and the chain stays verifiable — a FAILED re-baseline must
        // never chain off a stale head and corrupt the log into a BrokenLink.
        store.Append(new InfoEvent(T, "src", "after"));
        Assert.Equal(VerifyStatus.Valid, new EventLogStore(_dir).Verify().Status);
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
    public void Verify_RecomputedChainWithDuplicateSequence_DetectsBrokenLink()
    {
        var first = new InfoEvent(T, "src", "one")
        {
            TemporalSessionId = "s",
            Sequence = 1,
            RecordedAtUtc = T,
            MonotonicTicks = 1,
            MonotonicFrequency = 1_000,
        };
        var firstHash = LogChain.ComputeHash(LogChain.Genesis, LogChain.Canonicalize(first, new JsonSerializerOptions { WriteIndented = false }));
        first = first with { PrevHash = LogChain.Genesis, Hash = firstHash };

        var second = new InfoEvent(T, "src", "two")
        {
            TemporalSessionId = "s",
            Sequence = 1,
            RecordedAtUtc = T.AddSeconds(1),
            MonotonicTicks = 2,
            MonotonicFrequency = 1_000,
        };
        var secondHash = LogChain.ComputeHash(firstHash, LogChain.Canonicalize(second, new JsonSerializerOptions { WriteIndented = false }));
        second = second with { PrevHash = firstHash, Hash = secondHash };

        WriteRaw(new EventLogStore(_dir), [
            JsonSerializer.Serialize<ForemanEvent>(first),
            JsonSerializer.Serialize<ForemanEvent>(second),
        ]);

        var vr = new EventLogStore(_dir).Verify();
        Assert.Equal(VerifyStatus.BrokenLink, vr.Status);
        Assert.Equal(1, vr.Index);
        Assert.Contains("sequence", vr.Message);
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
    public void Verify_TimeAnchor_IsRecordedAndEnforced()
    {
        var store = new EventLogStore(
            _dir,
            clock: new TestClock { SessionId = "anchored", UtcNow = T.AddMinutes(1), MonotonicTicks = 12 },
            timeAnchor: new StubTimeAnchor());
        store.Append(new InfoEvent(T, "src", "one"));

        Assert.Equal(VerifyStatus.Valid, store.Verify().Status);
        var head = File.ReadAllText(store.FilePath + ".head");
        Assert.Contains("anchored", head);
        Assert.Contains("TIME", head);

        File.WriteAllText(store.FilePath + ".head", head.Replace("TIME", "FAKE"));
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

    [Fact]
    public void Load_MigratesMixedPreTemporalAndTemporalChain_ToNewCanonicalForm()
    {
        var store = new EventLogStore(_dir);

        var preTemporal = Obj(new InfoEvent(T, "src", "pre-temporal"));
        preTemporal.Remove(nameof(ForemanEvent.TemporalSessionId));
        preTemporal.Remove(nameof(ForemanEvent.Sequence));
        preTemporal.Remove(nameof(ForemanEvent.RecordedAtUtc));
        preTemporal.Remove(nameof(ForemanEvent.MonotonicTicks));
        preTemporal.Remove(nameof(ForemanEvent.MonotonicFrequency));
        preTemporal.Remove(nameof(ForemanEvent.TemporalAnomalies));
        var first = StoreHistorical(preTemporal, LogChain.Genesis);
        var firstHash = JsonSerializer.Deserialize<ForemanEvent>(first)!.Hash!;

        var temporal = Obj(new InfoEvent(T, "src", "temporal")
        {
            TemporalSessionId = "session-a",
            Sequence = 1,
            RecordedAtUtc = T.AddSeconds(1),
            MonotonicTicks = 10,
            MonotonicFrequency = 1_000,
            TemporalAnomalies = [],
        });
        var second = StoreHistorical(temporal, firstHash);

        WriteRaw(store, [first, second]);
        Assert.Equal(VerifyStatus.BrokenLink, store.Verify().Status);

        store.Load();

        var migrated = new EventLogStore(_dir).Verify();
        Assert.Equal(VerifyStatus.Valid, migrated.Status);
        Assert.Equal(2, migrated.Count);
    }

    [Fact]
    public void TryAppend_WhenPersistenceFails_ReturnsFalseAndStoresError()
    {
        var fileInsteadOfDirectory = Path.Combine(_dir, "not-a-directory");
        File.WriteAllText(fileInsteadOfDirectory, "occupied");
        var store = new EventLogStore(fileInsteadOfDirectory);

        var ok = store.TryAppend(new InfoEvent(T, "src", "one"), out var error);

        Assert.False(ok);
        Assert.False(string.IsNullOrWhiteSpace(error));
        Assert.NotNull(store.LastAppendError);
    }
}
