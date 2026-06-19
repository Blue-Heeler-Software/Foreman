using System.Text.Json;
using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Events;

/// <summary>
/// B8 deep-review #2 (external anchor / anti-rollback): the OS event log is an append-only witness of the chain
/// head the same-user agent can't surgically revert. These cover the format round-trip and the trim-tolerant
/// "is the witnessed head still present" policy that catches an offline rollback the in-file chain can't.
/// </summary>
public sealed class LogAnchorTests
{
    [Fact]
    public void Format_RoundTrips()
    {
        var a = new LogAnchor("DEADBEEF", 42);
        var parsed = LogAnchor.TryParse(a.Format());
        Assert.NotNull(parsed);
        Assert.Equal("DEADBEEF", parsed!.HeadHash);
        Assert.Equal(42, parsed.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("Foreman Agent Safety started — v0.1, pid 1234.")]
    [InlineData("head=ZZZ count=notanumber")]
    public void TryParse_NonAnchor_IsNull(string? message) => Assert.Null(LogAnchor.TryParse(message));

    [Fact]
    public void Check_NullOrEmptyAnchor_IsNoPrior()
    {
        Assert.Equal(AnchorVerdict.NoPriorAnchor, AnchorPolicy.Check(new[] { "A" }, null));
        Assert.Equal(AnchorVerdict.NoPriorAnchor, AnchorPolicy.Check(new[] { "A" }, new LogAnchor("", 0)));
        Assert.Equal(AnchorVerdict.NoPriorAnchor, AnchorPolicy.Check(new[] { "A" }, new LogAnchor("A", 0)));
    }

    [Fact]
    public void Check_HeadIsLastRecord_IsMatch() // clean stop→start cycle, nothing changed while down
        => Assert.Equal(AnchorVerdict.Match,
            AnchorPolicy.Check(new[] { "A", "B", "C" }, new LogAnchor("C", 3)));

    [Fact]
    public void Check_HeadIsInteriorRecord_IsMatch() // session appended past the anchor then was killed = honest growth
        => Assert.Equal(AnchorVerdict.Match,
            AnchorPolicy.Check(new[] { "A", "B", "C", "D", "E" }, new LogAnchor("C", 3)));

    [Fact]
    public void Check_HeadAbsent_IsRolledback() // restored an older snapshot — the witnessed head is gone
        => Assert.Equal(AnchorVerdict.Rolledback,
            AnchorPolicy.Check(new[] { "A", "B" }, new LogAnchor("C", 3)));

    [Fact]
    public void Check_EmptyOnDisk_WithNonEmptyAnchor_IsRolledback() // log wiped
        => Assert.Equal(AnchorVerdict.Rolledback,
            AnchorPolicy.Check(Array.Empty<string>(), new LogAnchor("C", 3)));

    [Fact]
    public void Check_TrimmedChain_DifferentHashes_ButHeadPresent_IsMatch()
    {
        // A trim re-anchors the chain so retained records get NEW hashes — but the most-recent (anchored) head is
        // never the one trimmed (trim drops from the FRONT), so the anchored head is still present → no false alarm.
        var afterTrim = new[] { "X2", "Y2", "C", "D" }; // C = the anchored head, survived a front-trim
        Assert.Equal(AnchorVerdict.Match, AnchorPolicy.Check(afterTrim, new LogAnchor("C", 3)));
    }

    [Fact]
    public void LogHeadReader_ReadsStoredHashes_InOrder()
    {
        var dir = Path.Combine(Path.GetTempPath(), "foreman-anchor-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, "events.log.jsonl");
        try
        {
            var json = new JsonSerializerOptions { WriteIndented = false };
            var lines = new[]
            {
                JsonSerializer.Serialize<ForemanEvent>(new InfoEvent(DateTimeOffset.UtcNow, "s", "legacy"), json), // no Hash → skipped
                JsonSerializer.Serialize<ForemanEvent>(new InfoEvent(DateTimeOffset.UtcNow, "s", "a") { PrevHash = "", Hash = "H1" }, json),
                JsonSerializer.Serialize<ForemanEvent>(new InfoEvent(DateTimeOffset.UtcNow, "s", "b") { PrevHash = "H1", Hash = "H2" }, json),
                "{ this is a torn line",
                JsonSerializer.Serialize<ForemanEvent>(new InfoEvent(DateTimeOffset.UtcNow, "s", "c") { PrevHash = "H2", Hash = "H3" }, json),
            };
            File.WriteAllLines(file, lines);

            var hashes = LogHeadReader.ReadChainedHashes(file);
            Assert.Equal(new[] { "H1", "H2", "H3" }, hashes);

            var current = LogHeadReader.CurrentAnchor(file);
            Assert.Equal("H3", current.HeadHash);
            Assert.Equal(3, current.Count);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void LogHeadReader_MissingFile_IsEmpty()
    {
        var hashes = LogHeadReader.ReadChainedHashes(Path.Combine(Path.GetTempPath(), "nope-" + Guid.NewGuid().ToString("N") + ".jsonl"));
        Assert.Empty(hashes);
    }

    // ── Anchor-MAC: the OS-log anchor is forgeable by a same-user agent once the source is registered, so when
    // head-sealing is on we trust only an authentically-sealed witness. ──────────────────────────────────────────

    /// <summary>Deterministic stand-in for the head-seal signer: "signs" with a recomputable tag so a test can
    /// mint valid seals and recognise forged ones (any seal != the canonical tag).</summary>
    private sealed class FakeSigner : ILogHeadSigner
    {
        private readonly bool _expects;
        public FakeSigner(bool expectsSeal) => _expects = expectsSeal;
        public bool ExpectsSeal => _expects;
        public string? SealHead(string headHash, long recordCount) => $"OK:{headHash}:{recordCount}";
        public bool VerifyHead(string headHash, long recordCount, string? seal) => seal == $"OK:{headHash}:{recordCount}";
    }

    /// <summary>Mints an anchor with an authentic seal over the DOMAIN-SEPARATED head input (what Evaluate verifies).</summary>
    private static LogAnchor Signed(ILogHeadSigner s, string head, long count)
    {
        var a = new LogAnchor(head, count);
        return a with { Seal = s.SealHead(a.SealPayloadHead(), count) };
    }

    [Fact]
    public void Format_RoundTrips_WithSeal()
    {
        var a = new LogAnchor("DEADBEEF", 42, "OK:DEADBEEF:42");
        var parsed = LogAnchor.TryParse(a.Format());
        Assert.NotNull(parsed);
        Assert.Equal("DEADBEEF", parsed!.HeadHash);
        Assert.Equal(42, parsed.Count);
        Assert.Equal("OK:DEADBEEF:42", parsed.Seal);
    }

    [Fact]
    public void TryParse_LegacyAnchor_HasNullSeal() // an anchor written before sealing still parses, seal null
        => Assert.Null(LogAnchor.TryParse(new LogAnchor("ABC", 3).Format())!.Seal);

    [Fact]
    public void Evaluate_NoSealExpected_NewestUsableWins() // casual NullHeadSigner path: unchanged "newest wins"
    {
        var eval = AnchorPolicy.Evaluate(
            new[] { "A", "B", "C" }, new[] { new LogAnchor("C", 3), new LogAnchor("B", 2) }, new FakeSigner(false));
        Assert.Equal(AnchorVerdict.Match, eval.Verdict);
        Assert.False(eval.ForgedSealSeen);
        Assert.Equal("C", eval.TrustedAnchor!.HeadHash);
    }

    [Fact]
    public void Evaluate_NoSealExpected_NoCandidates_NoPrior()
    {
        var eval = AnchorPolicy.Evaluate(new[] { "A" }, Array.Empty<LogAnchor>(), new FakeSigner(false));
        Assert.Equal(AnchorVerdict.NoPriorAnchor, eval.Verdict);
        Assert.Null(eval.TrustedAnchor);
    }

    [Fact]
    public void Evaluate_Sealing_ValidNewest_Match()
    {
        var signer = new FakeSigner(expectsSeal: true);
        var c = Signed(signer, "C", 3);
        var eval = AnchorPolicy.Evaluate(new[] { "A", "B", "C" }, new[] { c }, signer);
        Assert.Equal(AnchorVerdict.Match, eval.Verdict);
        Assert.Same(c, eval.TrustedAnchor);
        Assert.False(eval.ForgedSealSeen);
    }

    [Fact]
    public void Evaluate_Sealing_ValidWitnessGone_Rolledback()
    {
        var signer = new FakeSigner(expectsSeal: true);
        var c = Signed(signer, "C", 3);
        var eval = AnchorPolicy.Evaluate(new[] { "A", "B" }, new[] { c }, signer); // C reverted away
        Assert.Equal(AnchorVerdict.Rolledback, eval.Verdict);
        Assert.Same(c, eval.TrustedAnchor);
    }

    [Fact]
    public void Evaluate_Sealing_ForgedNewest_FallsBackToAuthentic_AndCatchesRollback()
    {
        // The money test: an agent rolls the on-disk log back to {A,B} (C gone) and plants a counterfeit NEWEST
        // anchor pointing at the still-present B. The forged seal is rejected; the authentic older C catches it.
        var signer = new FakeSigner(expectsSeal: true);
        var forged = new LogAnchor("B", 2, "BOGUS"); // newest, invalid seal, points at a present head
        var authentic = Signed(signer, "C", 3);      // older, genuine witness for the gone head
        var eval = AnchorPolicy.Evaluate(new[] { "A", "B" }, new[] { forged, authentic }, signer);
        Assert.Equal(AnchorVerdict.Rolledback, eval.Verdict);
        Assert.True(eval.ForgedSealSeen);
        Assert.Same(authentic, eval.TrustedAnchor);
    }

    [Fact]
    public void Evaluate_Sealing_LiftedHeadFileSeal_IsRejected()
    {
        // Domain separation (the HIGH the review caught): a seal made over the BARE head|count — exactly what the
        // on-disk .head / archived .head files store — must NOT verify as an anchor seal. Otherwise an agent could
        // read a .head, lift its genuine seal into a counterfeit anchor, and mask a rollback. Here C was reverted
        // away and the planted anchor carries a bare-head seal: it fails anchor verification -> Forged.
        var signer = new FakeSigner(expectsSeal: true);
        var lifted = new LogAnchor("C", 3, signer.SealHead("C", 3)); // bare-head seal, NOT the anchor-domain seal
        var eval = AnchorPolicy.Evaluate(new[] { "A", "B" }, new[] { lifted }, signer);
        Assert.Equal(AnchorVerdict.Forged, eval.Verdict);
        Assert.True(eval.ForgedSealSeen);
        Assert.Null(eval.TrustedAnchor);
    }

    [Fact]
    public void Evaluate_Sealing_OnlyForged_IsForged()
    {
        var eval = AnchorPolicy.Evaluate(
            new[] { "A", "B" }, new[] { new LogAnchor("B", 2, "BOGUS") }, new FakeSigner(true));
        Assert.Equal(AnchorVerdict.Forged, eval.Verdict);
        Assert.True(eval.ForgedSealSeen);
        Assert.Null(eval.TrustedAnchor);
    }

    [Fact]
    public void Evaluate_Sealing_OnlyUnsigned_IsMigrationNoPrior()
    {
        // First launch after enabling sealing: pre-existing anchors are unsigned. They must NOT read as tamper —
        // skipped as a clean upgrade → NoPriorAnchor (this launch then writes the first sealed anchor).
        var eval = AnchorPolicy.Evaluate(
            new[] { "A", "B", "C" }, new[] { new LogAnchor("C", 3) }, new FakeSigner(true));
        Assert.Equal(AnchorVerdict.NoPriorAnchor, eval.Verdict);
        Assert.False(eval.ForgedSealSeen);
        Assert.Null(eval.TrustedAnchor);
    }
}
