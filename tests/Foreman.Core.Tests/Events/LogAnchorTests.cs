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
}
