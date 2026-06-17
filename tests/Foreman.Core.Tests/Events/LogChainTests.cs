using System.Text.Json;
using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Events;

public sealed class LogChainTests
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
    private static readonly DateTimeOffset T = DateTimeOffset.UnixEpoch;

    [Fact]
    public void ComputeHash_KnownVector()   // pins the hashing scheme (NUL separator) — a change breaks the golden
        => Assert.Equal(
            "A0D346CD6FB5937CA6A1E0E2EF2CFAA5CF2682615CAD7EFA6543D8FEFE002C9B",
            LogChain.ComputeHash("ABC", "{\"x\":1}"));

    [Fact]
    public void ComputeHash_IsDeterministic()
        => Assert.Equal(LogChain.ComputeHash("p", "line"), LogChain.ComputeHash("p", "line"));

    [Fact]
    public void ComputeHash_DependsOnPrevHash()    // chaining: the prior link changes the hash
        => Assert.NotEqual(LogChain.ComputeHash("a", "line"), LogChain.ComputeHash("b", "line"));

    [Fact]
    public void ComputeHash_DependsOnContent()
        => Assert.NotEqual(LogChain.ComputeHash("p", "one"), LogChain.ComputeHash("p", "two"));

    [Fact]
    public void Canonicalize_NullsHashAndPrevHash()   // a record commits to content + prior, not its own hash
    {
        var e = new InfoEvent(T, "src", "msg") { PrevHash = "deadbeef", Hash = "cafef00d" };
        var canonical = LogChain.Canonicalize(e, Json);
        Assert.DoesNotContain("deadbeef", canonical);
        Assert.DoesNotContain("cafef00d", canonical);
    }

    [Fact]
    public void Canonicalize_IsStableAcrossReserialize()   // guards STJ ordering: hash survives a round-trip
    {
        var e = new CommandAlertEvent(T, ForemanSeverity.Critical, "src", "msg", "cmd", "net-001", "n", "d", "g", 7);
        var first = LogChain.ComputeHash(LogChain.Genesis, LogChain.Canonicalize(e, Json));

        var roundTripped = JsonSerializer.Deserialize<ForemanEvent>(JsonSerializer.Serialize<ForemanEvent>(e, Json), Json)!;
        var second = LogChain.ComputeHash(LogChain.Genesis, LogChain.Canonicalize(roundTripped, Json));

        Assert.Equal(first, second);
    }

    [Fact]
    public void NullHeadSigner_DoesNotSeal_ButVerifies()
    {
        var s = new NullHeadSigner();
        Assert.False(s.ExpectsSeal);
        Assert.Null(s.SealHead("h", 3));
        Assert.True(s.VerifyHead("h", 3, null));
    }

    [Fact]
    public void NullTimeAnchor_DoesNotAnchor_ButVerifies()
    {
        var a = new NullTimeAnchor();
        var checkpoint = new TemporalCheckpoint("s", 1, T, 10, 1_000);
        Assert.False(a.ExpectsAnchor);
        Assert.Null(a.AnchorHead("h", 3, checkpoint));
        Assert.True(a.VerifyAnchor("h", 3, checkpoint, null));
    }
}
