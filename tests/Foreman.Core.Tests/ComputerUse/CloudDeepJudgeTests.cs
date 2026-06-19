using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

public sealed class CloudDeepJudgeTests
{
    private static CuAction Nav(string url = "https://example.com") =>
        new(CuModality.Browser, "navigate", new Dictionary<string, string> { ["url"] = url });

    [Theory]
    [InlineData("{\"decision\":\"allow\",\"reason\":\"benign docs page\"}", CuDecision.Allow)]
    [InlineData("{\"decision\":\"block\",\"reason\":\"known C2 domain\"}", CuDecision.Block)]
    [InlineData("{\"decision\":\"hold\",\"reason\":\"unclear\"}", CuDecision.Hold)]
    [InlineData("{\"decision\":\"maybe?\",\"reason\":\"x\"}", CuDecision.Hold)]      // unknown -> fail safe
    public void Parse_MapsDecision(string raw, CuDecision expected)
        => Assert.Equal(expected, CloudDeepJudge.Parse(raw).Decision);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json at all")]
    [InlineData("{ broken json")]
    public void Parse_GarbageOrEmpty_FailsClosedToHold(string raw)
        => Assert.Equal(CuDecision.Hold, CloudDeepJudge.Parse(raw).Decision);

    [Fact]
    public void Parse_ExtractsJsonFromSurroundingProse()
    {
        var raw = "Sure! Here is my verdict:\n```json\n{\"decision\":\"block\",\"reason\":\"exfil\"}\n```\nHope that helps.";
        var v = CloudDeepJudge.Parse(raw);
        Assert.Equal(CuDecision.Block, v.Decision);
        Assert.Contains("exfil", v.Reason);
    }

    [Fact]
    public void Parse_CapturesReason_AndSource()
    {
        var v = CloudDeepJudge.Parse("{\"decision\":\"allow\",\"reason\":\"safe\"}");
        Assert.Equal("cloud", v.Source);
        Assert.Equal("safe", v.Reason);
    }

    [Fact]
    public async Task JudgeAsync_ReturnsParsedVerdict()
    {
        var judge = new CloudDeepJudge((_, _) => Task.FromResult("{\"decision\":\"block\",\"reason\":\"bad\"}"));
        var v = await judge.JudgeAsync(Nav(), new CuContext());
        Assert.Equal(CuDecision.Block, v.Decision);
    }

    [Fact]
    public async Task JudgeAsync_AskThrows_FailsClosedToHold()
    {
        var judge = new CloudDeepJudge((_, _) => throw new InvalidOperationException("network down"));
        var v = await judge.JudgeAsync(Nav(), new CuContext());
        Assert.Equal(CuDecision.Hold, v.Decision);
    }

    [Fact]
    public void BuildPrompt_IncludesVerbAndUrl_AndAsksForJson()
    {
        var prompt = CloudDeepJudge.BuildPrompt(Nav("https://site.test/page"));
        Assert.Contains("navigate", prompt);
        Assert.Contains("https://site.test/page", prompt);
        Assert.Contains("\"decision\"", prompt);
    }
}
