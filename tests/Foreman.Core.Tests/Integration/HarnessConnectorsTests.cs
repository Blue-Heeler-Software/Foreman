using Foreman.Core.Integration;

namespace Foreman.Core.Tests.Integration;

public sealed class HarnessConnectorsTests
{
    [Fact]
    public void All_CoversConnectableHarnesses_WithoutT3()
    {
        var ids = HarnessConnectors.All.Select(c => c.HarnessId).ToHashSet();
        foreach (var id in new[] { "claude-code", "codex", "cursor", "opencode", "github-copilot", "gemini-cli", "lm-studio" })
            Assert.Contains(id, ids);
        Assert.DoesNotContain("t3-code", ids);   // T3 has no MCP config of its own
    }

    [Fact]
    public void ReissueConfigured_OnlyReissuesConfigured_AndMintsPerHarness()
    {
        var minted = new List<string>();
        var fakes = new[]
        {
            new HarnessConnector("a", "A", _ => true,  (_, t) => new ConnectResult(ConnectStatus.Updated, "ok:" + t)),
            new HarnessConnector("b", "B", _ => false, (_, _) => throw new InvalidOperationException("must not connect an unconfigured harness")),
            new HarnessConnector("c", "C", _ => throw new InvalidOperationException("probe failed"), (_, _) => new ConnectResult(ConnectStatus.Added, "")),
        };

        var results = HarnessConnectors.ReissueConfigured(54321, id => { minted.Add(id); return "tok-" + id; }, fakes);

        Assert.Single(results);
        Assert.Equal("a", results[0].HarnessId);
        Assert.Equal(ConnectStatus.Updated, results[0].Status);
        Assert.Equal("ok:tok-a", results[0].Message);
        Assert.Equal(["a"], minted);   // b skipped (not configured), c skipped (probe threw)
    }

    [Fact]
    public void ReissueConfigured_ConnectorThatThrows_IsReportedFailed_NotPropagated()
    {
        var fakes = new[] { new HarnessConnector("x", "X", _ => true, (_, _) => throw new InvalidOperationException("boom")) };

        var results = HarnessConnectors.ReissueConfigured(1, _ => "t", fakes);

        Assert.Single(results);
        Assert.Equal(ConnectStatus.Failed, results[0].Status);
        Assert.Contains("boom", results[0].Message);
    }
}
