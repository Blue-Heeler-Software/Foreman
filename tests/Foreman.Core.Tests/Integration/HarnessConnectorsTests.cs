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

    [Fact]
    public void All_Entries_HaveInstalledProbe()
        => Assert.All(HarnessConnectors.All, c => Assert.NotNull(c.IsInstalled));

    [Fact]
    public void ConnectDetectedAndInstalled_Connects_Running_Configured_Installed_SkipsRest()
    {
        var minted = new List<string>();
        Func<int, string, ConnectResult> ok = (_, t) => new ConnectResult(ConnectStatus.Added, "ok:" + t);
        var fakes = new[]
        {
            new HarnessConnector("run",  "Run",  _ => false, ok, () => false),   // only via running set
            new HarnessConnector("cfg",  "Cfg",  _ => true,  ok, () => false),   // already configured
            new HarnessConnector("inst", "Inst", _ => false, ok, () => true),    // installed on disk
            new HarnessConnector("none", "None", _ => false,
                (_, _) => throw new InvalidOperationException("must not connect an irrelevant harness"), () => false),
        };

        var results = HarnessConnectors.ConnectDetectedAndInstalled(
            54321, id => { minted.Add(id); return "tok-" + id; },
            runningHarnessIds: new[] { "RUN" },   // case-insensitive match against HarnessId "run"
            connectors: fakes);

        Assert.Equal(["run", "cfg", "inst"], results.Select(r => r.HarnessId).ToArray());
        Assert.All(results, r => Assert.NotEqual(ConnectStatus.Failed, r.Status));
        Assert.Equal(["run", "cfg", "inst"], minted);                  // per-harness token minted for each, "none" skipped
        Assert.Equal("ok:tok-run", results[0].Message);               // minted token threaded into Connect
    }

    [Fact]
    public void ConnectDetectedAndInstalled_NoRunningIds_UsesConfiguredAndInstalledOnly()
    {
        Func<int, string, ConnectResult> ok = (_, _) => new ConnectResult(ConnectStatus.Updated, "");
        var fakes = new[]
        {
            new HarnessConnector("cfg",  "Cfg",  _ => true,  ok, () => false),
            new HarnessConnector("inst", "Inst", _ => false, ok, () => true),
            new HarnessConnector("none", "None", _ => false, (_, _) => throw new InvalidOperationException("nope"), () => false),
        };

        var results = HarnessConnectors.ConnectDetectedAndInstalled(1, _ => "t", runningHarnessIds: null, connectors: fakes);

        Assert.Equal(["cfg", "inst"], results.Select(r => r.HarnessId).ToArray());
    }

    [Fact]
    public void ConnectDetectedAndInstalled_NullIsInstalled_TreatedAsNotInstalled()
    {
        var fakes = new[] { new HarnessConnector("x", "X", _ => false, (_, _) => new ConnectResult(ConnectStatus.Added, "")) };  // IsInstalled omitted → null

        var results = HarnessConnectors.ConnectDetectedAndInstalled(1, _ => "t", runningHarnessIds: null, connectors: fakes);

        Assert.Empty(results);   // not running, not configured, IsInstalled null → skipped
    }

    [Fact]
    public void ConnectDetectedAndInstalled_ThrowingProbes_AreFalse_ThrowingConnect_IsFailed()
    {
        var fakes = new[]
        {
            // both probes throw and it isn't running → treated as not-relevant, skipped (Connect must not run)
            new HarnessConnector("probe-throws", "P", _ => throw new InvalidOperationException("probe boom"),
                (_, _) => new ConnectResult(ConnectStatus.Added, "should not run"),
                () => throw new InvalidOperationException("install boom")),
            // selected via the running set, but Connect throws → reported Failed, not propagated
            new HarnessConnector("run-throws", "R", _ => false,
                (_, _) => throw new InvalidOperationException("connect boom"), () => false),
        };

        var results = HarnessConnectors.ConnectDetectedAndInstalled(1, _ => "t",
            runningHarnessIds: new[] { "run-throws" }, connectors: fakes);

        Assert.Single(results);
        Assert.Equal("run-throws", results[0].HarnessId);
        Assert.Equal(ConnectStatus.Failed, results[0].Status);
        Assert.Contains("connect boom", results[0].Message);
    }
}
