using Foreman.Core.Models;
using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class CredentialSweepTests
{
    private static readonly DateTimeOffset T0 = new(2026, 6, 11, 0, 0, 0, TimeSpan.Zero);

    // ── InstallSubtree.IsPackageInstall ──────────────────────────────────────

    [Theory]
    [InlineData("npm install")]
    [InlineData("npm ci")]
    [InlineData("npm i lodash")]
    [InlineData("pnpm install --frozen-lockfile")]
    [InlineData("yarn add left-pad")]
    [InlineData("bun install")]
    [InlineData("node-gyp rebuild")]
    [InlineData("pip install requests")]
    [InlineData("pip3 install -r requirements.txt")]
    [InlineData("python setup.py build")]
    [InlineData("uv pip install ruff")]
    public void IsPackageInstall_True(string cmd) => Assert.True(InstallSubtree.IsPackageInstall(cmd));

    [Theory]
    [InlineData("node index.js")]
    [InlineData("npm run build")]
    [InlineData("npm run test")]
    [InlineData("git status")]
    [InlineData("dotnet build Foreman.slnx")]
    [InlineData("")]
    [InlineData(null)]
    public void IsPackageInstall_False(string? cmd) => Assert.False(InstallSubtree.IsPackageInstall(cmd));

    // ── Severities.EscalateOneLevel ──────────────────────────────────────────

    [Theory]
    [InlineData(ForemanSeverity.Low, ForemanSeverity.Medium)]
    [InlineData(ForemanSeverity.Medium, ForemanSeverity.High)]
    [InlineData(ForemanSeverity.High, ForemanSeverity.Critical)]
    [InlineData(ForemanSeverity.Critical, ForemanSeverity.Critical)]
    [InlineData(ForemanSeverity.Info, ForemanSeverity.Info)]
    public void Escalate(ForemanSeverity from, ForemanSeverity to) =>
        Assert.Equal(to, Severities.EscalateOneLevel(from));

    // ── CredentialSweepAggregator ────────────────────────────────────────────

    [Fact]
    public void BelowThreshold_DoesNotFire()
    {
        var agg = new CredentialSweepAggregator(distinctThreshold: 4, windowSeconds: 60);
        Assert.Null(agg.Observe("tree", "cred-003", T0));
        Assert.Null(agg.Observe("tree", "cred-002", T0.AddSeconds(1)));
        Assert.Null(agg.Observe("tree", "cred-020", T0.AddSeconds(2)));   // only 3 distinct
    }

    [Fact]
    public void FourDistinctInWindow_Fires_WithTheRuleSet()
    {
        var agg = new CredentialSweepAggregator(4, 60);
        agg.Observe("tree", "cred-003", T0);
        agg.Observe("tree", "cred-002", T0.AddSeconds(1));
        agg.Observe("tree", "cred-020", T0.AddSeconds(2));
        var fired = agg.Observe("tree", "cred-021", T0.AddSeconds(3));    // 4th distinct

        Assert.NotNull(fired);
        Assert.Equal(4, fired!.Count);
        Assert.Contains("cred-021", fired);
    }

    [Fact]
    public void SameRuleRepeated_IsNotASweep()
    {
        var agg = new CredentialSweepAggregator(4, 60);
        for (var i = 0; i < 6; i++)
            Assert.Null(agg.Observe("tree", "cred-003", T0.AddSeconds(i)));   // 1 distinct rule, never a sweep
    }

    [Fact]
    public void DistinctReadsSpreadBeyondWindow_DoNotFire()
    {
        var agg = new CredentialSweepAggregator(4, 60);
        agg.Observe("tree", "cred-003", T0);
        agg.Observe("tree", "cred-002", T0.AddSeconds(30));
        agg.Observe("tree", "cred-020", T0.AddSeconds(80));               // cred-003 now pruned (>60s)
        Assert.Null(agg.Observe("tree", "cred-021", T0.AddSeconds(90)));  // only 3 in the live window
    }

    [Fact]
    public void FiresAtMostOncePerWindow()
    {
        var agg = new CredentialSweepAggregator(4, 60);
        agg.Observe("tree", "cred-003", T0);
        agg.Observe("tree", "cred-002", T0.AddSeconds(1));
        agg.Observe("tree", "cred-020", T0.AddSeconds(2));
        Assert.NotNull(agg.Observe("tree", "cred-021", T0.AddSeconds(3)));         // fires
        Assert.Null(agg.Observe("tree", "cred-024", T0.AddSeconds(4)));            // 5th distinct, still cooling down

        // A fresh sweep well after the window fires again (the first burst's reads have aged out).
        agg.Observe("tree", "cred-003", T0.AddSeconds(120));
        agg.Observe("tree", "cred-002", T0.AddSeconds(121));
        agg.Observe("tree", "cred-020", T0.AddSeconds(122));
        Assert.NotNull(agg.Observe("tree", "cred-021", T0.AddSeconds(123)));
    }

    [Fact]
    public void DifferentHarnessTrees_AreIndependent()
    {
        var agg = new CredentialSweepAggregator(4, 60);
        // Tree A reaches only 3 distinct; tree B reaches 4 — only B fires (A's events don't bleed into B).
        agg.Observe("A", "cred-003", T0);
        agg.Observe("A", "cred-002", T0);
        Assert.Null(agg.Observe("A", "cred-020", T0));      // A at 3 distinct → no fire

        agg.Observe("B", "cred-003", T0);
        agg.Observe("B", "cred-002", T0);
        agg.Observe("B", "cred-020", T0);
        Assert.NotNull(agg.Observe("B", "cred-021", T0));   // B's 4th distinct → fires
    }
}
