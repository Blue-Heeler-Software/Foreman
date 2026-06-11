using Foreman.Core.Mcp;
using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Mcp;

public sealed class ModalityCatalogTests
{
    // ── Catalog shape ────────────────────────────────────────────────────────

    [Fact]
    public void Get_ResolvesKnown_AndIsCaseInsensitive()
    {
        Assert.NotNull(ModalityCatalog.Get("triage"));
        Assert.NotNull(ModalityCatalog.Get("Self-Check"));
        Assert.Null(ModalityCatalog.Get("nope"));
    }

    [Fact]
    public void DefaultAgentModalities_AreTheAgentFacingOnes()
    {
        Assert.Contains("self-check", ModalityCatalog.DefaultAgentModalities);
        Assert.Contains("log-report", ModalityCatalog.DefaultAgentModalities);
        Assert.DoesNotContain("triage", ModalityCatalog.DefaultAgentModalities);   // internal, not agent-facing
    }

    // ── triage: the constrained-enum, validate-or-escalate core ─────────────────

    [Theory]
    [InlineData("benign", ModalityStatus.Valid)]
    [InlineData("Benign.", ModalityStatus.Valid)]          // punctuation tolerated, first word
    [InlineData("suspicious", ModalityStatus.Valid)]
    [InlineData("unsure", ModalityStatus.Escalate)]        // low confidence → bump a tier
    [InlineData("I think it's probably benign", ModalityStatus.Escalate)]  // didn't follow one-word contract
    [InlineData("banana", ModalityStatus.Escalate)]
    [InlineData("", ModalityStatus.Escalate)]
    public void Triage_ValidatesOrEscalates(string output, ModalityStatus expected)
        => Assert.Equal(expected, ModalityCatalog.Validate(ModalityKind.Triage, output).Status);

    [Fact]
    public void Triage_NormalizesToTheBareVerdict()
        => Assert.Equal("suspicious", ModalityCatalog.Validate(ModalityKind.Triage, "Suspicious!").Normalized);

    // ── other modalities ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("clean", ModalityStatus.Valid)]
    [InlineData("all clean here", ModalityStatus.Valid)]
    [InlineData("flagged: cred-005 lsass dump", ModalityStatus.Valid)]
    [InlineData("everything is fine probably", ModalityStatus.Escalate)]
    public void SelfCheck_ValidatesOrEscalates(string output, ModalityStatus expected)
        => Assert.Equal(expected, ModalityCatalog.Validate(ModalityKind.SelfCheck, output).Status);

    [Fact]
    public void LogReport_EmptyEscalates_OtherwiseTruncatesToCap()
    {
        Assert.Equal(ModalityStatus.Escalate, ModalityCatalog.Validate(ModalityKind.LogReport, "   ").Status);
        var many = string.Join("\n", Enumerable.Range(1, 20).Select(i => $"line {i}"));
        var check = ModalityCatalog.Validate(ModalityKind.LogReport, many);
        Assert.Equal(ModalityStatus.Valid, check.Status);
        Assert.Equal(8, check.Normalized.Split('\n').Length);   // capped
    }

    [Theory]
    [InlineData("a-single-value", ModalityStatus.Valid)]
    [InlineData("", ModalityStatus.Escalate)]
    [InlineData("line one\nline two", ModalityStatus.Escalate)]   // not a single value
    public void Extract_ValidatesOrEscalates(string output, ModalityStatus expected)
        => Assert.Equal(expected, ModalityCatalog.Validate(ModalityKind.Extract, output).Status);

    [Fact]
    public void Extract_OverlongEscalates()
        => Assert.Equal(ModalityStatus.Escalate,
            ModalityCatalog.Validate(ModalityKind.Extract, new string('x', 500)).Status);

    [Theory]
    [InlineData("redacted [REDACTED] text", ModalityStatus.Valid)]
    [InlineData("", ModalityStatus.Escalate)]
    public void Redact_ValidatesNonEmpty(string output, ModalityStatus expected)
        => Assert.Equal(expected, ModalityCatalog.Validate(ModalityKind.Redact, output).Status);

    // ── per-harness selection (the restricted sysprompt) ────────────────────────

    [Fact]
    public void EnabledModalities_UnsetHarness_ReturnsDefaults()
        => Assert.Equal(ModalityCatalog.DefaultAgentModalities, new ForemanSettings().EnabledModalities("codex"));

    [Fact]
    public void EnabledModalities_SetHarness_ReturnsExplicitSelection()
    {
        var s = new ForemanSettings();
        s.HarnessModalities["codex"] = ["self-check"];
        Assert.Equal(["self-check"], s.EnabledModalities("codex"));
    }
}
