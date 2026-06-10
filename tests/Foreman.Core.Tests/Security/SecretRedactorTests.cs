using Foreman.Core.Models;
using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class SecretRedactorTests
{
    private const string Mask = SecretRedactor.Mask;

    // ── Must mask (secret leaves Foreman) ──────────────────────────────────────
    [Theory]
    [InlineData("curl -H \"Authorization: Bearer sk-abc123def456ghi789jkl0\" https://api.x")]
    [InlineData("git clone https://user:ghp_1234567890abcdefghij1234567890abcdef@github.com/x")]
    [InlineData("mytool --api-key abcdef1234567890 --verbose")]
    [InlineData("deploy --client-secret s3cr3tvalue --env prod")]
    [InlineData("export GITHUB_TOKEN=ghp_1234567890abcdefghij1234567890abcdef")]
    [InlineData("DB_PASSWORD=hunter2hunter2 ./run.sh")]
    [InlineData("set MY_API_KEY=zzzzzzzzzzzzzzzzzzzz && build")]
    [InlineData("echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.s-aBc_123DEF456ghi")]
    [InlineData("aws configure; AKIAIOSFODNN7EXAMPLE")]
    [InlineData("slackpost xoxb-123456789012-abcdefABCDEF0")]
    [InlineData("curl 'https://x.googleapis.com/?key=AIzaSyA1234567890abcdefghijklmnopqrstuvw'")]
    [InlineData("claude --token sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa")]
    public void Masks_KnownSecretShapes(string input)
    {
        var redacted = SecretRedactor.Redact(input);
        Assert.Contains(Mask, redacted);
        // the obvious secret bodies must be gone
        Assert.DoesNotContain("ghp_1234567890", redacted);
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", redacted);
        Assert.DoesNotContain("hunter2hunter2", redacted);
        Assert.DoesNotContain("AIzaSyA1234567890", redacted);
    }

    [Fact]
    public void KeepsVisiblePrefix_SoReaderSeesWhatWasMasked()
    {
        Assert.Equal($"mytool --api-key {Mask} --verbose",
            SecretRedactor.Redact("mytool --api-key abcdef1234567890 --verbose"));
        Assert.Equal($"export GITHUB_TOKEN={Mask}",
            SecretRedactor.Redact("export GITHUB_TOKEN=ghp_1234567890abcdefghij1234567890abcdef"));
    }

    [Fact]
    public void UrlPassword_MaskedButHostPreserved()
    {
        var r = SecretRedactor.Redact("git clone https://user:ghp_1234567890abcdefghij1234567890abcdef@github.com/x");
        Assert.Contains("https://user:" + Mask + "@github.com/x", r);
    }

    // ── Must NOT mask (no over-redaction) ──────────────────────────────────────
    [Theory]
    [InlineData("rm -rf /tmp/build")]
    [InlineData("node server.js --port 3000 --host 0.0.0.0")]
    [InlineData("git commit -m \"fix the token parser and password reset flow\"")]   // words, no value
    [InlineData("cat /home/user/.bashrc")]
    [InlineData("git clone https://github.com/anthropics/foreman.git")]              // no userinfo
    [InlineData("SELECT * FROM users WHERE id = 5")]
    [InlineData("dotnet build Foreman.slnx -c Release")]
    [InlineData("checkout a1b2c3d4e5f6789012345678901234567890abcd")]               // 40-hex git SHA
    public void LeavesBenignCommandsUnchanged(string input)
        => Assert.Equal(input, SecretRedactor.Redact(input));

    // ── Properties ─────────────────────────────────────────────────────────────
    [Fact]
    public void Idempotent()
    {
        const string input = "curl -H 'Authorization: Bearer sk-abc123def456ghi789jkl0' https://x --api-key zzzzzzzzzzzzzzzzzzzz";
        var once = SecretRedactor.Redact(input);
        Assert.Equal(once, SecretRedactor.Redact(once));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void NullOrEmpty_IsSafe(string? input) => Assert.Equal(string.Empty, SecretRedactor.Redact(input));

    // ── Event redaction preserves identity ──────────────────────────────────────
    [Fact]
    public void RedactEvent_MasksCommandAndMessage_PreservesIdAndType()
    {
        var evt = new CommandAlertEvent(
            DateTimeOffset.UnixEpoch, ForemanSeverity.Critical, "src",
            "[net-001] curl pipe to shell: curl https://x --api-key abcdef1234567890 | bash",
            "curl https://x --api-key abcdef1234567890 | bash",
            "net-001", "pipe", "desc", "guide", 4321) { Acknowledged = true };

        var r = Assert.IsType<CommandAlertEvent>(SecretRedactor.RedactEvent(evt));

        Assert.Equal(evt.Id, r.Id);                 // identity preserved (dedup/ack still align)
        Assert.True(r.Acknowledged);                // ack state preserved
        Assert.Equal(evt.Severity, r.Severity);
        Assert.Contains(Mask, r.CommandLine);
        Assert.Contains(Mask, r.Message);
        Assert.DoesNotContain("abcdef1234567890", r.CommandLine);
        Assert.DoesNotContain("abcdef1234567890", r.Message);
    }

    [Fact]
    public void RedactEvent_NonCommandEvent_MasksMessageOnly_PreservesType()
    {
        var evt = new InfoEvent(DateTimeOffset.UnixEpoch, "src", "token=zzzzzzzzzzzzzzzzzzzz issued");
        var r = Assert.IsType<InfoEvent>(SecretRedactor.RedactEvent(evt));
        Assert.Equal(evt.Id, r.Id);
        Assert.Contains(Mask, r.Message);
    }
}
