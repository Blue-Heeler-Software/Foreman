using Foreman.Core.Behavior;
using Foreman.Core.Models;
using Foreman.Core.Profiles;
using Foreman.McpServer;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

namespace Foreman.McpServer.Tests;

// ── Token scheme: mint / authenticate / forgery resistance ───────────────────────
public sealed class McpAuthTokenTests : IDisposable
{
    private readonly string _dir;
    private readonly McpAuthToken _token;

    public McpAuthTokenTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-token-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _token = new McpAuthToken(_dir);
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Fact]
    public void InstallToken_AuthenticatesAsOperator()
    {
        var r = _token.Authenticate(_token.Value);
        Assert.True(r.Ok);
        Assert.True(r.IsOperator);
        Assert.Null(r.HarnessId);
    }

    [Fact]
    public void MintedToken_AuthenticatesAsThatHarness_NotOperator()
    {
        var minted = _token.MintHarnessToken("codex");
        var r = _token.Authenticate(minted);
        Assert.True(r.Ok);
        Assert.False(r.IsOperator);
        Assert.Equal("codex", r.HarnessId);
    }

    [Fact]
    public void Minted_IsCaseInsensitiveOnHarnessId()
        => Assert.Equal("claude-code", _token.Authenticate(_token.MintHarnessToken("Claude-Code")).HarnessId);

    [Fact]
    public void TamperedMac_IsRejected()
    {
        var minted = _token.MintHarnessToken("codex");
        var tampered = minted[..^2] + (minted.EndsWith("AA") ? "BB" : "AA");
        Assert.False(_token.Authenticate(tampered).Ok);
    }

    [Fact]
    public void SwappedHarnessId_WithOldMac_IsRejected()
    {
        // Take codex's mac, splice it onto a claude-code id → must fail (mac is bound to the id).
        var codex = _token.MintHarnessToken("codex");
        var mac = codex.Split('.')[2];
        var claudeIdB64 = _token.MintHarnessToken("claude-code").Split('.')[1];
        var forged = $"fmh1.{claudeIdB64}.{mac}";
        Assert.False(_token.Authenticate(forged).Ok);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("fmh1.notbase64!.zzz")]
    [InlineData("fmh1.Y29kZXg")]            // missing mac segment
    public void Junk_IsRejected(string? presented) => Assert.False(_token.Authenticate(presented).Ok);
}

// ── Tool scoping: a per-harness caller can't see or act on another harness ───────
public sealed class CallerScopeToolTests : IDisposable
{
    private readonly string _profileDir;
    private readonly ProfileStore _store;
    private readonly ForemanState _state;
    private readonly ProcessRecord _codex, _codexChild, _claude;
    private string? _lastReset;

    public CallerScopeToolTests()
    {
        _profileDir = Path.Combine(Path.GetTempPath(), "foreman-scope-" + Guid.NewGuid().ToString("N")[..8]);
        _store = new ProfileStore(_profileDir);
        _store.Initialize();

        _codex      = Proc(940_001, 0, "codex.exe", "codex");
        _codexChild = Proc(940_002, 940_001, "bash.exe", null);
        _claude     = Proc(940_011, 0, "node.exe", "claude-code");

        _state = new ForemanState
        {
            GetProcessSnapshot = () => [_codex, _codexChild, _claude],
            FindHarnessAncestorByPid = pid => pid == _codexChild.Pid ? _codex : null,
            GetBehaviorProfiles = () => [new BehaviorProfile("codex"), new BehaviorProfile("claude-code")],
            ResetBehaviorProfile = id => _lastReset = id,
        };
        ForemanMcpTools.SetState(_state);
    }

    public void Dispose() { try { Directory.Delete(_profileDir, true); } catch { } }

    private static ProcessRecord Proc(int pid, int parent, string name, string? harness) => new()
    {
        Pid = pid, ParentPid = parent, Name = name, StartTime = DateTimeOffset.UtcNow,
        IsHarness = harness is not null, HarnessType = harness,
    };

    // NB: the real HttpContextAccessor stores HttpContext in a shared AsyncLocal, so multiple instances
    // would alias each other in a test. This per-instance fake returns exactly the context we set.
    private sealed class FixedHttpContextAccessor : IHttpContextAccessor
    {
        public HttpContext? HttpContext { get; set; }
    }

    private static IHttpContextAccessor Caller(string? harnessId, bool isOperator)
    {
        var ctx = new DefaultHttpContext();
        ctx.Items[CallerScope.HttpItemKey] = new CallerScope(harnessId, isOperator);
        return new FixedHttpContextAccessor { HttpContext = ctx };
    }

    private static readonly IHttpContextAccessor AsCodex  = Caller("codex", false);
    private static readonly IHttpContextAccessor AsClaude = Caller("claude-code", false);
    private static readonly IHttpContextAccessor AsOperator = Caller(null, true);

    private static JsonDocument J(object o) => JsonDocument.Parse(JsonSerializer.Serialize(o));

    [Fact]
    public void ListMonitoredProcesses_Operator_SeesAllHarnesses()
    {
        using var doc = J(ForemanMcpTools.ListMonitoredProcesses(http: AsOperator));
        var pids = doc.RootElement.GetProperty("processes").EnumerateArray().Select(e => e.GetProperty("Pid").GetInt32()).ToHashSet();
        Assert.Contains(_codex.Pid, pids);
        Assert.Contains(_claude.Pid, pids);
    }

    [Fact]
    public void ListMonitoredProcesses_CodexCaller_SeesOnlyOwnTree()
    {
        using var doc = J(ForemanMcpTools.ListMonitoredProcesses(http: AsCodex));
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
        var pids = doc.RootElement.GetProperty("processes").EnumerateArray().Select(e => e.GetProperty("Pid").GetInt32()).ToHashSet();
        Assert.Contains(_codex.Pid, pids);
        Assert.Contains(_codexChild.Pid, pids);
        Assert.DoesNotContain(_claude.Pid, pids);   // can't see the sibling
    }

    [Fact]
    public void ListMonitoredProcesses_CodexCaller_CannotEnumerateClaudeByParam()
    {
        // Even if it asks for claude-code, the token scope wins.
        using var doc = J(ForemanMcpTools.ListMonitoredProcesses(harnessId: "claude-code", http: AsCodex));
        Assert.Equal("codex", doc.RootElement.GetProperty("harnessId").GetString());
        var pids = doc.RootElement.GetProperty("processes").EnumerateArray().Select(e => e.GetProperty("Pid").GetInt32()).ToHashSet();
        Assert.DoesNotContain(_claude.Pid, pids);
    }

    [Fact]
    public void QueryProcessDetail_CodexCaller_DeniedOnClaudeProcess()
    {
        using var doc = J(ForemanMcpTools.QueryProcessDetail(_claude.Pid, http: AsCodex));
        Assert.True(doc.RootElement.TryGetProperty("error", out _));
    }

    [Fact]
    public void QueryProcessDetail_CodexCaller_AllowedOnOwnChild()
    {
        using var doc = J(ForemanMcpTools.QueryProcessDetail(_codexChild.Pid, http: AsCodex));
        Assert.False(doc.RootElement.TryGetProperty("error", out _));
        Assert.Equal(_codexChild.Pid, doc.RootElement.GetProperty("pid").GetInt32());
    }

    [Fact]
    public void AcknowledgeAlert_CodexCaller_DeniedOnClaudeAlert()
    {
        var alert = new CommandAlertEvent(DateTimeOffset.UtcNow, ForemanSeverity.Medium, "src", "msg",
            "cmd", "del-009", "rule", "desc", "guide", _claude.Pid);
        _state.AddEvent(alert);

        using var doc = J(ForemanMcpTools.AcknowledgeAlert(alert.Id, http: AsCodex));
        Assert.False(doc.RootElement.GetProperty("acknowledged").GetBoolean());
        Assert.False(alert.Acknowledged);   // not silenced
    }

    [Fact]
    public void ResetBehaviorMetrics_CodexCaller_DeniedOnClaude()
    {
        using var doc = J(ForemanMcpTools.ResetBehaviorMetrics("claude-code", http: AsCodex));
        Assert.False(doc.RootElement.GetProperty("reset").GetBoolean());
        Assert.Null(_lastReset);

        using var ok = J(ForemanMcpTools.ResetBehaviorMetrics("codex", http: AsCodex));
        Assert.True(ok.RootElement.GetProperty("reset").GetBoolean());
        Assert.Equal("codex", _lastReset);
    }

    [Fact]
    public void GetBehaviorMetrics_CodexCaller_SeesOnlyOwnProfile()
    {
        using var doc = J(ForemanMcpTools.GetBehaviorMetrics(http: AsCodex));
        var ids = doc.RootElement.GetProperty("harnesses").EnumerateArray().Select(h => h.GetProperty("harnessId").GetString()).ToHashSet();
        Assert.Contains("codex", ids);
        Assert.DoesNotContain("claude-code", ids);
    }

    [Fact]
    public void ReplyToAskHarness_CodexCaller_CannotAnswerClaudeRequestByParam()
    {
        var req = _state.CreateAskHarnessRequest("claude-code", "sys", "justify", "alert-x", _claude.Pid, "node.exe");
        // Codex caller tries to answer claude's request, even passing harnessId=claude-code → must be rejected
        // because identity comes from the token (codex), and codex doesn't own this request.
        using var doc = J(ForemanMcpTools.ReplyToAskHarnessRequest(req.RequestId, "done", harnessId: "claude-code", http: AsCodex));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("pending", _state.GetAskHarnessRequest(req.RequestId)!.Status);
    }
}
