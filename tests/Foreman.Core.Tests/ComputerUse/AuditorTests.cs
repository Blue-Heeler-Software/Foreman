using Foreman.Core.ComputerUse;
using Foreman.Core.Heuristics;

namespace Foreman.Core.Tests.ComputerUse;

public sealed class AuditorTests
{
    // The fast path reuses the command pattern library, which must be loaded once before Analyze is called.
    static AuditorTests() => PatternLibrary.Instance.Initialize();

    private static CuAction Nav(string url) =>
        new(CuModality.Browser, "navigate", new Dictionary<string, string> { ["url"] = url });

    private static CuAction TypeInto(string text, string fieldType) =>
        new(CuModality.Browser, "type", new Dictionary<string, string> { ["text"] = text, ["fieldType"] = fieldType });

    private static CuAction Read() =>
        new(CuModality.Browser, "read", new Dictionary<string, string> { ["selector"] = "body" });

    private sealed class FakeAuditor : IAuditor
    {
        private readonly Func<CuAction, CuContext, CancellationToken, Task<CuVerdict>> _impl;
        public int Calls;
        public FakeAuditor(CuVerdict fixedVerdict) : this((_, _, _) => Task.FromResult(fixedVerdict)) { }
        public FakeAuditor(Func<CuAction, CuContext, CancellationToken, Task<CuVerdict>> impl) => _impl = impl;
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Calls);
            return _impl(a, c, ct);
        }
    }

    // ── Fast path ────────────────────────────────────────────────────────────
    [Fact]
    public void FastPath_BenignNavigate_Allows()
        => Assert.Equal(CuDecision.Allow, FastPathAuditor.Judge(Nav("https://example.com/docs"), new CuContext()).Decision);

    [Fact]
    public void FastPath_JavascriptScheme_Blocks()
        => Assert.Equal(CuDecision.Block, FastPathAuditor.Judge(Nav("javascript:alert(document.cookie)"), new CuContext()).Decision);

    [Fact]
    public void FastPath_FileScheme_Blocks()
        => Assert.Equal(CuDecision.Block, FastPathAuditor.Judge(Nav("file:///C:/Users/me/.ssh/id_rsa"), new CuContext()).Decision);

    [Fact]
    public void FastPath_TypingIntoPasswordField_Holds()
        => Assert.Equal(CuDecision.Hold, FastPathAuditor.Judge(TypeInto("hunter2", "password"), new CuContext()).Decision);

    [Fact]
    public void Project_IncludesUrlAndTypedText()
    {
        var a = new CuAction(CuModality.Browser, "type",
            new Dictionary<string, string> { ["url"] = "https://site.test", ["text"] = "hello world" });
        var projection = FastPathAuditor.Project(a);
        Assert.Contains("https://site.test", projection);
        Assert.Contains("hello world", projection);
    }

    // ── Pipeline ─────────────────────────────────────────────────────────────
    [Fact]
    public async Task Pipeline_FastPathBlock_IsFinal_DeepJudgeNotCalled()
    {
        var deep = new FakeAuditor(CuVerdict.Allow("cloud"));
        var pipe = new AuditPipeline(new FakeAuditor(CuVerdict.Block("fast-path", "obvious-bad")), deep);
        var v = await pipe.JudgeAsync(Nav("x"), new CuContext());
        Assert.Equal(CuDecision.Block, v.Decision);
        Assert.Equal(0, deep.Calls);
    }

    [Fact]
    public async Task Pipeline_ConfidentAllow_DeepJudgeNotCalled()
    {
        var deep = new FakeAuditor(CuVerdict.Block("cloud", "x"));
        var pipe = new AuditPipeline(new FakeAuditor(CuVerdict.Allow("fast-path", "ok", confidence: 1.0)), deep);
        var v = await pipe.JudgeAsync(Nav("x"), new CuContext());
        Assert.Equal(CuDecision.Allow, v.Decision);
        Assert.Equal(0, deep.Calls);
    }

    [Fact]
    public async Task Pipeline_AmbiguousHold_StateChanging_EscalatesToDeepJudge()
    {
        var deep = new FakeAuditor(CuVerdict.Block("cloud", "caught by judge"));
        var pipe = new AuditPipeline(new FakeAuditor(CuVerdict.Hold("fast-path", "uncertain")), deep);
        var v = await pipe.JudgeAsync(Nav("x"), new CuContext());
        Assert.Equal(CuDecision.Block, v.Decision);
        Assert.Equal("cloud", v.Source);
        Assert.Equal(1, deep.Calls);
    }

    [Fact]
    public async Task Pipeline_LowConfidenceAllow_StateChanging_Escalates()
    {
        var deep = new FakeAuditor(CuVerdict.Allow("cloud", "cleared", confidence: 1.0));
        var pipe = new AuditPipeline(new FakeAuditor(CuVerdict.Allow("fast-path", "low-signal", confidence: 0.5)), deep);
        var v = await pipe.JudgeAsync(Nav("x"), new CuContext());
        Assert.Equal("cloud", v.Source);
        Assert.Equal(1, deep.Calls);
    }

    [Fact]
    public async Task Pipeline_ReadOnlyVerb_NeverEscalates()
    {
        var deep = new FakeAuditor(CuVerdict.Block("cloud", "x"));
        var pipe = new AuditPipeline(new FakeAuditor(CuVerdict.Allow("fast-path", "low", confidence: 0.1)), deep);
        var v = await pipe.JudgeAsync(Read(), new CuContext());
        Assert.Equal(CuDecision.Allow, v.Decision);
        Assert.Equal(0, deep.Calls);
    }

    [Fact]
    public async Task Pipeline_NoDeepJudge_FastPathHoldBecomesOperatorHold()
    {
        var pipe = new AuditPipeline(new FakeAuditor(CuVerdict.Hold("fast-path", "uncertain")));
        var v = await pipe.JudgeAsync(Nav("x"), new CuContext());
        Assert.Equal(CuDecision.Hold, v.Decision);
    }

    [Fact]
    public async Task Pipeline_DeepJudgeThrows_FailsClosedToHold()
    {
        var deep = new FakeAuditor((_, _, _) => throw new InvalidOperationException("boom"));
        var pipe = new AuditPipeline(new FakeAuditor(CuVerdict.Hold("fast-path", "uncertain")), deep);
        var v = await pipe.JudgeAsync(Nav("x"), new CuContext());
        Assert.Equal(CuDecision.Hold, v.Decision);
        Assert.Equal("cloud", v.Source);
    }

    [Fact]
    public async Task Pipeline_DeepJudgeTimesOut_FailsClosedToHold()
    {
        var deep = new FakeAuditor(async (_, _, ct) => { await Task.Delay(5000, ct); return CuVerdict.Allow("cloud"); });
        var opts = new CuAuditOptions(MaxHoldOverride: TimeSpan.FromMilliseconds(20));
        var pipe = new AuditPipeline(new FakeAuditor(CuVerdict.Hold("fast-path", "uncertain")), deep, opts);
        var v = await pipe.JudgeAsync(Nav("x"), new CuContext());
        Assert.Equal(CuDecision.Hold, v.Decision);
        Assert.Contains("timed out", v.Reason);
    }
}
