using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

/// <summary>Slice 2: auditor honesty for desktop CU - a coordinate click is judged on its resolved target, sensitive
/// / consent surfaces are held or blocked, an unidentifiable target never auto-Allows, and floods are rate-limited.</summary>
public sealed class CuDesktopAuditTests
{
    private static CuAction Desk(string verb, Dictionary<string, string> args)
        => new(CuModality.Desktop, verb, args, ByHarness: "operator");
    private static CuVerdict Judge(CuAction a) => FastPathAuditor.Judge(a, new CuContext());

    [Fact]
    public void Project_DesktopClick_IncludesResolvedTarget_NotEmpty()
    {
        var p = FastPathAuditor.Project(Desk("click", new() { ["x"] = "10", ["y"] = "20", ["targetLabel"] = "Save", ["targetRole"] = "button" }));
        Assert.Contains("Save", p);   // before the fix a coordinate-only click projected to "" and was judged on nothing
    }

    [Fact]
    public void SensitiveControlLabel_Held()
    {
        var v = Judge(Desk("click", new() { ["targetLabel"] = "Confirm wire transfer", ["targetRole"] = "button" }));
        Assert.Equal(CuDecision.Hold, v.Decision);
    }

    [Fact]
    public void UnlabeledClick_Held_NeverAutoAllow()
    {
        var v = Judge(Desk("click", new() { ["x"] = "100", ["y"] = "200" }));   // bare coordinate, no resolved target
        Assert.Equal(CuDecision.Hold, v.Decision);
    }

    [Fact]
    public void ConsentClassDialog_Blocked()
    {
        var v = Judge(Desk("click", new() { ["targetLabel"] = "Save", ["windowClass"] = "#32770", ["windowTitle"] = "Save As" }));
        Assert.Equal(CuDecision.Block, v.Decision);
    }

    [Fact]
    public void UacWindow_Blocked()
    {
        var v = Judge(Desk("click", new() { ["targetLabel"] = "Yes", ["windowTitle"] = "User Account Control" }));
        Assert.Equal(CuDecision.Block, v.Decision);
    }

    [Fact]
    public void BenignLabeledClick_Allowed()
    {
        var v = Judge(Desk("click", new() { ["targetLabel"] = "Cancel", ["targetRole"] = "button", ["windowTitle"] = "Untitled - Notepad" }));
        Assert.Equal(CuDecision.Allow, v.Decision);
    }

    private sealed class Allow : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default)
            => Task.FromResult(CuVerdict.Allow("test"));
    }

    [Fact]
    public async Task RateLimit_BurstAboveHumanSpeed_IsHeld()
    {
        var b = new CuBroker(new Allow());
        b.SetDriver("codex");
        CuActionState last = CuActionState.Auditing;
        for (var i = 0; i < 20; i++)   // a tight loop drains the token bucket (refill ~0) -> later submits are rate-Held
        {
            var item = await b.SubmitAsync(
                new CuAction(CuModality.Browser, "read", new Dictionary<string, string>(), ByHarness: "codex"), new CuContext());
            last = item.State;
        }
        Assert.Equal(CuActionState.Held, last);
    }

    [Fact]
    public async Task RateLimit_OperatorExempt()
    {
        var b = new CuBroker(new Allow());
        CuActionState last = CuActionState.Auditing;
        for (var i = 0; i < 20; i++)   // operator's own actions are never rate-limited
        {
            var item = await b.SubmitAsync(
                new CuAction(CuModality.Browser, "read", new Dictionary<string, string>(), ByHarness: "operator"), new CuContext());
            last = item.State;
        }
        Assert.Equal(CuActionState.Approved, last);
    }
}
