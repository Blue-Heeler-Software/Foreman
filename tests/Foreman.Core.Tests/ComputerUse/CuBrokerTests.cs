using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

public sealed class CuBrokerTests
{
    private sealed class FixedAuditor(CuVerdict verdict) : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default) => Task.FromResult(verdict);
    }

    private sealed class ThrowingAuditor : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default)
            => throw new InvalidOperationException("boom");
    }

    private static CuAction Act(string verb = "click", string? byHarness = "operator") =>
        new(CuModality.Browser, verb, new Dictionary<string, string>(), ByHarness: byHarness);

    [Fact]
    public async Task Submit_Allow_BecomesApproved()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);
    }

    [Fact]
    public async Task Submit_Hold_BecomesHeld_ThenApprove_ThenClaimExecutes()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Hold("test", "why")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);
        Assert.Single(b.ListHeld());

        Assert.True(b.ApproveHeld(item.ActionId).Ok);
        Assert.Equal(CuActionState.Approved, b.Get(item.ActionId)!.State);

        var claimed = b.Claim(10);
        Assert.Single(claimed);
        Assert.Equal(CuActionState.Executing, claimed[0].State);
    }

    [Fact]
    public async Task Submit_Hold_Reject_NeverClaimable()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Hold("test", "why")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.True(b.RejectHeld(item.ActionId).Ok);
        Assert.Equal(CuActionState.Rejected, b.Get(item.ActionId)!.State);
        Assert.Empty(b.Claim(10));
    }

    [Fact]
    public async Task Submit_Block_BecomesBlocked_NeverClaimable()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Block("test", "bad")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Blocked, item.State);
        Assert.Empty(b.Claim(10));
    }

    [Fact]
    public async Task ApproveHeld_OnNonHeld_Fails()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        var item = await b.SubmitAsync(Act(), new CuContext());   // Approved, not Held
        Assert.False(b.ApproveHeld(item.ActionId).Ok);
    }

    [Fact]
    public async Task Claim_Then_Complete_Lifecycle()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Single(b.Claim(10));
        Assert.True(b.Complete(item.ActionId, ok: true, result: "done", error: null).Ok);
        Assert.Equal(CuActionState.Completed, b.Get(item.ActionId)!.State);
    }

    [Fact]
    public async Task Claim_SkipsHeld()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Hold("t", "h")));
        await b.SubmitAsync(Act(), new CuContext());
        Assert.Empty(b.Claim(10));   // Held is not claimable
    }

    [Fact]
    public async Task AuditorThrows_FailsClosedToHeld()
    {
        var b = new CuBroker(new ThrowingAuditor());
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Held, item.State);
    }

    [Fact]
    public async Task Halted_Submit_Blocked_And_Claim_Empty()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")), isHalted: () => true);
        var item = await b.SubmitAsync(Act(), new CuContext());
        Assert.Equal(CuActionState.Blocked, item.State);
        Assert.Empty(b.Claim(10));
    }

    [Fact]
    public async Task Driver_NonDriverHarness_RejectedAtClaim()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));   // no driver set => operator only
        var item = await b.SubmitAsync(Act(byHarness: "y"), new CuContext());
        Assert.Equal(CuActionState.Approved, item.State);   // audit clears it...
        Assert.Empty(b.Claim(10));                          // ...but the driver re-check rejects it
        Assert.Equal(CuActionState.Rejected, b.Get(item.ActionId)!.State);
    }

    [Fact]
    public async Task Driver_AuthorizedHarness_Claims()
    {
        var b = new CuBroker(new FixedAuditor(CuVerdict.Allow("test")));
        b.SetDriver("y");
        var item = await b.SubmitAsync(Act(byHarness: "y"), new CuContext());
        var claimed = b.Claim(10);
        Assert.Single(claimed);
        Assert.Equal(CuActionState.Executing, claimed[0].State);
    }
}
