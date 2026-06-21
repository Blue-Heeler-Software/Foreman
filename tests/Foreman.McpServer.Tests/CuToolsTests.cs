using System.Text.Json;
using Foreman.Core.ComputerUse;

namespace Foreman.McpServer.Tests;

public sealed class CuToolsTests
{
    private sealed class FixedAuditor(CuVerdict verdict) : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default) => Task.FromResult(verdict);
    }

    private static JsonDocument Json(object o) => JsonDocument.Parse(JsonSerializer.Serialize(o));

    private static ForemanState StateWith(CuVerdict verdict)
    {
        var state = new ForemanState { Cu = new CuBroker(new FixedAuditor(verdict)) };
        ForemanMcpTools.SetState(state);
        return state;
    }

    // A POCO IHttpContextAccessor (the real one uses a shared AsyncLocal) so each test can pose as a specific
    // non-operator harness and exercise the executor-identity gate on cu_poll_actions / cu_complete_action.
    private sealed class FixedHttpContextAccessor : Microsoft.AspNetCore.Http.IHttpContextAccessor
    {
        public Microsoft.AspNetCore.Http.HttpContext? HttpContext { get; set; }
    }
    private static Microsoft.AspNetCore.Http.IHttpContextAccessor AsHarness(string id)
    {
        var ctx = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        ctx.Items[CallerScope.HttpItemKey] = new CallerScope(id, IsOperator: false);
        return new FixedHttpContextAccessor { HttpContext = ctx };
    }

    [Fact]
    public async Task CuSubmit_Allow_IsApproved()
    {
        StateWith(CuVerdict.Allow("test"));
        using var doc = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{\"url\":\"https://example.com\"}"));
        Assert.True(doc.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("approved", doc.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task CuSubmit_Block_IsBlocked_AndNotAccepted()
    {
        StateWith(CuVerdict.Block("test", "dangerous"));
        using var doc = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{\"url\":\"x\"}"));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
        Assert.Equal("blocked", doc.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task CuSubmit_BadModality_Rejected()
    {
        StateWith(CuVerdict.Allow("test"));
        using var doc = Json(await ForemanMcpTools.CuSubmit("hologram", "navigate", "{}"));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuSubmit_Hold_OperatorApprove_PollExecute_Complete()
    {
        StateWith(CuVerdict.Hold("test", "uncertain"));
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "click", "{}"));
        Assert.Equal("held", sub.RootElement.GetProperty("state").GetString());
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;

        using var appr = Json(ForemanMcpTools.CuApprove(actionId));            // operator approves
        Assert.True(appr.RootElement.GetProperty("ok").GetBoolean());

        using var poll = Json(ForemanMcpTools.CuPollActions(10));              // executor claims it
        Assert.Equal(1, poll.RootElement.GetProperty("actions").GetArrayLength());

        using var st = Json(ForemanMcpTools.CuActionStatus(actionId));
        Assert.Equal("executing", st.RootElement.GetProperty("state").GetString());

        using var done = Json(ForemanMcpTools.CuCompleteAction(actionId, ok: true, resultJson: null, error: null));
        Assert.True(done.RootElement.GetProperty("accepted").GetBoolean());

        using var st2 = Json(ForemanMcpTools.CuActionStatus(actionId));
        Assert.Equal("completed", st2.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task CuSubmit_Hold_OperatorReject_NotClaimable()
    {
        StateWith(CuVerdict.Hold("test", "uncertain"));
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "click", "{}"));
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;

        using var rej = Json(ForemanMcpTools.CuReject(actionId, "not now"));
        Assert.True(rej.RootElement.GetProperty("ok").GetBoolean());

        using var poll = Json(ForemanMcpTools.CuPollActions(10));
        Assert.Equal(0, poll.RootElement.GetProperty("actions").GetArrayLength());
    }

    [Fact]
    public async Task CuSubmit_NotWired_ReportsUnavailable()
    {
        ForemanMcpTools.SetState(new ForemanState());   // Cu is null
        using var doc = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{}"));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuStatus_SurfacesHeld()
    {
        StateWith(CuVerdict.Hold("test", "why"));
        _ = await ForemanMcpTools.CuSubmit("browser", "type", "{\"text\":\"x\"}");
        using var doc = Json(ForemanMcpTools.CuStatus());
        Assert.True(doc.RootElement.GetProperty("available").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("heldCount").GetInt32() >= 1);
    }

    [Fact]
    public async Task CuPoll_NonExecutorHarness_Refused_ButBrowserExtensionAllowed()
    {
        StateWith(CuVerdict.Allow("test"));
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{\"url\":\"https://example.com\"}"));
        Assert.Equal("approved", sub.RootElement.GetProperty("state").GetString());

        // A submitting/driving harness (codex) must NOT be able to claim the approved action…
        using var codexPoll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("codex")));
        Assert.Equal(0, codexPoll.RootElement.GetProperty("actions").GetArrayLength());

        // …only the browser-extension executor (or the operator) may.
        using var extPoll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension")));
        Assert.Equal(1, extPoll.RootElement.GetProperty("actions").GetArrayLength());
    }

    [Fact]
    public async Task CuComplete_NonExecutorHarness_Refused()
    {
        StateWith(CuVerdict.Allow("test"));
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "navigate", "{\"url\":\"https://example.com\"}"));
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;
        using var extPoll = Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension")));   // claim -> executing
        Assert.Equal(1, extPoll.RootElement.GetProperty("actions").GetArrayLength());

        using var codexDone = Json(ForemanMcpTools.CuCompleteAction(actionId, true, null, null, AsHarness("codex")));
        Assert.False(codexDone.RootElement.GetProperty("accepted").GetBoolean());
    }
}
