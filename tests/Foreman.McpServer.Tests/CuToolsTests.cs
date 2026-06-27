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
    public async Task CuSubmit_DesktopOverMcp_Rejected()
    {
        // Desktop CU is operator-driven in-process only (INV-7 / Codex review #2) — never over MCP.
        StateWith(CuVerdict.Allow("test"));
        using var doc = Json(await ForemanMcpTools.CuSubmit("desktop", "click", "{}"));
        Assert.False(doc.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public async Task CuSubmit_Hold_OperatorApprove_PollExecute_Complete()
    {
        StateWith(CuVerdict.Hold("test", "uncertain"));
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "click", "{}"));
        Assert.Equal("held", sub.RootElement.GetProperty("state").GetString());
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;

        using var appr = Json(await ForemanMcpTools.CuApprove(actionId));      // operator approves (CuApprove is async)
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

    [Fact]
    public async Task CuSetDriver_GatesWhoMaySubmit()
    {
        StateWith(CuVerdict.Allow("test"));   // browser (desktop is MCP-rejected now); default browser policy = Allow,
                                              // so this isolates the DRIVER gate.

        // Default: no driver -> a harness cannot submit (operator-only).
        using var noDrv = Json(await ForemanMcpTools.CuSubmit("browser", "read", "{}", AsHarness("codex")));
        Assert.False(noDrv.RootElement.GetProperty("accepted").GetBoolean());

        // Operator designates codex as the driver.
        using var set = Json(ForemanMcpTools.CuSetDriver("codex"));   // null http = operator
        Assert.True(set.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("codex", set.RootElement.GetProperty("driver").GetString());

        // codex may now submit...
        using var codexOk = Json(await ForemanMcpTools.CuSubmit("browser", "read", "{}", AsHarness("codex")));
        Assert.True(codexOk.RootElement.GetProperty("accepted").GetBoolean());

        // ...a different harness still may not.
        using var claudeNo = Json(await ForemanMcpTools.CuSubmit("browser", "read", "{}", AsHarness("claude-code")));
        Assert.False(claudeNo.RootElement.GetProperty("accepted").GetBoolean());
    }

    [Fact]
    public void CuSetDriver_OperatorOnly()
    {
        StateWith(CuVerdict.Allow("test"));
        using var doc = Json(ForemanMcpTools.CuSetDriver("codex", AsHarness("codex")));   // a non-operator harness
        Assert.False(doc.RootElement.GetProperty("ok").GetBoolean());
    }

    // ── cu_resolve_vault (the browser-extension executor's reference -> plaintext resolve) ──────────────────
    private static async Task<string> ExecutingBrowserAction(string text)
    {
        using var sub = Json(await ForemanMcpTools.CuSubmit("browser", "type", $"{{\"text\":\"{text}\"}}"));
        var actionId = sub.RootElement.GetProperty("actionId").GetString()!;
        Json(ForemanMcpTools.CuPollActions(10, AsHarness("browser-extension"))).Dispose();   // Approved -> Executing
        return actionId;
    }

    [Fact]
    public async Task CuResolveVault_Executor_ResolvesBoundReference()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason)>((true, "s3cret", "ok"));
        var actionId = await ExecutingBrowserAction("login {{vault:github.com/password}}");

        using var res = Json(await ForemanMcpTools.CuResolveVault(
            actionId, "{{vault:github.com/password}}", "github.com", AsHarness("browser-extension")));
        Assert.True(res.RootElement.GetProperty("ok").GetBoolean());
        Assert.Equal("s3cret", res.RootElement.GetProperty("value").GetString());
    }

    [Fact]
    public async Task CuResolveVault_SubmittingHarness_Refused()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason)>((true, "x", "ok"));
        var actionId = await ExecutingBrowserAction("{{vault:github.com/password}}");

        // A driving/submitting harness (not the browser-extension executor) can never resolve.
        using var res = Json(await ForemanMcpTools.CuResolveVault(
            actionId, "{{vault:github.com/password}}", "github.com", AsHarness("codex")));
        Assert.False(res.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task CuResolveVault_ReferenceNotInApprovedAction_Refused()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason)>((true, "x", "ok"));
        var actionId = await ExecutingBrowserAction("{{vault:github.com/password}}");

        // A reference the agent never put in the approved action is refused — no resolving arbitrary credentials.
        using var res = Json(await ForemanMcpTools.CuResolveVault(
            actionId, "{{vault:bank.com/password}}", "bank.com", AsHarness("browser-extension")));
        Assert.False(res.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task CuResolveVault_WhilePanicHalted_Refused()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason)>((true, "s3cret", "ok"));
        state.Panic = new Foreman.Core.Security.CuPanicState();
        state.Panic.Halt();
        using var res = Json(await ForemanMcpTools.CuResolveVault(
            "any", "{{vault:github.com/password}}", "github.com", AsHarness("browser-extension")));
        Assert.False(res.RootElement.GetProperty("ok").GetBoolean());   // panic voids any credential release
    }

    [Fact]
    public async Task CuResolveVault_ReferenceCaseInsensitive_Accepted()
    {
        var state = StateWith(CuVerdict.Allow("test"));
        state.ResolveVaultAsync = (_, _, _) => Task.FromResult<(bool Ok, string? Value, string Reason)>((true, "s3cret", "ok"));
        var actionId = await ExecutingBrowserAction("login {{vault:github.com/Password}}");   // capital P in the action
        using var res = Json(await ForemanMcpTools.CuResolveVault(
            actionId, "{{vault:github.com/password}}", "github.com", AsHarness("browser-extension")));
        Assert.True(res.RootElement.GetProperty("ok").GetBoolean());    // whole-token, case-insensitive match
    }
}
