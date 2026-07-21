using Foreman.Core.Events;
using Foreman.Core.Models;

namespace Foreman.McpServer.Tests;

public sealed class ForemanStateTests
{
    [Fact]
    public void InfoEvents_DoNotCountAsActiveAlerts()
    {
        var state = new ForemanState();

        ((IEventSink)state).OnEvent(new InfoEvent(DateTimeOffset.UtcNow, "Foreman", "startup"));

        Assert.Equal(0, state.ActiveAlerts);
        Assert.False(state.HasCritical);
    }

    [Fact]
    public void AcknowledgedAlerts_DoNotRemainActive()
    {
        var state = new ForemanState();
        var alert = new CommandAlertEvent(
            DateTimeOffset.UtcNow,
            ForemanSeverity.High,
            "cmd.exe (pid 1)",
            "suspicious",
            "reg save HKLM\\SAM sam.hiv",
            "cred-001",
            "SAM hive export",
            "credential access",
            "review",
            1);

        ((IEventSink)state).OnEvent(alert);
        Assert.Equal(1, state.ActiveAlerts);
        Assert.True(state.HasCritical);

        Assert.True(state.AcknowledgeAlert(alert.Id));

        Assert.Equal(0, state.ActiveAlerts);
        Assert.False(state.HasCritical);
    }

    [Fact]
    public void SuspiciousCommandLimiter_IsPerCallerAndRecoversAfterWindow()
    {
        var limiter = new SuspiciousCommandAlertLimiter(permitLimit: 2, window: TimeSpan.FromMinutes(1));
        var now = DateTimeOffset.UnixEpoch;

        Assert.True(limiter.TryAcquire("codex", now, out _));
        Assert.True(limiter.TryAcquire("codex", now.AddSeconds(1), out _));
        Assert.False(limiter.TryAcquire("codex", now.AddSeconds(2), out var retry));
        Assert.True(retry > TimeSpan.Zero);
        Assert.True(limiter.TryAcquire("claude-code", now.AddSeconds(2), out _));
        Assert.True(limiter.TryAcquire("codex", now.AddMinutes(1).AddSeconds(1), out _));
    }

    // ── Ask-Harness lifecycle: TTL expiry, late reply, prune order ──────────────────────────────

    private static ForemanState WithAsk(out AskHarnessRequest req, string harness = "claude-code")
    {
        var state = new ForemanState();
        req = state.CreateAskHarnessRequest(harness, "sys", "justify yourself", "alert-1", null, null);
        return state;
    }

    [Fact]
    public void ExpireStale_AgesOutPendingPastTtl()
    {
        var state = WithAsk(out var req);
        var ttl = TimeSpan.FromMinutes(30);

        Assert.Empty(state.ExpireStale(req.CreatedAt + TimeSpan.FromMinutes(10), ttl));   // still fresh
        Assert.Equal(1, state.PendingAskHarnessCount);

        var expired = state.ExpireStale(req.CreatedAt + TimeSpan.FromMinutes(31), ttl);   // past TTL
        Assert.Single(expired);
        Assert.Equal(AskHarnessStatus.Expired, expired[0].Status);
        Assert.Equal(0, state.PendingAskHarnessCount);
    }

    [Fact]
    public void ExpireStale_ZeroTtl_DisablesExpiry()
    {
        var state = WithAsk(out var req);
        Assert.Empty(state.ExpireStale(req.CreatedAt + TimeSpan.FromDays(7), TimeSpan.Zero));
        Assert.Equal(1, state.PendingAskHarnessCount);
    }

    [Fact]
    public void ExpireStale_LeavesAnsweredAlone()
    {
        var state = WithAsk(out var req);
        Assert.True(state.ReplyToAskHarnessRequest(req.RequestId, "done", null, "claude-code", null).Ok);
        Assert.Empty(state.ExpireStale(req.CreatedAt + TimeSpan.FromHours(1), TimeSpan.FromMinutes(30)));
    }

    [Fact]
    public void LateReplyToExpiredRequest_IsAccepted()
    {
        var state = WithAsk(out var req);
        state.ExpireStale(req.CreatedAt + TimeSpan.FromMinutes(31), TimeSpan.FromMinutes(30));

        var (ok, reason, updated) =
            state.ReplyToAskHarnessRequest(req.RequestId, "sorry, late", "cleaned up", "claude-code", null);
        Assert.True(ok);
        Assert.Contains("Late reply", reason);
        Assert.Equal(AskHarnessStatus.Answered, updated!.Status);
        Assert.Equal("cleaned up", updated.ActionTaken);
    }

    [Fact]
    public void ReplyToAlreadyAnswered_IsRejected_OriginalPreserved()
    {
        var state = WithAsk(out var req);
        Assert.True(state.ReplyToAskHarnessRequest(req.RequestId, "first", null, "claude-code", null).Ok);

        var (ok, reason, kept) =
            state.ReplyToAskHarnessRequest(req.RequestId, "second", null, "claude-code", null);
        Assert.False(ok);
        Assert.Contains("already answered", reason);
        Assert.Equal("first", kept!.ReplyText);   // not clobbered
    }

    [Fact]
    public void AnonymousReply_IsStillRejected()   // identity guard must survive the lifecycle work
    {
        var state = WithAsk(out var req);
        Assert.False(state.ReplyToAskHarnessRequest(req.RequestId, "hi", null, null, null).Ok);
    }

    [Fact]
    public void SelectPruneVictims_DropsTerminalBeforePending()
    {
        var t0 = DateTimeOffset.UnixEpoch;
        AskHarnessRequest Mk(string id, string status, int min) =>
            new(id, t0.AddMinutes(min), "a", "claude-code", null, null, "s", "p", status);

        var all = new[]
        {
            Mk("old-pending",  AskHarnessStatus.Pending,   0),   // oldest, but still open → must survive
            Mk("old-answered", AskHarnessStatus.Answered,  1),
            Mk("new-expired",  AskHarnessStatus.Expired,   9),
            Mk("new-pending",  AskHarnessStatus.Pending,  10),
        };

        // cap 2 → drop 2: both terminal (resolved) go first, oldest-first; both pending survive.
        var victims = ForemanState.SelectPruneVictims(all, cap: 2).ToList();
        Assert.Equal(new[] { "old-answered", "new-expired" }, victims);
    }
}
