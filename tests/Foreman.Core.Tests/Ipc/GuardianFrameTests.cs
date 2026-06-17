using Foreman.Core.Guardian;
using Foreman.Core.Ipc.Guardian;

namespace Foreman.Core.Tests.Ipc;

/// <summary>
/// Circle-back Phase A, step 1 (contract): the duplex guardian RPC envelope + DTOs round-trip as single JSON
/// lines, and the NullGuardianClient (the casual-user default) returns the "absent" sentinel for every call so
/// callers fall back to local logic.
/// </summary>
public sealed class GuardianFrameTests
{
    [Fact]
    public void RequestEnvelope_RoundTrips()
    {
        var args = new SealHeadArgs { HeadHash = "DEADBEEF", RecordCount = 99 };
        var req = new GuardianRequest { RequestId = "r1", Kind = GuardianRpc.SealHead, Payload = GuardianFrameJson.Encode(args) };

        var line = GuardianFrameJson.Line(req);
        Assert.DoesNotContain("\n", line); // one frame == one line

        var back = GuardianFrameJson.Decode<GuardianRequest>(line)!;
        Assert.Equal("r1", back.RequestId);
        Assert.Equal(GuardianRpc.SealHead, back.Kind);
        var innerBack = GuardianFrameJson.Decode<SealHeadArgs>(back.Payload)!;
        Assert.Equal("DEADBEEF", innerBack.HeadHash);
        Assert.Equal(99, innerBack.RecordCount);
    }

    [Fact]
    public void ResponseEnvelope_RoundTrips()
    {
        var res = new GuardianResponse
        {
            RequestId = "r1",
            Kind = GuardianRpc.SealHead,
            Ok = true,
            Payload = GuardianFrameJson.Encode(new SealHeadResult { Seal = "c2ln" }),
        };
        var back = GuardianFrameJson.Decode<GuardianResponse>(GuardianFrameJson.Line(res))!;
        Assert.True(back.Ok);
        Assert.Equal("r1", back.RequestId);
        Assert.Equal("c2ln", GuardianFrameJson.Decode<SealHeadResult>(back.Payload)!.Seal);
    }

    [Fact]
    public void SealSettingsArgs_RoundTrips_WithPresenceToken()
    {
        var args = new SealSettingsArgs
        {
            SecurityProjection = "{\"presenceLock\":true}",
            Action = "DisablePresenceLock",
            Detail = "user toggled off",
            PresenceToken = "tok-123",
        };
        var back = GuardianFrameJson.Decode<SealSettingsArgs>(GuardianFrameJson.Encode(args))!;
        Assert.Equal("DisablePresenceLock", back.Action);
        Assert.Equal("tok-123", back.PresenceToken);
        Assert.Equal(args.SecurityProjection, back.SecurityProjection);
    }

    [Fact]
    public void Decode_NullOrEmptyPayload_IsDefault()
    {
        Assert.Null(GuardianFrameJson.Decode<SealHeadArgs>(null));
        Assert.Null(GuardianFrameJson.Decode<SealHeadArgs>(""));
    }

    [Fact]
    public async Task NullGuardianClient_IsAbsent_ForEveryCall()
    {
        IGuardianClient c = NullGuardianClient.Instance;
        Assert.False(c.IsAvailable);
        Assert.Null(await c.HelloAsync());
        Assert.Null(await c.SealHeadAsync("h", 1));
        Assert.Null(await c.GetPinnedHeadKeyAsync());
        Assert.Null(await c.VerifySettingsAsync("proj", "seal"));

        var sealRes = await c.SealSettingsAsync(new SealSettingsArgs());
        Assert.False(sealRes.Denied);          // absent ≠ denied; caller falls back to local sealing
        Assert.Equal("guardian-absent", sealRes.Reason);
        Assert.Null(sealRes.Seal);
    }
}
