using System.Text.Json;
using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

/// <summary>Slice 3 (device-free part): the challenge-response crypto and wire contract the desktop sidecar handshake
/// is built on. The live process handshake (PID pinning, integrity, parent-death) is the on-device gate; here we pin
/// the math: a correct response verifies, every wrong input is rejected, and a scraped nonce cannot be replayed.</summary>
public sealed class CuHandshakeTests
{
    [Fact]
    public void Hmac_IsDeterministic_ForSameInputs()
    {
        var a = CuHandshake.Hmac("nonce-123", "challenge-abc");
        var b = CuHandshake.Hmac("nonce-123", "challenge-abc");
        Assert.Equal(a, b);
        Assert.NotEmpty(a);
    }

    [Fact]
    public void Verify_AcceptsCorrectResponse()
    {
        const string nonce = "s3cr3t-nonce";
        var challenge = "9f8e7d6c";
        var response = CuHandshake.Hmac(nonce, challenge);   // what the genuine sidecar returns
        Assert.True(CuHandshake.Verify(nonce, challenge, response));
    }

    [Fact]
    public void Verify_RejectsWrongNonce()
    {
        var challenge = "9f8e7d6c";
        var response = CuHandshake.Hmac("the-real-nonce", challenge);
        Assert.False(CuHandshake.Verify("a-different-nonce", challenge, response));
    }

    [Fact]
    public void Verify_RejectsNullOrEmpty()
    {
        Assert.False(CuHandshake.Verify("nonce", "challenge", null));
        Assert.False(CuHandshake.Verify("nonce", "challenge", ""));
    }

    [Fact]
    public void ScrapedNonce_ReplayedOnNewChallenge_Fails()
    {
        // The threat: a same-user process scrapes the nonce off our command line and the response to challenge A,
        // then connects on a NEW pipe where the App issues a FRESH challenge B. The old response must not work.
        const string nonce = "leaked-nonce";
        var challengeA = "aaaa1111";
        var stolenResponse = CuHandshake.Hmac(nonce, challengeA);
        var challengeB = "bbbb2222";   // the App's fresh challenge on the impostor's connection
        Assert.False(CuHandshake.Verify(nonce, challengeB, stolenResponse));
    }

    [Fact]
    public void ResponseMac_BindsIdKindOkErrorAndPayload()
    {
        // Responses that differ in ANY authenticated field must produce different MAC material, so a pipe peer
        // cannot lift the HMAC from one frame onto another or flip the Ok/Error decision bits (Slice 4 trusts Ok).
        var baseMac = CuJson.ResponseMac(DesktopCuKind.ExecuteAction, "req-1", ok: true, error: null, payloadB64: "AAAA");
        Assert.NotEqual(baseMac, CuJson.ResponseMac(DesktopCuKind.ExecuteAction, "req-1", true, null, "BBBB"));   // payload
        Assert.NotEqual(baseMac, CuJson.ResponseMac(DesktopCuKind.Heartbeat,     "req-1", true, null, "AAAA"));   // kind
        Assert.NotEqual(baseMac, CuJson.ResponseMac(DesktopCuKind.ExecuteAction, "req-2", true, null, "AAAA"));   // id
        Assert.NotEqual(baseMac, CuJson.ResponseMac(DesktopCuKind.ExecuteAction, "req-1", false, null, "AAAA"));  // Ok flip
        Assert.NotEqual(baseMac, CuJson.ResponseMac(DesktopCuKind.ExecuteAction, "req-1", true, "boom", "AAAA")); // Error inject
    }

    [Fact]
    public void HandshakeMac_IsDomainSeparatedFromResponseMac()
    {
        // The same nonce keys both the handshake proof and per-response MACs; the domain tags must keep them from
        // ever colliding, so a captured handshake reply can't be replayed as a response MAC (or vice versa).
        const string nonce = "shared-nonce";
        var challenge = "deadbeef";
        var handshake = CuHandshake.Hmac(nonce, CuHandshake.HandshakeMessage(challenge));
        var asResponse = CuHandshake.Hmac(nonce, CuJson.ResponseMac(DesktopCuKind.Hello, challenge, true, null, null));
        Assert.NotEqual(handshake, asResponse);
        Assert.StartsWith("cu-handshake-v1|", CuHandshake.HandshakeMessage(challenge));
    }

    [Fact]
    public void Request_RoundTrips_WithKindAsString()
    {
        var req = new DesktopCuRequest("req-42", DesktopCuKind.BindWindow, "cGF5bG9hZA==");
        var json = JsonSerializer.Serialize(req, CuJson.Options);
        Assert.Contains("BindWindow", json);   // string-named enum, not "1"
        var back = JsonSerializer.Deserialize<DesktopCuRequest>(json, CuJson.Options);
        Assert.Equal(req, back);
    }

    [Fact]
    public void ExecuteActionArgs_RoundTrips()
    {
        var args = new ExecuteActionArgs("act-1", "click",
            new Dictionary<string, string> { ["x"] = "10", ["y"] = "20" }, BoundHwnd: 0x1234, DryRun: true);
        var json = JsonSerializer.Serialize(args, CuJson.Options);
        var back = JsonSerializer.Deserialize<ExecuteActionArgs>(json, CuJson.Options);
        Assert.NotNull(back);
        Assert.Equal("click", back!.Verb);
        Assert.Equal(0x1234, back.BoundHwnd);
        Assert.True(back.DryRun);
        Assert.Equal("10", back.Args["x"]);
    }
}
