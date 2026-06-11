using System.Security.Cryptography;
using System.Text;

namespace Foreman.Core.Mcp;

/// <summary>
/// Reusable HMAC challenge/response — the "hardwired challenge/response" of the closed-loop spec. The server
/// issues a fresh random <see cref="NewChallenge"/> nonce; a client that holds the shared pairing key answers
/// with <see cref="Respond"/>; the server checks it with <see cref="Verify"/> (constant-time). This proves the
/// client holds the key without the key crossing the wire, and the per-connection nonce defeats replay.
///
/// Pure crypto, no transport — used by the pairing flow (extension &lt;-&gt; Foreman) and unit-tested here.
/// </summary>
public static class ChallengeResponse
{
    /// <summary>A fresh 256-bit random challenge nonce, hex-encoded. Issue one per connection attempt.</summary>
    public static string NewChallenge() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    /// <summary>The client's answer: HMAC-SHA256(key, challenge), hex-encoded.</summary>
    public static string Respond(string key, string challenge) =>
        Convert.ToHexString(HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(key ?? string.Empty),
            Encoding.UTF8.GetBytes(challenge ?? string.Empty)));

    /// <summary>True iff <paramref name="response"/> is the correct answer for (key, challenge). Constant-time
    /// comparison; a wrong length, null, or mismatched value all return false.</summary>
    public static bool Verify(string key, string challenge, string? response)
    {
        if (string.IsNullOrEmpty(response)) return false;
        var expected = Respond(key, challenge);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(response));
    }
}
