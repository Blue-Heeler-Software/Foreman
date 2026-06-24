using System.Security.Cryptography;
using System.Text;

namespace Foreman.App.ComputerUse;

/// <summary>
/// One-time, short-TTL bind tokens for the desktop CU window bind (spec INV-17). The bind flow mints a token only after
/// a fresh operator presence tap, then hands it to <see cref="Foreman.Core.ComputerUse.CuBroker.SetActiveWindow"/>,
/// whose <see cref="Foreman.Core.ComputerUse.CuBroker.BindTokenValidator"/> calls <see cref="Validate"/> - which accepts
/// the token at most once and only within the TTL. So a caller cannot fabricate a <c>CuWindowRef</c> for an attacker
/// window and bind it without the live tap that minted the token.
/// </summary>
public sealed class BindTokenStore
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(20);

    private readonly object _lock = new();
    private byte[]? _token;
    private DateTimeOffset _expiry;

    /// <summary>Mint a fresh one-time token (replaces any pending one) and return it as hex. Call AFTER the presence tap,
    /// immediately before SetActiveWindow.</summary>
    public string Mint()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        lock (_lock) { _token = bytes; _expiry = DateTimeOffset.UtcNow + Ttl; }
        return Convert.ToHexString(bytes);
    }

    /// <summary>True at most once, only if <paramref name="token"/> matches the pending token and the TTL hasn't lapsed.
    /// Consumed on success (replay-proof); constant-time compare.</summary>
    public bool Validate(string? token)
    {
        lock (_lock)
        {
            if (_token is null || string.IsNullOrEmpty(token)) return false;
            byte[] presented;
            try { presented = Convert.FromHexString(token); } catch { return false; }
            var ok = DateTimeOffset.UtcNow <= _expiry
                     && CryptographicOperations.FixedTimeEquals(presented, _token);
            if (ok) { _token = null; _expiry = default; }   // consume once on success; a wrong token just expires
            return ok;
        }
    }
}
