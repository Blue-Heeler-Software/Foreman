using OtpNet;

namespace Foreman.Core.Vault;

/// <summary>RFC-6238 TOTP via Otp.NET (MIT). Seeds are Base32 (the standard <c>otpauth://</c> format).</summary>
public static class VaultTotp
{
    public static string Generate(byte[] secret, DateTime utc, int digits = 6, int periodSeconds = 30) =>
        new Totp(secret, step: periodSeconds, totpSize: digits).ComputeTotp(utc);

    public static string FromBase32(string base32Seed, DateTime utc, int digits = 6, int periodSeconds = 30) =>
        Generate(Base32Encoding.ToBytes(base32Seed), utc, digits, periodSeconds);
}
