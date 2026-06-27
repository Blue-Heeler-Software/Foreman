using Foreman.Core.Vault;

namespace Foreman.Core.Tests.Vault;

public sealed class VaultTotpTests
{
    // RFC 6238 Appendix B test vector (SHA-1, seed = ASCII "12345678901234567890" = this Base32):
    // at T = 59s the 8-digit code is 94287082, so the 6-digit code is 287082.
    [Fact]
    public void Rfc6238_TestVector_Matches()
    {
        const string seedB32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        var t59 = DateTimeOffset.FromUnixTimeSeconds(59).UtcDateTime;
        Assert.Equal("94287082", VaultTotp.FromBase32(seedB32, t59, digits: 8));
        Assert.Equal("287082",   VaultTotp.FromBase32(seedB32, t59, digits: 6));
    }
}
