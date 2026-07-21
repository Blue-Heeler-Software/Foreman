using Foreman.Core.Security;

namespace Foreman.Core.Tests.Security;

public sealed class DecoyAuditOwnershipLeaseTests
{
    [Fact]
    public void FreshVersionedLease_RoundTrips()
    {
        var now = DateTimeOffset.UtcNow;
        var id = Guid.NewGuid().ToString("N");

        Assert.True(DecoyAuditOwnershipLeaseCodec.TryParse(
            DecoyAuditOwnershipLeaseCodec.Create(id, now), out var lease));
        Assert.NotNull(lease);
        Assert.Equal(id, lease!.InstanceId);
        Assert.True(DecoyAuditOwnershipLeaseCodec.IsFresh(lease, now.AddMinutes(4)));
    }

    [Fact]
    public void StaleOrFutureLease_IsNotFresh()
    {
        var now = DateTimeOffset.UtcNow;
        var id = Guid.NewGuid().ToString("N");

        DecoyAuditOwnershipLeaseCodec.TryParse(
            DecoyAuditOwnershipLeaseCodec.Create(id, now.AddMinutes(-6)), out var stale);
        DecoyAuditOwnershipLeaseCodec.TryParse(
            DecoyAuditOwnershipLeaseCodec.Create(id, now.AddMinutes(2)), out var future);

        Assert.False(DecoyAuditOwnershipLeaseCodec.IsFresh(stale!, now));
        Assert.False(DecoyAuditOwnershipLeaseCodec.IsFresh(future!, now));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{\"Version\":1,\"Owner\":\"Another.Tool\",\"InstanceId\":\"00000000000000000000000000000000\",\"RefreshedAtUtc\":\"2026-01-01T00:00:00Z\"}")]
    public void MalformedOrForeignMarker_IsRejected(string marker)
    {
        Assert.False(DecoyAuditOwnershipLeaseCodec.TryParse(marker, out _));
    }
}
