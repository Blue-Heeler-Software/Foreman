using Foreman.Core.Ipc.Guardian;

namespace Foreman.App;

/// <summary>Rejects legacy guardians that predate authenticated client-policy reporting.</summary>
internal static class GuardianTrust
{
    public const string PublisherSigned = "publisher_signed";
    public const string PathHashPinned = "path_hash_pinned";

    public static bool IsAccepted(HelloResult? hello) =>
        hello is not null &&
        (string.Equals(hello.TrustMode, PublisherSigned, StringComparison.Ordinal) ||
         string.Equals(hello.TrustMode, PathHashPinned, StringComparison.Ordinal));

    public static string ProbeInstalledMode()
    {
        if (!GuardianDiscovery.IsGuardianInstalled()) return string.Empty;
        try
        {
            var client = new GuardianPipeClient(connectTimeoutMs: 500);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            if (!client.IsServerSystemOwnedAsync(cts.Token).GetAwaiter().GetResult())
                return "legacy_or_unavailable";
            var hello = client.HelloAsync(cts.Token).GetAwaiter().GetResult();
            return IsAccepted(hello) ? hello!.TrustMode : "legacy_or_unavailable";
        }
        catch
        {
            return "legacy_or_unavailable";
        }
    }
}
