using Foreman.Core.Mcp;

namespace Foreman.Platform;

public interface ILocalPeerResolver
{
    PeerBindingVerdict TryResolve(
        int remotePort,
        int localPort,
        string claimedHarness,
        out int? pid,
        out string? attributedHarnessId);
}
