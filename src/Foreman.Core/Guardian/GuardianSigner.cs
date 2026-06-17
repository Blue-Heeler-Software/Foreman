using Foreman.Core.Events;

namespace Foreman.Core.Guardian;

/// <summary>
/// An <see cref="ILogHeadSigner"/> that delegates SEALING to the guardian over IPC but keeps VERIFICATION local.
/// Plugged into <see cref="EventLogStore"/> in guardian mode so the head is signed by the SYSTEM-held key (which
/// the medium-IL agent can't use) while reads stay fast and offline.
///
/// Platform-agnostic by design (it only touches <see cref="IGuardianClient"/> + <see cref="SignedHeadSigner"/>,
/// no Windows API), so it lives in Core and is fully unit-testable with a fake client.
///
/// AVAILABILITY IS SACRED: <see cref="SealHead"/> is called on every append, sometimes on the UI dispatcher. A
/// slow/hung guardian must NEVER stall that path — sealing is bounded by a hard timeout and degrades to null
/// (unsigned-this-append, which <see cref="EventLogStore"/> already tolerates). Verification never touches the
/// pipe at all.
/// </summary>
public sealed class GuardianSigner : ILogHeadSigner
{
    private readonly IGuardianClient _client;
    private readonly byte[]? _pinnedPublicKey;
    private readonly int _sealTimeoutMs;
    private readonly SignedHeadSigner _verifier;   // local, verify-only (key: null), against the pinned public key

    public GuardianSigner(IGuardianClient client, byte[]? pinnedPublicKey, int sealTimeoutMs = 250)
    {
        _client = client;
        _pinnedPublicKey = pinnedPublicKey is { Length: > 0 } ? pinnedPublicKey : null;
        _sealTimeoutMs = sealTimeoutMs > 0 ? sealTimeoutMs : 250;
        _verifier = new SignedHeadSigner(key: null, pinnedPublicKey: _pinnedPublicKey);
    }

    /// <summary>We expect a seal once a public key has been pinned — same TOFU gate as the local signer.</summary>
    public bool ExpectsSeal => _pinnedPublicKey is not null;

    public string? SealHead(string headHash, long recordCount)
    {
        try
        {
            using var cts = new CancellationTokenSource(_sealTimeoutMs);
            // GetResult blocks the caller only until the async pipe round-trip completes OR the timeout cancels it;
            // because the client uses async I/O bound to this token, a hung guardian releases the thread on timeout.
            return _client.SealHeadAsync(headHash, recordCount, cts.Token).GetAwaiter().GetResult();
        }
        catch
        {
            return null;   // timeout / pipe error / guardian down → unsigned this append (best-effort head)
        }
    }

    /// <summary>Verifies LOCALLY against the pinned public key — fast, offline, never touches the guardian pipe.</summary>
    public bool VerifyHead(string headHash, long recordCount, string? seal) =>
        _verifier.VerifyHead(headHash, recordCount, seal);
}
