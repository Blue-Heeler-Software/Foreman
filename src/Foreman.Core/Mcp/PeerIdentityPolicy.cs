namespace Foreman.Core.Mcp;

/// <summary>
/// The verdict of binding a per-harness MCP token's CLAIMED identity to the OS-attributed identity of the
/// loopback peer process that presented it — the second factor on top of the bearer token. A token proves
/// "I hold harness X's credential"; peer attribution proves "the process speaking IS harness X". A
/// <see cref="Mismatch"/> means a different process replayed X's token (theft/leak) — never legitimate, so
/// token theft alone stops being sufficient to impersonate a harness.
/// </summary>
public enum PeerBindingVerdict
{
    /// <summary>The connecting process resolves to the claimed harness (itself or a descendant) — token + transport agree.</summary>
    Match,

    /// <summary>
    /// The peer couldn't be attributed to a harness — a PID-lookup miss, a classification race on a
    /// just-spawned process, or an unclassified caller. Inconclusive: it must FAIL OPEN and is never treated
    /// as an attack, so a transient race can't brick a legitimate session.
    /// </summary>
    Unattributed,

    /// <summary>The peer is a DIFFERENT known harness than the token claims — a replayed/stolen token.</summary>
    Mismatch,
}

/// <summary>
/// Pure decision for loopback peer-PID binding (see <see cref="PeerBindingVerdict"/>). No I/O: the caller does
/// the TCP-table lookup + process classification and passes the two identities in, so this stays unit-testable
/// with no Windows dependency. Comparison is case-insensitive over the canonical harness id
/// (claude-code, codex, custom:foo.exe).
/// </summary>
public static class PeerIdentityPolicy
{
    /// <param name="claimedHarnessId">Harness id decoded from the per-harness bearer token. Null/empty for an
    /// operator token (no harness claim) — out of scope, returns <see cref="PeerBindingVerdict.Unattributed"/>.</param>
    /// <param name="attributedHarnessId">Harness the connecting PID resolves to (itself or a harness ancestor),
    /// or null when the peer can't be attributed.</param>
    public static PeerBindingVerdict Evaluate(string? claimedHarnessId, string? attributedHarnessId)
    {
        if (string.IsNullOrWhiteSpace(claimedHarnessId)) return PeerBindingVerdict.Unattributed;    // operator / no claim
        if (string.IsNullOrWhiteSpace(attributedHarnessId)) return PeerBindingVerdict.Unattributed; // peer not attributable
        return string.Equals(claimedHarnessId.Trim(), attributedHarnessId.Trim(), StringComparison.OrdinalIgnoreCase)
            ? PeerBindingVerdict.Match
            : PeerBindingVerdict.Mismatch;
    }
}
