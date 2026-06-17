using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Foreman.Core.Models;

namespace Foreman.Core.Events;

/// <summary>
/// An EXTERNAL, out-of-band witness of the event-log chain head, committed to the OS event log (an append-only
/// store the same-user agent can't surgically revert — there is no API to delete a single Windows event entry,
/// only to clear a whole channel, which is itself elevated + conspicuous). It records the chain head that was on
/// disk the last time Foreman wrote a lifecycle anchor (at clean stop, and at startup).
///
/// WHY THIS EXISTS — the gap the in-file chain provably can't close: a rogue same-user agent can snapshot the
/// whole on-disk log (<c>events.log.jsonl</c> + its head seal), let Foreman record incriminating events, then
/// restore the snapshot. The restored state is internally consistent, so <see cref="EventLogStore.Verify"/>
/// passes — the agent rolled BOTH the chain and its head back together. The external anchor defeats exactly this:
/// on launch we check that the head we last witnessed EXTERNALLY is still present in the on-disk chain. A rollback
/// removes it (the restored snapshot predates that head) → <see cref="AnchorVerdict.Rolledback"/>.
/// </summary>
public sealed record LogAnchor(string HeadHash, long Count)
{
    private static readonly Regex _parse = new(
        @"head=(?<h>[0-9A-Fa-f]+)\s+count=(?<c>\d+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>The OS-event-log message body that carries the anchor — a stable, SIEM-greppable one-liner.</summary>
    public string Format() =>
        $"Foreman log-chain anchor — head={HeadHash} count={Count.ToString(CultureInfo.InvariantCulture)}. " +
        "External rollback witness; do not edit.";

    /// <summary>Parses an anchor previously written by <see cref="Format"/>; null if the text isn't an anchor.</summary>
    public static LogAnchor? TryParse(string? message)
    {
        if (string.IsNullOrEmpty(message)) return null;
        var m = _parse.Match(message);
        if (!m.Success) return null;
        return long.TryParse(m.Groups["c"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var count)
            ? new LogAnchor(m.Groups["h"].Value, count)
            : null;
    }
}

/// <summary>Outcome of checking the on-disk chain against the last external anchor.</summary>
public enum AnchorVerdict
{
    /// <summary>No prior external anchor (first run, OS log unavailable, or the witnessed chain was empty).</summary>
    NoPriorAnchor,
    /// <summary>The externally-witnessed head is still present in the on-disk chain — clean cycle or honest forward growth.</summary>
    Match,
    /// <summary>The externally-witnessed head is GONE from the on-disk chain — the log was reverted/rewritten while Foreman was down.</summary>
    Rolledback,
}

/// <summary>
/// Pure decision for the external-anchor check. Deliberately trim-tolerant: Foreman trims the on-disk log to a
/// cap during a RUNNING session (which re-anchors the hash chain and changes every retained record's hash), but
/// it never trims while DOWN. So the test isn't "does the head still equal the anchor" (a trim would change it) —
/// it's "is the anchored head still PRESENT anywhere in the chain":
///  - present as the last record  → clean stop→start cycle, nothing touched while down;
///  - present as an interior record → this session appended past the anchor then was killed (honest forward progress);
///  - ABSENT                       → the on-disk log no longer contains the state we externally committed to = rollback.
/// The residual false-positive (a single session appends more than the on-disk cap AND a trim evicts the anchored
/// head from the front before a kill) is rare and surfaces as a recheck-worthy notice, never silent.
/// </summary>
public static class AnchorPolicy
{
    public static AnchorVerdict Check(IReadOnlyCollection<string> onDiskChainedHashes, LogAnchor? anchor)
    {
        if (anchor is null || anchor.Count <= 0 || string.IsNullOrEmpty(anchor.HeadHash))
            return AnchorVerdict.NoPriorAnchor;
        return onDiskChainedHashes.Contains(anchor.HeadHash) ? AnchorVerdict.Match : AnchorVerdict.Rolledback;
    }
}

/// <summary>
/// Reads the on-disk event-log JSONL independently of <see cref="EventLogStore"/> (so the anchor check doesn't
/// couple to that type's internals) and returns the chained record hashes in file order. It TRUSTS the stored
/// <c>Hash</c> fields — internal chain consistency is the separate job of <see cref="EventLogStore.Verify"/>; here
/// we only need the set/sequence of committed heads to test the external anchor against.
/// </summary>
public static class LogHeadReader
{
    private static readonly JsonSerializerOptions _json = new() { WriteIndented = false };

    /// <summary>Stored hashes of every chained (Hash-bearing) record, oldest first; empty if the file is missing/unreadable.</summary>
    public static IReadOnlyList<string> ReadChainedHashes(string filePath)
    {
        var hashes = new List<string>();
        try
        {
            if (!File.Exists(filePath)) return hashes;
            foreach (var line in File.ReadLines(filePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var e = JsonSerializer.Deserialize<ForemanEvent>(line, _json);
                    if (e is not null && !string.IsNullOrEmpty(e.Hash)) hashes.Add(e.Hash);
                }
                catch { /* torn/legacy line — skip, consistent with EventLogStore.Verify */ }
            }
        }
        catch { /* best-effort: an unreadable log is reported elsewhere by Verify */ }
        return hashes;
    }

    /// <summary>The current on-disk head (last chained hash) and the chained count; ("", 0) when none.</summary>
    public static LogAnchor CurrentAnchor(string filePath)
    {
        var hashes = ReadChainedHashes(filePath);
        return hashes.Count == 0 ? new LogAnchor(string.Empty, 0) : new LogAnchor(hashes[^1], hashes.Count);
    }
}
