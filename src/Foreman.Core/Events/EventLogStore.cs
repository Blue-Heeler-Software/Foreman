using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Foreman.Core.Models;
using Foreman.Core.Security;
using Foreman.Core.Settings;

namespace Foreman.Core.Events;

/// <summary>
/// Durable, append-only event log on disk (JSONL — one polymorphic <see cref="ForemanEvent"/> per
/// line) so the Event Log survives restarts. Append is best-effort and never throws into the publish
/// path; Load tolerates corrupt lines and trims to the most recent <c>maxEntries</c>, rewriting the
/// file when it does. This feeds the Log VIEW only — it is deliberately separate from the in-memory
/// EventBus history, so reloading persisted events never resurrects stale alerts as "active".
///
/// TAMPER-EVIDENCE (P1): when <see cref="LogIntegritySettings.HashChainEnabled"/> is on, each written record
/// commits to the hash of the previous on-disk record (<see cref="LogChain"/>), and the chain head is sealed
/// via <see cref="ILogHeadSigner"/> (no-op in P1; TPM-backed in P3). <see cref="Verify"/> detects any
/// edit/drop/reorder of a past record, and — once a real seal exists — truncation. The audit log is exactly
/// what a rogue same-user agent would rewrite to hide its tracks, so this is a core self-protection layer.
/// </summary>
public sealed class EventLogStore
{
    private static readonly JsonSerializerOptions _json = new() { WriteIndented = false };

    private readonly string _file;
    private readonly int _maxEntries;
    private readonly object _lock = new();
    private readonly bool _chain;
    private readonly ILogHeadSigner _signer;
    private readonly ITemporalClock _clock;
    private readonly ILogTimeAnchor _timeAnchor;

    private string? _headHash;   // last chained record's Hash; null until seeded, then "" (genesis) or a hash
    private long _count;         // number of chained records (bound into the head seal)
    private long? _lastSequence;
    private DateTimeOffset? _lastRecordedAtUtc;
    private long? _lastMonotonicTicks;
    private string? _lastTemporalSessionId;
    private long _lastMonotonicFrequency;

    public EventLogStore(string? baseDir = null, int maxEntries = 5000,
                         LogIntegritySettings? integrity = null, ILogHeadSigner? signer = null,
                         ITemporalClock? clock = null, ILogTimeAnchor? timeAnchor = null)
    {
        var dir = baseDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Foreman");
        _file = Path.Combine(dir, "events.log.jsonl");
        _maxEntries = Math.Max(1, maxEntries);
        _chain = (integrity ?? new LogIntegritySettings()).HashChainEnabled;
        _signer = signer ?? new NullHeadSigner();
        _clock = clock ?? new SystemTemporalClock();
        _timeAnchor = timeAnchor ?? new NullTimeAnchor();
    }

    public string FilePath => _file;
    private string HeadFile => _file + ".head";

    public Exception? LastAppendError { get; private set; }

    /// <summary>Appends one event. Best-effort: any IO/serialization failure is swallowed.</summary>
    public void Append(ForemanEvent evt) => TryAppend(evt, out _);

    /// <summary>Appends one event and reports whether persistence succeeded.</summary>
    public bool TryAppend(ForemanEvent evt, out string? error)
    {
        try
        {
            AppendCore(evt);
            LastAppendError = null;
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            LastAppendError = ex;
            error = ex.Message;
            return false;
        }
    }

    private void AppendCore(ForemanEvent evt)
    {
        // Disk is an egress boundary: mask secret-shaped text before it lands at rest.
        var redacted = SecretRedactor.RedactEvent(evt);
        lock (_lock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_file)!);

            if (_headHash is null || _lastSequence is null)
                SeedState();   // continue chain + sequence across store instances/restarts

            var recordedAt = _clock.UtcNow;
            var monotonicTicks = _clock.MonotonicTicks;
            var sequence = (_lastSequence ?? 0) + 1;
            redacted = redacted with
            {
                TemporalSessionId = _clock.SessionId,
                Sequence = sequence,
                RecordedAtUtc = recordedAt,
                MonotonicTicks = monotonicTicks,
                MonotonicFrequency = _clock.MonotonicFrequency,
                TemporalAnomalies = DetectTemporalAnomalies(recordedAt, monotonicTicks),
            };

            if (_chain)
            {
                var canonical = LogChain.Canonicalize(redacted, _json);
                var hash = LogChain.ComputeHash(_headHash, canonical);
                redacted = redacted with { PrevHash = _headHash ?? LogChain.Genesis, Hash = hash };
                _headHash = hash;
                _count++;
            }

            _lastSequence = sequence;
            _lastRecordedAtUtc = recordedAt;
            _lastMonotonicTicks = monotonicTicks;
            _lastTemporalSessionId = _clock.SessionId;
            _lastMonotonicFrequency = _clock.MonotonicFrequency;

            File.AppendAllText(_file, JsonSerializer.Serialize(redacted, _json) + "\n");

            if (_chain)
                WriteHeadSeal(_signer.SealHead(_headHash!, _count));   // no-op file under NullHeadSigner
        }
    }

    /// <summary>Loads persisted events oldest-first, skipping corrupt lines and trimming to maxEntries.</summary>
    public IReadOnlyList<ForemanEvent> Load()
    {
        lock (_lock)
        {
            try
            {
                if (!File.Exists(_file)) return [];

                var lines = File.ReadAllLines(_file);
                var events = new List<ForemanEvent>();
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        if (JsonSerializer.Deserialize<ForemanEvent>(line, _json) is { } e)
                            events.Add(e);
                    }
                    catch { /* skip a corrupt/partial line */ }
                }

                MigrateCanonicalDriftIfNeeded(lines, events);

                if (events.Count > _maxEntries)
                {
                    events = events.GetRange(events.Count - _maxEntries, _maxEntries);
                    Rewrite(events);   // keep the file bounded across restarts (re-anchors the chain)
                }
                return events;
            }
            catch { return []; }
        }
    }

    private void MigrateCanonicalDriftIfNeeded(string[] lines, IReadOnlyList<ForemanEvent> events)
    {
        if (!_chain || events.Count == 0) return;
        var current = Verify();
        if (current.Status != VerifyStatus.BrokenLink ||
            !current.Message.Contains("content hash mismatch", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (!HistoricalStoredCanonicalChainVerifies(lines))
            return;

        Rewrite(events);
    }

    private bool HistoricalStoredCanonicalChainVerifies(string[] lines)
    {
        string? prevHash = null;
        long chained = 0;
        var started = false;

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            ForemanEvent? e;
            try { e = JsonSerializer.Deserialize<ForemanEvent>(line, _json); }
            catch { return false; }
            if (e is null) continue;

            if (!started)
            {
                if (string.IsNullOrEmpty(e.Hash)) continue;
                started = true;
                prevHash = LogChain.Genesis;
            }
            else if (string.IsNullOrEmpty(e.Hash))
            {
                return false;
            }

            var expected = LogChain.ComputeHash(prevHash, HistoricalStoredCanonicalize(line));
            if (e.PrevHash != prevHash || e.Hash != expected)
                return false;

            prevHash = e.Hash;
            chained++;
        }

        if (!started) return false;

        var head = ReadHeadSeal();
        if (head is null)
            return !_signer.ExpectsSeal && !_timeAnchor.ExpectsAnchor;
        if (_signer.ExpectsSeal && !_signer.VerifyHead(head.HeadHash, head.Count, head.Seal))
            return false;
        if (_timeAnchor.ExpectsAnchor && !_timeAnchor.VerifyAnchor(head.HeadHash, head.Count, head.Temporal, head.TimeAnchor))
            return false;
        return head.Count == chained && head.HeadHash == prevHash;
    }

    private static string HistoricalStoredCanonicalize(string line)
    {
        var node = JsonNode.Parse(line)?.AsObject()
            ?? throw new JsonException("Event log record is not a JSON object.");
        node[nameof(ForemanEvent.Hash)] = null;
        node[nameof(ForemanEvent.PrevHash)] = null;
        return node.ToJsonString(_json);
    }

    /// <summary>
    /// Verifies the on-disk hash chain + head seal. A leading run of pre-chain records (no Hash) is treated as
    /// an unverifiable LEGACY prefix (not tamper), so enabling the chain over an existing log is graceful. A
    /// torn LAST line is an "unverified tail" (crash mid-append); a torn MIDDLE line is Corrupt. Read-only.
    /// </summary>
    public VerifyResult Verify()
    {
        lock (_lock)
        {
            if (!File.Exists(_file)) return VerifyResult.Empty;
            string[] lines;
            try { lines = File.ReadAllLines(_file); } catch { return VerifyResult.Empty; }

            string? prevHash = null;   // null until the chain starts (after any legacy prefix)
            long chained = 0;
            var started = false;
            long? priorSequence = null;
            string? priorTemporalSession = null;
            long? priorMonotonicTicks = null;

            for (var i = 0; i < lines.Length; i++)
            {
                if (string.IsNullOrWhiteSpace(lines[i])) continue;
                ForemanEvent? e;
                try { e = JsonSerializer.Deserialize<ForemanEvent>(lines[i], _json); }
                catch
                {
                    return IsLastNonBlank(lines, i)
                        ? VerifyResult.UnverifiedTail(chained)   // torn LAST line = crash, not tamper
                        : VerifyResult.Corrupt(i);               // torn MIDDLE line = reorder/insert damage
                }
                if (e is null) continue;

                if (!started)
                {
                    if (string.IsNullOrEmpty(e.Hash)) continue;   // legacy pre-chain prefix
                    started = true;
                    prevHash = LogChain.Genesis;
                }

                var expected = LogChain.ComputeHash(prevHash, LogChain.Canonicalize(e, _json));
                if (e.PrevHash != prevHash) return VerifyResult.BrokenLink(i, "prev-hash mismatch (dropped/reordered)");
                if (e.Hash != expected)     return VerifyResult.BrokenLink(i, "content hash mismatch (edited)");
                if (e.Sequence is { } seq)
                {
                    if (priorSequence is { } prior && seq <= prior)
                        return VerifyResult.BrokenLink(i, "sequence did not increase");
                    priorSequence = seq;
                }
                if (e.TemporalSessionId is { } session && e.MonotonicTicks is { } mono)
                {
                    if (string.Equals(session, priorTemporalSession, StringComparison.Ordinal) &&
                        priorMonotonicTicks is { } priorMono &&
                        mono < priorMono)
                    {
                        return VerifyResult.BrokenLink(i, "monotonic clock regressed within session");
                    }
                    priorTemporalSession = session;
                    priorMonotonicTicks = mono;
                }
                prevHash = e.Hash;
                chained++;
            }

            if (!started) return VerifyResult.Valid(0);   // empty or all-legacy: nothing chained to verify

            var head = ReadHeadSeal();
            if (head is null)
                return _signer.ExpectsSeal || _timeAnchor.ExpectsAnchor
                    ? VerifyResult.HeadUnsealed(chained)
                    : VerifyResult.Valid(chained);
            if (_signer.ExpectsSeal && !_signer.VerifyHead(head.HeadHash, head.Count, head.Seal))
                return VerifyResult.HeadUnsealed(chained);                  // seal forged / wrong key
            if (_timeAnchor.ExpectsAnchor && !_timeAnchor.VerifyAnchor(head.HeadHash, head.Count, head.Temporal, head.TimeAnchor))
                return VerifyResult.HeadUnsealed(chained);                  // time anchor forged / missing
            if (head.Count != chained || head.HeadHash != prevHash)
                return VerifyResult.HeadMismatch(chained);                  // authentic seal, file truncated/extended
            return VerifyResult.Valid(chained);
        }
    }

    // Seed the in-memory head from the file so a new store instance continues the existing chain. Counts only
    // CHAINED records (those with a Hash); a legacy prefix leaves the head at genesis (a fresh chain appends
    // after it). Tolerates a torn last line.
    private void SeedState()
    {
        _headHash = LogChain.Genesis;
        _count = 0;
        _lastSequence = 0;
        _lastRecordedAtUtc = null;
        _lastMonotonicTicks = null;
        _lastTemporalSessionId = null;
        _lastMonotonicFrequency = 0;
        try
        {
            if (!File.Exists(_file)) return;
            foreach (var raw in File.ReadLines(_file))
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;
                try
                {
                    var e = JsonSerializer.Deserialize<ForemanEvent>(raw, _json);
                    if (e is null) continue;
                    if (!string.IsNullOrEmpty(e.Hash)) { _headHash = e.Hash; _count++; }
                    if (e.Sequence is { } seq && seq > _lastSequence) _lastSequence = seq;
                    if (e.RecordedAtUtc is { } rec) _lastRecordedAtUtc = rec;
                    if (e.MonotonicTicks is { } mono) _lastMonotonicTicks = mono;
                    if (e.TemporalSessionId is { } session) _lastTemporalSessionId = session;
                    if (e.MonotonicFrequency is { } freq) _lastMonotonicFrequency = freq;
                }
                catch { /* torn line — skip */ }
            }
        }
        catch
        {
            _headHash = LogChain.Genesis;
            _count = 0;
            _lastSequence = 0;
            _lastRecordedAtUtc = null;
            _lastMonotonicTicks = null;
            _lastTemporalSessionId = null;
            _lastMonotonicFrequency = 0;
        }
    }

    // Trimming drops the genesis and the PrevHash links before the cut, so we RE-ANCHOR: the first retained
    // record becomes the new genesis and the chain is recomputed forward, then the head is re-sealed. A
    // re-anchored trim is byte-indistinguishable from a malicious truncate — acceptable only because re-sealing
    // requires the signer (the TPM key in P3); Verify reports a trimmed file as valid from the new anchor.
    private void Rewrite(IReadOnlyList<ForemanEvent> events)
    {
        try
        {
            var sb = new StringBuilder(events.Count * 128);
            string? prev = LogChain.Genesis;
            long n = 0;
            ForemanEvent? last = null;
            foreach (var e in events)
            {
                var rec = e;
                if (_chain)
                {
                    var canonical = LogChain.Canonicalize(e, _json);
                    var hash = LogChain.ComputeHash(prev, canonical);
                    rec = e with { PrevHash = prev, Hash = hash };
                    prev = hash;
                    n++;
                }
                sb.Append(JsonSerializer.Serialize(rec, _json)).Append('\n');
                last = rec;
            }
            File.WriteAllText(_file, sb.ToString());
            if (_chain)
            {
                _headHash = prev;
                _count = n;
                _lastSequence = last?.Sequence ?? n;
                _lastRecordedAtUtc = last?.RecordedAtUtc;
                _lastMonotonicTicks = last?.MonotonicTicks;
                _lastTemporalSessionId = last?.TemporalSessionId;
                _lastMonotonicFrequency = last?.MonotonicFrequency ?? 0;
                WriteHeadSeal(_signer.SealHead(prev!, n));
            }
        }
        catch { /* best-effort */ }
    }

    // The head seal lives in a sibling events.log.head file (small JSON), written atomically, so routine
    // appends never rewrite the JSONL. Under the no-op signer (P1) SealHead returns null and no file is written.
    private void WriteHeadSeal(string? seal)
    {
        var checkpoint = BuildTemporalCheckpoint();
        var anchor = checkpoint is null ? null : _timeAnchor.AnchorHead(_headHash ?? LogChain.Genesis, _count, checkpoint);
        if (seal is null && anchor is null) return;
        try
        {
            var json = JsonSerializer.Serialize(
                new HeadSeal(_headHash ?? LogChain.Genesis, _count, seal ?? string.Empty, checkpoint, anchor),
                _json);
            var tmp = HeadFile + ".tmp";
            File.WriteAllText(tmp, json);
            if (File.Exists(HeadFile)) File.Replace(tmp, HeadFile, destinationBackupFileName: null);
            else File.Move(tmp, HeadFile);
        }
        catch { /* best-effort; a missing/failed seal surfaces at Verify */ }
    }

    private HeadSeal? ReadHeadSeal()
    {
        try
        {
            return File.Exists(HeadFile)
                ? JsonSerializer.Deserialize<HeadSeal>(File.ReadAllText(HeadFile), _json)
                : null;
        }
        catch { return null; }
    }

    private string[] DetectTemporalAnomalies(DateTimeOffset recordedAt, long monotonicTicks)
    {
        var anomalies = new List<string>();
        if (_lastRecordedAtUtc is { } lastWall && recordedAt < lastWall)
            anomalies.Add("wall-clock-moved-backward");
        if (_lastMonotonicTicks is { } lastMono && monotonicTicks < lastMono)
            anomalies.Add("monotonic-clock-regressed");

        if (_lastRecordedAtUtc is { } prevWall &&
            _lastMonotonicTicks is { } prevMono &&
            _lastMonotonicFrequency > 0 &&
            monotonicTicks >= prevMono)
        {
            var wallDeltaMs = (recordedAt - prevWall).TotalMilliseconds;
            var monoDeltaMs = (monotonicTicks - prevMono) * 1000.0 / _lastMonotonicFrequency;
            if (Math.Abs(wallDeltaMs - monoDeltaMs) > TimeSpan.FromMinutes(5).TotalMilliseconds)
                anomalies.Add("wall-monotonic-divergence");
        }

        return anomalies.ToArray();
    }

    private TemporalCheckpoint? BuildTemporalCheckpoint()
    {
        return _lastTemporalSessionId is null ||
               _lastSequence is null ||
               _lastRecordedAtUtc is null ||
               _lastMonotonicTicks is null ||
               _lastMonotonicFrequency <= 0
            ? null
            : new TemporalCheckpoint(
                _lastTemporalSessionId,
                _lastSequence.Value,
                _lastRecordedAtUtc.Value,
                _lastMonotonicTicks.Value,
                _lastMonotonicFrequency);
    }

    private static bool IsLastNonBlank(string[] lines, int i)
    {
        for (var j = i + 1; j < lines.Length; j++)
            if (!string.IsNullOrWhiteSpace(lines[j])) return false;
        return true;
    }
}
