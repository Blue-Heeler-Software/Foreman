namespace Foreman.Core.Alerts;

/// <summary>Config for the notification cadence governor (operational-toast burst coalescing).</summary>
public sealed class CadenceGovernorSettings
{
    /// <summary>Coalesce bursts of OPERATIONAL alert toasts (hang/orphan) per class. Off = every toast shows.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Toasts allowed per class within the window before the rest are coalesced. Must be &gt;= 1.</summary>
    public int BurstThreshold { get; set; } = 3;

    /// <summary>Sliding window (seconds) the per-class burst budget applies over, and the rollup cadence.</summary>
    public int WindowSeconds { get; set; } = 90;

    /// <summary>The single clamped window every consumer must use (governor slide, flush timer, rollup label),
    /// so they can never disagree. Floors at 5s (matches the flush-timer minimum) and caps at one hour.</summary>
    public int EffectiveWindowSeconds => Math.Clamp(WindowSeconds, 5, 3600);

    /// <summary>The clamped per-class burst budget (always allow at least the first toast through).</summary>
    public int EffectiveBurstThreshold => Math.Max(1, BurstThreshold);
}

/// <summary>
/// Caps the NOTIFICATION cadence of high-frequency OPERATIONAL alert classes (hang/orphan) so a flood of, say,
/// idle harness-child hang notices becomes a few toasts plus a periodic rollup instead of dozens of popups.
///
/// Three invariants make this safe for a watchdog:
///   1. It governs ONLY the toast. Every raw event is still published + logged (the Tier-2 always-on record);
///      coalescing never erases history, only quiets the popup.
///   2. Callers MUST route only NON-security, non-Critical operational alerts through it. Security/cred/exec/
///      escalation/Critical notify individually and are never coalesced — so an attacker can't flood an
///      operational class to bury a real alert under the budget.
///   3. The budget is PER CLASS (keyed by harness/owner), so a flood from one harness can't suppress the first
///      alert of another.
///
/// Stateful + thread-safe; clock injected for tests. <see cref="ShouldNotify"/> is the per-toast gate;
/// <see cref="Flush"/> drains the coalesced counts for a periodic rollup notice.
/// </summary>
public sealed class AlertCadenceGovernor
{
    private readonly CadenceGovernorSettings _settings;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _lock = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _recent = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _coalesced = new(StringComparer.OrdinalIgnoreCase);

    public AlertCadenceGovernor(CadenceGovernorSettings settings, Func<DateTimeOffset>? now = null)
    {
        _settings = settings;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// True = show this toast; false = COALESCE it (suppress the toast — the raw event is still logged). Allows up
    /// to <see cref="CadenceGovernorSettings.BurstThreshold"/> toasts per class within the window, then coalesces
    /// the rest (counting them for the next <see cref="Flush"/> rollup).
    /// </summary>
    public bool ShouldNotify(string classKey)
    {
        if (!_settings.Enabled) return true;
        var budget = _settings.EffectiveBurstThreshold;
        var window = TimeSpan.FromSeconds(_settings.EffectiveWindowSeconds);
        lock (_lock)
        {
            var now = _now();
            if (!_recent.TryGetValue(classKey, out var q)) _recent[classKey] = q = new Queue<DateTimeOffset>();
            while (q.Count > 0 && now - q.Peek() > window) q.Dequeue();   // slide the window
            if (q.Count < budget)
            {
                q.Enqueue(now);
                return true;
            }
            _coalesced[classKey] = _coalesced.GetValueOrDefault(classKey) + 1;
            return false;
        }
    }

    /// <summary>
    /// Per-class counts of toasts coalesced since the last flush, and resets them. A periodic caller emits one
    /// rollup notice per entry ("N more [class] notices, in the log") so the suppression is itself visible.
    /// </summary>
    public IReadOnlyList<(string ClassKey, int Suppressed)> Flush()
    {
        lock (_lock)
        {
            // Periodic GC: age each per-class queue to now and drop the ones that have fully emptied, so a
            // long-lived process that sees many distinctly-named transient harnesses doesn't accrue stale
            // entries forever. (Empty queues hold no budget, so dropping them is purely hygiene.)
            var now = _now();
            var window = TimeSpan.FromSeconds(_settings.EffectiveWindowSeconds);
            foreach (var key in _recent.Keys.ToList())
            {
                var q = _recent[key];
                while (q.Count > 0 && now - q.Peek() > window) q.Dequeue();
                if (q.Count == 0) _recent.Remove(key);
            }

            var result = _coalesced.Where(kv => kv.Value > 0)
                .Select(kv => (kv.Key, kv.Value))
                .ToList();
            _coalesced.Clear();
            return result;
        }
    }

    /// <summary>Diagnostic: how many in-window timestamps are currently tracked for a class (0 if the key is absent).</summary>
    public int RecentKeyCount(string classKey)
    {
        lock (_lock) return _recent.TryGetValue(classKey, out var q) ? q.Count : 0;
    }
}
