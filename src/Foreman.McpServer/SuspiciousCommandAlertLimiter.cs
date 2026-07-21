namespace Foreman.McpServer;

/// <summary>Per-caller sliding-window cap for operator-visible alerts minted by command pre-flight checks.</summary>
internal sealed class SuspiciousCommandAlertLimiter(int permitLimit = 12, TimeSpan? window = null)
{
    private readonly int _permitLimit = permitLimit > 0 ? permitLimit : throw new ArgumentOutOfRangeException(nameof(permitLimit));
    private readonly TimeSpan _window = window ?? TimeSpan.FromMinutes(1);
    private readonly object _gate = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _accepted = new(StringComparer.OrdinalIgnoreCase);

    public bool TryAcquire(string callerKey, DateTimeOffset now, out TimeSpan retryAfter)
    {
        callerKey = string.IsNullOrWhiteSpace(callerKey) ? "unattributed" : callerKey;
        lock (_gate)
        {
            if (!_accepted.TryGetValue(callerKey, out var timestamps))
                _accepted[callerKey] = timestamps = new Queue<DateTimeOffset>();

            var cutoff = now - _window;
            while (timestamps.TryPeek(out var oldest) && oldest <= cutoff)
                timestamps.Dequeue();

            if (timestamps.Count >= _permitLimit)
            {
                retryAfter = timestamps.Peek() + _window - now;
                return false;
            }

            timestamps.Enqueue(now);
            retryAfter = TimeSpan.Zero;
            return true;
        }
    }
}
