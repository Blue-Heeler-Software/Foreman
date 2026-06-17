using System.Diagnostics;

namespace Foreman.Core.Events;

/// <summary>
/// Per-session local time source. Wall UTC is for human correlation; monotonic ticks are for local intervals.
/// </summary>
public interface ITemporalClock
{
    string SessionId { get; }
    DateTimeOffset UtcNow { get; }
    long MonotonicTicks { get; }
    long MonotonicFrequency { get; }
}

public sealed class SystemTemporalClock : ITemporalClock
{
    private readonly long _startTicks = Stopwatch.GetTimestamp();

    public string SessionId { get; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    public long MonotonicTicks => Stopwatch.GetTimestamp() - _startTicks;
    public long MonotonicFrequency => Stopwatch.Frequency;
}
