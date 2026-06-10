using Foreman.Core.Models;
using System.Collections.Concurrent;

namespace Foreman.Core.Events;

public interface IEventSink
{
    void OnEvent(ForemanEvent evt);
}

/// <summary>
/// Thread-safe in-process pub/sub. Subscribers receive events on the publisher's thread.
/// UI subscribers must marshal to the UI thread themselves.
/// Also maintains a rolling history of recent events so late subscribers (e.g. LogWindow
/// opened after startup) can hydrate their views.
/// </summary>
public sealed class EventBus
{
    private readonly ConcurrentDictionary<IEventSink, byte> _sinks = new();
    private readonly ConcurrentDictionary<Action<ForemanEvent>, byte> _handlers = new();
    private readonly ConcurrentQueue<ForemanEvent> _history = new();
    private const int MaxHistory = 1000;

    /// <summary>The process-wide bus used in production (the App composition root and monitors subscribe to it).</summary>
    public static EventBus Instance { get; } = new();

    /// <summary>
    /// Public so tests can use an isolated bus instead of the shared <see cref="Instance"/> — which
    /// otherwise leaks subscriptions across tests and forced cross-class parallelization off.
    /// </summary>
    public EventBus() { }

    public void Subscribe(IEventSink sink) => _sinks.TryAdd(sink, 0);
    public void Subscribe(Action<ForemanEvent> handler) => _handlers.TryAdd(handler, 0);

    public void Unsubscribe(IEventSink sink) => _sinks.TryRemove(sink, out _);
    public void Unsubscribe(Action<ForemanEvent> handler) => _handlers.TryRemove(handler, out _);

    /// <summary>Returns a snapshot of all events since startup, oldest first (capped at 1000).</summary>
    public IReadOnlyList<ForemanEvent> GetHistory() => _history.ToArray();

    public void Publish(ForemanEvent evt)
    {
        // buffer for late subscribers (log window opened after events already fired)
        _history.Enqueue(evt);
        while (_history.Count > MaxHistory)
            _history.TryDequeue(out _);

        foreach (var sink in _sinks.Keys)
        {
            try { sink.OnEvent(evt); }
            catch { /* never let a bad sink kill the bus */ }
        }

        foreach (var handler in _handlers.Keys)
        {
            try { handler(evt); }
            catch { }
        }
    }
}
