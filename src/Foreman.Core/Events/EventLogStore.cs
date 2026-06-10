using System.Text;
using System.Text.Json;
using Foreman.Core.Models;
using Foreman.Core.Security;

namespace Foreman.Core.Events;

/// <summary>
/// Durable, append-only event log on disk (JSONL — one polymorphic <see cref="ForemanEvent"/> per
/// line) so the Event Log survives restarts. Append is best-effort and never throws into the publish
/// path; Load tolerates corrupt lines and trims to the most recent <c>maxEntries</c>, rewriting the
/// file when it does. This feeds the Log VIEW only — it is deliberately separate from the in-memory
/// EventBus history, so reloading persisted events never resurrects stale alerts as "active".
/// </summary>
public sealed class EventLogStore
{
    private static readonly JsonSerializerOptions _json = new() { WriteIndented = false };

    private readonly string _file;
    private readonly int _maxEntries;
    private readonly object _lock = new();

    public EventLogStore(string? baseDir = null, int maxEntries = 5000)
    {
        var dir = baseDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Foreman");
        _file = Path.Combine(dir, "events.log.jsonl");
        _maxEntries = Math.Max(1, maxEntries);
    }

    public string FilePath => _file;

    /// <summary>Appends one event. Best-effort: any IO/serialization failure is swallowed.</summary>
    public void Append(ForemanEvent evt)
    {
        try
        {
            // Disk is an egress boundary: mask secret-shaped text before it lands at rest.
            var line = JsonSerializer.Serialize(SecretRedactor.RedactEvent(evt), _json);
            lock (_lock)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
                File.AppendAllText(_file, line + "\n");
            }
        }
        catch { /* never let persistence disrupt the event bus */ }
    }

    /// <summary>Loads persisted events oldest-first, skipping corrupt lines and trimming to maxEntries.</summary>
    public IReadOnlyList<ForemanEvent> Load()
    {
        lock (_lock)
        {
            try
            {
                if (!File.Exists(_file)) return [];

                var events = new List<ForemanEvent>();
                foreach (var line in File.ReadLines(_file))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        if (JsonSerializer.Deserialize<ForemanEvent>(line, _json) is { } e)
                            events.Add(e);
                    }
                    catch { /* skip a corrupt/partial line */ }
                }

                if (events.Count > _maxEntries)
                {
                    events = events.GetRange(events.Count - _maxEntries, _maxEntries);
                    Rewrite(events);   // keep the file bounded across restarts
                }
                return events;
            }
            catch { return []; }
        }
    }

    private void Rewrite(IReadOnlyList<ForemanEvent> events)
    {
        try
        {
            var sb = new StringBuilder(events.Count * 128);
            foreach (var e in events)
                sb.Append(JsonSerializer.Serialize(e, _json)).Append('\n');
            File.WriteAllText(_file, sb.ToString());
        }
        catch { /* best-effort */ }
    }
}
