using System.Text.Json;
using Foreman.Core.Events;
using Foreman.Core.Mcp;
using Foreman.Core.Models;

namespace Foreman.Monitor;

/// <summary>
/// Tier 0: watches the MCP servers configured across AI harnesses and raises a Medium alert when a
/// new (or changed-target) server appears — supply-chain / "who added this MCP server?" detection.
/// Config-file reads only (no network, no elevation). The seen-set is persisted so only genuinely
/// new servers alert across restarts; the very first run establishes a silent baseline.
/// </summary>
public sealed class McpInventoryMonitor : IDisposable
{
    private readonly EventBus _bus;
    private readonly string _seenFile;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private Timer? _timer;
    private volatile IReadOnlyList<McpServerEntry> _current = [];

    public McpInventoryMonitor(EventBus bus, string? baseDir = null)
    {
        _bus = bus;
        var dir = baseDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Foreman");
        _seenFile = Path.Combine(dir, "mcp-seen.json");
    }

    public IReadOnlyList<McpServerEntry> Current => _current;

    public void Start()
    {
        var firstRun = !File.Exists(_seenFile);
        LoadSeen();
        Scan(firstRun);   // baseline silently on the very first run; alert on new thereafter
        _timer = new Timer(_ => Scan(firstRun: false), null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
    }

    private void Scan(bool firstRun)
    {
        List<McpServerEntry> found;
        try { found = McpInventoryScanner.Scan(); }
        catch { return; }
        _current = found;

        lock (_lock)
        {
            var newOnes = new List<McpServerEntry>();
            foreach (var entry in found)
                if (_seen.Add(entry.Key) && !firstRun)
                    newOnes.Add(entry);

            if (firstRun || newOnes.Count > 0)
                SaveSeen();

            foreach (var entry in newOnes)
            {
                if (IsForemanSelfServer(entry))
                {
                    _bus.Publish(new InfoEvent(
                        DateTimeOffset.UtcNow,
                        "Foreman.McpInventory",
                        $"Foreman MCP connector registered for {entry.Harness}: {Trunc(entry.Target, 100)}"));
                    continue;
                }

                _bus.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow,
                    ForemanSeverity.Medium,
                    "Foreman.McpInventory",
                    $"New MCP server '{entry.Name}' ({entry.Transport}) configured for {entry.Harness}: {Trunc(entry.Target, 100)}"));
            }
        }
    }

    public static bool IsForemanSelfServer(McpServerEntry entry)
    {
        if (!string.Equals(entry.Name, "foreman", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!string.Equals(entry.Transport, "http", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(entry.Transport, "sse", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!Uri.TryCreate(entry.Target, UriKind.Absolute, out var uri))
            return false;
        if (!uri.IsLoopback)
            return false;

        var path = uri.AbsolutePath.TrimEnd('/');
        return string.Equals(path, "/mcp", StringComparison.OrdinalIgnoreCase);
    }

    private void LoadSeen()
    {
        try
        {
            if (!File.Exists(_seenFile)) return;
            var keys = JsonSerializer.Deserialize<string[]>(File.ReadAllText(_seenFile));
            if (keys is not null)
                foreach (var k in keys) _seen.Add(k);
        }
        catch { /* corrupt seen-file — treat as empty */ }
    }

    private void SaveSeen()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_seenFile)!);
            File.WriteAllText(_seenFile, JsonSerializer.Serialize(_seen.ToArray()));
        }
        catch { /* best-effort */ }
    }

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    public void Dispose() => _timer?.Dispose();
}
