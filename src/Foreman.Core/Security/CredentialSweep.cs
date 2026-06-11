using System.Text.RegularExpressions;
using Foreman.Core.Models;

namespace Foreman.Core.Security;

/// <summary>
/// Recognises a package-install command line (npm/pnpm/yarn/bun install, node-gyp build, pip/uv install,
/// python setup.py). Used to walk a process's ancestry and decide whether a credential/network rule fired
/// INSIDE an install subtree — where such a read is almost never legitimate (the Miasma / Phantom-Gyp
/// install-time detonation), so it gets escalated.
/// </summary>
public static class InstallSubtree
{
    private static readonly Regex _install = new(
        @"\b(?:npm|pnpm|yarn|bun)\b[^\n]*\b(?:install|ci|rebuild|add|update)\b" +
        @"|\bnpm\s+i\b|\bnode-gyp\b" +
        @"|\bpip[0-9.]*\s+install\b|python[0-9.]*\s+setup\.py\b|\buv\s+(?:pip\s+)?(?:install|sync)\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50));

    public static bool IsPackageInstall(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        try { return _install.IsMatch(commandLine); }
        catch (RegexMatchTimeoutException) { return false; }
    }
}

/// <summary>Severity helpers for the install-subtree correlation escalation.</summary>
public static class Severities
{
    /// <summary>One severity up, capped at Critical; Info/Critical are unchanged.</summary>
    public static ForemanSeverity EscalateOneLevel(ForemanSeverity s) => s switch
    {
        ForemanSeverity.Low    => ForemanSeverity.Medium,
        ForemanSeverity.Medium => ForemanSeverity.High,
        ForemanSeverity.High   => ForemanSeverity.Critical,
        _                      => s,
    };
}

/// <summary>
/// Sliding-window aggregator for the credential-store sweep: when ONE harness tree reads several DIFFERENT
/// credential stores within a short window, that is the Miasma harvester's fingerprint, not normal dev work.
/// Each individual read may look benign (and stays a low/medium alert), but the burst is Critical.
///
/// Thread-safe (WMI analysis runs on the thread pool). Fires at most once per window per harness tree, so an
/// ongoing sweep doesn't spam. Pure logic with an injected clock — fully unit-testable.
/// </summary>
public sealed class CredentialSweepAggregator
{
    private readonly int _threshold;
    private readonly TimeSpan _window;
    private readonly object _lock = new();
    private readonly Dictionary<string, List<(string ruleId, DateTimeOffset at)>> _events = new();
    private readonly Dictionary<string, DateTimeOffset> _lastFired = new();

    public CredentialSweepAggregator(int distinctThreshold = 4, int windowSeconds = 60)
    {
        _threshold = Math.Max(2, distinctThreshold);
        _window = TimeSpan.FromSeconds(Math.Max(5, windowSeconds));
    }

    /// <summary>
    /// Records a credential-rule hit for the given harness tree. Returns the distinct rule-id set when this
    /// observation just crossed the threshold inside the window (caller fires a Critical sweep alert); else
    /// null. At most one fire per window per tree.
    /// </summary>
    public IReadOnlyCollection<string>? Observe(string treeKey, string ruleId, DateTimeOffset now)
    {
        lock (_lock)
        {
            if (!_events.TryGetValue(treeKey, out var list))
            {
                list = [];
                _events[treeKey] = list;
            }

            list.Add((ruleId, now));
            list.RemoveAll(e => now - e.at > _window);

            var distinct = list.Select(e => e.ruleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (distinct.Count < _threshold) return null;

            if (_lastFired.TryGetValue(treeKey, out var last) && now - last < _window) return null;
            _lastFired[treeKey] = now;
            return distinct;
        }
    }
}
