// Alias avoids the Foreman.McpServer namespace shadowing ModelContextProtocol.Server.McpServer
using McpServerType = global::ModelContextProtocol.Server.McpServer;
using System.Collections.Concurrent;
using ModelContextProtocol.Protocol;

namespace Foreman.McpServer;

/// <summary>A connected MCP client's self-announced identity and the capabilities it advertised.</summary>
public sealed record McpClientInfo(string Name, string? Version, bool Sampling, bool Elicitation);

/// <summary>How an "Ask Harness" request to the offender's own session was delivered.</summary>
public enum AskOutcome { Sampled, Notified, NoSession }

/// <summary>
/// Result of asking the offending harness to justify/act. <see cref="ReplyText"/> is non-null only
/// for <see cref="AskOutcome.Sampled"/> (a true round-trip); for a notification it's fire-and-forget.
/// </summary>
public sealed record AskOffenderResult(AskOutcome Outcome, string? ReplyText, string? MatchedClient, string? RequestId = null);

/// <summary>
/// Tracks live MCP SSE sessions and broadcasts server-initiated notifications
/// (notifications/message) to all connected clients.
/// </summary>
public sealed class SseSessionManager
{
    private sealed record Entry(McpServerType Server, DateTimeOffset At);
    private readonly ConcurrentDictionary<string, Entry> _sessions = new();
    // These are short-lived per-request transport sessions; a disconnect that doesn't Unregister leaks an entry, so
    // an entry older than this is almost certainly dead -> reaped. MaxSessions hard-caps a runaway leak (and the
    // broadcast amplification / dashboard inflation it caused: 241 live entries vs 3 real clients).
    private static readonly TimeSpan StaleTtl = TimeSpan.FromMinutes(15);
    private const int MaxSessions = 128;

    // Sticky activity, keyed by harness id (from the authenticated token). These clients use short-lived
    // per-request MCP sessions, so the live _sessions set reads ~0 between calls — the dashboard would flicker
    // "No MCP"/"restart to link" even for a connected, working agent. MarkSeen records each authenticated
    // request so the UI can treat a harness that has talked to Foreman within a TTL as connected.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recent = new(StringComparer.OrdinalIgnoreCase);

    public int Count { get { Prune(); return _sessions.Count; } }

    // Reap leaked (long-stale) registrations; bounded O(n) with MaxSessions, so cheap to call on every access.
    private void Prune()
    {
        var cutoff = DateTimeOffset.UtcNow - StaleTtl;
        foreach (var kv in _sessions)
            if (kv.Value.At < cutoff) _sessions.TryRemove(kv.Key, out _);
    }

    /// <summary>Record that an authenticated request from this harness just arrived (drives sticky "connected").</summary>
    public void MarkSeen(string? harnessId)
    {
        if (!string.IsNullOrWhiteSpace(harnessId))
            _recent[harnessId] = DateTimeOffset.UtcNow;
    }

    /// <summary>Harness ids that made an authenticated MCP request within <paramref name="ttl"/>; prunes older entries.</summary>
    public IReadOnlyCollection<string> RecentlyActiveHarnessIds(TimeSpan ttl)
    {
        var cutoff = DateTimeOffset.UtcNow - ttl;
        foreach (var kv in _recent)
            if (kv.Value < cutoff) _recent.TryRemove(kv.Key, out _);
        return _recent.Keys.ToArray();
    }

    /// <summary>Registers a connected session. Returns the session key for later unregistration.</summary>
    public string Register(McpServerType server)
    {
        Prune();
        // Bound a registration leak: if we're at the cap after pruning, evict the oldest entry.
        if (_sessions.Count >= MaxSessions)
        {
            var oldest = _sessions.OrderBy(kv => kv.Value.At).FirstOrDefault();
            if (oldest.Key is not null) _sessions.TryRemove(oldest.Key, out _);
        }
        var id = Guid.NewGuid().ToString("N")[..8];
        _sessions[id] = new Entry(server, DateTimeOffset.UtcNow);
        return id;
    }

    public void Unregister(string id) => _sessions.TryRemove(id, out _);

    /// <summary>
    /// Snapshot of every connected client's announced identity + capabilities. Used by the dashboard
    /// to show which agents are connected and whether each supports the sampling round-trip that makes
    /// Ask Harness a true poll (vs. a one-way notification).
    /// </summary>
    public IReadOnlyList<McpClientInfo> DescribeSessions()
    {
        Prune();
        return _sessions.Values.Select(e => e.Server).Select(s => new McpClientInfo(
            ClientLabel(s) ?? "unknown client",
            s.ClientInfo?.Version,
            s.ClientCapabilities?.Sampling is not null,
            s.ClientCapabilities?.Elicitation is not null)).ToList();
    }

    /// <summary>
    /// Pushes notifications/message to every currently-connected MCP client.
    /// Failures on individual sessions are swallowed so a dead client can't block others.
    /// </summary>
    public async Task BroadcastNotificationAsync(string level, string logger, object data)
    {
        Prune();
        if (_sessions.IsEmpty) return;

        var tasks = _sessions.Values.Select(e => e.Server).Select(server =>
            server.SendNotificationAsync("notifications/message", new { level, logger, data })
                  .ContinueWith(t => { /* swallow per-client errors */ }, TaskScheduler.Default));

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    /// <summary>
    /// "Ask Harness": deliver a justify/act prompt to the OFFENDING harness's own session, by the
    /// highest-fidelity channel available. Ladder:
    ///   1. <b>Sampling round-trip</b> — if a matching session advertises the sampling capability,
    ///      ask its model and return the reply (a true poll).
    ///   2. <b>Targeted notification</b> — else push the prompt into matching session(s) fire-and-forget.
    ///   3. <b>NoSession</b> — the offender isn't connected to Foreman's MCP; caller falls back to clipboard.
    /// Session→harness matching is by the client's self-announced name (advisory only, never auth).
    /// </summary>
    public async Task<AskOffenderResult> AskOffenderAsync(
        string harnessId,
        string systemPrompt,
        string userPrompt,
        string? requestId = null,
        CancellationToken ct = default)
    {
        var matches = _sessions.Values.Select(e => e.Server)
            .Where(s => MatchesHarness(s.ClientInfo?.Name, s.ClientInfo?.Title, harnessId))
            .ToList();

        // 1) true round-trip via sampling, on the first matching session that supports it
        var sampler = matches.FirstOrDefault(s => s.ClientCapabilities?.Sampling is not null);
        if (sampler is not null)
        {
            try
            {
                var req = new CreateMessageRequestParams
                {
                    SystemPrompt = systemPrompt,
                    MaxTokens    = 1000,
                    Messages     = [new SamplingMessage
                    {
                        Role    = Role.User,
                        Content = [new TextContentBlock { Text = userPrompt }],
                    }],
                };
                var res = await sampler.SampleAsync(req, ct).ConfigureAwait(false);
                return new AskOffenderResult(AskOutcome.Sampled, ExtractText(res.Content), ClientLabel(sampler), requestId);
            }
            catch { /* client declined / errored / timed out — degrade to notification */ }
        }

        // 2) targeted, fire-and-forget notification to matching sessions
        if (matches.Count > 0)
        {
            var data = new { type = "ask_harness", harnessId, requestId, prompt = userPrompt };
            var tasks = matches.Select(s =>
                s.SendNotificationAsync("notifications/message", new { level = "warning", logger = "foreman", data })
                 .ContinueWith(_ => { /* swallow per-client errors */ }, TaskScheduler.Default));
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return new AskOffenderResult(AskOutcome.Notified, null, ClientLabel(matches[0]), requestId);
        }

        // 3) offender not connected to Foreman's MCP
        return new AskOffenderResult(AskOutcome.NoSession, null, null, requestId);
    }

    private static string? ClientLabel(McpServerType s) =>
        !string.IsNullOrWhiteSpace(s.ClientInfo?.Title) ? s.ClientInfo!.Title : s.ClientInfo?.Name;

    private static string? ExtractText(IList<ContentBlock>? content)
    {
        if (content is null) return null;
        var joined = string.Join("\n",
            content.OfType<TextContentBlock>().Select(b => b.Text).Where(t => !string.IsNullOrWhiteSpace(t)));
        return string.IsNullOrWhiteSpace(joined) ? null : joined.Trim();
    }

    /// <summary>
    /// Best-effort match of an MCP client's self-announced name/title to a Foreman harness id
    /// (e.g. "Claude Code" ⇄ "claude-code"). Self-declared and not authoritative — multiple
    /// instances of one harness are indistinguishable — so it's used only for advisory delivery,
    /// never for authorization.
    /// </summary>
    public static bool MatchesHarness(string? clientName, string? clientTitle, string harnessId)
    {
        var h = Norm(harnessId);
        if (h.Length < 3) return false;
        foreach (var cand in new[] { Norm(clientName), Norm(clientTitle) })
        {
            if (cand.Length < 3) continue;
            // The announced name contains the full harness id ("claudecodemcp" ⊃ "claudecode"), or the
            // harness id BEGINS with the announced name ("claudecode" starts with "claude"). Prefix —
            // not substring — on the second case, so a generic "code" can't match opencode/t3-code.
            if (cand.Contains(h) || h.StartsWith(cand)) return true;
        }
        return false;
    }

    private static string Norm(string? s) =>
        new string((s ?? "").Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
}
