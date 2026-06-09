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
    private readonly ConcurrentDictionary<string, McpServerType> _sessions = new();

    public int Count => _sessions.Count;

    /// <summary>Registers a connected session. Returns the session key for later unregistration.</summary>
    public string Register(McpServerType server)
    {
        var id = Guid.NewGuid().ToString("N")[..8];
        _sessions[id] = server;
        return id;
    }

    public void Unregister(string id) => _sessions.TryRemove(id, out _);

    /// <summary>
    /// Snapshot of every connected client's announced identity + capabilities. Used by the dashboard
    /// to show which agents are connected and whether each supports the sampling round-trip that makes
    /// Ask Harness a true poll (vs. a one-way notification).
    /// </summary>
    public IReadOnlyList<McpClientInfo> DescribeSessions() =>
        _sessions.Values.Select(s => new McpClientInfo(
            ClientLabel(s) ?? "unknown client",
            s.ClientInfo?.Version,
            s.ClientCapabilities?.Sampling is not null,
            s.ClientCapabilities?.Elicitation is not null)).ToList();

    /// <summary>
    /// Pushes notifications/message to every currently-connected MCP client.
    /// Failures on individual sessions are swallowed so a dead client can't block others.
    /// </summary>
    public async Task BroadcastNotificationAsync(string level, string logger, object data)
    {
        if (_sessions.IsEmpty) return;

        var tasks = _sessions.Values.Select(server =>
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
        var matches = _sessions.Values
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
