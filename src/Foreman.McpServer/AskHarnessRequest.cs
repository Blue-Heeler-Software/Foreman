namespace Foreman.McpServer;

/// <summary>
/// Durable hand-off for "Ask Harness" prompts. Server-initiated MCP delivery is best-effort, so
/// harnesses can also poll Foreman for pending prompts and reply through MCP tools.
/// </summary>
public sealed record AskHarnessRequest(
    string RequestId,
    DateTimeOffset CreatedAt,
    string AlertId,
    string HarnessId,
    int? ProcessId,
    string? ProcessName,
    string SystemPrompt,
    string Prompt,
    string Status,
    DateTimeOffset? RepliedAt = null,
    string? ReplyText = null,
    string? ActionTaken = null);
