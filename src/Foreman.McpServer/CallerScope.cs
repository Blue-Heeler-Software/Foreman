using Microsoft.AspNetCore.Http;

namespace Foreman.McpServer;

/// <summary>
/// The authenticated identity of an MCP caller, resolved from its bearer token by the auth gate and
/// carried in <c>HttpContext.Items</c> so static tool methods can scope by it (via an injected
/// <see cref="IHttpContextAccessor"/>). The raw install token authenticates as the unscoped OPERATOR;
/// a per-harness token scopes the caller to its own harness so it can't read or act on another's data.
/// </summary>
public sealed record CallerScope(string? HarnessId, bool IsOperator)
{
    public const string HttpItemKey = "foreman.caller";

    /// <summary>
    /// Default when no caller is present (non-HTTP / in-process / unit tests): operator. This is safe
    /// because every real MCP tool call passes through the auth gate, which sets the item — a tool is
    /// never reached unauthenticated, so the only null-context path is in-process code we trust.
    /// </summary>
    public static readonly CallerScope OperatorDefault = new(null, true);

    public static CallerScope From(IHttpContextAccessor? http)
        => http?.HttpContext?.Items.TryGetValue(HttpItemKey, out var v) == true && v is CallerScope c
            ? c
            : OperatorDefault;

    /// <summary>True if this caller may see/act on <paramref name="harnessId"/>. Operator: anything. Harness: only itself; unattributable (null) is denied.</summary>
    public bool CanAccess(string? harnessId)
        => IsOperator || (harnessId is not null && string.Equals(harnessId, HarnessId, StringComparison.OrdinalIgnoreCase));

    /// <summary>The harness a non-operator caller is locked to (its own); null for operator (unscoped).</summary>
    public string? ScopeHarness => IsOperator ? null : HarnessId;
}
