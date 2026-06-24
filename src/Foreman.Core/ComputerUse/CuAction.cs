namespace Foreman.Core.ComputerUse;

/// <summary>Which computer-use surface an action targets.</summary>
public enum CuModality { Browser, Desktop }

/// <summary>How a DESKTOP CU action is isolated from the operator's own input/screen (spec Slice 7).
/// SharedMonopilot = the one real desktop, time-shared (re-skinned cursor); IsolatedDesktop = the AI's own Win32
/// desktop object; IsolatedSession = a separate login session. Default SharedMonopilot.</summary>
public enum CuIsolationMode { SharedMonopilot, IsolatedDesktop, IsolatedSession }

/// <summary>
/// One structured computer/browser-use action an agent asked Foreman to perform, captured BEFORE execution. This is
/// what the auditor judges and the broker logs. Judging structured intent (verb + args) rather than raw pixels is
/// what makes Foreman-mediated CU auditable and cheap. <see cref="Args"/> carries verb-specific fields, e.g.
/// "url", "text", "selector", "fieldType", "key".
/// </summary>
public sealed record CuAction(
    CuModality Modality,
    string Verb,
    IReadOnlyDictionary<string, string> Args,
    string? ByHarness = null,
    string? ActionId = null,
    string? SessionId = null,
    CuIsolationMode Isolation = CuIsolationMode.SharedMonopilot)
{
    /// <summary>Arg value or empty string (never null) for projection/heuristics.</summary>
    public string Arg(string key) => Args.TryGetValue(key, out var v) ? v ?? string.Empty : string.Empty;
}

/// <summary>
/// Verb classification for the audit pipeline. Read-only verbs (read/screenshot/scroll/…) never need the expensive
/// deep judge; everything else — including any UNKNOWN verb — is treated as state-changing, the safe default.
/// </summary>
public static class CuVerbs
{
    private static readonly HashSet<string> ReadOnly = new(StringComparer.OrdinalIgnoreCase)
    {
        "read", "screenshot", "scroll", "move", "status", "snapshot", "get_text", "list_tabs", "tabs",
    };

    // Trim + case-insensitive so the classification is correct regardless of which path constructs the action
    // (the MCP submit path normalizes, but a future desktop sidecar / direct caller might not).
    public static bool IsStateChanging(string? verb) => !ReadOnly.Contains((verb ?? string.Empty).Trim());

    // Cursor-moving verbs are READ-ONLY for the audit pipeline (no state change) but they still LEAVE the confined
    // window, so the desktop one-window gate treats them as gated: a bare move/scroll to another window is an
    // excursion, not a free pass (spec Slice 1, Critical #1).
    private static readonly HashSet<string> CursorMoving = new(StringComparer.OrdinalIgnoreCase)
    {
        "move", "scroll", "drag", "mouse_move", "left_click_drag",
    };

    public static bool IsCursorMoving(string? verb) => CursorMoving.Contains((verb ?? string.Empty).Trim());

    // The ONLY verbs a DESKTOP action may carry. An unknown or over-length verb is rejected at the broker before it can
    // reach the auditor or the injector (defense in depth - the injector also rejects unknown verbs), so a crafted verb
    // from a relayed agent proposal cannot smuggle through.
    // Aligned with what CuInputInjector actually executes (move/left_click/right_click/middle_click/scroll/key/type)
    // plus the read-only capture verbs. Anything else is rejected at the broker (the injector also rejects unknowns).
    private static readonly HashSet<string> DesktopVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "move", "left_click", "right_click", "middle_click", "scroll", "key", "type",
        "screenshot", "read", "status", "snapshot",
    };

    public static bool IsKnownDesktop(string? verb)
    {
        var v = (verb ?? string.Empty).Trim();
        return v.Length is > 0 and <= 40 && DesktopVerbs.Contains(v);
    }
}
