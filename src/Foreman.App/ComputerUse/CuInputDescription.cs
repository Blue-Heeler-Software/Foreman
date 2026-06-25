using System.Text;
using System.Windows.Automation;
using Foreman.Core.ComputerUse;
using Foreman.Core.Security;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Formats a <see cref="CuAction"/>'s INPUT for the HUD's blue row - the keys / macros / typed text the driving harness
/// is sending. Defense-in-depth against painting a SECRET on the persistent, screen-shareable HUD:
///   1. if the focused control is a PASSWORD / credential field (UIA IsPassword), the whole row is hidden;
///   2. a printable single key WITHOUT a modifier (plain typing) is masked to a dot - only macros (Ctrl+L) and named
///      keys (Enter/Tab/F4/arrows) show, so a password typed char-by-char never paints a glyph;
///   3. typed text is run through <see cref="SecretRedactor"/> (catches token shapes) and stripped of control / bidi
///      characters (no spoofing or layout-break), truncated on a safe boundary.
/// This is best-effort, NOT a guarantee a bare password never appears - the credential-field hide (1) is the real guard;
/// SecretRedactor is a shape matcher and won't catch an arbitrary password typed into a non-credential field.
/// </summary>
internal static class CuInputDescription
{
    public static string Of(CuAction a)
    {
        if (IsCredentialFieldFocused()) return "(input hidden — credential field)";
        var verb = (a.Verb ?? string.Empty).Trim().ToLowerInvariant();
        return verb switch
        {
            "type"          => "type  " + Trunc(Sanitize(SecretRedactor.Redact(a.Arg("text") ?? string.Empty)), 64),
            "key"           => "keys  " + Chord(a.Arg("vk"), a.Arg("mods")),
            "left_click"    => "mouse  left-click",
            "right_click"   => "mouse  right-click",
            "middle_click"  => "mouse  middle-click",
            "double_click"  => "mouse  double-click",
            "scroll"        => "mouse  scroll " + a.Arg("amount"),
            "move" or "mouse_move" => "mouse  move",
            _               => verb,
        };
    }

    // True if the system-focused control is a password/credential field - i.e. input is about to be typed into a secret.
    private static bool IsCredentialFieldFocused()
    {
        try { return AutomationElement.FocusedElement?.Current.IsPassword == true; }
        catch { return false; }   // UIA unavailable -> rely on the single-key mask + SecretRedactor
    }

    // Render a key + its modifiers as a chord, e.g. "Ctrl+L", "Enter", "Ctrl+Shift+F4". A printable single key WITHOUT a
    // modifier is plain typing -> masked to a dot (so char-by-char secret entry never paints a glyph); WITH a modifier
    // it's a macro/shortcut, shown in full (transparency, not secret content).
    private static string Chord(string? vk, string? mods)
    {
        var parts = new List<string>();
        foreach (var m in (mods ?? string.Empty).Split(new[] { ',', ' ', '+' }, StringSplitOptions.RemoveEmptyEntries))
            parts.Add(m.Trim().ToLowerInvariant() switch
            {
                "ctrl" or "control" => "Ctrl",
                "alt" or "menu"     => "Alt",
                "shift"             => "Shift",
                "win" or "lwin"     => "Win",
                _                   => m.Trim(),
            });
        var hasMods = parts.Count > 0;
        var code = ushort.TryParse(vk, out var c) ? c : (ushort)0;
        var name = !hasMods && IsPrintableSingle(code) ? "·" : code != 0 ? KeyName(code) : vk ?? "?";
        parts.Add(name);
        return string.Join("+", parts);
    }

    private static bool IsPrintableSingle(ushort vk) => vk is (>= 0x30 and <= 0x39) or (>= 0x41 and <= 0x5A);

    // Strip control + bidi-format chars (no U+202E spoofing, no newline layout-break) and replace whitespace breaks.
    private static string Sanitize(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            if (ch is '\r' or '\n' or '\t') { sb.Append(' '); continue; }
            if (char.IsControl(ch)) continue;
            if (ch is (>= '‪' and <= '‮') or (>= '⁦' and <= '⁩') or '‎' or '‏') continue;  // bidi
            sb.Append(ch);
        }
        return sb.ToString();
    }

    private static string Trunc(string s, int n)
    {
        if (s.Length <= n) return s;
        var cut = char.IsHighSurrogate(s[n - 1]) ? n - 1 : n;   // never split a surrogate pair
        return s[..cut] + "…";
    }

    private static string KeyName(ushort vk) => vk switch
    {
        0x08 => "Backspace", 0x09 => "Tab", 0x0D => "Enter", 0x1B => "Esc", 0x20 => "Space",
        0x25 => "Left", 0x26 => "Up", 0x27 => "Right", 0x28 => "Down",
        0x2E => "Delete", 0x24 => "Home", 0x23 => "End", 0x21 => "PgUp", 0x22 => "PgDn",
        >= 0x70 and <= 0x7B => "F" + (vk - 0x6F),     // F1..F12
        >= 0x30 and <= 0x39 => ((char)vk).ToString(), // 0..9 (only reached WITH a modifier, e.g. Ctrl+1)
        >= 0x41 and <= 0x5A => ((char)vk).ToString(), // A..Z (only reached WITH a modifier, e.g. Ctrl+L)
        _ => "VK_" + vk,
    };
}
