using Foreman.Core.ComputerUse;
using Foreman.Core.Security;

namespace Foreman.App.ComputerUse;

/// <summary>
/// Formats a <see cref="CuAction"/>'s INPUT into a short, human-readable line for the HUD's blue input row - what the
/// driving harness is actually typing/keying/clicking. Typed text is run through <see cref="SecretRedactor"/> first, so
/// a secret-shaped string (token/key/password-ish) is shown redacted rather than painted on the operator's screen.
/// </summary>
internal static class CuInputDescription
{
    public static string Of(CuAction a)
    {
        var verb = (a.Verb ?? string.Empty).Trim().ToLowerInvariant();
        return verb switch
        {
            "type"          => "type  " + Trunc(SecretRedactor.Redact(a.Arg("text") ?? string.Empty), 64),
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

    // Render a key + its modifiers as a chord, e.g. "Ctrl+L", "Enter", "Ctrl+Shift+F4".
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
        parts.Add(ushort.TryParse(vk, out var code) ? KeyName(code) : vk ?? "?");
        return string.Join("+", parts);
    }

    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    private static string KeyName(ushort vk) => vk switch
    {
        0x08 => "Backspace", 0x09 => "Tab", 0x0D => "Enter", 0x1B => "Esc", 0x20 => "Space",
        0x25 => "Left", 0x26 => "Up", 0x27 => "Right", 0x28 => "Down",
        0x2E => "Delete", 0x24 => "Home", 0x23 => "End", 0x21 => "PgUp", 0x22 => "PgDn",
        >= 0x70 and <= 0x7B => "F" + (vk - 0x6F),     // F1..F12
        >= 0x30 and <= 0x39 => ((char)vk).ToString(), // 0..9
        >= 0x41 and <= 0x5A => ((char)vk).ToString(), // A..Z
        _ => "VK_" + vk,
    };
}
