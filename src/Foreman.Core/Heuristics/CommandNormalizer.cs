using System.Text;
using System.Text.RegularExpressions;

namespace Foreman.Core.Heuristics;

/// <summary>
/// Produces a de-obfuscated view of a command line for the heuristic matcher to ALSO check (the raw
/// line is still matched too, so this can only add detections, never drop one). Closes a class of
/// shell-obfuscation bypasses:
///   • cmd caret escapes  — <c>c^u^r^l ^| bash</c>  → <c>curl | bash</c>
///   • PowerShell backtick escapes — <c>i`e`x (i`w`r '…')</c> → <c>iex (iwr '…')</c>
///   • split/odd whitespace — <c>rm   -rf</c> → <c>rm -rf</c>
///   • PowerShell -EncodedCommand — the base64 payload is decoded and appended so the inner command
///     (e.g. an IEX download) is visible to the rules while the original -enc flag still trips win-001.
/// All transforms are linear-time; regexes carry a short timeout.
/// </summary>
public static class CommandNormalizer
{
    private static readonly Regex EncodedCommand = new(
        @"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*?-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+([A-Za-z0-9+/=_-]{16,})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));

    private static readonly Regex Whitespace = new(@"\s+", RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    /// <summary>Returns the de-obfuscated form. Equal to the input when there's nothing to normalize.</summary>
    public static string Normalize(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine)) return commandLine ?? string.Empty;

        var s = DecodeEncodedCommand(commandLine);
        // Drop cmd (^) and PowerShell (`) escape characters — they exist only to break up tokens.
        // Safe on this matching-only copy: the raw line is matched separately, so we never lose a hit.
        s = s.Replace("^", string.Empty).Replace("`", string.Empty);
        s = Whitespace.Replace(s, " ").Trim();
        return s;
    }

    private static string DecodeEncodedCommand(string s)
    {
        Match m;
        try { m = EncodedCommand.Match(s); }
        catch (RegexMatchTimeoutException) { return s; }
        if (!m.Success) return s;

        try
        {
            var b64 = m.Groups[1].Value.Replace('-', '+').Replace('_', '/');
            b64 += (b64.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
            var bytes = Convert.FromBase64String(b64);

            // PowerShell -EncodedCommand is UTF-16LE; fall back to UTF-8 if that yields control junk.
            var decoded = Encoding.Unicode.GetString(bytes);
            if (LooksBinary(decoded)) decoded = Encoding.UTF8.GetString(bytes);
            if (LooksBinary(decoded)) return s;   // not text — leave it

            return s + "  " + decoded;            // append (two spaces) so win-001 still matches the -enc flag
        }
        catch
        {
            return s;   // not valid base64 — nothing to decode
        }
    }

    private static bool LooksBinary(string s)
    {
        foreach (var c in s)
            if (char.IsControl(c) && c is not ('\n' or '\r' or '\t')) return true;
        return false;
    }
}
