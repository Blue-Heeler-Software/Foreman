using System.Text.RegularExpressions;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// CU-specific deterministic checks the generic command pattern library doesn't cover — the highest-value
/// browser/desktop threats judged directly from the structured action. Returns the concern, or null when clean.
/// </summary>
public static class CuHeuristics
{
    private const string Src = "fast-path:cu";

    // javascript:/data:/vbscript:/file: "navigations" are local exfil or script injection, never a normal page visit.
    private static readonly Regex DangerousScheme = new(
        @"^\s*(?:javascript|data|vbscript|file)\s*:",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    public static CuVerdict? Evaluate(CuAction a)
    {
        // An AI typing into a password / credential field is a prohibited action — hold for the operator to do it.
        if (string.Equals(a.Verb, "type", StringComparison.OrdinalIgnoreCase))
        {
            var field = a.Arg("fieldType");
            if (field.Contains("password", StringComparison.OrdinalIgnoreCase)
                || field.Contains("credential", StringComparison.OrdinalIgnoreCase))
                return CuVerdict.Hold(Src,
                    "typing into a password/credential field — an agent must not enter credentials");
        }

        // Dangerous navigation schemes.
        if (string.Equals(a.Verb, "navigate", StringComparison.OrdinalIgnoreCase))
        {
            var url = a.Arg("url");
            try
            {
                if (DangerousScheme.IsMatch(url))
                    return CuVerdict.Block(Src, $"navigation to a dangerous URL scheme: {Trim(url)}");
            }
            catch (RegexMatchTimeoutException) { /* treat as no match */ }
        }

        return null;
    }

    private static string Trim(string s) => s.Length <= 80 ? s : s[..80] + "…";
}
