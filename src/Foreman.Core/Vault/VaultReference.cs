using System.Text.RegularExpressions;

namespace Foreman.Core.Vault;

/// <summary>
/// Parses and rewrites <c>{{vault:ORIGIN/FIELD}}</c> references (e.g. <c>{{vault:github.com/password}}</c>). The
/// reference is all an agent ever sends and all that ever reaches the audit log; the real value is substituted only at
/// the injection boundary by <see cref="VaultResolver"/>. ORIGIN is a host (letters/digits/dot/hyphen, optional :port);
/// FIELD is one of <see cref="VaultField"/>.
/// </summary>
public static partial class VaultReference
{
    // {{vault:github.com/password}} — origin = host[:port], field = a VaultField name (case-insensitive).
    [GeneratedRegex(@"\{\{vault:(?<origin>[A-Za-z0-9.\-]+(?::\d+)?)/(?<field>[A-Za-z]+)\}\}", RegexOptions.CultureInvariant)]
    private static partial Regex Pattern();

    public static bool HasReference(string? text) => !string.IsNullOrEmpty(text) && Pattern().IsMatch(text);

    /// <summary>
    /// Replace every <c>{{vault:o/f}}</c> via <paramref name="resolve"/>. Fail-closed: if any reference has an unknown
    /// field, or <paramref name="resolve"/> returns null, the WHOLE result is null (never a partial fill). A non-null
    /// result is the fully-substituted (sensitive) string.
    /// </summary>
    public static string? Replace(string? text, Func<string, VaultField, string?> resolve)
    {
        if (string.IsNullOrEmpty(text)) return text;
        var failed = false;
        var output = Pattern().Replace(text, m =>
        {
            if (failed) return m.Value;
            if (!Enum.TryParse<VaultField>(m.Groups["field"].Value, ignoreCase: true, out var field))
            { failed = true; return m.Value; }
            var value = resolve(m.Groups["origin"].Value, field);
            if (value is null) { failed = true; return m.Value; }
            return value;
        });
        return failed ? null : output;
    }
}
