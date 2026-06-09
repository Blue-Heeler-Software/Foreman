using System.Text;
using System.Text.RegularExpressions;

namespace Foreman.Core.Integration;

/// <summary>
/// One-click "connect Codex to Foreman": writes Foreman's streamable-HTTP MCP
/// server into Codex's user config (<c>~/.codex/config.toml</c>).
///
/// Codex stores MCP servers as TOML tables under <c>[mcp_servers.&lt;name&gt;]</c>.
/// This helper only owns the <c>foreman</c> table, preserves unrelated config,
/// and backs up the original file before writing.
/// </summary>
public static class CodexMcpConnector
{
    private const string SectionName = "mcp_servers.foreman";

    public static string DefaultConfigPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".codex",
            "config.toml");

    public static string Url(int port) => $"http://localhost:{port}/mcp";

    public static string BuildConfigSnippet(int port, string token) =>
        BuildSection(port, token).TrimEnd();

    public static bool IsConfigured(int port, string? configPath = null)
    {
        try
        {
            var path = configPath ?? DefaultConfigPath;
            if (!File.Exists(path)) return false;

            var section = ExtractForemanSection(File.ReadAllText(path));
            if (section is null) return false;

            return HasAssignment(section, "url", Url(port)) &&
                   (HasInlineAuthorizationHeader(section) ||
                    Regex.IsMatch(section, @"(?im)^\s*bearer_token_env_var\s*=\s*""[^""]+""\s*(?:#.*)?$"));
        }
        catch
        {
            return false;
        }
    }

    public static ConnectResult Connect(int port, string token, string? configPath = null)
    {
        var path = configPath ?? DefaultConfigPath;
        try
        {
            var original = File.Exists(path) ? File.ReadAllText(path) : "";
            var updated = UpsertForemanSection(original, port, token, out var existed);

            string? backup = null;
            if (original.Length > 0)
            {
                backup = path + ".foreman-bak";
                File.WriteAllText(backup, original);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, updated);

            return new ConnectResult(
                existed ? ConnectStatus.Updated : ConnectStatus.Added,
                existed
                    ? "Updated the existing foreman MCP entry in Codex's config."
                    : "Added a user-scope foreman MCP entry to Codex's config.",
                backup);
        }
        catch (Exception ex)
        {
            return new ConnectResult(ConnectStatus.Failed, ex.Message);
        }
    }

    private static string UpsertForemanSection(string original, int port, string token, out bool existed)
    {
        var lines = NormalizeLines(original);
        if (lines.Count == 1 && lines[0].Length == 0)
            lines.Clear();

        var range = FindForemanSectionRange(lines);
        var section = BuildSection(port, token).TrimEnd().Split('\n');

        existed = range is not null;
        if (range is { } r)
        {
            lines.RemoveRange(r.Start, r.EndExclusive - r.Start);
            lines.InsertRange(r.Start, section);
        }
        else
        {
            if (lines.Count > 0 && !string.IsNullOrWhiteSpace(lines[^1]))
                lines.Add("");
            lines.AddRange(section);
        }

        return string.Join(Environment.NewLine, lines).TrimEnd() + Environment.NewLine;
    }

    private static string BuildSection(int port, string token) =>
        $"[{SectionName}]\n" +
        $"url = \"{TomlEscape(Url(port))}\"\n" +
        $"http_headers = {{ Authorization = \"Bearer {TomlEscape(token)}\" }}\n" +
        "enabled = true\n";

    private static string? ExtractForemanSection(string text)
    {
        var lines = NormalizeLines(text);
        var range = FindForemanSectionRange(lines);
        return range is null
            ? null
            : string.Join("\n", lines.Skip(range.Value.Start).Take(range.Value.EndExclusive - range.Value.Start));
    }

    private static (int Start, int EndExclusive)? FindForemanSectionRange(List<string> lines)
    {
        var start = -1;
        for (var i = 0; i < lines.Count; i++)
        {
            if (IsForemanHeader(lines[i]))
            {
                start = i;
                break;
            }
        }

        if (start < 0) return null;

        var end = lines.Count;
        for (var i = start + 1; i < lines.Count; i++)
        {
            if (!TryGetHeaderName(lines[i], out var header)) continue;
            if (!IsForemanHeaderName(header) && !IsForemanChildHeaderName(header))
            {
                end = i;
                break;
            }
        }

        return (start, end);
    }

    private static bool IsForemanHeader(string line) =>
        TryGetHeaderName(line, out var header) && IsForemanHeaderName(header);

    private static bool IsForemanHeaderName(string header) =>
        string.Equals(NormalizeHeader(header), SectionName, StringComparison.OrdinalIgnoreCase);

    private static bool IsForemanChildHeaderName(string header)
    {
        var normalized = NormalizeHeader(header);
        return normalized.StartsWith(SectionName + ".", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetHeaderName(string line, out string header)
    {
        header = "";
        var match = Regex.Match(line, @"^\s*\[([^\]]+)\]\s*(?:#.*)?$");
        if (!match.Success) return false;
        header = match.Groups[1].Value.Trim();
        return true;
    }

    private static string NormalizeHeader(string header)
    {
        var parts = header.Split('.');
        for (var i = 0; i < parts.Length; i++)
            parts[i] = parts[i].Trim().Trim('"', '\'');
        return string.Join(".", parts);
    }

    private static bool HasAssignment(string section, string key, string value)
    {
        var escaped = Regex.Escape(value);
        return Regex.IsMatch(
            section,
            $@"(?im)^\s*{Regex.Escape(key)}\s*=\s*""{escaped}""\s*(?:#.*)?$");
    }

    private static bool HasInlineAuthorizationHeader(string section) =>
        Regex.IsMatch(
            section,
            @"(?ims)^\s*http_headers\s*=\s*\{[^}]*Authorization\s*=\s*""Bearer\s+[^""]+""[^}]*\}\s*(?:#.*)?$");

    private static List<string> NormalizeLines(string text) =>
        text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n').ToList();

    private static string TomlEscape(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            sb.Append(c switch
            {
                '\\' => "\\\\",
                '"'  => "\\\"",
                '\b' => "\\b",
                '\t' => "\\t",
                '\n' => "\\n",
                '\f' => "\\f",
                '\r' => "\\r",
                _    => c,
            });
        }

        return sb.ToString();
    }
}
