using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Foreman.Core.Mcp;

/// <summary>
/// Discovers the MCP servers an AI harness is configured to use, by reading its config files.
/// Tier 0: pure config reads — no network, no elevation. Currently understands Claude Code's
/// .claude.json shape and Codex's config.toml MCP tables; structured so other harnesses can be
/// added as more sources.
/// </summary>
public static class McpInventoryScanner
{
    /// <summary>Config files to scan by default, paired with the harness they belong to.</summary>
    public static IEnumerable<(string Path, string Harness)> DefaultSources()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        yield return (Path.Combine(home, ".claude.json"), "claude-code");
        yield return (Path.Combine(home, ".codex", "config.toml"), "codex");
    }

    public static List<McpServerEntry> Scan() => Scan(DefaultSources());

    public static List<McpServerEntry> Scan(IEnumerable<(string Path, string Harness)> sources)
    {
        var found = new List<McpServerEntry>();
        foreach (var (path, harness) in sources)
        {
            if (!File.Exists(path)) continue;
            try
            {
                var text = File.ReadAllText(path);
                found.AddRange(string.Equals(harness, "codex", StringComparison.OrdinalIgnoreCase)
                    ? ParseCodexToml(text, harness, path)
                    : ParseClaudeJson(text, harness, path));
            }
            catch { /* unreadable / malformed — skip this source */ }
        }
        // A server can appear both globally and under a project; collapse by identity.
        return found.GroupBy(e => e.Key).Select(g => g.First()).ToList();
    }

    /// <summary>Parses Claude Code's .claude.json: top-level "mcpServers" plus "projects.*.mcpServers".</summary>
    public static List<McpServerEntry> ParseClaudeJson(string json, string harness, string sourceFile)
    {
        var list = new List<McpServerEntry>();
        JsonNode? root;
        try { root = JsonNode.Parse(json); }
        catch { return list; }
        if (root is null) return list;

        AddServers(list, root["mcpServers"], harness, "global", sourceFile);

        if (root["projects"] is JsonObject projects)
            foreach (var project in projects)
                AddServers(list, project.Value?["mcpServers"], harness, project.Key, sourceFile);

        return list;
    }

    /// <summary>Parses Codex config.toml MCP tables: [mcp_servers.name].</summary>
    public static List<McpServerEntry> ParseCodexToml(string toml, string harness, string sourceFile)
    {
        var list = new List<McpServerEntry>();
        var lines = toml.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');

        string? name = null;
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        void Flush()
        {
            if (string.IsNullOrWhiteSpace(name)) return;

            values.TryGetValue("url", out var url);
            values.TryGetValue("command", out var command);
            values.TryGetValue("args", out var args);

            var transport = !string.IsNullOrWhiteSpace(url)
                ? "http"
                : !string.IsNullOrWhiteSpace(command)
                    ? "stdio"
                    : "unknown";

            var target = !string.IsNullOrWhiteSpace(url)
                ? url
                : !string.IsNullOrWhiteSpace(command)
                    ? (command + " " + args).Trim()
                    : "";

            list.Add(new McpServerEntry(harness, name, transport, target, "global", sourceFile));
        }

        for (var i = 0; i < lines.Length; i++)
        {
            var raw = lines[i];
            if (TryGetTomlHeader(raw, out var header))
            {
                Flush();
                values.Clear();
                name = TryGetCodexMcpServerName(header);
                continue;
            }

            if (name is null) continue;

            // Join multi-line arrays / inline tables onto one logical line so the value isn't lost.
            // TOML lets arrays span lines:  args = [\n  "-y",\n  "@scope/server"\n]
            var combined = raw;
            var guard = 0;
            while (UnclosedBracketDepth(combined) > 0 && i + 1 < lines.Length && guard++ < 500)
            {
                if (TryGetTomlHeader(lines[i + 1], out _)) break;   // never swallow the next table on malformed input
                combined += " " + lines[++i].Trim();
            }

            if (TryGetTomlAssignment(combined, out var key, out var value))
                values[key] = value;
        }

        Flush();
        return list;
    }

    private static void AddServers(List<McpServerEntry> list, JsonNode? mcpServers, string harness, string scope, string sourceFile)
    {
        if (mcpServers is not JsonObject servers) return;

        foreach (var kv in servers)
        {
            var cfg     = kv.Value;
            var type    = Str(cfg?["type"])?.ToLowerInvariant();
            var url     = Str(cfg?["url"]);
            var command = Str(cfg?["command"]);

            var transport = type
                ?? (!string.IsNullOrEmpty(url) ? "http"
                    : !string.IsNullOrEmpty(command) ? "stdio"
                    : "unknown");

            string target;
            if (!string.IsNullOrEmpty(url))
            {
                target = url;
            }
            else if (!string.IsNullOrEmpty(command))
            {
                var args = (cfg?["args"] as JsonArray)?.Select(a => Str(a) ?? "").Where(s => s.Length > 0)
                           ?? Enumerable.Empty<string>();
                target = (command + " " + string.Join(" ", args)).Trim();
            }
            else
            {
                target = "";
            }

            list.Add(new McpServerEntry(harness, kv.Key, transport, target, scope, sourceFile));
        }
    }

    private static string? Str(JsonNode? node)
    {
        try { return node?.GetValue<string>(); }
        catch { return null; }   // value wasn't a string
    }

    private static bool TryGetTomlHeader(string line, out string header)
    {
        header = "";
        var match = Regex.Match(line, @"^\s*\[([^\]]+)\]\s*(?:#.*)?$");
        if (!match.Success) return false;
        header = match.Groups[1].Value.Trim();
        return true;
    }

    private static string? TryGetCodexMcpServerName(string header)
    {
        const string prefix = "mcp_servers.";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;

        var name = header[prefix.Length..].Trim();
        if (name.Length == 0 || name.Contains('.')) return null; // child table, e.g. .env or .tools.x

        return name.Trim('"', '\'');
    }

    private static bool TryGetTomlAssignment(string line, out string key, out string value)
    {
        key = "";
        value = "";

        // Capture key + the FULL right-hand side, then strip a trailing comment quote-awarely.
        // A blind `(?:#.*)?` would wrongly cut a `#` living inside a quoted value (e.g. a URL fragment
        // or a token), corrupting the Target and therefore the change-detection dedup key.
        var match = Regex.Match(line, @"^\s*([A-Za-z0-9_\-]+)\s*=\s*(.+)$");
        if (!match.Success) return false;

        key = match.Groups[1].Value;
        value = ParseTomlValue(StripTomlComment(match.Groups[2].Value).Trim());
        return true;
    }

    /// <summary>Strips a trailing `# …` comment, but only when the `#` is outside single/double quotes.</summary>
    private static string StripTomlComment(string s)
    {
        var quote = '\0';
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (quote != '\0')
            {
                if (c == quote) quote = '\0';
            }
            else if (c is '"' or '\'')
            {
                quote = c;
            }
            else if (c == '#')
            {
                return s[..i];
            }
        }
        return s;
    }

    /// <summary>Net unclosed `[`/`{` depth, ignoring brackets inside quotes (and stopping at a comment).</summary>
    private static int UnclosedBracketDepth(string s)
    {
        var depth = 0;
        var quote = '\0';
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (quote != '\0')
            {
                if (c == quote) quote = '\0';
                continue;
            }
            switch (c)
            {
                case '"' or '\'': quote = c; break;
                case '[' or '{':  depth++;   break;
                case ']' or '}':  if (depth > 0) depth--; break;
                case '#':         return depth;   // rest of the line is a comment
            }
        }
        return depth;
    }

    private static string ParseTomlValue(string raw)
    {
        if (raw.StartsWith('['))
            return string.Join(" ", Regex.Matches(raw, "\"((?:\\\\.|[^\"])*)\"")
                .Select(m => UnescapeTomlString(m.Groups[1].Value)));

        if (raw.Length >= 2 && raw[0] == '"' && raw[^1] == '"')
            return UnescapeTomlString(raw[1..^1]);

        if (raw.Length >= 2 && raw[0] == '\'' && raw[^1] == '\'')
            return raw[1..^1];

        return raw;
    }

    private static string UnescapeTomlString(string value) =>
        value
            .Replace("\\\"", "\"", StringComparison.Ordinal)
            .Replace("\\\\", "\\", StringComparison.Ordinal)
            .Replace("\\n", "\n", StringComparison.Ordinal)
            .Replace("\\r", "\r", StringComparison.Ordinal)
            .Replace("\\t", "\t", StringComparison.Ordinal);
}
