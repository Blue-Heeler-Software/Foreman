using System.Text;
using System.Text.RegularExpressions;

namespace Foreman.Core.Integration;

/// <summary>
/// One-click "connect Codex to Foreman Agent Safety": writes Foreman Agent Safety's streamable-HTTP MCP
/// server into Codex's user config (<c>~/.codex/config.toml</c>) and adds a
/// bounded Foreman Agent Safety section to <c>~/.codex/AGENTS.md</c>.
///
/// Codex stores MCP servers as TOML tables under <c>[mcp_servers.&lt;name&gt;]</c>.
/// This helper only owns the <c>foreman</c> table, preserves unrelated config,
/// and backs up the original file before writing.
/// </summary>
public static class CodexMcpConnector
{
    private const string SectionName = "mcp_servers.foreman";
    private const string AgentsBeginMarker = "<!-- foreman-mcp:begin -->";
    private const string AgentsEndMarker = "<!-- foreman-mcp:end -->";

    public static string DefaultConfigPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".codex",
            "config.toml");

    public static string DefaultAgentsPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".codex",
            "AGENTS.md");

    public static string Url(int port) => $"http://localhost:{port}/mcp";

    public static string BuildConfigSnippet(int port, string token) =>
        BuildSection(port, token).TrimEnd();

    public static string BuildAgentsInstructions() =>
        $"""
        {AgentsBeginMarker}
        ## Foreman Agent Safety MCP Monitor

        When the `foreman` MCP server is available:

        - Identify this agent as `harnessId: "codex"` when Foreman Agent Safety tools accept a harness id.
        - At the start of a new task, call `report_task_start(taskDescription, harnessId: "codex")`.
        - If `foreman_status` or `report_task_start` reports `pendingAskHarnessRequests`, call `list_ask_harness_requests(harnessId: "codex")`.
        - For each pending request addressed to Codex (Ask Harness or queued audit prompt), answer with `reply_to_ask_harness_request(requestId, response, actionTaken, harnessId: "codex")`.
        - Treat each request as a safety prompt: explain what happened, whether it was expected, and any corrective action you took or recommend.

        {AgentsEndMarker}
        """;

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

    public static ConnectResult Connect(
        int port,
        string token,
        string? configPath = null,
        string? agentsPath = null)
    {
        var path = configPath ?? DefaultConfigPath;
        try
        {
            var bytes = File.Exists(path) ? File.ReadAllBytes(path) : [];
            var hadBom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
            var original = bytes.Length == 0
                ? ""
                : new UTF8Encoding(false).GetString(hadBom ? bytes[3..] : bytes);

            // Respect a user who already set up the more secure bearer_token_env_var form for this port.
            // Do not silently overwrite it with a plaintext inline token (IsConfigured accepts both forms).
            var existingSection = ExtractForemanSection(original);
            if (existingSection is not null &&
                HasAssignment(existingSection, "url", Url(port)) &&
                Regex.IsMatch(existingSection, @"(?im)^\s*bearer_token_env_var\s*=\s*""[^""]+""\s*(?:#.*)?$"))
            {
                var secureEntryMessage =
                    "Codex already has a foreman entry using bearer_token_env_var for this port - left it " +
                    "unchanged (the more secure form). Update that environment variable to rotate the token.";

                return new ConnectResult(
                    ConnectStatus.Updated,
                    AppendAgentsNote(secureEntryMessage, agentsPath ?? DefaultAgentsPath),
                    null);
            }

            // Preserve the file's own newline + BOM so a one-click connect only changes the foreman table,
            // not the whole file's encoding (avoids noisy LF/CRLF or BOM diffs under git).
            var newline = original.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
            var updated = UpsertForemanSection(original, port, token, newline, out var existed);

            string? backup = null;
            if (bytes.Length > 0)
            {
                backup = path + ".foreman-bak";
                File.WriteAllBytes(backup, bytes);   // verbatim copy preserves the original's exact bytes
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, updated, new UTF8Encoding(encoderShouldEmitUTF8Identifier: hadBom));

            var message = existed
                ? "Updated the existing foreman MCP entry in Codex's config."
                : "Added a user-scope foreman MCP entry to Codex's config.";

            return new ConnectResult(
                existed ? ConnectStatus.Updated : ConnectStatus.Added,
                AppendAgentsNote(message, agentsPath ?? DefaultAgentsPath),
                backup);
        }
        catch (Exception ex)
        {
            return new ConnectResult(ConnectStatus.Failed, ex.Message);
        }
    }

    private static string UpsertForemanSection(string original, int port, string token, string newline, out bool existed)
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

        return string.Join(newline, lines).TrimEnd() + newline;
    }

    private static string BuildSection(int port, string token) =>
        $"[{SectionName}]\n" +
        $"url = \"{TomlEscape(Url(port))}\"\n" +
        $"http_headers = {{ Authorization = \"Bearer {TomlEscape(token)}\" }}\n" +
        "enabled = true\n";

    private static string AppendAgentsNote(string message, string agentsPath)
    {
        TryUpsertAgentsInstructions(
            agentsPath,
            out var agentsBackup,
            out var agentsChanged,
            out var agentsError);

        if (agentsError is not null)
            return message + $" Codex config is ready, but Foreman Agent Safety couldn't update AGENTS.md: {agentsError}";

        if (!agentsChanged)
            return message + " Foreman Agent Safety's Codex instructions in AGENTS.md were already current.";

        message += " Added/updated Foreman Agent Safety's Codex instructions in AGENTS.md.";
        if (agentsBackup is not null)
            message += $" AGENTS backup saved: {agentsBackup}";
        return message;
    }

    private static bool TryUpsertAgentsInstructions(
        string agentsPath,
        out string? backupPath,
        out bool changed,
        out string? error)
    {
        backupPath = null;
        changed = false;
        error = null;

        try
        {
            var original = File.Exists(agentsPath) ? File.ReadAllText(agentsPath) : "";
            var newline = original.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
            var desired = BuildAgentsInstructions().Replace("\r\n", "\n").Replace("\n", newline).TrimEnd();
            var updated = UpsertMarkedBlock(original, desired, newline);

            if (string.Equals(original, updated, StringComparison.Ordinal))
                return true;

            if (original.Length > 0)
            {
                backupPath = agentsPath + ".foreman-bak";
                File.WriteAllText(backupPath, original, new UTF8Encoding(false));
            }

            Directory.CreateDirectory(Path.GetDirectoryName(agentsPath)!);
            File.WriteAllText(agentsPath, updated, new UTF8Encoding(false));
            changed = true;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static string UpsertMarkedBlock(string original, string block, string newline)
    {
        var normalized = original.Replace("\r\n", "\n").Replace('\r', '\n');
        var normalizedBlock = block.Replace("\r\n", "\n").Replace('\r', '\n').TrimEnd();
        var begin = normalized.IndexOf(AgentsBeginMarker, StringComparison.Ordinal);
        var end = normalized.IndexOf(AgentsEndMarker, StringComparison.Ordinal);

        string updated;
        if (begin >= 0 && end > begin)
        {
            end += AgentsEndMarker.Length;
            updated = normalized[..begin].TrimEnd() + "\n\n" + normalizedBlock + "\n\n" + normalized[end..].TrimStart();
        }
        else
        {
            updated = normalized.TrimEnd();
            if (updated.Length > 0)
                updated += "\n\n";
            updated += normalizedBlock + "\n";
        }

        return updated.Replace("\n", newline);
    }

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
                '"' => "\\\"",
                '\b' => "\\b",
                '\t' => "\\t",
                '\n' => "\\n",
                '\f' => "\\f",
                '\r' => "\\r",
                _ => c,
            });
        }

        return sb.ToString();
    }
}
