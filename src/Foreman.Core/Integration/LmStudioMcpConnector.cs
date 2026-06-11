using System.Text.Json;
using System.Text.Json.Nodes;

namespace Foreman.Core.Integration;

/// <summary>
/// One-click "connect LM Studio to Foreman Agent Safety": writes a <c>foreman</c> entry into LM Studio's
/// <c>~/.lmstudio/mcp.json</c> under <c>mcpServers</c> as a remote server (<c>url</c> + an
/// <c>Authorization: Bearer</c> header — LM Studio's remote-server shape mirrors the common <c>url</c> form,
/// like Cursor; there is deliberately no <c>type</c> field).
///
/// CAVEAT EMPTOR: LM Studio's MCP support is newer and its <c>mcp.json</c> honoring a <c>headers</c> block for
/// remote servers is NOT clearly documented. If a given LM Studio build ignores <c>headers</c>, Foreman's
/// token-gated <c>/mcp</c> endpoint will reject the connection as unauthorized — verify in LM Studio's MCP /
/// Program panel after connecting. Everything else (atomic write, backup, fail-safe parse) is hardened the
/// same as the other connectors; only the headers-support assumption is unverified.
/// </summary>
public static class LmStudioMcpConnector
{
    public static string DefaultConfigPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".lmstudio", "mcp.json");

    public static string Url(int port) => $"http://localhost:{port}/mcp";

    private static JsonObject ServerObject(int port, string token) => new()
    {
        ["url"]     = Url(port),
        ["headers"] = new JsonObject { ["Authorization"] = $"Bearer {token}" },
    };

    private static readonly JsonSerializerOptions _pretty = new() { WriteIndented = true };
    private static readonly JsonDocumentOptions _lenient =
        new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>The full mcpServers wrapper to paste into ~/.lmstudio/mcp.json (merge into mcpServers).</summary>
    public static string BuildConfigSnippet(int port, string token) =>
        new JsonObject { ["mcpServers"] = new JsonObject { ["foreman"] = ServerObject(port, token) } }
            .ToJsonString(_pretty);

    /// <summary>True if mcp.json already has an mcpServers.foreman remote entry for this port with a token.</summary>
    public static bool IsConfigured(int port, string? configPath = null)
    {
        try
        {
            var path = configPath ?? DefaultConfigPath;
            if (!File.Exists(path)) return false;
            var entry = (JsonNode.Parse(File.ReadAllText(path), documentOptions: _lenient) as JsonObject)?["mcpServers"]?["foreman"];
            if (entry is null) return false;
            var url  = entry["url"]?.GetValue<string>();
            var auth = entry["headers"]?["Authorization"]?.GetValue<string>();
            return string.Equals(url, Url(port), StringComparison.OrdinalIgnoreCase)
                   && !string.IsNullOrWhiteSpace(auth);
        }
        catch { return false; }
    }

    /// <summary>
    /// Adds or updates the foreman remote server under mcpServers, preserving every other entry. Backs up the
    /// original and swaps atomically. A malformed existing file fails safely (returns Failed; the user can
    /// copy-paste) rather than being clobbered.
    /// </summary>
    public static ConnectResult Connect(int port, string token, string? configPath = null)
    {
        var path = configPath ?? DefaultConfigPath;
        try
        {
            string original = File.Exists(path) ? File.ReadAllText(path) : "";
            var root = (original.Length > 0 ? JsonNode.Parse(original, documentOptions: _lenient) : new JsonObject()) as JsonObject
                       ?? throw new InvalidOperationException("~/.lmstudio/mcp.json root is not a JSON object.");

            if (root["mcpServers"] is not JsonObject servers)
            {
                servers = new JsonObject();
                root["mcpServers"] = servers;
            }

            var existed = servers["foreman"] is not null;
            servers["foreman"] = ServerObject(port, token);

            string? backup = null;
            if (original.Length > 0)
            {
                backup = path + ".foreman-bak";
                File.WriteAllText(backup, original);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            AtomicWrite(path, root.ToJsonString(_pretty));

            return new ConnectResult(
                existed ? ConnectStatus.Updated : ConnectStatus.Added,
                existed
                    ? "Updated the foreman MCP entry in LM Studio's config (~/.lmstudio/mcp.json)."
                    : "Added a foreman MCP entry to LM Studio's config (~/.lmstudio/mcp.json).",
                backup);
        }
        catch (Exception ex)
        {
            return new ConnectResult(ConnectStatus.Failed, ex.Message);
        }
    }

    private static void AtomicWrite(string path, string contents)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, contents);
        try
        {
            if (File.Exists(path)) File.Replace(tmp, path, destinationBackupFileName: null);
            else File.Move(tmp, path);
        }
        catch
        {
            File.Copy(tmp, path, overwrite: true);   // AV/indexer lock fallback
            try { File.Delete(tmp); } catch { }
        }
    }
}
