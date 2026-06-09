using System.Security.Cryptography;
using System.Text;

namespace Foreman.McpServer;

/// <summary>
/// A stable, per-install bearer token that gates the MCP HTTP endpoint.
///
/// The MCP server binds to localhost, but "localhost" is not an authorization boundary on a
/// shared machine - any process or a browser via a forged request can reach it. Requiring a
/// secret token means a caller must be able to read the token file under the user's profile,
/// which a browser cannot do and a drive-by request cannot guess. It does not and cannot stop
/// a process already running as the same user from reading the file. That is the OS trust
/// boundary, documented in the setup file, but it closes the "anyone on loopback" hole.
///
/// The token is generated once and persisted, so a harness's MCP config can reference it
/// statically; it is regenerated only if the file is missing or empty.
/// </summary>
public sealed class McpAuthToken
{
    private readonly string _tokenPath;
    private readonly string _setupPath;

    public string Value { get; }

    /// <summary>Absolute path of the token file, so the host can harden its ACL on Windows.</summary>
    public string TokenFilePath => _tokenPath;

    public McpAuthToken(string? baseDirectory = null)
    {
        var dir = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Foreman");
        _tokenPath = Path.Combine(dir, "mcp.token");
        _setupPath = Path.Combine(dir, "mcp-setup.txt");
        Value = LoadOrCreate(dir, _tokenPath);
    }

    private static string LoadOrCreate(string dir, string tokenPath)
    {
        try
        {
            if (File.Exists(tokenPath))
            {
                var existing = File.ReadAllText(tokenPath).Trim();
                if (existing.Length >= 32) return existing;
            }
        }
        catch { /* unreadable - fall through and mint a fresh one */ }

        var token = Generate();
        try
        {
            Directory.CreateDirectory(dir);
            File.WriteAllText(tokenPath, token);
        }
        catch { /* can't persist - token still works for this run, just not reusable */ }
        return token;
    }

    private static string Generate()
    {
        // 32 random bytes, URL-safe base64, no padding.
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    /// <summary>Constant-time comparison of a presented token against the real one.</summary>
    public bool Matches(string? presented)
    {
        if (string.IsNullOrEmpty(presented)) return false;
        var a = Encoding.UTF8.GetBytes(presented);
        var b = Encoding.UTF8.GetBytes(Value);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>Writes a human-readable, ready-to-paste setup file next to the token.</summary>
    public void WriteSetupFile(int port)
    {
        var snippet =
$$"""
Foreman MCP - connection setup
==============================

Foreman's MCP server requires a bearer token. It listens on:

    http://localhost:{{port}}/mcp        (tools - requires the token)
    http://localhost:{{port}}/health     (liveness - open)

Your token is in the file 'mcp.token' next to this file - it is readable only by you.
Add it as an Authorization header in your harness's MCP client config, replacing <TOKEN>
with the contents of mcp.token.

Claude Code JSON example:

{
  "mcpServers": {
    "foreman": {
      "type": "http",
      "url": "http://localhost:{{port}}/mcp",
      "headers": { "Authorization": "Bearer <TOKEN>" }
    }
  }
}

Codex TOML example:

[mcp_servers.foreman]
url = "http://localhost:{{port}}/mcp"
http_headers = { Authorization = "Bearer <TOKEN>" }
enabled = true

Keep mcp.token private - anyone who can read it can call Foreman's MCP tools.
Delete mcp.token to force a new token (you must then update every client config).
""";
        try { File.WriteAllText(_setupPath, snippet); }
        catch { /* best-effort */ }
    }
}
