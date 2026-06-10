#pragma warning disable MCPEXP002 // RunSessionHandler is experimental but stable enough for our use
// Alias avoids Foreman.McpServer namespace shadowing ModelContextProtocol.Server.McpServer
using McpServerType = global::ModelContextProtocol.Server.McpServer;
using Foreman.Core.Events;
using Foreman.Core.Settings;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.AspNetCore;

namespace Foreman.McpServer;

/// <summary>
/// Hosts an embedded Kestrel MCP HTTP+SSE server.
/// Call StartAsync() from App startup, DisposeAsync() on shutdown.
/// </summary>
public sealed class McpServerHost : IAsyncDisposable
{
    private readonly ForemanSettings _settings;
    private readonly EventBus _bus;
    private readonly McpAuthToken _authToken = new();
    private WebApplication? _app;

    public ForemanState State { get; } = new();
    public SseSessionManager Sessions { get; } = new();

    /// <summary>Path of the MCP bearer-token file, so the (Windows) app shell can ACL-restrict it.</summary>
    public string TokenFilePath => _authToken.TokenFilePath;

    /// <summary>The per-install bearer token, so the app shell can build connect instructions/config.</summary>
    public string McpToken => _authToken.Value;

    public McpServerHost(ForemanSettings settings, EventBus bus)
    {
        _settings = settings;
        _bus = bus;
        State.McpPort = settings.McpPort;
        State.LlmTriage = settings.LlmTriage;
        State.GetMcpSessionCount = () => Sessions.Count;
        State.GetMcpClients = () => Sessions.DescribeSessions();
    }

    public async Task StartAsync(CancellationToken ct = default)
    {
        // inject shared state into the static tool type
        ForemanMcpTools.SetState(State);

        // subscribe state to the event bus
        _bus.Subscribe(State);

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseKestrel(opts =>
        {
            opts.ListenLocalhost(_settings.McpPort);
        });

        builder.Logging.SetMinimumLevel(LogLevel.Warning); // suppress Kestrel noise from tray

        builder.Services
            .AddSingleton(Sessions)
            .AddSingleton<AlertDispatcher>()
            .AddMcpServer()
            .WithHttpTransport(options =>
            {
                // Register/unregister each SSE session so AlertDispatcher can push
                // notifications/message proactively without the client polling.
                options.RunSessionHandler = async (Microsoft.AspNetCore.Http.HttpContext httpCtx, McpServerType server, CancellationToken sessionCt) =>
                {
                    var id = Sessions.Register(server);
                    try
                    {
                        await server.RunAsync(sessionCt).ConfigureAwait(false);
                    }
                    finally
                    {
                        Sessions.Unregister(id);
                    }
                };
            })
            .WithToolsFromAssembly(typeof(ForemanMcpTools).Assembly);

        _app = builder.Build();

        // Register the alert dispatcher as an event sink
        var dispatcher = _app.Services.GetRequiredService<AlertDispatcher>();
        _bus.Subscribe(dispatcher);

        // ── MCP auth gate ────────────────────────────────────────────────────────
        // localhost is not an authorization boundary on a shared box. Require the bearer
        // token (and reject cross-origin/browser requests) on /mcp so a random local process
        // or a drive-by browser POST cannot drive Foreman's tools. /health stays open.
        _authToken.WriteSetupFile(_settings.McpPort);
        _app.Use(async (ctx, next) =>
        {
            var isMcpRequest = ctx.Request.Path.StartsWithSegments("/mcp");
            try
            {
                if (isMcpRequest)
                {
                    var origin = ctx.Request.Headers.Origin.ToString();
                    if (!string.IsNullOrEmpty(origin) && !IsLoopbackOrigin(origin))
                    {
                        await Deny(ctx, StatusCodes.Status403Forbidden, "Cross-origin requests are not allowed.").ConfigureAwait(false);
                        return;
                    }
                    if (!_authToken.Matches(ExtractToken(ctx.Request)))
                    {
                        ctx.Response.Headers.WWWAuthenticate = "Bearer";
                        await Deny(ctx, StatusCodes.Status401Unauthorized,
                            "A valid Foreman MCP token is required. See mcp-setup.txt in %LocalAppData%\\Foreman.").ConfigureAwait(false);
                        return;
                    }
                }
                await next().ConfigureAwait(false);
            }
            catch (System.Text.Json.JsonException ex) when (isMcpRequest && !ctx.Response.HasStarted)
            {
                LogMcpException(ex);
                await Deny(ctx, StatusCodes.Status400BadRequest, "Invalid JSON-RPC request body.").ConfigureAwait(false);
            }
            catch (Exception ex) when (isMcpRequest)
            {
                LogMcpException(ex);
                throw;
            }
        });

        _app.MapMcp("/mcp");
        // Liveness only — no session count: /health is unauthenticated, so it shouldn't
        // tell a local prober how many agents are connected.
        _app.MapGet("/health", () => new { status = "ok", port = _settings.McpPort });

        await _app.StartAsync(ct).ConfigureAwait(false);
    }

    private static string? ExtractToken(HttpRequest req)
    {
        var auth = req.Headers.Authorization.ToString();
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return auth["Bearer ".Length..].Trim();
        var x = req.Headers["X-Foreman-Token"].ToString();
        return string.IsNullOrEmpty(x) ? null : x;
    }

    private static bool IsLoopbackOrigin(string origin) =>
        Uri.TryCreate(origin, UriKind.Absolute, out var u)
        && (u.IsLoopback || u.Host is "localhost" or "127.0.0.1" or "::1");

    private static async Task Deny(HttpContext ctx, int status, string message)
    {
        ctx.Response.StatusCode = status;
        await ctx.Response.WriteAsJsonAsync(new { error = message }).ConfigureAwait(false);
    }

    private static void LogMcpException(Exception ex)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Foreman");
            Directory.CreateDirectory(dir);
            File.AppendAllText(
                Path.Combine(dir, "mcp-errors.log"),
                $"[{DateTimeOffset.UtcNow:O}] {ex}\n\n");
        }
        catch { /* best-effort diagnostics only */ }
    }

    public async ValueTask DisposeAsync()
    {
        if (_app is not null)
            await _app.DisposeAsync().ConfigureAwait(false);
    }
}
