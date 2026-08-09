using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Foreman.Core.Events;
using Foreman.Core.Heuristics;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using Foreman.McpServer;
using Foreman.Platform.Linux;

namespace Foreman.Agent;

[SupportedOSPlatform("linux")]
internal static class Program
{
    private const string Version = "0.1.0-ubuntu-alpha1";

    public static async Task<int> Main(string[] args)
    {
        var command = args.FirstOrDefault()?.ToLowerInvariant() ?? "help";
        try
        {
            return command switch
            {
                "run" or "--foreground" => await RunAsync(args.Skip(1).ToArray()),
                "status" => await StatusAsync(),
                "doctor" => await DoctorAsync(),
                "events" => ShowEvents(ParseCount(args.Skip(1).FirstOrDefault(), 25)),
                "token" => ShowToken(args.Skip(1).ToArray()),
                "connect" => ShowConnection(args.Skip(1).FirstOrDefault()),
                "version" or "--version" or "-v" => ShowVersion(),
                "help" or "--help" or "-h" => ShowHelp(),
                _ => Unknown(command),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"foreman-agent: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> RunAsync(string[] args)
    {
        if (!OperatingSystem.IsLinux())
        {
            Console.Error.WriteLine("foreman-agent: this executable is the Linux/Ubuntu agent.");
            return 2;
        }

        var paths = LinuxXdgPaths.FromCurrentEnvironment();
        EnsurePrivateDirectories(paths.ConfigDir, paths.StateDir, paths.DataDir, paths.RuntimeDir);

        var settingsPath = Path.Combine(paths.ConfigDir, "settings.json");
        var installToken = new McpAuthToken(paths.StateDir);
        SettingsStore.IntegritySecret = () => installToken.Value;
        var settings = SettingsStore.Load(settingsPath);
        settings.ProfilesDirectory = Path.Combine(paths.ConfigDir, "profiles");
        if (TryReadPort(args, out var port)) settings.McpPort = port;
        if (!File.Exists(settingsPath)) SettingsStore.Save(settings, settingsPath);

        PatternLibrary.Instance.Initialize();
        CommandAnalyzer.DecoySentinelToken = settings.DecoyCredentials.InstanceSentinel;

        var bus = new EventBus();
        var eventLog = new EventLogStore(paths.StateDir, integrity: settings.LogIntegrity);
        var integrity = eventLog.Verify();
        var persistenceFailureReported = 0;
        bus.Subscribe(evt =>
        {
            WriteEvent(evt);
            if (!settings.EventLogPersist) return;
            if (eventLog.TryAppend(evt, out var error) ||
                Interlocked.Exchange(ref persistenceFailureReported, 1) != 0) return;
            Console.Error.WriteLine($"foreman-agent: event log persistence degraded: {error}");
        });

        if (!integrity.Ok)
        {
            bus.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.LogIntegrity",
                $"Event log integrity verification failed ({integrity.Status}): {integrity.Message}"));
        }
        if (SettingsStore.LastLoadFault is { } loadFault)
        {
            bus.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Settings", loadFault));
        }

        var snapshots = new LinuxProcProcessSnapshotProvider();
        using var processEvents = new LinuxPollingProcessEventSource(snapshots);
        using var monitor = new LinuxMonitorService(
            settings, bus, snapshots, processEvents, new LinuxProcessIoReader(), paths.StateDir);
        await using var mcp = new McpServerHost(settings, bus, paths.StateDir);

        mcp.State.GetProcessSnapshot = () => monitor.Tree.GetAll();
        mcp.State.GetBehaviorProfiles = () => monitor.Behavior.Profiles;
        mcp.State.ResetBehaviorProfile = monitor.Behavior.ResetProfile;
        mcp.State.GetProfileByName = monitor.Profiles.Get;
        mcp.State.GetDefaultProfileNameByHarnessId = HarnessIntegrationRegistry.GetDefaultProfileName;
        mcp.State.FindHarnessAncestorByPid = pid => monitor.Tree.FindHarnessTypeAncestor(pid);
        mcp.State.GetMcpInventory = () => monitor.McpInventory.Current;
        mcp.State.KillProcessByPid = monitor.Tree.KillProcess;

        var protector = new LinuxTokenFileProtector();
        ReportProtection(bus, "MCP token", protector.Protect(mcp.TokenFilePath));

        monitor.Start();
        await mcp.StartAsync();
        ReportProtection(bus, "MCP setup", protector.Protect(mcp.SetupFilePath));

        bus.Publish(new InfoEvent(
            DateTimeOffset.UtcNow, "Foreman.Agent",
            $"Foreman Agent Safety {Version} started on Ubuntu/Linux; MCP listening on loopback port {settings.McpPort}."));

        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stopped.TrySetResult();
        };
        using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context =>
        {
            context.Cancel = true;
            stopped.TrySetResult();
        });
        using var sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, context =>
        {
            context.Cancel = true;
            stopped.TrySetResult();
        });

        await stopped.Task;
        bus.Publish(new InfoEvent(DateTimeOffset.UtcNow, "Foreman.Agent", "Foreman Agent Safety stopping cleanly."));
        return 0;
    }

    private static async Task<int> StatusAsync()
    {
        var settings = LoadSettings(out _);
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        try
        {
            var health = await http.GetFromJsonAsync<Health>($"http://127.0.0.1:{settings.McpPort}/health");
            Console.WriteLine($"running  Foreman Agent Safety {Version}");
            Console.WriteLine($"health   {health?.status ?? "unknown"}");
            Console.WriteLine($"mcp      http://127.0.0.1:{settings.McpPort}/mcp");
            return health?.status == "ok" ? 0 : 1;
        }
        catch
        {
            Console.WriteLine("stopped  Foreman Agent Safety is not responding");
            Console.WriteLine($"mcp      http://127.0.0.1:{settings.McpPort}/mcp");
            return 3;
        }
    }

    private static async Task<int> DoctorAsync()
    {
        var settings = LoadSettings(out var paths);
        var tokenPath = Path.Combine(paths.StateDir, "mcp.token");
        Console.WriteLine($"Foreman Agent Safety {Version}");
        Console.WriteLine($"OS       {RuntimeInformation.OSDescription} ({RuntimeInformation.ProcessArchitecture})");
        Console.WriteLine($"binary   {Environment.ProcessPath}");
        Console.WriteLine($"config   {paths.ConfigDir}");
        Console.WriteLine($"state    {paths.StateDir}");
        Console.WriteLine($"port     {settings.McpPort}");

        var ok = true;
        if (File.Exists(tokenPath))
        {
            var mode = File.GetUnixFileMode(tokenPath);
            var secure = (mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                                  UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) == 0;
            Console.WriteLine($"token    {(secure ? "secure" : "INSECURE")} ({FormatMode(mode)}) {tokenPath}");
            ok &= secure;
        }
        else
        {
            Console.WriteLine($"token    missing (created on first run) {tokenPath}");
        }

        var service = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".config", "systemd", "user", "foreman-agent.service");
        Console.WriteLine($"service  {(File.Exists(service) ? "installed" : "not installed")}");
        var status = await StatusAsync();
        return ok && status == 0 ? 0 : 1;
    }

    private static int ShowEvents(int count)
    {
        var paths = LinuxXdgPaths.FromCurrentEnvironment();
        var events = new EventLogStore(paths.StateDir).Load().TakeLast(count);
        foreach (var evt in events)
            WriteEvent(evt);
        return 0;
    }

    private static int ShowToken(string[] args)
    {
        var paths = LinuxXdgPaths.FromCurrentEnvironment();
        EnsurePrivateDirectories(paths.StateDir);
        var auth = new McpAuthToken(paths.StateDir);
        var protector = new LinuxTokenFileProtector();
        var result = protector.Protect(auth.TokenFilePath);
        if (!result.Ok)
        {
            Console.Error.WriteLine($"foreman-agent: token protection failed: {result.Warning}");
            return 1;
        }
        var harnessIndex = Array.IndexOf(args, "--harness");
        Console.WriteLine(harnessIndex >= 0 && harnessIndex + 1 < args.Length
            ? auth.MintHarnessToken(args[harnessIndex + 1])
            : auth.Value);
        return 0;
    }

    private static int ShowConnection(string? harness)
    {
        var settings = LoadSettings(out var paths);
        if (string.IsNullOrWhiteSpace(harness))
        {
            Console.Error.WriteLine("usage: foreman-agent connect <codex|claude-code|generic>");
            return 2;
        }
        harness = harness.Trim().ToLowerInvariant();
        var envName = "FOREMAN_MCP_TOKEN_" + harness.Replace('-', '_').ToUpperInvariant();
        Console.WriteLine($"Endpoint: http://127.0.0.1:{settings.McpPort}/mcp");
        Console.WriteLine($"Scoped token: foreman-agent token --harness {harness}");
        if (harness == "codex")
        {
            Console.WriteLine();
            Console.WriteLine($"export {envName}=\"$(foreman-agent token --harness codex)\"");
            Console.WriteLine("Add to ~/.codex/config.toml:");
            Console.WriteLine("[mcp_servers.foreman]");
            Console.WriteLine($"url = \"http://127.0.0.1:{settings.McpPort}/mcp\"");
            Console.WriteLine($"bearer_token_env_var = \"{envName}\"");
            Console.WriteLine("enabled = true");
        }
        else
        {
            Console.WriteLine($"Set Authorization: Bearer $(foreman-agent token --harness {harness}) in your client's secure environment/configuration.");
        }
        return 0;
    }

    private static ForemanSettings LoadSettings(out Foreman.Platform.ForemanPaths paths)
    {
        paths = LinuxXdgPaths.FromCurrentEnvironment();
        var settings = SettingsStore.Load(Path.Combine(paths.ConfigDir, "settings.json"));
        settings.ProfilesDirectory = Path.Combine(paths.ConfigDir, "profiles");
        return settings;
    }

    private static void EnsurePrivateDirectories(params string[] directories)
    {
        foreach (var directory in directories)
        {
            Directory.CreateDirectory(directory);
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void ReportProtection(EventBus bus, string label, Foreman.Platform.TokenFileProtectionResult result)
    {
        if (result.Ok) return;
        bus.Publish(new MonitoringNoticeEvent(
            DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.Permissions",
            $"{label} permissions could not be restricted to the current user: {result.Warning}"));
    }

    private static bool TryReadPort(string[] args, out int port)
    {
        port = 0;
        var i = Array.IndexOf(args, "--mcp-port");
        return i >= 0 && i + 1 < args.Length && int.TryParse(args[i + 1], out port) && port is > 1024 and <= 65535;
    }

    private static string FormatMode(UnixFileMode mode) => Convert.ToString((int)mode, 8).PadLeft(3, '0');
    private static int ParseCount(string? value, int fallback) => int.TryParse(value, out var n) ? Math.Clamp(n, 1, 500) : fallback;

    private static void WriteEvent(ForemanEvent evt) =>
        Console.WriteLine($"{evt.Timestamp:O} [{evt.Severity.ToString().ToUpperInvariant()}] {evt.Source}: {evt.Message}");

    private static int ShowVersion()
    {
        Console.WriteLine($"Foreman Agent Safety {Version} (Ubuntu/Linux)");
        return 0;
    }

    private static int ShowHelp()
    {
        Console.WriteLine("Foreman Agent Safety for Ubuntu/Linux");
        Console.WriteLine();
        Console.WriteLine("  foreman-agent run [--mcp-port PORT]  Run the monitor in the foreground");
        Console.WriteLine("  foreman-agent status                 Check the running service");
        Console.WriteLine("  foreman-agent doctor                 Check paths, permissions, and health");
        Console.WriteLine("  foreman-agent events [COUNT]         Show recent persisted events");
        Console.WriteLine("  foreman-agent token [--harness ID]   Print an operator or scoped MCP token");
        Console.WriteLine("  foreman-agent connect HARNESS        Print MCP connection instructions");
        Console.WriteLine("  foreman-agent version                Print version information");
        return 0;
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"foreman-agent: unknown command '{command}'");
        ShowHelp();
        return 2;
    }

    private sealed record Health(string status, int port);
}
