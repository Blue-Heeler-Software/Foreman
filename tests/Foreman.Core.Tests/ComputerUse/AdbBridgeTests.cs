using System.Text;
using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

public sealed class AdbBridgeTests
{
    private sealed class Allow : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default) =>
            Task.FromResult(CuVerdict.Allow("test"));
    }

    private sealed class FakeRunner : IAdbCommandRunner
    {
        public bool IsAvailable { get; set; } = true;
        public bool Cancelled { get; private set; }
        public List<IReadOnlyList<string>> Calls { get; } = [];
        public Queue<AdbCommandResult> Results { get; } = [];
        public Action<IReadOnlyList<string>>? OnRun { get; set; }

        public Task<AdbCommandResult> RunAsync(
            IReadOnlyList<string> arguments,
            int maxOutputBytes,
            TimeSpan timeout,
            CancellationToken ct = default)
        {
            Calls.Add(arguments.ToArray());
            OnRun?.Invoke(arguments);
            return Task.FromResult(Results.Count > 0
                ? Results.Dequeue()
                : new AdbCommandResult(0, Encoding.UTF8.GetBytes("device\n"), string.Empty));
        }

        public void CancelCurrent() => Cancelled = true;
    }

    private static CuAction Android(string verb, Dictionary<string, string>? args = null, string by = "codex") =>
        new(CuModality.Android, verb, args ?? new(), ByHarness: by);

    [Fact]
    public void CommandBuilder_BuildsFixedTapArguments_NoRawCommandString()
    {
        var action = Android("tap", new() { ["x"] = "120", ["y"] = "340" });

        Assert.True(AdbBridgeExecutor.TryBuildArguments(action, "emulator-5554", out var args, out _));
        Assert.Equal(["-s", "emulator-5554", "shell", "input", "tap", "120", "340"], args);
        Assert.DoesNotContain(args, a => a.Contains(';') || a.Contains("&&", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("device;rm -rf /")]
    [InlineData("device && whoami")]
    [InlineData("../transport")]
    [InlineData("")]
    public void SerialInjection_IsRejected(string serial)
    {
        var action = Android("screenshot");
        Assert.False(AdbBridgeExecutor.TryBuildArguments(action, serial, out _, out _));
    }

    [Theory]
    [InlineData("hello;reboot")]
    [InlineData("$(id)")]
    [InlineData("a&b")]
    [InlineData("`whoami`")]
    [InlineData("quote\"")]
    public void TypeShellMetacharacters_AreRejected(string text)
    {
        var action = Android("type", new() { ["text"] = text });
        Assert.False(AdbBridgeExecutor.TryBuildArguments(action, "device-1", out _, out _));
    }

    [Fact]
    public void TypeSpaces_AreEncodedWithoutShellMetacharacters()
    {
        var action = Android("type", new() { ["text"] = "hello Android_1@example.com" });
        Assert.True(AdbBridgeExecutor.TryBuildArguments(action, "device-1", out var args, out _));
        Assert.Equal("hello%sAndroid_1@example.com", args[^1]);
    }

    [Fact]
    public async Task Broker_ObserveOnlyAction_FromApprovedHarness_IsApproved()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDrivers(["codex", "claude-code"]);
        broker.SetAndroidDevices(["device-1"]);

        var item = await broker.SubmitAsync(Android("ui_dump", new() { ["serial"] = "device-1" }), new CuContext("codex"));

        Assert.Equal(CuActionState.Approved, item.State);
        Assert.Single(broker.Claim(5, CuModality.Android));
    }

    [Fact]
    public async Task Broker_EachApprovedHarness_CanUseTheSameAndroidModality()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDrivers(["codex", "claude-code"]);
        broker.SetAndroidDevices(["device-1"]);

        var codex = await broker.SubmitAsync(Android("screenshot", new() { ["serial"] = "device-1" }, "codex"), new CuContext("codex"));
        var claude = await broker.SubmitAsync(Android("logcat", new() { ["serial"] = "device-1" }, "claude-code"), new CuContext("claude-code"));
        var cursor = await broker.SubmitAsync(Android("ui_dump", new() { ["serial"] = "device-1" }, "cursor"), new CuContext("cursor"));

        Assert.Equal(CuActionState.Approved, codex.State);
        Assert.Equal(CuActionState.Approved, claude.State);
        Assert.Equal(CuActionState.Blocked, cursor.State);
    }

    [Fact]
    public async Task Broker_StateChangingAndroidAction_IsHeldUntilOperatorApproves()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);
        var item = await broker.SubmitAsync(
            Android("tap", new() { ["serial"] = "device-1", ["x"] = "1", ["y"] = "2" }),
            new CuContext("codex"));

        Assert.Equal(CuActionState.Held, item.State);
        Assert.Empty(broker.Claim(5, CuModality.Android));
        Assert.True(broker.ApproveHeld(item.ActionId).Ok);
        Assert.Single(broker.Claim(5, CuModality.Android));
    }

    [Fact]
    public async Task Broker_UnknownVerbAndUnenrolledDevice_FailClosed()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);

        var raw = await broker.SubmitAsync(Android("shell", new() { ["serial"] = "device-1" }), new CuContext("codex"));
        var other = await broker.SubmitAsync(Android("screenshot", new() { ["serial"] = "device-2" }), new CuContext("codex"));

        Assert.Equal(CuActionState.Blocked, raw.State);
        Assert.Equal(CuActionState.Blocked, other.State);
    }

    [Fact]
    public async Task Broker_OneEnrolledDevice_IsStampedBeforeAudit()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);

        var item = await broker.SubmitAsync(Android("screenshot"), new CuContext("codex"));

        Assert.Equal(CuActionState.Approved, item.State);
        Assert.Equal("device-1", item.Action.Arg("serial"));
    }

    [Fact]
    public async Task Broker_PanicRejectsQueuedAndExecutingAndroidActions()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);
        _ = await broker.SubmitAsync(
            Android("screenshot", new() { ["serial"] = "device-1" }), new CuContext("codex"));
        var executing = broker.Claim(1, CuModality.Android).Single();
        var held = await broker.SubmitAsync(
            Android("tap", new() { ["serial"] = "device-1", ["x"] = "1", ["y"] = "2" }), new CuContext("codex"));

        broker.OnPanicHalt();

        Assert.Equal(CuActionState.Rejected, broker.Get(executing.ActionId)!.State);
        Assert.Equal(CuActionState.Rejected, broker.Get(held.ActionId)!.State);
        Assert.Empty(broker.Claim(5, CuModality.Android));
    }

    [Fact]
    public async Task Broker_LiveRevocationRejectsPreviouslyApprovedAndroidActions()
    {
        var broker = new CuBroker(new Allow());
        broker.SetDriver("codex");
        broker.SetAndroidDevices(["device-1"]);
        var approved = await broker.SubmitAsync(
            Android("screenshot", new() { ["serial"] = "device-1" }), new CuContext("codex"));

        var count = broker.RevokeModality(CuModality.Android, "settings changed");
        broker.SetAndroidDevices([]);

        Assert.Equal(1, count);
        Assert.Equal(CuActionState.Rejected, broker.Get(approved.ActionId)!.State);
        Assert.Empty(broker.Claim(5, CuModality.Android));
    }

    [Fact]
    public async Task Executor_RechecksDeviceState_ThenRunsBoundedCommand()
    {
        var runner = new FakeRunner();
        runner.Results.Enqueue(new AdbCommandResult(0, Encoding.UTF8.GetBytes("device\n"), ""));
        runner.Results.Enqueue(new AdbCommandResult(0, Encoding.UTF8.GetBytes("<hierarchy />"), ""));
        using var executor = new AdbBridgeExecutor(
            AdbBridgeOptions.Create(@"C:\Android\adb.exe", ["device-1"]),
            runner);
        var item = new CuBrokerItem("a1", Android("ui_dump", new() { ["serial"] = "device-1" }),
            CuActionState.Executing, null, DateTimeOffset.UtcNow);

        var result = await executor.ExecuteAsync(item);

        Assert.True(result.Ok);
        Assert.Equal(["-s", "device-1", "get-state"], runner.Calls[0]);
        Assert.Equal(["-s", "device-1", "exec-out", "uiautomator", "dump", "/dev/tty"], runner.Calls[1]);
    }

    [Fact]
    public async Task Executor_PanicBetweenStateCheckAndAction_StopsBeforeSecondAdbCall()
    {
        var halted = false;
        var runner = new FakeRunner { OnRun = _ => halted = true };
        using var executor = new AdbBridgeExecutor(
            AdbBridgeOptions.Create(@"C:\Android\adb.exe", ["device-1"]),
            runner,
            () => halted);
        var item = new CuBrokerItem("a1", Android("tap", new()
        {
            ["serial"] = "device-1", ["x"] = "1", ["y"] = "2",
        }), CuActionState.Executing, null, DateTimeOffset.UtcNow);

        var result = await executor.ExecuteAsync(item);

        Assert.False(result.Ok);
        Assert.Single(runner.Calls);
        Assert.Contains("halted", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Executor_InventoryMarksOnlyEnrolledDevices()
    {
        var runner = new FakeRunner();
        runner.Results.Enqueue(new AdbCommandResult(0,
            Encoding.UTF8.GetBytes("List of devices attached\ndevice-1 device product:x\nother offline\n"), ""));
        using var executor = new AdbBridgeExecutor(
            AdbBridgeOptions.Create(@"C:\Android\adb.exe", ["device-1"]),
            runner);
        var item = new CuBrokerItem("a1", Android("devices"), CuActionState.Executing, null, DateTimeOffset.UtcNow);

        var result = await executor.ExecuteAsync(item);

        Assert.True(result.Ok);
        var json = System.Text.Json.JsonSerializer.Serialize(result.Result);
        Assert.Contains("\"serial\":\"device-1\"", json);
        Assert.Contains("\"enrolled\":true", json);
        Assert.Contains("\"serial\":\"other\"", json);
        Assert.Contains("\"enrolled\":false", json);
    }

    [Fact]
    public void PanicStop_CancelsTheCurrentAdbClient()
    {
        var runner = new FakeRunner();
        using var executor = new AdbBridgeExecutor(
            AdbBridgeOptions.Create(@"C:\Android\adb.exe", ["device-1"]),
            runner);

        executor.PanicStop();

        Assert.True(runner.Cancelled);
    }

    [Fact]
    public void ProcessRunner_RefusesBinaryWhoseEnrolledHashDoesNotMatch()
    {
        var path = Path.Combine(Path.GetTempPath(), $"foreman-adb-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllText(path, "known adb test bytes");
            var hash = AdbProcessRunner.ComputeSha256(path);
            using var matching = new AdbProcessRunner(path, hash);
            using var replaced = new AdbProcessRunner(path, new string('0', 64));

            Assert.True(matching.IsAvailable);
            Assert.False(replaced.IsAvailable);
        }
        finally
        {
            try { File.Delete(path); } catch { }
        }
    }

    [Fact]
    public async Task ProcessRunner_HashPinnedExecutable_CanLaunchAndCaptureBoundedOutput()
    {
        var windows = OperatingSystem.IsWindows();
        var executable = windows
            ? Environment.GetEnvironmentVariable("ComSpec")!
            : "/bin/sh";
        var arguments = windows
            ? new[] { "/d", "/c", "echo adb-runner-ok" }
            : new[] { "-c", "printf adb-runner-ok" };
        var hash = AdbProcessRunner.ComputeSha256(executable);
        using var runner = new AdbProcessRunner(executable, hash);

        var result = await runner.RunAsync(arguments, 16 * 1024, TimeSpan.FromSeconds(5));

        Assert.True(runner.IsAvailable);
        Assert.Equal(0, result.ExitCode);
        Assert.Contains("adb-runner-ok", Encoding.UTF8.GetString(result.StandardOutput));
    }
}
