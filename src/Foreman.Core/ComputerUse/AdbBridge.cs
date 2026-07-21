using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Foreman.Core.ComputerUse;

/// <summary>
/// Configuration for Foreman's bounded Android Debug Bridge executor. The executable is an absolute, operator-chosen
/// path (never a PATH lookup) and every target serial must be explicitly enrolled before a device-scoped action can
/// enter the broker.
/// </summary>
public sealed record AdbBridgeOptions(
    string ExecutablePath,
    string ExecutableSha256,
    IReadOnlyCollection<string> EnrolledSerials,
    TimeSpan CommandTimeout)
{
    public static AdbBridgeOptions Create(
        string executablePath,
        IEnumerable<string>? enrolledSerials,
        string? executableSha256 = null,
        TimeSpan? commandTimeout = null) =>
        new(
            executablePath,
            (executableSha256 ?? string.Empty).Trim().ToUpperInvariant(),
            (enrolledSerials ?? [])
                .Select(static s => (s ?? string.Empty).Trim())
                .Where(static s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            commandTimeout ?? TimeSpan.FromSeconds(30));
}

public sealed record AdbCommandResult(int ExitCode, byte[] StandardOutput, string StandardError);

/// <summary>Small seam around adb process execution so command construction and executor behaviour are unit-testable.</summary>
public interface IAdbCommandRunner
{
    bool IsAvailable { get; }
    Task<AdbCommandResult> RunAsync(
        IReadOnlyList<string> arguments,
        int maxOutputBytes,
        TimeSpan timeout,
        CancellationToken ct = default);
    void CancelCurrent();
}

/// <summary>
/// Launches one fixed adb executable without a shell. ArgumentList is used throughout, output is bounded, and a panic
/// can kill the current adb client process tree. Foreman never exposes this runner directly to an MCP caller.
/// </summary>
public sealed class AdbProcessRunner : IAdbCommandRunner, IDisposable
{
    private readonly string _executablePath;
    private readonly string _launchPath;
    private readonly FileStream? _binaryPin;
    private readonly string? _unavailableReason;
    private readonly object _gate = new();
    private Process? _current;

    public AdbProcessRunner(string executablePath, string? expectedSha256 = null)
    {
        _executablePath = executablePath ?? string.Empty;
        _launchPath = _executablePath;
        try
        {
            if (!Path.IsPathFullyQualified(_executablePath) || !File.Exists(_executablePath))
            {
                _unavailableReason = "The configured adb executable is unavailable.";
                return;
            }

            // Pin the enrolled binary against write/delete for Foreman's lifetime. This closes the hash-check→launch
            // replacement window and deliberately makes an SDK update require closing Foreman + re-enrolling the hash.
            _binaryPin = new FileStream(_executablePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            _launchPath = ResolveFinalPath(_binaryPin) ?? Path.GetFullPath(_executablePath);
            var actual = ComputeSha256(_binaryPin);
            var expected = (expectedSha256 ?? string.Empty).Trim();
            if (expected.Length > 0 && !string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            {
                _binaryPin.Dispose();
                _binaryPin = null;
                _unavailableReason = "The adb executable changed since the operator enrolled it.";
            }
        }
        catch (Exception ex)
        {
            _binaryPin?.Dispose();
            _binaryPin = null;
            _unavailableReason = $"The adb executable could not be pinned: {ex.Message}";
        }
    }

    public bool IsAvailable => _binaryPin is not null;

    public async Task<AdbCommandResult> RunAsync(
        IReadOnlyList<string> arguments,
        int maxOutputBytes,
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        if (!IsAvailable)
            return new AdbCommandResult(-1, [], _unavailableReason ?? "The configured adb executable is unavailable.");
        if (maxOutputBytes is < 1 or > 16 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(maxOutputBytes));

        var psi = new ProcessStartInfo
        {
            // Launch the final path resolved from the PINNED file handle, not the configurable path text. An NTFS
            // junction swap of a parent directory can no longer redirect a later Process.Start to different bytes.
            FileName = _launchPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = false,
        };
        // Do not inherit caller-controlled ADB routing. In particular, ADB_SERVER_SOCKET can redirect the trusted
        // client to a remote/untrusted server and ANDROID_SERIAL can create an implicit target. Foreman always uses
        // the local ADB server and supplies an explicit enrolled serial for device-scoped commands.
        psi.Environment.Remove("ADB_SERVER_SOCKET");
        psi.Environment.Remove("ANDROID_ADB_SERVER_PORT");
        psi.Environment.Remove("ANDROID_SERIAL");
        foreach (var arg in arguments)
            psi.ArgumentList.Add(arg);

        using var process = new Process { StartInfo = psi };

        try
        {
            // Publish + start under the same lock used by CancelCurrent. A panic can therefore happen before publish,
            // or wait until Start returns and kill the live client; it cannot fall into a pre-start gap and be lost.
            lock (_gate)
            {
                if (_current is not null)
                    throw new InvalidOperationException("Another adb command is already running.");
                _current = process;
                if (!process.Start())
                    return new AdbCommandResult(-1, [], "adb did not start.");
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout);
            var stdout = ReadBoundedAsync(process.StandardOutput.BaseStream, maxOutputBytes, timeoutCts.Token);
            var stderr = ReadBoundedAsync(process.StandardError.BaseStream, 64 * 1024, timeoutCts.Token);

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
                var outBytes = await stdout.ConfigureAwait(false);
                var errBytes = await stderr.ConfigureAwait(false);
                return new AdbCommandResult(
                    process.ExitCode,
                    outBytes,
                    Encoding.UTF8.GetString(errBytes));
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                return new AdbCommandResult(-1, [], ct.IsCancellationRequested
                    ? "adb action cancelled."
                    : $"adb action timed out after {timeout.TotalSeconds:0} seconds.");
            }
            catch (InvalidDataException ex)
            {
                TryKill(process);
                return new AdbCommandResult(-1, [], ex.Message);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            TryKill(process);
            return new AdbCommandResult(-1, [], $"adb failed: {ex.Message}");
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_current, process))
                    _current = null;
            }
        }
    }

    public void CancelCurrent()
    {
        Process? process;
        lock (_gate) process = _current;
        if (process is not null) TryKill(process);
    }

    public void Dispose()
    {
        CancelCurrent();
        _binaryPin?.Dispose();
    }

    public static string ComputeSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return ComputeSha256(stream);
    }

    private static string ComputeSha256(Stream stream)
    {
        stream.Position = 0;
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string? ResolveFinalPath(FileStream stream)
    {
        if (!OperatingSystem.IsWindows()) return Path.GetFullPath(stream.Name);
        var buffer = new StringBuilder(1024);
        var length = GetFinalPathNameByHandle(stream.SafeFileHandle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0) return null;
        if (length >= buffer.Capacity)
        {
            buffer = new StringBuilder(checked((int)length + 1));
            length = GetFinalPathNameByHandle(stream.SafeFileHandle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity) return null;
        }
        return buffer.ToString();
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
        StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, int cap, CancellationToken ct)
    {
        using var output = new MemoryStream(Math.Min(cap, 64 * 1024));
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > cap)
                throw new InvalidDataException($"adb output exceeded the {cap / 1024} KiB safety cap.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static void TryKill(Process process)
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch { /* best-effort panic/timeout cancellation */ }
    }
}

/// <summary>
/// The in-process executor for Foreman's Android modality. It accepts only the structured verbs below, targets only
/// enrolled device serials, performs a fresh device-state check, and never offers raw adb shell/exec access.
/// </summary>
public sealed class AdbBridgeExecutor : ICuExecutor, IDisposable
{
    private const int TextOutputCap = 2 * 1024 * 1024;
    private const int ScreenshotOutputCap = 8 * 1024 * 1024;
    private readonly AdbBridgeOptions _options;
    private readonly IAdbCommandRunner _runner;
    private readonly HashSet<string> _enrolled;
    private readonly Func<bool> _isHalted;

    public AdbBridgeExecutor(AdbBridgeOptions options, IAdbCommandRunner? runner = null, Func<bool>? isHalted = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _runner = runner ?? new AdbProcessRunner(options.ExecutablePath, options.ExecutableSha256);
        _enrolled = new HashSet<string>(options.EnrolledSerials, StringComparer.OrdinalIgnoreCase);
        _isHalted = isHalted ?? (() => false);
    }

    public CuModality Modality => CuModality.Android;
    public bool IsReady => _runner.IsAvailable;
    public string ExecutablePath => _options.ExecutablePath;
    public IReadOnlyList<string> EnrolledSerials => _enrolled.Order(StringComparer.OrdinalIgnoreCase).ToArray();

    public async Task<CuExecResult> ExecuteAsync(CuBrokerItem item, CancellationToken ct = default)
    {
        if (_isHalted()) return Fail("Computer use is halted by the operator panic stop.");
        if (item.Action.Modality != CuModality.Android)
            return Fail("The ADB bridge only executes Android actions.");
        if (!CuVerbs.IsKnownAndroid(item.Action.Verb))
            return Fail("Unsupported Android verb.");

        var verb = item.Action.Verb.Trim().ToLowerInvariant();
        if (verb == "devices")
        {
            var inventory = await _runner.RunAsync(
                ["devices", "-l"], 256 * 1024, _options.CommandTimeout, ct).ConfigureAwait(false);
            if (inventory.ExitCode != 0) return FromFailure(inventory);
            return new CuExecResult(true, new
            {
                devices = ParseDevices(Text(inventory.StandardOutput), _enrolled),
                enrolledSerials = EnrolledSerials,
            }, null);
        }

        var serial = item.Action.Arg("serial").Trim();
        if (!_enrolled.Contains(serial))
            return Fail("Target device is not enrolled.");

        // Re-check immediately before every scoped operation. "unauthorized", "offline", or a disconnected/recycled
        // endpoint fails closed rather than sending the approved action somewhere ambiguous.
        var state = await _runner.RunAsync(
            ["-s", serial, "get-state"], 16 * 1024, _options.CommandTimeout, ct).ConfigureAwait(false);
        if (state.ExitCode != 0 || !string.Equals(Text(state.StandardOutput).Trim(), "device", StringComparison.Ordinal))
            return Fail($"Enrolled device '{serial}' is not connected and authorised.");

        // Panic may have fired while get-state was running. Re-check at the final boundary before the actual device
        // operation so a halt cannot lose the gap between the two adb invocations.
        if (_isHalted()) return Fail("Computer use was halted before the Android action could execute.");

        if (!TryBuildArguments(item.Action, serial, out var arguments, out var error))
            return Fail(error);

        var cap = verb == "screenshot" ? ScreenshotOutputCap : TextOutputCap;
        var result = await _runner.RunAsync(arguments, cap, _options.CommandTimeout, ct).ConfigureAwait(false);
        if (result.ExitCode != 0) return FromFailure(result);

        if (verb == "screenshot")
        {
            return new CuExecResult(true, new
            {
                serial,
                mimeType = "image/png",
                bytes = result.StandardOutput.Length,
                base64 = Convert.ToBase64String(result.StandardOutput),
            }, null);
        }

        return new CuExecResult(true, new
        {
            serial,
            output = Foreman.Core.Security.SecretRedactor.Redact(Text(result.StandardOutput)),
        }, null);
    }

    /// <summary>Best-effort immediate stop for the current adb client. Pending actions remain blocked by CuPanicState.</summary>
    public void PanicStop() => _runner.CancelCurrent();

    public void Dispose()
    {
        if (_runner is IDisposable disposable)
            disposable.Dispose();
        else
            _runner.CancelCurrent();
    }

    public static bool TryBuildArguments(
        CuAction action,
        string serial,
        out IReadOnlyList<string> arguments,
        out string error)
    {
        arguments = [];
        error = string.Empty;
        if (!IsSafeSerial(serial))
        {
            error = "Invalid Android device serial.";
            return false;
        }

        switch (action.Verb.Trim().ToLowerInvariant())
        {
            case "screenshot":
                arguments = ["-s", serial, "exec-out", "screencap", "-p"];
                return true;
            case "ui_dump":
                arguments = ["-s", serial, "exec-out", "uiautomator", "dump", "/dev/tty"];
                return true;
            case "logcat":
                if (!TryInt(action.Arg("lines"), 1, 500, defaultValue: 200, out var lines))
                {
                    error = "logcat lines must be an integer from 1 to 500.";
                    return false;
                }
                arguments = ["-s", serial, "logcat", "-d", "-t", lines.ToString(CultureInfo.InvariantCulture)];
                return true;
            case "tap":
                if (!TryCoordinate(action, "x", out var tx) || !TryCoordinate(action, "y", out var ty))
                {
                    error = "tap requires integer x/y coordinates from 0 to 100000.";
                    return false;
                }
                arguments = ["-s", serial, "shell", "input", "tap", tx, ty];
                return true;
            case "swipe":
                if (!TryCoordinate(action, "x1", out var x1) || !TryCoordinate(action, "y1", out var y1)
                    || !TryCoordinate(action, "x2", out var x2) || !TryCoordinate(action, "y2", out var y2)
                    || !TryInt(action.Arg("durationMs"), 0, 10_000, defaultValue: 300, out var duration))
                {
                    error = "swipe requires x1/y1/x2/y2 coordinates and optional durationMs from 0 to 10000.";
                    return false;
                }
                arguments =
                [
                    "-s", serial, "shell", "input", "swipe", x1, y1, x2, y2,
                    duration.ToString(CultureInfo.InvariantCulture),
                ];
                return true;
            case "type":
                var text = action.Arg("text");
                if (!TryEncodeInputText(text, out var encoded))
                {
                    error = "Android text must be 1-1000 characters and use only letters, numbers, spaces, or .,_@:/+-.";
                    return false;
                }
                arguments = ["-s", serial, "shell", "input", "text", encoded];
                return true;
            case "key":
                if (!TryKey(action.Arg("key"), out var key))
                {
                    error = "Unsupported Android key. Allowed: back, home, enter, tab, delete, escape, dpad directions, app_switch, volume_up/down/mute.";
                    return false;
                }
                arguments = ["-s", serial, "shell", "input", "keyevent", key];
                return true;
            default:
                error = "Unsupported Android verb.";
                return false;
        }
    }

    private static readonly Regex SafeSerial = new(
        "^[A-Za-z0-9._:-]{1,128}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(50));

    public static bool IsSafeSerial(string? serial)
    {
        try { return SafeSerial.IsMatch((serial ?? string.Empty).Trim()); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static bool TryCoordinate(CuAction action, string name, out string canonical)
    {
        canonical = string.Empty;
        if (!int.TryParse(action.Arg(name), NumberStyles.None, CultureInfo.InvariantCulture, out var value)
            || value is < 0 or > 100_000)
            return false;
        canonical = value.ToString(CultureInfo.InvariantCulture);
        return true;
    }

    private static bool TryInt(string text, int min, int max, int defaultValue, out int value)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            value = defaultValue;
            return true;
        }
        return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value)
               && value >= min && value <= max;
    }

    private static bool TryEncodeInputText(string text, out string encoded)
    {
        encoded = string.Empty;
        if (string.IsNullOrEmpty(text) || text.Length > 1000) return false;
        foreach (var c in text)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is ' ' or '.' or ',' or '_' or '@' or ':' or '/' or '+' or '-'))
                return false;
        }
        encoded = text.Replace(" ", "%s", StringComparison.Ordinal);
        return true;
    }

    private static readonly Dictionary<string, string> Keys = new(StringComparer.OrdinalIgnoreCase)
    {
        ["back"] = "KEYCODE_BACK",
        ["home"] = "KEYCODE_HOME",
        ["enter"] = "KEYCODE_ENTER",
        ["tab"] = "KEYCODE_TAB",
        ["delete"] = "KEYCODE_DEL",
        ["del"] = "KEYCODE_DEL",
        ["escape"] = "KEYCODE_ESCAPE",
        ["dpad_up"] = "KEYCODE_DPAD_UP",
        ["dpad_down"] = "KEYCODE_DPAD_DOWN",
        ["dpad_left"] = "KEYCODE_DPAD_LEFT",
        ["dpad_right"] = "KEYCODE_DPAD_RIGHT",
        ["dpad_center"] = "KEYCODE_DPAD_CENTER",
        ["app_switch"] = "KEYCODE_APP_SWITCH",
        ["volume_up"] = "KEYCODE_VOLUME_UP",
        ["volume_down"] = "KEYCODE_VOLUME_DOWN",
        ["volume_mute"] = "KEYCODE_VOLUME_MUTE",
    };

    private static bool TryKey(string? value, out string key) =>
        Keys.TryGetValue((value ?? string.Empty).Trim(), out key!);

    private static object[] ParseDevices(string output, IReadOnlySet<string> enrolled) =>
        output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Skip(1)
            .Select(static line => line.Trim())
            .Where(static line => line.Length > 0 && !line.StartsWith("*", StringComparison.Ordinal))
            .Select(line =>
            {
                var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                var serial = fields.ElementAtOrDefault(0) ?? string.Empty;
                return (object)new
                {
                    serial,
                    state = fields.ElementAtOrDefault(1) ?? "unknown",
                    enrolled = enrolled.Contains(serial),
                    details = fields.Skip(2).Take(12).ToArray(),
                };
            })
            .ToArray();

    private static string Text(byte[] bytes) => Encoding.UTF8.GetString(bytes);

    private static CuExecResult FromFailure(AdbCommandResult result)
    {
        var message = string.IsNullOrWhiteSpace(result.StandardError)
            ? $"adb exited with code {result.ExitCode}."
            : result.StandardError.Trim();
        message = Foreman.Core.Security.SecretRedactor.Redact(message);
        return Fail(message.Length <= 500 ? message : message[..500] + "…");
    }

    private static CuExecResult Fail(string error) => new(false, null, error);
}
