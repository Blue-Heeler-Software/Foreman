using Foreman.Core.Settings;

namespace Foreman.Core.Tests.Settings;

public sealed class SettingsStoreTests : IDisposable
{
    private readonly string _dir;
    private readonly string _path;

    public SettingsStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "foreman-settings-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dir);
        _path = Path.Combine(_dir, "settings.json");
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Fact]
    public void Save_ThenLoad_RoundTrips()
    {
        var settings = new ForemanSettings { McpPort = 49152, HangThresholdMinutes = 7, IdleCleanupEnabled = true };
        settings.CustomHarnessExes.Add("myagent.exe");

        SettingsStore.Save(settings, _path);
        var loaded = SettingsStore.Load(_path);

        Assert.Equal(49152, loaded.McpPort);
        Assert.Equal(7, loaded.HangThresholdMinutes);
        Assert.True(loaded.IdleCleanupEnabled);
        Assert.Contains("myagent.exe", loaded.CustomHarnessExes);
        Assert.Null(SettingsStore.LastLoadFault);
    }

    [Fact]
    public void Save_OverwritesExisting_Atomically_NoTempLeft()
    {
        SettingsStore.Save(new ForemanSettings { McpPort = 11111 }, _path);
        SettingsStore.Save(new ForemanSettings { McpPort = 22222 }, _path);   // exercises the File.Replace swap path

        Assert.Equal(22222, SettingsStore.Load(_path).McpPort);
        Assert.False(File.Exists(_path + ".tmp"), "atomic write should not leave a .tmp behind");
    }

    [Fact]
    public void MissingFile_ReturnsDefaults_NoFault()
    {
        var loaded = SettingsStore.Load(_path);
        Assert.Equal(new ForemanSettings().McpPort, loaded.McpPort);
        Assert.Null(SettingsStore.LastLoadFault);
    }

    [Fact]
    public void CorruptFile_IsQuarantined_DefaultsLoaded_FaultReported()
    {
        File.WriteAllText(_path, "{ this is not valid json ");

        var loaded = SettingsStore.Load(_path);

        // defaults, not a crash or partial state
        Assert.Equal(new ForemanSettings().McpPort, loaded.McpPort);
        // the unreadable file was moved aside (so security posture isn't silently reset without trace)
        Assert.False(File.Exists(_path), "corrupt settings.json should be moved aside");
        Assert.NotEmpty(Directory.GetFiles(_dir, "settings.json.*.bad"));
        // and the fault is reported for the UI to surface
        Assert.NotNull(SettingsStore.LastLoadFault);
        Assert.Contains(".bad", SettingsStore.LastLoadFault!);
    }

    [Fact]
    public void Quarantine_ThenSave_ProducesAReadableFileAgain()
    {
        File.WriteAllText(_path, "}{ broken");
        SettingsStore.Load(_path);                                   // quarantines
        SettingsStore.Save(new ForemanSettings { McpPort = 33333 }, _path);

        Assert.Equal(33333, SettingsStore.Load(_path).McpPort);
        Assert.Null(SettingsStore.LastLoadFault);                    // a clean load clears the prior fault
    }
}
