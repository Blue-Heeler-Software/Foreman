using Foreman.Core.Models;
using Foreman.Monitor;

namespace Foreman.Agent.Tests;

public sealed class LinuxHarnessClassifierTests
{
    [Theory]
    [InlineData("codex", "", "codex")]
    [InlineData("claude", "", "claude-code")]
    [InlineData("gemini", "", "gemini-cli")]
    [InlineData("opencode", "", "opencode")]
    [InlineData("aider", "", "aider")]
    [InlineData("ollama", "serve", "ollama")]
    [InlineData("node", "/usr/lib/node_modules/@openai/codex/bin/codex", "codex")]
    [InlineData("python3", "/venv/bin/python3 -m aider", "aider")]
    public void ClassifiesLinuxProcessNames(string name, string commandLine, string expected)
    {
        var record = new ProcessRecord
        {
            Pid = 100,
            ParentPid = 1,
            Name = name,
            CommandLine = commandLine,
            StartTime = DateTimeOffset.UtcNow,
            LastIoChangeTime = DateTimeOffset.UtcNow,
        };

        HarnessClassifier.Classify(record);

        Assert.True(record.IsHarness);
        Assert.Equal(expected, record.HarnessType);
    }

    [Theory]
    [InlineData("foreman-agent")]
    [InlineData("systemd")]
    [InlineData("dbus-broker")]
    [InlineData("gnome-shell")]
    [InlineData("kwin_wayland")]
    public void LinuxSafetyProcessesAreNeverKillable(string name)
    {
        Assert.True(KillGuard.IsProtected(9000, name));
    }
}
