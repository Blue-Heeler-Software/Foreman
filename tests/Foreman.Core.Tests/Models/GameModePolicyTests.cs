using Foreman.Core.Models;

namespace Foreman.Core.Tests.Models;

public sealed class GameModePolicyTests
{
    [Theory]
    [InlineData(UserNotificationState.Busy, true)]
    [InlineData(UserNotificationState.RunningD3DFullScreen, true)]
    [InlineData(UserNotificationState.PresentationMode, true)]
    [InlineData(UserNotificationState.AcceptsNotifications, false)]
    [InlineData(UserNotificationState.QuietTime, false)]
    [InlineData(UserNotificationState.NotPresent, false)]
    [InlineData(UserNotificationState.App, false)]
    public void IsFullscreen_MapsTheGameAndFullscreenStates(UserNotificationState state, bool expected)
        => Assert.Equal(expected, GameModePolicy.IsFullscreen(state));

    private static readonly GameModeSettings On = new() { Enabled = true, AllowCriticalBreakThrough = false };
    private static readonly GameModeSettings OnBreakThrough = new() { Enabled = true, AllowCriticalBreakThrough = true };
    private static readonly GameModeSettings Off = new() { Enabled = false };

    [Fact]
    public void NotInGameMode_AlwaysSurfaces()
        => Assert.True(GameModePolicy.ShouldSurface(ForemanSeverity.Critical, On, gameModeActive: false));

    [Fact]
    public void Disabled_AlwaysSurfaces_EvenWhenGameDetected()
        => Assert.True(GameModePolicy.ShouldSurface(ForemanSeverity.Critical, Off, gameModeActive: true));

    [Theory]
    [InlineData(ForemanSeverity.Medium)]
    [InlineData(ForemanSeverity.High)]
    [InlineData(ForemanSeverity.Critical)]
    public void InGameMode_SuppressesEverything_ByDefault(ForemanSeverity sev)
        => Assert.False(GameModePolicy.ShouldSurface(sev, On, gameModeActive: true));

    [Fact]
    public void InGameMode_BreakThrough_LetsCriticalSurface_ButNotHigh()
    {
        Assert.True(GameModePolicy.ShouldSurface(ForemanSeverity.Critical, OnBreakThrough, gameModeActive: true));
        Assert.False(GameModePolicy.ShouldSurface(ForemanSeverity.High, OnBreakThrough, gameModeActive: true));
    }
}
