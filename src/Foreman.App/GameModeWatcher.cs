using Foreman.Core.Models;
using System.Runtime.InteropServices;

namespace Foreman.App;

/// <summary>
/// Detects "game mode" by polling <c>SHQueryUserNotificationState</c> — the same shell signal Windows uses
/// to decide whether to show toast notifications. Reports active when a fullscreen DirectX game, a
/// fullscreen app, or presentation mode is running, and raises <see cref="Changed"/> on transitions so the
/// tray can pause its on-screen popups. Cheap; polled every few seconds. Best-effort — any query failure
/// just leaves game mode off.
/// </summary>
public sealed class GameModeWatcher : IDisposable
{
    [DllImport("shell32.dll")]
    private static extern int SHQueryUserNotificationState(out int state);

    private readonly System.Threading.Timer _timer;

    /// <summary>True while a fullscreen game/app/presentation is detected.</summary>
    public bool IsActive { get; private set; }

    /// <summary>Raised on transition; argument is the new IsActive (true = entered game mode).</summary>
    public event Action<bool>? Changed;

    public GameModeWatcher()
        => _timer = new System.Threading.Timer(_ => Poll(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4));

    private void Poll()
    {
        try
        {
            if (SHQueryUserNotificationState(out var raw) != 0) return;   // HRESULT != S_OK
            var active = GameModePolicy.IsFullscreen((UserNotificationState)raw);
            if (active != IsActive)
            {
                IsActive = active;
                Changed?.Invoke(active);
            }
        }
        catch { /* shell query is best-effort; leave state unchanged */ }
    }

    public void Dispose() => _timer.Dispose();
}
