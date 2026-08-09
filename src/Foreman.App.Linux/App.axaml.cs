using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Platform;

namespace Foreman.App.Linux;

public sealed partial class App : Application
{
    private MainWindow? _window;
    private TrayIcon? _tray;
    private bool _quitting;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _window = new MainWindow();
            var startHidden = desktop.Args?.Any(static a => a == "--background") == true;
            if (startHidden)
                _window.Opened += (_, _) => _window.Hide();
            _window.Closing += (_, e) =>
            {
                if (_quitting) return;
                e.Cancel = true;
                _window.Hide();
            };
            desktop.MainWindow = _window;
            BuildTray(desktop);
        }
        base.OnFrameworkInitializationCompleted();
    }

    private void BuildTray(IClassicDesktopStyleApplicationLifetime desktop)
    {
        try
        {
            using var stream = AssetLoader.Open(new Uri("avares://foreman-desktop/Assets/foreman.png"));
            var show = new NativeMenuItem("Open Foreman");
            show.Click += (_, _) => ShowWindow();
            var refresh = new NativeMenuItem("Refresh now");
            refresh.Click += async (_, _) => { if (_window is not null) await _window.RefreshNowAsync(); };
            var quit = new NativeMenuItem("Quit desktop UI");
            quit.Click += (_, _) =>
            {
                _quitting = true;
                _tray?.Dispose();
                desktop.Shutdown();
            };
            var menu = new NativeMenu();
            menu.Items.Add(show);
            menu.Items.Add(refresh);
            menu.Items.Add(new NativeMenuItemSeparator());
            menu.Items.Add(quit);
            _tray = new TrayIcon
            {
                Icon = new WindowIcon(stream),
                ToolTipText = "Foreman Agent Safety",
                Menu = menu,
                IsVisible = true,
            };
            _tray.Clicked += (_, _) => ShowWindow();
        }
        catch
        {
            // Some Linux shells do not expose a tray protocol. The main window remains fully usable.
        }
    }

    private void ShowWindow()
    {
        if (_window is null) return;
        _window.Show();
        _window.Activate();
        _ = _window.RefreshNowAsync();
    }
}
