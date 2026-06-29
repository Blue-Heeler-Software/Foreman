using System.Windows;
using Foreman.Vault;

namespace Foreman.App.Windows;

/// <summary>
/// Standalone window (tray -> Vault…) that hosts the shared <see cref="VaultView"/>. The same view is also hosted
/// in the dashboard's Vault tab; both are backed by the one <see cref="VaultService"/>, so the vault's locked/
/// unlocked state is consistent and each surface refreshes its own display.
/// </summary>
public partial class VaultWindow : Window
{
    public VaultWindow(VaultService vault)
    {
        InitializeComponent();
        Content = new VaultView(vault);
    }
}
