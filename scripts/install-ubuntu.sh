#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dotnet_bin="${DOTNET_ROOT:-$HOME/.dotnet}/dotnet"
publish_dir="$repo_dir/artifacts/ubuntu-linux-x64"
desktop_publish_dir="$repo_dir/artifacts/ubuntu-desktop-linux-x64"
install_dir="$HOME/.local/lib/foreman"
bin_dir="$HOME/.local/bin"
unit_dir="$HOME/.config/systemd/user"
applications_dir="$HOME/.local/share/applications"
autostart_dir="$HOME/.config/autostart"
icon_dir="$HOME/.local/share/icons/hicolor/128x128/apps"

if [[ ! -x "$dotnet_bin" ]]; then
  echo "A .NET 10 SDK is required. Set DOTNET_ROOT or install it under ~/.dotnet." >&2
  exit 1
fi

"$dotnet_bin" publish "$repo_dir/src/Foreman.Agent/Foreman.Agent.csproj" \
  -c Release -r linux-x64 --self-contained true -o "$publish_dir"
"$dotnet_bin" publish "$repo_dir/src/Foreman.App.Linux/Foreman.App.Linux.csproj" \
  -c Release -r linux-x64 --self-contained true -o "$desktop_publish_dir"

install -d -m 700 "$install_dir"
install -d -m 755 "$bin_dir" "$unit_dir" "$applications_dir" "$autostart_dir" "$icon_dir"
install -d -m 700 "$HOME/.config/foreman" "$HOME/.local/state/foreman" "$HOME/.local/share/foreman"
install -m 755 "$publish_dir/foreman-agent" "$install_dir/foreman-agent"
install -m 755 "$desktop_publish_dir/foreman-desktop" "$install_dir/foreman-desktop"
ln -sfn "$install_dir/foreman-agent" "$bin_dir/foreman-agent"
ln -sfn "$install_dir/foreman-desktop" "$bin_dir/foreman-desktop"
install -m 644 "$repo_dir/packaging/ubuntu/foreman-agent.service" "$unit_dir/foreman-agent.service"
install -m 644 "$repo_dir/src/Foreman.App/Resources/foreman.png" "$icon_dir/foreman-agent-safety.png"

desktop_tmp="$(mktemp)"
autostart_tmp="$(mktemp)"
trap 'rm -f -- "$desktop_tmp" "$autostart_tmp"' EXIT
sed "s|@HOME@|$HOME|g" "$repo_dir/packaging/ubuntu/foreman-desktop.desktop.in" > "$desktop_tmp"
sed "s|@HOME@|$HOME|g" "$repo_dir/packaging/ubuntu/foreman-desktop-autostart.desktop.in" > "$autostart_tmp"
install -m 644 "$desktop_tmp" "$applications_dir/foreman-desktop.desktop"
install -m 644 "$autostart_tmp" "$autostart_dir/foreman-desktop.desktop"

if command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload; then
  systemctl --user enable foreman-agent.service
  systemctl --user restart foreman-agent.service
  echo "Foreman Agent Safety installed and started."
else
  echo "Installed, but no systemd user session was available. Start with: foreman-agent run" >&2
fi

# Replace an older desktop process so an upgrade immediately uses the matching operator API/UI build.
systemctl --user stop foreman-desktop-session.service 2>/dev/null || true
pkill -x foreman-desktop 2>/dev/null || true
if [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
  if command -v systemd-run >/dev/null 2>&1 && systemd-run --user --unit=foreman-desktop-session --collect "$install_dir/foreman-desktop" >/dev/null; then
    echo "Foreman desktop opened in the current session."
  else
    nohup "$install_dir/foreman-desktop" >/dev/null 2>&1 < /dev/null &
  fi
fi

echo "Binary: $bin_dir/foreman-agent"
echo "GUI:    $bin_dir/foreman-desktop"
echo "Check:  $bin_dir/foreman-agent doctor"
