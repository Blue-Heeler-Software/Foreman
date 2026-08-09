#!/usr/bin/env bash
set -euo pipefail

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now foreman-agent.service 2>/dev/null || true
fi
systemctl --user stop foreman-desktop-session.service 2>/dev/null || true
pkill -x foreman-desktop 2>/dev/null || true

for target in \
  "$HOME/.config/systemd/user/foreman-agent.service" \
  "$HOME/.local/bin/foreman-agent" \
  "$HOME/.local/bin/foreman-desktop" \
  "$HOME/.local/lib/foreman/foreman-agent" \
  "$HOME/.local/lib/foreman/foreman-desktop" \
  "$HOME/.local/share/applications/foreman-desktop.desktop" \
  "$HOME/.config/autostart/foreman-desktop.desktop" \
  "$HOME/.local/share/icons/hicolor/128x128/apps/foreman-agent-safety.png"
do
  if [[ -e "$target" || -L "$target" ]]; then
    rm -f -- "$target"
  fi
done
rmdir "$HOME/.local/lib/foreman" 2>/dev/null || true
systemctl --user daemon-reload 2>/dev/null || true

echo "Foreman Agent Safety was removed. Config and audit evidence were preserved."
echo "To purge them explicitly, remove ~/.config/foreman, ~/.local/state/foreman, and ~/.local/share/foreman."
