#!/usr/bin/env bash
# Build a checksum-verified, self-contained Ubuntu x86-64 deployment bundle.

set -Eeuo pipefail

readonly REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly DOTNET_BIN="${DOTNET_ROOT:-$HOME/.dotnet}/dotnet"
readonly RID="linux-x64"
readonly ARTIFACTS_DIR="$REPO_DIR/artifacts"

[[ "$(uname -s)" == "Linux" ]] || {
  printf 'Run this packager on Linux.\n' >&2
  exit 1
}
[[ "$(uname -m)" == "x86_64" ]] || {
  printf 'This alpha packager currently targets x86-64 only.\n' >&2
  exit 1
}
[[ -x "$DOTNET_BIN" ]] || {
  printf 'A .NET 10 SDK is required at %s (or set DOTNET_ROOT).\n' "$DOTNET_BIN" >&2
  exit 1
}

mkdir -p "$ARTIFACTS_DIR"
work_dir="$(mktemp -d "$ARTIFACTS_DIR/.ubuntu-package.XXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

agent_publish="$work_dir/agent"
desktop_publish="$work_dir/desktop"

"$DOTNET_BIN" publish "$REPO_DIR/src/Foreman.Agent/Foreman.Agent.csproj" \
  -c Release -r "$RID" --self-contained true -o "$agent_publish"
"$DOTNET_BIN" publish "$REPO_DIR/src/Foreman.App.Linux/Foreman.App.Linux.csproj" \
  -c Release -r "$RID" --self-contained true -o "$desktop_publish"

version_output="$("$agent_publish/foreman-agent" version)"
version="$(printf '%s\n' "$version_output" | sed -n 's/^Foreman Agent Safety \([^ ]*\).*/\1/p')"
[[ -n "$version" && "$version" =~ ^[0-9A-Za-z.+-]+$ ]] || {
  printf 'Could not derive a safe version from: %s\n' "$version_output" >&2
  exit 1
}

bundle_name="foreman-agent-safety-${version}-${RID}"
bundle_dir="$work_dir/$bundle_name"
archive="$ARTIFACTS_DIR/$bundle_name.tar.gz"
archive_checksum="$archive.sha256"

if [[ -e "$archive" || -e "$archive_checksum" ]]; then
  printf 'Refusing to replace an existing release artifact:\n  %s\n' "$archive" >&2
  exit 1
fi

install -d -m 755 "$bundle_dir/payload"
install -m 755 "$agent_publish/foreman-agent" "$bundle_dir/payload/foreman-agent"
install -m 755 "$desktop_publish/foreman-desktop" "$bundle_dir/payload/foreman-desktop"
install -m 644 "$REPO_DIR/src/Foreman.App/Resources/foreman.png" "$bundle_dir/payload/foreman.png"

sed "s|@VERSION@|$version|g" \
  "$REPO_DIR/packaging/ubuntu/install-bundle.sh.in" > "$bundle_dir/install.sh"
sed "s|@VERSION@|$version|g" \
  "$REPO_DIR/packaging/ubuntu/BUNDLE_README.md.in" > "$bundle_dir/README.md"
install -m 755 "$REPO_DIR/packaging/ubuntu/uninstall-bundle.sh" "$bundle_dir/uninstall.sh"
chmod 755 "$bundle_dir/install.sh"
chmod 644 "$bundle_dir/README.md"

(
  cd "$bundle_dir"
  sha256sum \
    README.md \
    install.sh \
    uninstall.sh \
    payload/foreman-agent \
    payload/foreman-desktop \
    payload/foreman.png > SHA256SUMS
  sha256sum --check SHA256SUMS
)

tar -C "$work_dir" -czf "$archive" "$bundle_name"
(
  cd "$ARTIFACTS_DIR"
  sha256sum "$(basename -- "$archive")" > "$(basename -- "$archive_checksum")"
)

printf '\nUbuntu bundle created:\n  %s\n  %s\n' "$archive" "$archive_checksum"
