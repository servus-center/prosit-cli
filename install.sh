#!/bin/sh
# Download a public release and verify its archive checksum before installation.
set -eu
umask 077
repository=https://github.com/servus-center/prosit-cli
version=${PROSIT_VERSION:-latest}
install_dir=${PROSIT_INSTALL_DIR:-"$HOME/.local/bin"}
case "$version" in
  latest) base="$repository/releases/latest/download" ;;
  v[0-9]*)
    case "$version" in *[!a-zA-Z0-9.-]*) echo "Invalid PROSIT_VERSION" >&2; exit 1;; esac
    base="$repository/releases/download/$version" ;;
  *) echo "Use PROSIT_VERSION=latest or a release tag such as v0.1.2" >&2; exit 1 ;;
esac
case "$(uname -s):$(uname -m)" in
  Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-gnu ;;
  Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu ;;
  Darwin:arm64) target=aarch64-apple-darwin ;;
  *) echo "Supported: Linux amd64/arm64 and macOS Apple Silicon." >&2; exit 1 ;;
esac
command -v curl >/dev/null
command -v tar >/dev/null
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
archive="prosit-$target.tar.gz"
curl --proto '=https' --tlsv1.2 -fsSL "$base/$archive" -o "$work/$archive"
curl --proto '=https' --tlsv1.2 -fsSL "$base/prosit-$target.sha256" -o "$work/checksum"
expected=$(awk 'NR==1 {print $1}' "$work/checksum")
case "$expected" in *[!a-fA-F0-9]*|'') echo "Invalid release checksum" >&2; exit 1;; esac
[ "${#expected}" -eq 64 ] || { echo "Invalid release checksum" >&2; exit 1; }
if command -v sha256sum >/dev/null; then
  actual=$(sha256sum "$work/$archive" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$work/$archive" | awk '{print $1}')
fi
[ "$actual" = "$expected" ] || { echo "Checksum mismatch; nothing installed." >&2; exit 1; }
[ "$(tar -tzf "$work/$archive")" = "prosit" ] || { echo "Unexpected archive contents" >&2; exit 1; }
tar -xzf "$work/$archive" -C "$work" prosit
[ -f "$work/prosit" ] && [ ! -L "$work/prosit" ] || { echo "Invalid executable" >&2; exit 1; }
mkdir -p "$install_dir"
install -m 755 "$work/prosit" "$install_dir/prosit"
printf 'Installed %s/prosit\nAdd %s to PATH if needed.\n' "$install_dir" "$install_dir"
"$install_dir/prosit" --version
