#!/usr/bin/env bash
# A made-up but very typical "curl | sh" installer for a tool called `zap`.
set -euo pipefail

VERSION="${ZAP_VERSION:-1.4.2}"
INSTALL_DIR="${ZAP_INSTALL:-$HOME/.zap}"
BIN_DIR="$INSTALL_DIR/bin"

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) echo "unsupported OS" >&2; exit 1 ;;
esac

arch="$(uname -m)"
url="https://github.com/example/zap/releases/download/v${VERSION}/zap-${os}-${arch}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading zap ${VERSION}..."
curl --fail --location --progress-bar --output "$tmp/zap.tar.gz" "$url"
tar -xzf "$tmp/zap.tar.gz" -C "$tmp"

mkdir -p "$BIN_DIR"
mv "$tmp/zap" "$BIN_DIR/zap"
chmod +x "$BIN_DIR/zap"

case "$SHELL" in
  */zsh)  PROFILE="$HOME/.zshrc" ;;
  */bash) PROFILE="$HOME/.bashrc" ;;
  *)      PROFILE="$HOME/.profile" ;;
esac

if ! grep -q '.zap/bin' "$PROFILE" 2>/dev/null; then
  echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$PROFILE"
fi

"$BIN_DIR/zap" --version
echo "Done! Restart your shell."
