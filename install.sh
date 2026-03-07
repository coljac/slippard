#!/bin/sh
set -e

REPO="coljac/slippard"
INSTALL_DIR="${SLPD_INSTALL_DIR:-$HOME/.local/bin}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="macos" ;;
    *)      echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)             echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# macOS builds are both under "macos" directory name
if [ "$OS" = "macos" ]; then
    ASSET_PATTERN="slpd_.*_macos_${ARCH}\\.tar\\.gz"
else
    ASSET_PATTERN="slpd_.*_${OS}_${ARCH}\\.tar\\.gz"
fi

echo "Detecting latest release..."
DOWNLOAD_URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o "\"browser_download_url\": *\"[^\"]*${ASSET_PATTERN}\"" \
    | head -1 \
    | cut -d'"' -f4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "Error: could not find a release for ${OS}/${ARCH}" >&2
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading $(basename "$DOWNLOAD_URL")..."
curl -fsSL "$DOWNLOAD_URL" -o "$TMPDIR/slpd.tar.gz"

echo "Installing to ${INSTALL_DIR}/slpd..."
mkdir -p "$INSTALL_DIR"
tar -xzf "$TMPDIR/slpd.tar.gz" -C "$TMPDIR"
install -m 755 "$TMPDIR/slpd" "$INSTALL_DIR/slpd"

# Check if install dir is in PATH
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "Note: ${INSTALL_DIR} is not in your PATH. Add it with:"
       echo "  export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac

echo "slpd installed successfully: ${INSTALL_DIR}/slpd"
