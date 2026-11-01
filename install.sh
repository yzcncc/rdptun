#!/bin/sh
# ============================================================
# rdptun 一键安装脚本
#
# 用法：
#   安装最新 release（server + client）：
#     curl -fsSL https://raw.githubusercontent.com/yzcncc/rdptun/main/install.sh | sh
#
#   只装 server 或 client：
#     curl -fsSL ... | sh -s -- --only server
#
#   指定版本 / 安装目录 / 本地文件：
#     sh install.sh --version v0.1.0
#     sh install.sh --prefix /usr/local
#     sh install.sh --file rdptun-v0.1.0-linux-x86_64.tar.gz
#
# 安装内容：
#   $PREFIX/bin/rdptun-server
#   $PREFIX/bin/rdptun-client
#   $PREFIX/share/rdptun/server.example.toml
#   $PREFIX/share/rdptun/client.example.toml
# ============================================================
set -eu

REPO_DEFAULT="yzcncc/rdptun"
REPO="${RDPTUN_REPO:-$REPO_DEFAULT}"
PREFIX="${RDPTUN_PREFIX:-/usr/local}"
VERSION=""
ONLY=""
LOCAL_FILE=""

usage() { sed -n '2,25p' "$0"; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)     REPO="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        --prefix)   PREFIX="$2"; shift 2 ;;
        --only)     ONLY="$2"; shift 2 ;;
        --file)     LOCAL_FILE="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

# ---- 平台探测 ----
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   HOST="x86_64" ;;
    aarch64|arm64)  HOST="aarch64" ;;
    *) echo "error: unsupported arch: $ARCH" >&2; exit 1 ;;
esac

OS="$(uname -s)"
[ "$OS" = "Linux" ] || { echo "error: only Linux is supported (got $OS)" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }
FETCH=""
if have curl; then FETCH="curl -fsSL";
elif have wget; then FETCH="wget -qO-";
else echo "error: need curl or wget" >&2; exit 1; fi

fetch() { # fetch <url> <outfile>
    if have curl; then curl -fsSL "$1" -o "$2"; else wget -qO "$2" "$1"; fi
}

# ---- 决定版本 ----
if [ -z "$VERSION" ] && [ -z "$LOCAL_FILE" ]; then
    echo "==> resolving latest release..."
    LATEST_URL="https://api.github.com/repos/$REPO/releases/latest"
    VERSION=$($FETCH "$LATEST_URL" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$VERSION" ] || { echo "error: cannot resolve latest release; specify --version" >&2; exit 1; }
fi
echo "==> version: ${VERSION:-<local file>}"

# ---- 下载 ----
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -n "$LOCAL_FILE" ]; then
    cp "$LOCAL_FILE" "$TMP/pkg.tar.gz"
else
    BASE="https://github.com/$REPO/releases/download/$VERSION"
    PKG="rdptun-${VERSION}-linux-${HOST}.tar.gz"
    echo "==> downloading $PKG ..."
    fetch "$BASE/$PKG" "$TMP/pkg.tar.gz" || { echo "error: download failed" >&2; exit 1; }
    # 校验 sha256（如果提供）
    if fetch "$BASE/$PKG.sha256" "$TMP/pkg.sha256" 2>/dev/null; then
        (cd "$TMP" && sed -i "s| .*$|  $PKG|" pkg.sha256 && sha256sum -c pkg.sha256 >/dev/null 2>&1) \
            && echo "==> checksum OK" || echo "!! checksum check skipped/failed, continuing" >&2
    fi
fi

echo "==> extracting..."
tar xzf "$TMP/pkg.tar.gz" -C "$TMP"

# ---- 安装 ----
BIN_DIR="$PREFIX/bin"
SHARE_DIR="$PREFIX/share/rdptun"
mkdir -p "$BIN_DIR" "$SHARE_DIR"

install_one() { # install_one <binary name in archive> <install name>
    [ -f "$TMP/$1" ] || { echo "error: $1 not found in package" >&2; exit 1; }
    install -m 0755 "$TMP/$1" "$BIN_DIR/$2"
    echo "==> installed $BIN_DIR/$2"
}

case "$ONLY" in
    server) install_one "rdptun-server-linux-$HOST" rdptun-server ;;
    client) install_one "rdptun-client-linux-$HOST" rdptun-client ;;
    ""|all)
        install_one "rdptun-server-linux-$HOST" rdptun-server
        install_one "rdptun-client-linux-$HOST" rdptun-client
        ;;
    *) echo "error: --only must be server|client" >&2; exit 1 ;;
esac

# 示例配置
[ -f "$TMP/server.example.toml" ] && install -m 0644 "$TMP/server.example.toml" "$SHARE_DIR/" 2>/dev/null || true
[ -f "$TMP/client.example.toml" ] && install -m 0644 "$TMP/client.example.toml" "$SHARE_DIR/" 2>/dev/null || true
echo "==> examples in $SHARE_DIR"

echo
echo "rdptun installed."
echo "  server: $BIN_DIR/rdptun-server --config server.toml"
echo "  client: $BIN_DIR/rdptun-client --config client.toml"
