#!/bin/sh
# ============================================================
# rdptun-server 一键安装脚本（交互式向导）
#
#   curl -fsSL https://raw.githubusercontent.com/yzcncc/rdptun/main/install-server.sh | sh
#
# 向导依次询问：
#   1. 对外监听地址（默认 0.0.0.0:3389，伪装成 Windows 远程桌面）
#   2. 转发目标 host:port（必填，例如 127.0.0.1:22）
#   3. NLA 登录用户名 / 密码（客户端连接时使用）
#   4. 证书方式：自动生成 Windows 风格自签名证书 / 指定 PEM
#
# 完成后：
#   - 二进制安装到 /usr/local/bin/rdptun-server
#   - 配置写入 /etc/rdptun/server.toml（0600）
#   - 注册 systemd 服务 rdptun-server 并立即启动
#
# 非交互模式（CI/脚本）：
#   RDPTUN_BIND=0.0.0.0:3389 RDPTUN_TARGET=127.0.0.1:22 \
#   RDPTUN_USER=operator RDPTUN_PASS='secret' \
#   sh install-server.sh --yes
#
# 其它参数：
#   --prefix /usr/local   安装前缀
#   --repo owner/repo     GitHub 仓库（默认 yzcncc/rdptun）
#   --version vX.Y.Z      指定版本
#   --file <tar.gz>       离线安装包
#   --no-systemd          不安装 systemd 服务
# ============================================================
set -eu

REPO="${RDPTUN_REPO:-yzcncc/rdptun}"
PREFIX="${RDPTUN_PREFIX:-/usr/local}"
CONF_DIR="/etc/rdptun"
SERVICE="rdptun-server"
ASSUME_YES=0
USE_SYSTEMD=auto
VERSION=""
LOCAL_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes)     ASSUME_YES=1; shift ;;
        --prefix)     PREFIX="$2"; shift 2 ;;
        --repo)       REPO="$2"; shift 2 ;;
        --version)    VERSION="$2"; shift 2 ;;
        --file)       LOCAL_FILE="$2"; shift 2 ;;
        --no-systemd) USE_SYSTEMD=no; shift ;;
        -h|--help)    sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

[ "$(id -u)" = "0" ] || { echo "error: 需要 root 权限运行" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

if have curl; then
    fetch() {
        curl -fsSL --retry 3 --retry-delay 1 "$1" -o "$2" 2>/dev/null && return 0
        curl -fsSL --http1.1 --retry 3 --retry-delay 1 "$1" -o "$2" 2>/dev/null && return 0
        have wget && wget -q --tries=3 -O "$2" "$1"
    }
elif have wget; then
    fetch() { wget -q --tries=3 -O "$2" "$1"; }
else
    echo "error: 需要 curl 或 wget" >&2; exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  HOST="x86_64" ;;
    aarch64|arm64) HOST="aarch64" ;;
    *) echo "error: 不支持的架构 $ARCH" >&2; exit 1 ;;
esac

# ---------- 交互输入辅助 ----------
ask() { # ask <var> <prompt> <default>
    _var="$1"; _prompt="$2"; _default="$3"
    if [ "$ASSUME_YES" = "1" ]; then
        eval "$_var=\"\${$_var:-$_default}\""
        return
    fi
    if [ -n "$_default" ]; then
        printf '%s [%s]: ' "$_prompt" "$_default"
    else
        printf '%s: ' "$_prompt"
    fi
    IFS= read -r _ans || _ans=""
    [ -n "$_ans" ] || _ans="$_default"
    eval "$_var=\"\$_ans\""
}

ask_secret() { # ask_secret <var> <prompt>
    _var="$1"; _prompt="$2"
    if [ "$ASSUME_YES" = "1" ]; then
        eval "$_var=\"\${$_var:-}\""
        return
    fi
    printf '%s: ' "$_prompt"
    stty -echo 2>/dev/null || true
    IFS= read -r _ans || _ans=""
    stty echo 2>/dev/null || true
    printf '\n'
    eval "$_var=\"\$_ans\""
}

echo "============================================================"
echo "  rdptun-server 安装向导"
echo "  对外呈现为开启了 NLA 的 Windows 远程桌面"
echo "============================================================"
echo

BIND="${RDPTUN_BIND:-}"
TARGET="${RDPTUN_TARGET:-}"
USER_NAME="${RDPTUN_USER:-}"
PASS="${RDPTUN_PASS:-}"
CHANNEL="${RDPTUN_CHANNEL:-TUNNEL}"
MACHINE="${RDPTUN_MACHINE:-}"
CERT_PATH="${RDPTUN_CERT:-}"
KEY_PATH="${RDPTUN_KEY:-}"

[ -n "$BIND" ]      || ask BIND "监听地址 (对外 RDP 端口)" "0.0.0.0:3389"
[ -n "$TARGET" ]    || ask TARGET "转发目标 host:port" ""
[ -n "$USER_NAME" ] || ask USER_NAME "NLA 登录用户名" "operator"
[ -n "$PASS" ]      || ask_secret PASS "NLA 登录密码"

[ -n "$TARGET" ] || { echo "error: 转发目标是必填项" >&2; exit 1; }
[ -n "$PASS" ]   || { echo "error: 密码不能为空" >&2; exit 1; }

if [ -z "$CERT_PATH" ] && [ "$ASSUME_YES" != "1" ]; then
    echo
    echo "证书方式："
    echo "  1) 自动生成 Windows 风格 RDP 自签名证书（推荐，6 个月自动续期）"
    echo "  2) 指定已有的 PEM 证书与私钥"
    printf '请选择 [1]: '
    IFS= read -r _choice || _choice=""
    case "${_choice:-1}" in
        2)
            ask CERT_PATH "证书路径 (PEM)" ""
            ask KEY_PATH  "私钥路径 (PEM)" ""
            ;;
        *) : ;;
    esac
fi

if [ -z "$MACHINE" ] && [ "$ASSUME_YES" != "1" ]; then
    ask MACHINE "证书里的计算机名 (留空随机生成)" ""
fi

echo
echo "---- 确认配置 ----"
echo "  监听       : $BIND"
echo "  转发目标   : $TARGET"
echo "  NLA 用户   : $USER_NAME"
echo "  隧道通道名 : $CHANNEL"
if [ -n "$CERT_PATH" ]; then
    echo "  证书       : $CERT_PATH / $KEY_PATH"
else
    echo "  证书       : 自动生成 (Windows 风格自签名)"
    [ -n "$MACHINE" ] && echo "  计算机名   : $MACHINE"
fi
echo
if [ "$ASSUME_YES" != "1" ]; then
    printf '继续安装？[Y/n]: '
    IFS= read -r _go || _go=""
    case "$_go" in [nN]*) echo "已取消"; exit 1 ;; esac
fi

# ---------- 获取安装包 ----------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -n "$LOCAL_FILE" ]; then
    echo "==> 使用本地安装包: $LOCAL_FILE"
    cp "$LOCAL_FILE" "$TMP/pkg.tar.gz"
else
    if [ -z "$VERSION" ]; then
        echo "==> 获取最新版本..."
        API="https://api.github.com/repos/$REPO/releases/latest"
        if fetch "$API" "$TMP/rel.json" 2>/dev/null; then
            VERSION=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$TMP/rel.json" | head -1)
        fi
        [ -n "$VERSION" ] || { echo "error: 无法获取最新版本，请用 --version 指定" >&2; exit 1; }
    fi
    echo "    版本: $VERSION"
    PKG="rdptun-${VERSION}-linux-${HOST}.tar.gz"
    echo "==> 下载 $PKG ..."
    fetch "https://github.com/$REPO/releases/download/$VERSION/$PKG" "$TMP/pkg.tar.gz" \
        || { echo "error: 下载失败" >&2; exit 1; }
fi

echo "==> 解包..."
tar xzf "$TMP/pkg.tar.gz" -C "$TMP"
[ -f "$TMP/rdptun-server-linux-$HOST" ] || { echo "error: 包内缺少 server 二进制" >&2; exit 1; }

# ---------- 安装 ----------
echo "==> 安装二进制到 $PREFIX/bin ..."
install -d "$PREFIX/bin"
install -m 0755 "$TMP/rdptun-server-linux-$HOST" "$PREFIX/bin/rdptun-server"

echo "==> 写入配置 $CONF_DIR/server.toml ..."
install -d -m 0700 "$CONF_DIR"

{
    printf '# rdptun-server 配置（由 install-server.sh 生成）\n'
    printf 'bind = "%s"\n' "$BIND"
    printf 'target = "%s"\n' "$TARGET"
    printf 'username = "%s"\n' "$USER_NAME"
    printf 'password = "%s"\n' "$PASS"
    printf 'channel = "%s"\n' "$CHANNEL"
    printf 'cert_store_dir = "%s/certs"\n' "$CONF_DIR"
    [ -n "$MACHINE" ] && printf 'machine_name = "%s"\n' "$MACHINE"
    if [ -n "$CERT_PATH" ] && [ -n "$KEY_PATH" ]; then
        printf 'cert_path = "%s"\n' "$CERT_PATH"
        printf 'key_path = "%s"\n' "$KEY_PATH"
    fi
    printf 'max_sessions = 64\n'
    printf 'desktop_size = [1280, 720]\n'
} > "$CONF_DIR/server.toml"
chmod 0600 "$CONF_DIR/server.toml"

# ---------- systemd ----------
if [ "$USE_SYSTEMD" != "no" ] && have systemctl && [ -d /run/systemd/system ]; then
    echo "==> 注册 systemd 服务 ..."
    cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=rdptun server (RDP-camouflaged TCP tunnel)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PREFIX/bin/rdptun-server --config $CONF_DIR/server.toml
Restart=always
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$CONF_DIR
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    systemctl restart "$SERVICE"
    sleep 1
    if systemctl is-active --quiet "$SERVICE"; then
        echo "==> 服务已启动"
    else
        echo "!! 服务启动失败，请查看: journalctl -u $SERVICE -n 50" >&2
    fi
else
    echo "==> 未安装 systemd 服务，可手动运行："
    echo "    $PREFIX/bin/rdptun-server --config $CONF_DIR/server.toml"
fi

echo
echo "============================================================"
echo "  安装完成"
echo "============================================================"
echo "  服务端监听 : $BIND"
echo "  转发目标   : $TARGET"
echo "  客户端填写 : 服务器 <本机IP>:$BIND  用户 $USER_NAME  通道 $CHANNEL"
echo
echo "  管理命令："
echo "    systemctl status $SERVICE"
echo "    systemctl restart $SERVICE"
echo "    journalctl -u $SERVICE -f"
echo
echo "  提示：若开启了防火墙，请放行对应端口。"
echo "============================================================"
