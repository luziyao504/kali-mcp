#!/usr/bin/env bash
# kali-mcp 一键安装（在 Kali / Debian 系上运行）
#
#   git clone https://github.com/<you>/kali-mcp.git && cd kali-mcp
#   sudo bash install.sh                 # 装成 systemd 服务，开机自启
#   bash install.sh --port 9000          # 换端口
#   bash install.sh --no-service         # 只装依赖，手动运行
#   sudo bash install.sh --uninstall     # 卸载
#
# 安装后：systemctl status kali-mcp / journalctl -u kali-mcp -f
set -euo pipefail

APP=/opt/kali-mcp
SERVICE=kali-mcp
PORT="${KALI_MCP_PORT:-8765}"
BIND="${KALI_MCP_BIND:-0.0.0.0}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WITH_SERVICE=1

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --host) BIND="$2"; shift 2 ;;
    --prefix) APP="$2"; shift 2 ;;
    --no-service) WITH_SERVICE=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

if [ "${UNINSTALL:-0}" = "1" ]; then
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE}.service"
  systemctl daemon-reload
  read -r -p "删除 $APP ？[y/N] " yn
  [ "$yn" = "y" ] && rm -rf "$APP"
  echo "已卸载 $SERVICE"
  exit 0
fi

if [ "$(id -u)" != "0" ] && [ "$WITH_SERVICE" = "1" ]; then
  echo "装 systemd 服务需要 root：sudo bash install.sh"
  exit 1
fi

echo "==> 1/6 准备目录 $APP"
mkdir -p "$APP/data"
cp -r "$SRC/kali_mcp" "$APP/"
cp -f "$SRC/pyproject.toml" "$SRC/README.md" "$APP/" 2>/dev/null || true

echo "==> 2/6 创建 venv"
if [ ! -x "$APP/venv/bin/python" ]; then
  python3 -m venv "$APP/venv"
fi
"$APP/venv/bin/pip" install -q --upgrade pip

echo "==> 3/6 安装 kali-mcp"
"$APP/venv/bin/pip" install -q "$APP"

echo "==> 4/6 生成令牌"
TOKEN_FILE="$APP/data/token.txt"
if [ -s "$TOKEN_FILE" ]; then
  TOKEN="$(cat "$TOKEN_FILE")"
else
  TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
  printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
fi
chmod 600 "$TOKEN_FILE"

if [ "$WITH_SERVICE" = "0" ]; then
  echo
  echo "安装完成（未装服务）。前台启动："
  echo "  $APP/venv/bin/kali-mcp --host $BIND --port $PORT --state-dir $APP/data --token $TOKEN"
  exit 0
fi

echo "==> 5/6 写入 systemd 服务"
cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=kali-mcp - Kali 维护与渗透 MCP Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP
Environment=KALI_MCP_TOKEN=$TOKEN
Environment=KALI_MCP_BIND=$BIND
Environment=KALI_MCP_PORT=$PORT
Environment=KALI_MCP_DATA=$APP/data
ExecStart=$APP/venv/bin/kali-mcp --host $BIND --port $PORT --state-dir $APP/data
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"
echo -n "    等待监听 $PORT "
for _ in $(seq 1 25); do
  sleep 1
  if ss -tln 2>/dev/null | grep -q ":${PORT} "; then echo "ok"; break; fi
  echo -n "."
done

echo "==> 6/6 自检"
systemctl is-active "$SERVICE" || true
echo -n "    health: "
curl -s -m 8 -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:${PORT}/health" || echo "000"
echo -n "    无令牌应 401: "
curl -s -m 8 -o /dev/null -w '%{http_code}\n' -X POST "http://127.0.0.1:${PORT}/mcp" || echo "000"

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

✅ 安装完成
  服务:      $SERVICE ($(systemctl is-active "$SERVICE"))，开机自启
  监听:      $BIND:$PORT   路径 /mcp   （$BIND 是绑定地址，不能写进客户端 URL）
  令牌:      $TOKEN
  令牌文件:  $TOKEN_FILE (600)

  客户端 URL 按你的位置选：
    本机         http://127.0.0.1:$PORT/mcp        （只在 Kali 本机可用）
    同内网机器   http://${IP:-<内网IP>}:$PORT/mcp   （跨网络不通，需 VPN/隧道）
    VPN/隧道     用 VPN 分配的地址或隧道域名替换主机部分

客户端 mcpServers 配置（以本机为例）：
{
  "mcpServers": {
    "kali": {
      "type": "streamableHttp",
      "url": "http://127.0.0.1:$PORT/mcp",
      "headers": { "Authorization": "Bearer $TOKEN" }
    }
  }
}
不支持自定义 Header 的客户端，把令牌写进 URL：
    http://127.0.0.1:$PORT/mcp?token=$TOKEN

常用命令：
  systemctl status $SERVICE
  journalctl -u $SERVICE -f
  systemctl restart $SERVICE
EOF
