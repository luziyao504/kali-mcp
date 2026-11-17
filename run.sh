#!/usr/bin/env bash
# 前台启动（开发调试用，不用装 systemd）
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -e .
fi

exec .venv/bin/kali-mcp --host "${KALI_MCP_BIND:-127.0.0.1}" --port "${KALI_MCP_PORT:-8765}" \
  --state-dir "${KALI_MCP_DATA:-$(pwd)/data}" "$@"
