"""kali-mcp 服务端：FastMCP + Bearer Token 鉴权 + Resources + Prompts + CLI。

用法:
    kali-mcp                        # 默认 0.0.0.0:8765 /mcp
    kali-mcp --port 9000 --host 127.0.0.1
    kali-mcp --transport stdio      # 本地 stdio 模式（Claude Desktop 直连）
    kali-mcp --token <自定令牌>
"""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import sys

from mcp.server.fastmcp import FastMCP

from . import __version__
from .engine import Engine
from .tools import register_all

log = logging.getLogger("kali-mcp")


# ------------------------------------------------------------------ 令牌

def load_token(data_dir: str, override: str = "") -> str:
    token = (override or os.getenv("KALI_MCP_TOKEN") or "").strip()
    token_file = os.path.join(data_dir, "token.txt")
    if token:
        _write_token(token_file, token)
        return token
    if os.path.isfile(token_file):
        with open(token_file, "r", encoding="utf-8") as fh:
            saved = fh.read().strip()
        if saved:
            return saved
    token = secrets.token_urlsafe(32)
    _write_token(token_file, token)
    log.warning("未提供令牌，已生成并保存到 %s", token_file)
    return token


def _write_token(path: str, token: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


# ------------------------------------------------------------------ 组装

def build(eng: Engine, token: str, host: str, port: int, path: str) -> FastMCP:
    mcp = FastMCP("kali-mcp", host=host, port=port, streamable_http_path=path)
    register_all(mcp, eng)
    _register_resources(mcp, eng)
    _register_prompts(mcp)
    return mcp


def _register_resources(mcp: FastMCP, eng: Engine) -> None:
    """把范围、findings、产物暴露成 MCP resources，客户端可直接读取。"""

    @mcp.resource("kali://scope")
    def scope_resource() -> str:
        entries = eng.scope()
        return ("未设置授权范围（不限制）" if not entries else
                "\n".join(f"- {e}" for e in entries))

    @mcp.resource("kali://notes")
    def notes_resource() -> str:
        return eng.note_list()

    @mcp.resource("kali://artifacts")
    def artifacts_resource() -> str:
        rows = eng.artifacts(50)
        return "\n".join(f"{r['mtime']}  {r['size']:>8}  {r['path']}" for r in rows) or "(暂无产物)"

    @mcp.resource("kali://host")
    def host_resource() -> str:
        return eng.status()


def _register_prompts(mcp: FastMCP) -> None:
    """常见任务的标准流程模板，客户端可直接选用。"""

    @mcp.prompt()
    def recon(domain: str) -> str:
        """对目标做一轮完整的只读侦察，最后给出资产与风险清单。"""
        return (
            f"目标：{domain}\n\n"
            "请按顺序执行，并在每步后记录结果：\n"
            f"1. kali_scope_show 确认授权范围；不在范围内则 kali_scope_set 添加后重来\n"
            f"2. kali_whois / kali_dns_lookup / kali_dns_enum 收集归属与解析\n"
            f"3. kali_subfinder 或 kali_amass 枚举子域\n"
            f"4. kali_http_probe + kali_tls_info + kali_whatweb 做指纹\n"
            f"5. kali_nmap（-sV，常见端口）确认暴露面\n"
            "6. 把每个结论用 kali_note_add 记录（severity 按风险判定）\n"
            "7. kali_report 导出报告并给出下一步建议"
        )

    @mcp.prompt()
    def web_assessment(url: str) -> str:
        """对单个 Web 目标做分层测试，从低影响逐步升级。"""
        return (
            f"目标：{url}\n\n"
            "1. kali_http_probe / kali_tls_info 看响应头与证书\n"
            "2. kali_whatweb / kali_wafw00f 判指纹与 WAF\n"
            "3. kali_ffuf 目录爆破（先小字典），命中后 kali_gobuster -x 扩展\n"
            "4. kali_nikto 做基线扫描\n"
            "5. kali_nuclei 按 severity=medium,high,high 打模板\n"
            "6. 有参数点再上 kali_sqlmap（level=1 risk=1 起步）或 kali_dalfox\n"
            "7. 全部结论用 kali_note_add 记录，最后 kali_report"
        )

    @mcp.prompt()
    def internal_pentest(subnet: str) -> str:
        """内网横向：主机发现 → 服务枚举 → 凭据面 → 横向路径。"""
        return (
            f"网段：{subnet}\n\n"
            "1. kali_arp_scan / kali_nmap -sn 找出存活主机\n"
            "2. 对存活主机 kali_nmap（-sV -sC，全端口或 top 1000）\n"
            "3. SMB 面：kali_enum4linux、kali_smbclient、kali_cme\n"
            "4. 弱口令：kali_hydra（先确认授权，limit 用户/密码列表规模）\n"
            "5. 拿到凭据后 kali_cme 批量验证，评估可扩散范围\n"
            "6. 记录 findings 并 kali_report，注意只做授权范围内的动作"
        )

    @mcp.prompt()
    def hardening() -> str:
        """对这台 Kali 自身做一次体检与加固建议。"""
        return (
            "1. kali_doctor 看环境与依赖\n"
            "2. kali_users 检查可登录账户，kali_service list 看多余服务\n"
            "3. kali_ports 看监听面，确认没有意外暴露的服务\n"
            "4. kali_cron_list 检查定时任务是否被植入\n"
            "5. kali_history 回看近期操作，判定期望外行为\n"
            "6. 汇总成加固清单，并用 kali_report 导出"
        )


# ------------------------------------------------------------------ HTTP 鉴权

def http_app(mcp: FastMCP, token: str):
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    class TokenAuth(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.method == "OPTIONS":
                return await call_next(request)
            if request.url.path.rstrip("/") in ("", "/health"):
                return JSONResponse({"ok": True, "server": "kali-mcp", "version": __version__})
            auth = request.headers.get("authorization", "")
            given = auth[7:].strip() if auth.lower().startswith("bearer ") else \
                request.headers.get("x-mcp-token", "") or request.query_params.get("token", "")
            if not secrets.compare_digest(given, token):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return await call_next(request)

    app = mcp.streamable_http_app()
    app.add_middleware(TokenAuth)
    return app


# ------------------------------------------------------------------ CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kali-mcp", description="Kali 维护与渗透 MCP 服务")
    ap.add_argument("--host", default=os.getenv("KALI_MCP_BIND", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.getenv("KALI_MCP_PORT", "8765")))
    ap.add_argument("--path", default=os.getenv("KALI_MCP_PATH", "/mcp"))
    ap.add_argument("--token", default="", help="访问令牌，默认读环境/文件/自动生成")
    ap.add_argument("--state-dir", default=os.getenv("KALI_MCP_DATA", ""))
    ap.add_argument("--transport", choices=["http", "stdio"], default="http")
    ap.add_argument("--version", action="version", version=f"kali-mcp {__version__}")
    args = ap.parse_args(argv)

    data_dir = args.state_dir or os.path.join(os.getcwd(), "data")
    os.makedirs(data_dir, exist_ok=True)

    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s [kali-mcp] %(levelname)s %(message)s")

    eng = Engine(data_dir)
    token = "" if args.transport == "stdio" else load_token(data_dir, args.token)
    mcp = build(eng, token, args.host, args.port, args.path)

    if args.transport == "stdio":
        mcp.run("stdio")
        return 0

    import uvicorn
    log.info("kali-mcp %s 启动: http://%s:%s%s", __version__, args.host, args.port, args.path)
    log.info("令牌文件: %s", os.path.join(data_dir, "token.txt"))
    uvicorn.run(http_app(mcp, token), host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
