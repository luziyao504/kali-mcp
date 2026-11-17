"""通用工具函数：文本清洗、截断、格式化、目标解析。"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex

MAX_OUTPUT = int(os.getenv("KALI_MCP_MAX_OUTPUT", "30000"))
DEFAULT_TIMEOUT = int(os.getenv("KALI_MCP_TIMEOUT", "120"))
SHELL_IDLE = 900

# 动态哨兵：拆两段打印，终端回显里永远拼不出完整标记，因此不依赖 shell 类型，
# 也不需要关回显或改 PS1。
MARKER_RE = re.compile(r"__MCP_READY_:(\d+)")
SENTINEL_CMD = "printf '%s%s:%s\\n' '__MC' 'P_READY_' \"$?\""

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def decode(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _ANSI.sub("", text)


def clip(text: str) -> str:
    if len(text) <= MAX_OUTPUT:
        return text
    head = text[: int(MAX_OUTPUT * 0.7)]
    tail = text[-int(MAX_OUTPUT * 0.3):]
    return f"{head}\n\n... [输出过长，中间已截断，共 {len(text)} 字符] ...\n\n{tail}"


def strip_echo(body: str, command: str) -> str:
    """去掉持久 shell 里回显的命令行与哨兵，让输出更干净。"""
    lines = body.split("\n")
    cmd_lines = [ln.strip() for ln in command.rstrip("\n").split("\n")]
    for i in range(max(0, len(lines) - len(cmd_lines) + 1)):
        window = [ln.strip() for ln in lines[i:i + len(cmd_lines)]]
        if window == cmd_lines:
            j = i + len(cmd_lines)
            while j < len(lines) and ("P_READY_" in lines[j] or "'__MC'" in lines[j]):
                j += 1
            return "\n".join(lines[:i] + lines[j:])
    return "\n".join(ln for ln in lines if "P_READY_" not in ln and "'__MC'" not in ln)


def fmt(res: dict) -> str:
    body = (res.get("output") or "").strip("\n")
    head = (
        f"exit_code: {res.get('exit_code')}\n"
        f"timed_out: {str(res.get('timed_out')).lower()}\n"
        f"elapsed: {res.get('elapsed')}s"
    )
    if res.get("artifact"):
        head += f"\nartifact: {res['artifact']}"
    return head + "\n---\n" + (body if body else "(无输出)")


def perm(mode: int) -> str:
    return oct(mode)[-3:]


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024 or unit == "TB":
            return f"{num:.0f}{unit}" if unit == "B" else f"{num:.1f}{unit}"
        num /= 1024
    return f"{num:.1f}TB"


def q(value: str) -> str:
    return shlex.quote(str(value))


def strip_scheme(target: str) -> str:
    """把 https://host:443/path 归一成 host。"""
    t = (target or "").strip()
    for prefix in ("http://", "https://", "ftp://", "ssh://"):
        if t.lower().startswith(prefix):
            t = t[len(prefix):]
    t = t.split("/")[0]
    return t


def target_kind(target: str) -> str:
    """判断目标是 ip / cidr / host / url。"""
    t = strip_scheme(target)
    try:
        ipaddress.ip_network(t, strict=False)
        return "cidr" if "/" in t else "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[a-zA-Z0-9._-]+", t):
        return "host"
    return "unknown"


def sanitize_token(value: str, allowed: str = r"[A-Za-z0-9._:/\-]") -> str:
    """给 ports / 文件名 之类的参数做白名单校验。"""
    return value if re.fullmatch(f"{allowed}+", value or "") else ""


def redact(text: str) -> str:
    """把疑似令牌/密码打码，避免产物里留下敏感串。"""
    return re.sub(r"(?i)(password|passwd|token|secret|api[_-]?key)(\s*[=:]\s*)(\S+)",
                  r"\1\2***", text)
