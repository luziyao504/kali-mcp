"""工具层通用封装：命令执行 + 安装检查 + 授权范围校验 + 产物归档 + 审计。

所有工具函数都走这里，保证行为一致：缺工具会提示怎么装，越界目标会被拦，
每次执行都会留审计和原始产物。
"""

from __future__ import annotations

import shlex

from .engine import Engine
from .util import fmt


def need(eng: Engine, binary: str, pkg: str = "", alt: str = "") -> str | None:
    """检查依赖工具是否安装；返回 None 表示可用，否则返回给模型的提示文本。"""
    cands = [b.strip() for b in (binary or "").split(",") if b.strip()]
    for name in cands:
        if eng.which(name):
            return None
    pkg = pkg or (cands[0] if cands else binary)
    hint = f"sudo apt install -y {pkg}" if pkg else "用 kali_install_tool 安装"
    tip = f"；也可用 {alt}" if alt else ""
    return (f"缺少命令: {' / '.join(cands)}。\n安装: {hint}{tip}\n"
            f"安装后重试，或用 kali_exec 直接执行其他等价命令。")


def guard(eng: Engine, target: str) -> str | None:
    """校验目标是否在授权范围内（未设置范围时不拦）。"""
    if not target:
        return None
    ok = eng.in_scope(target)
    if ok is False:
        entries = eng.scope()
        return (f"目标 {target!r} 不在当前授权范围 {entries} 内，已拦下。\n"
                f"确属授权目标请先 kali_scope_set 更新范围。")
    return None


def _finish(eng: Engine, tool: str, res: dict, command: str, artifact: bool) -> str:
    text = res.get("output") or ""
    if artifact:
        path = eng.save_artifact(tool, text, command)
        if path:
            res = dict(res, artifact=path)
    return fmt(res)


def sh(eng: Engine, tool: str, command: str, timeout: int = 120, sudo: bool = False,
       artifact: bool = True, note: str = "") -> str:
    """跑一条 shell 命令（参数已由调用方 quote）。"""
    eng.audit(tool, note or command)
    res = eng.run(command, timeout, sudo=sudo)
    return _finish(eng, tool, res, command, artifact)


def shv(eng: Engine, tool: str, argv: list[str], timeout: int = 120, sudo: bool = False,
        artifact: bool = True, note: str = "") -> str:
    """跑一个参数化命令（不经过 shell）。"""
    command = " ".join(shlex.quote(str(a)) for a in argv)
    eng.audit(tool, note or command)
    res = eng.runv([str(a) for a in argv], timeout, sudo=sudo)
    return _finish(eng, tool, res, command, artifact)


def table(rows: list[list[str]], headers: list[str]) -> str:
    if not rows:
        return "(空)"
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    out = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    out.append("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        out.append("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
    return "\n".join(out)
