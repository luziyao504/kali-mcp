"""工具注册总入口。"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..engine import Engine
from . import creds, exploit, files, meta, net, recon, system, web, wireless


def register_all(mcp: FastMCP, eng: Engine) -> None:
    for module in (system, files, net, recon, web, creds, exploit, wireless, meta):
        module.register(mcp, eng)
