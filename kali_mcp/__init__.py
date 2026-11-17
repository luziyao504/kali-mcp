"""kali-mcp —— 把 Kali Linux 的全部维护与渗透能力包装成一个 MCP Server。

在 Kali 本机启动服务，任何支持 MCP 的客户端（Claude Desktop / Cherry Studio /
Cursor / Cline / 自研 Agent）即可通过自然语言驱动整台机器。

依赖的第三方工具都是 Kali 自带的 CLI，本项目只做封装、编排、留痕与报告。
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
