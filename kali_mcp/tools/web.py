"""Web 安全测试：目录/参数爆破、指纹、漏洞扫描、注入测试、WAF 识别。"""

from __future__ import annotations

import re

from mcp.server.fastmcp import FastMCP

from ..engine import Engine
from ..toolkit import guard, need, sh, shv
from ..util import q

_WL = "/usr/share/wordlists/dirb/common.txt"


def _wordlist(eng: Engine, custom: str) -> str:
    if custom:
        return custom
    for cand in (_WL, "/usr/share/seclists/Discovery/Web-Content/common.txt",
                 "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"):
        try:
            import os
            if os.path.isfile(cand):
                return cand
        except Exception:
            continue
    return _WL


def register(mcp: FastMCP, eng: Engine) -> None:

    @mcp.tool()
    def kali_http_request(url: str, method: str = "GET", headers: str = "", body: str = "",
                          timeout: int = 60, insecure: bool = True) -> str:
        """发任意 HTTP 请求（自定义方法/头/体），常用于验证接口、盲测、复现 PoC。

        Args:
            url: 完整 URL
            method: GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS
            headers: 形如 "X-Token: abc;Content-Type: application/json"
            body: 请求体
            insecure: 忽略证书错误
        """
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("curl"):
            return need(eng, "curl", "curl") or ""
        m = method.upper()
        if m not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            return f"不支持的方法: {method}"
        argv = ["curl", "-k" if insecure else "-s", "-sS", "-m", str(max(5, int(timeout))),
                "-i", "-X", m]
        for h in [x.strip() for x in (headers or "").split(";") if x.strip()]:
            argv += ["-H", h]
        if body:
            argv += ["--data-raw", body]
        argv.append(url)
        return shv(eng, "kali_http_request", argv, timeout + 20)

    @mcp.tool()
    def kali_whatweb(url: str, aggressive: bool = False, timeout: int = 120) -> str:
        """Web 指纹识别：CMS、框架、中间件、版本、插件。"""
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("whatweb"):
            return need(eng, "whatweb", "whatweb") or ""
        argv = ["whatweb", "-a", "3" if aggressive else "1", url]
        return shv(eng, "kali_whatweb", argv, timeout)

    @mcp.tool()
    def kali_wafw00f(url: str, timeout: int = 120) -> str:
        """WAF 识别（有 WAF 时后续扫描策略要相应调整）。"""
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("wafw00f"):
            return need(eng, "wafw00f", "wafw00f") or ""
        return shv(eng, "kali_wafw00f", ["wafw00f", url], timeout)

    @mcp.tool()
    def kali_nikto(url: str, tuning: str = "123b", timeout: int = 600) -> str:
        """Nikto Web 服务器扫描（常见危险文件、配置错误、过时组件）。"""
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("nikto"):
            return need(eng, "nikto", "nikto") or ""
        return shv(eng, "kali_nikto", ["nikto", "-host", url, "-Tuning", tuning, "-nointeractive"], timeout)

    @mcp.tool()
    def kali_ffuf(url: str, wordlist: str = "", mode: str = "dir", extensions: str = "",
                  timeout: int = 600, extra: str = "") -> str:
        """ffuf 高速模糊测试（目录发现 / 参数发现 / 子域发现）。

        Args:
            url: 目标，FUZZ 位置用 FUZZ 占位，如 "https://x.com/FUZZ"
            wordlist: 字典路径，留空用内置字典
            mode: dir（默认）/ vhost / param（决定匹配策略）
            extensions: 如 "php,html,js"
            extra: 额外参数，如 "-mc 200,301 -fs 0"
        """
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("ffuf"):
            return need(eng, "ffuf", "ffuf") or ""
        wl = _wordlist(eng, wordlist)
        argv = ["ffuf", "-w", wl]
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        argv += ["-u", url]
        if extensions:
            if not re.fullmatch(r"[A-Za-z0-9,.]+", extensions):
                return f"extensions 不合法: {extensions}"
            argv += ["-e", extensions]
        if mode == "vhost":
            argv += ["-H", "Host: FUZZ"]
        elif mode == "param":
            argv += ["-H", "Content-Type: application/x-www-form-urlencoded"]
        argv += ["-s", "-t", "40", "-timeout", "10"]
        if extra:
            argv += [t for t in extra.split() if re.fullmatch(r"[-A-Za-z0-9_.,:/=]+", t)]
        return shv(eng, "kali_ffuf", argv, timeout)

    @mcp.tool()
    def kali_gobuster(url: str, wordlist: str = "", mode: str = "dir", extensions: str = "",
                      timeout: int = 600) -> str:
        """gobuster 目录/DNS/VHost 枚举。

        Args:
            url: 目标 URL（dir 模式）或域名（dns 模式）
            wordlist: 字典，留空用内置
            mode: dir / dns / vhost / fuzz
            extensions: 如 "php,html"
        """
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("gobuster"):
            return need(eng, "gobuster", "gobuster") or ""
        wl = _wordlist(eng, wordlist)
        argv = ["gobuster", mode, "-w", wl]
        if mode == "dir":
            argv += ["-u", url, "--no-error", "--timeout", "10s"]
            if extensions:
                argv += ["-x", extensions]
        elif mode == "dns":
            argv += ["-d", url]
        elif mode == "vhost":
            argv += ["-u", url]
        else:
            argv += ["-u", url]
        return shv(eng, "kali_gobuster", argv, timeout)

    @mcp.tool()
    def kali_dirb(url: str, wordlist: str = "", timeout: int = 600) -> str:
        """dirb 经典目录爆破（保守但兼容性最好）。"""
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("dirb"):
            return need(eng, "dirb", "dirb") or ""
        argv = ["dirb", url] + ([_wordlist(eng, wordlist)] if wordlist else [])
        return shv(eng, "kali_dirb", argv, timeout)

    @mcp.tool()
    def kali_nuclei(target: str, severity: str = "", tags: str = "", templates: str = "",
                    timeout: int = 900) -> str:
        """nuclei 模板化漏洞扫描（CVE、默认配置、暴露面板、敏感文件）。

        Args:
            target: URL 或 host
            severity: 如 "critical,high,medium"
            tags: 如 "cve,exposure,panel"
            templates: 指定模板路径或关键字，如 "http/cves/2024"
        """
        err = guard(eng, target)
        if err:
            return err
        if not eng.which("nuclei"):
            return need(eng, "nuclei", "nuclei") or ""
        argv = ["nuclei", "-u", target, "-nc", "-duc"]
        if severity and re.fullmatch(r"[a-z,]+", severity):
            argv += ["-severity", severity]
        if tags and re.fullmatch(r"[A-Za-z0-9,._-]+", tags):
            argv += ["-tags", tags]
        if templates:
            argv += ["-t", templates]
        return shv(eng, "kali_nuclei", argv, timeout)

    @mcp.tool()
    def kali_sqlmap(url: str, level: int = 1, risk: int = 1, data: str = "", cookie: str = "",
                    extra: str = "", timeout: int = 900, batch: bool = True) -> str:
        """sqlmap SQL 注入检测（默认 batch 模式，不交互）。

        Args:
            url: 目标 URL（含参数）
            level: 1-5，测试深度
            risk: 1-3，测试风险
            data: POST 数据
            cookie: Cookie 串
            extra: 额外参数，如 "--dbs"、"‑‑tables"
            batch: 默认 True 全自动
        """
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("sqlmap"):
            return need(eng, "sqlmap", "sqlmap") or ""
        argv = ["sqlmap", "-u", url, f"--level={max(1, min(5, int(level)))}",
                f"--risk={max(1, min(3, int(risk)))}"]
        if batch:
            argv += ["--batch", "--smart"]
        if data:
            argv += ["--data", data]
        if cookie:
            argv += ["--cookie", cookie]
        if extra:
            argv += [t for t in extra.split() if re.fullmatch(r"[-A-Za-z0-9_.,:/=]+", t)]
        return shv(eng, "kali_sqlmap", argv, timeout)

    @mcp.tool()
    def kali_wpscan(url: str, enumerate: str = "vp,vt,u", timeout: int = 600) -> str:
        """WordPress 专项扫描（版本、插件、主题、用户枚举）。"""
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("wpscan"):
            return need(eng, "wpscan", "wpscan") or ""
        argv = ["wpscan", "--url", url, "--no-banner", "--random-user-agent"]
        if enumerate:
            argv += ["--enumerate", enumerate]
        return shv(eng, "kali_wpscan", argv, timeout)

    @mcp.tool()
    def kali_dalfox(url: str, timeout: int = 300) -> str:
        """dalfox XSS 扫描（反射型/基于 DOM 的参数验证）。"""
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("dalfox"):
            return need(eng, "dalfox", "dalfox", alt="用 ffuf + 手工验证") or ""
        return shv(eng, "kali_dalfox", ["dalfox", "url", url, "--no-spinner"], timeout)
