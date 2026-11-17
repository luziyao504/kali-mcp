"""元工具：武器库盘点、依赖体检、工具安装、findings 记录、范围管理、报告导出。"""

from __future__ import annotations

import os
import shlex

from mcp.server.fastmcp import FastMCP

from ..engine import Engine
from ..toolkit import sh, table
from ..util import clip, fmt

# 按用途分类的常用 Kali 工具，arsenal / doctor 都基于它
ARSENAL = {
    "侦察/扫描": ["nmap", "masscan", "rustscan", "arp-scan", "netdiscover", "nbtscan"],
    "DNS/OSINT": ["dig", "whois", "dnsenum", "dnsrecon", "amass", "subfinder", "theHarvester"],
    "Web": ["curl", "whatweb", "wafw00f", "nikto", "ffuf", "gobuster", "dirb", "wfuzz",
            "sqlmap", "nuclei", "wpscan", "dalfox", "burpsuite", "zaproxy"],
    "凭据": ["hydra", "medusa", "john", "hashcat", "hashid", "zip2john"],
    "利用": ["msfconsole", "msfvenom", "searchsploit", "setoolkit", "impacket-GetNPUsers"],
    "内网/AD": ["enum4linux", "smbclient", "crackmapexec", "nxc", "ldapsearch", "snmpwalk",
                "responder", "bettercap", "chisel", "proxychains4"],
    "无线": ["aircrack-ng", "airmon-ng", "airodump-ng", "hcxdumptool", "wifite"],
    "流量/取证": ["tcpdump", "tshark", "wireshark", "binwalk", "strings", "foremost", "volatility3"],
    "开发/环境": ["python3", "gcc", "make", "git", "docker", "tmux", "jq", "nc", "socat"],
}


def _presence(eng: Engine) -> tuple[list[tuple[str, str, bool]], int]:
    rows = []
    present = 0
    total = 0
    for group, tools in ARSENAL.items():
        for t in tools:
            total += 1
            ok = bool(eng.which(t))
            present += 1 if ok else 0
            rows.append((group, t, ok))
    return rows, total, present


def register(mcp: FastMCP, eng: Engine) -> None:

    @mcp.tool()
    def kali_arsenal(extra_check: str = "") -> str:
        """武器库盘点：按类别列出常用工具是否就绪，并给出缺失项的安装命令。

        Args:
            extra_check: 额外检查的命令，逗号分隔，如 "impacket-secretsdump,bloodhound-python"
        """
        rows, total, present = _presence(eng)
        missing = [t for _, t, ok in rows if not ok]
        lines = [f"武器库盘点：{present} 个可用 / {len(missing)} 个缺失（共检查 {total} 个）", ""]
        for group in ARSENAL:
            items = [(t, ok) for g, t, ok in rows if g == group]
            lines.append(f"[{group}]")
            for t, ok in items:
                lines.append(f"  {'✓' if ok else '✗'} {t}")
            lines.append("")
        if extra_check:
            names = [x.strip() for x in extra_check.split(",") if x.strip()]
            lines.append("[额外检查]")
            for n in names:
                lines.append(f"  {'✓' if eng.which(n) else '✗'} {n}")
        if missing:
            lines.append("缺失项建议安装：sudo apt install -y " + " ".join(sorted(set(missing))[:20]))
            lines.append("（个别工具需 pipx/git 安装，可用 kali_install_tool 处理）")
        return "\n".join(lines)

    @mcp.tool()
    def kali_tools_check(binaries: str) -> str:
        """批量检查命令是否存在并给出版本号。

        Args:
            binaries: 逗号分隔的命令名，如 "nmap,sqlmap,ffuf"
        """
        names = [x.strip() for x in binaries.split(",") if x.strip()]
        rows = []
        for n in names[:40]:
            if eng.which(n):
                rows.append([n, "✓", eng.version_of(n)])
            else:
                rows.append([n, "✗", "未安装"])
        return table(rows, ["命令", "状态", "版本"])

    @mcp.tool()
    def kali_install_tool(name: str, method: str = "apt", timeout: int = 900) -> str:
        """安装缺失的工具（apt / pipx / git / go）。

        Args:
            name: 包名或仓库地址（method=git 时填 URL）
            method: apt / pipx / git / go
            timeout: 超时
        """
        m = method.lower()
        if m == "apt":
            if not shlex.quote(name).strip("'"):
                return "name 为空"
            return sh(eng, "kali_install_tool",
                      f"DEBIAN_FRONTEND=noninteractive apt-get install -y {shlex.quote(name)} "
                      f"2>&1 | tail -25", timeout, sudo=True)
        if m == "pipx":
            return sh(eng, "kali_install_tool", f"pipx install {shlex.quote(name)} 2>&1 | tail -20", timeout)
        if m == "go":
            return sh(eng, "kali_install_tool", f"go install {shlex.quote(name)} 2>&1 | tail -20", timeout)
        if m == "git":
            if not name.startswith(("http://", "https://", "git@")):
                return "git 方式需要填仓库 URL"
            dst = "/opt/" + os.path.basename(name).replace(".git", "")
            cmd = (f"rm -rf {shlex.quote(dst)} && git clone --depth 1 {shlex.quote(name)} {shlex.quote(dst)} "
                   f"2>&1 | tail -15; ls -la {shlex.quote(dst)} | head -10")
            return sh(eng, "kali_install_tool", cmd, timeout, sudo=True)
        return "method 只支持 apt / pipx / git / go"

    @mcp.tool()
    def kali_note_add(title: str, target: str = "", severity: str = "info",
                      detail: str = "", tag: str = "") -> str:
        """记录一条 finding（后面可用 kali_report 生成报告）。

        Args:
            title: 一句话结论，如 "22 端口开放 SSH"
            target: 关联目标
            severity: info / low / medium / high / critical
            detail: 证据、复现步骤、原始输出
            tag: 标签，如 "nmap"、"web"
        """
        item = eng.note_add(title, detail, target, severity, tag)
        eng.audit("kali_note_add", f"{severity} {target} {title}")
        return f"已记录 [{item['id']}] {item['severity']} {item['title']}"

    @mcp.tool()
    def kali_note_list(severity: str = "", target: str = "") -> str:
        """列出已记录的 findings，可按级别/目标过滤。"""
        return eng.note_list(severity, target)

    @mcp.tool()
    def kali_note_clear() -> str:
        """清空所有 findings（报告前想重新组织时用）。"""
        eng.audit("kali_note_clear", "清空 findings")
        return eng.note_clear()

    @mcp.tool()
    def kali_report(title: str = "渗透测试报告") -> str:
        """把 findings + 审计记录导出成 Markdown 报告，返回文件路径。"""
        path = eng.report(title)
        eng.audit("kali_report", path)
        return f"报告已生成: {path}\n---\n{clip(eng.head(path, 40).get('output', ''))}"

    @mcp.tool()
    def kali_scope_show() -> str:
        """查看当前授权目标范围（为空表示不做限制）。"""
        entries = eng.scope()
        if not entries:
            return "未设置范围（不限制目标）。建议用 kali_scope_set 明确授权范围。"
        return "当前授权范围（%d 条）：\n%s" % (len(entries), "\n".join(f"- {e}" for e in entries))

    @mcp.tool()
    def kali_scope_set(entries: str, append: bool = False) -> str:
        """设置授权目标范围（之后所有带目标的工具都会先校验）。

        Args:
            entries: 逗号或换行分隔，支持 IP / CIDR / 域名 / 通配（如 *.example.com）
            append: True 追加而非覆盖
        """
        raw = [x.strip() for x in entries.replace("\n", ",").split(",") if x.strip()]
        if append:
            raw = eng.scope() + raw
        saved = eng.scope_set(raw)
        eng.audit("kali_scope_set", ",".join(saved))
        return "已设置范围（%d 条）：\n%s" % (len(saved), "\n".join(f"- {e}" for e in saved))

    @mcp.tool()
    def kali_doctor() -> str:
        """环境体检：权限、依赖、磁盘、网络、常见工具、数据目录，一次性给出结论与修复建议。"""
        checks = []
        checks.append(("运行身份", "root" if eng.is_root else "非 root（部分扫描需 sudo）"))
        py = eng.run("python3 --version 2>&1", 20)["output"].strip()
        checks.append(("Python", py))
        ver = eng.run("uname -r; grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null", 20)["output"].strip().replace("\n", " ")
        checks.append(("系统", ver))
        disk = eng.run("df -h / | tail -1", 20)["output"].strip()
        checks.append(("根分区", disk))
        net = eng.run("ip -4 route | head -3", 20)["output"].strip().replace("\n", " | ")
        checks.append(("网络", net))
        nd = eng.run("getent hosts kali.org >/dev/null 2>&1 && echo ok || echo fail", 30)["output"].strip()
        checks.append(("出网/DNS", nd))
        rows, total, present = _presence(eng)
        missing = [t for _, t, ok in rows if not ok]
        checks.append(("工具覆盖", f"{present}/{total} 就绪"))
        checks.append(("数据目录", eng.state_dir))
        checks.append(("产物目录", f"{eng.artifact_dir}（{len(eng.artifacts(200))} 个文件）"))
        body = table([[k, str(v)] for k, v in checks], ["项目", "结果"])
        tail = []
        if missing:
            tail.append("缺失工具：" + ", ".join(sorted(set(missing))[:25]))
            tail.append("一键补装：sudo apt install -y " + " ".join(sorted(set(missing))[:25]))
        if not eng.is_root:
            tail.append("提示：Set KALI_MCP_SUDO_PASS 以便自动 sudo。")
        return body + ("\n\n" + "\n".join(tail) if tail else "")
