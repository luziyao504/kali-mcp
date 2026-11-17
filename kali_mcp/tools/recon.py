"""信息收集：子域名、OSINT、DNS 枚举、SMB/AD 枚举，以及一键只读侦察编排。"""

from __future__ import annotations

import shlex

from mcp.server.fastmcp import FastMCP

from ..engine import Engine
from ..toolkit import guard, need, sh, shv
from ..util import q


def register(mcp: FastMCP, eng: Engine) -> None:

    @mcp.tool()
    def kali_subfinder(domain: str, timeout: int = 300) -> str:
        """用 subfinder 被动枚举子域名（不接触目标，最安全的第一步）。"""
        err = guard(eng, domain)
        if err:
            return err
        if not eng.which("subfinder"):
            return need(eng, "subfinder", "subfinder", alt="amass enum -passive -d <域名>") or ""
        return shv(eng, "kali_subfinder", ["subfinder", "-d", domain, "-silent"], timeout)

    @mcp.tool()
    def kali_amass(domain: str, passive: bool = True, timeout: int = 600) -> str:
        """OWASP Amass 资产枚举（passive=True 只做被动查询）。"""
        err = guard(eng, domain)
        if err:
            return err
        if not eng.which("amass"):
            return need(eng, "amass", "amass") or ""
        argv = ["amass", "enum"] + (["-passive"] if passive else []) + ["-d", domain]
        return shv(eng, "kali_amass", argv, timeout)

    @mcp.tool()
    def kali_theharvester(domain: str, source: str = "all", timeout: int = 600) -> str:
        """theHarvester：收集邮箱、主机、子域名等 OSINT 信息。"""
        err = guard(eng, domain)
        if err:
            return err
        if not eng.which("theHarvester"):
            return need(eng, "theHarvester", "theharvester") or ""
        return shv(eng, "kali_theharvester", ["theHarvester", "-d", domain, "-b", source], timeout)

    @mcp.tool()
    def kali_dns_enum(domain: str, timeout: int = 240) -> str:
        """DNS 枚举：区域传送、NS/MX/TXT、常见子域爆破（dnsenum，回落 dig 脚本）。"""
        err = guard(eng, domain)
        if err:
            return err
        if eng.which("dnsenum"):
            return shv(eng, "kali_dns_enum", ["dnsenum", "--noreverse", domain], timeout)
        if not eng.which("dig"):
            return need(eng, "dig", "dnsutils") or ""
        cmd = (f"echo '[NS]'; dig +short NS {q(domain)}; echo '[MX]'; dig +short MX {q(domain)}; "
               f"echo '[TXT]'; dig +short TXT {q(domain)}; echo '[AXFR]'; "
               f"ns=$(dig +short NS {q(domain)} | head -1); [ -n \"$ns\" ] && dig AXFR {q(domain)} @$ns | head -20 || echo '无'")
        return sh(eng, "kali_dns_enum", cmd, timeout)

    @mcp.tool()
    def kali_dnsrecon(domain: str, timeout: int = 300) -> str:
        """dnsrecon：DNS 记录、SRV、暴力枚举综合报告。"""
        err = guard(eng, domain)
        if err:
            return err
        if not eng.which("dnsrecon"):
            return need(eng, "dnsrecon", "dnsrecon") or ""
        return shv(eng, "kali_dnsrecon", ["dnsrecon", "-d", domain], timeout)

    @mcp.tool()
    def kali_enum4linux(target: str, timeout: int = 300) -> str:
        """enum4linux：SMB/NetBIOS 枚举（用户、组、共享、密码策略）。"""
        err = guard(eng, target)
        if err:
            return err
        binary = eng.has("enum4linux-ng", "enum4linux")
        if not binary:
            return need(eng, "enum4linux", "enum4linux", alt="nmap --script smb-enum-users") or ""
        return shv(eng, "kali_enum4linux", [binary, "-a", target], timeout)

    @mcp.tool()
    def kali_smbclient(target: str, share: str = "", user: str = "", password: str = "",
                       command: str = "") -> str:
        """SMB 共享访问：列共享、进目录、下载文件（空密码匿名也支持）。

        Args:
            target: 主机
            share: 共享名，留空只列共享
            user: 用户名，匿名留空
            password: 密码
            command: 进共享后执行的 smbclient 命令，如 "ls"、"get a.txt"
        """
        err = guard(eng, target)
        if err:
            return err
        binary = eng.which("smbclient")
        if not binary:
            return need(eng, "smbclient", "smbclient") or ""
        auth = f"{user or ''}%{password or ''}"
        if not share:
            return shv(eng, "kali_smbclient", [binary, "-L", f"//{target}", "-U", auth, "-N"], 120)
        argv = [binary, f"//{target}/{share}", "-U", auth]
        if command:
            argv += ["-c", command]
        return shv(eng, "kali_smbclient", argv, 180)

    @mcp.tool()
    def kali_nbtscan(target: str, timeout: int = 120) -> str:
        """NetBIOS 名字服务扫描（快速摸清同网段 Windows 主机）。"""
        err = guard(eng, target)
        if err:
            return err
        if not eng.which("nbtscan"):
            return need(eng, "nbtscan", "nbtscan") or ""
        return shv(eng, "kali_nbtscan", ["nbtscan", target], timeout)

    @mcp.tool()
    def kali_cme(target: str, protocol: str = "smb", user: str = "", password: str = "",
                 timeout: int = 300) -> str:
        """CrackMapExec（或 nxc）批量探测：SMB/LDAP/WinRM 认证与主机信息。"""
        err = guard(eng, target)
        if err:
            return err
        binary = eng.has("nxc", "crackmapexec", "cme")
        if not binary:
            return need(eng, "crackmapexec, nxc", "crackmapexec") or ""
        argv = [binary, protocol, target]
        if user:
            argv += ["-u", user, "-p", password or ""]
        return shv(eng, "kali_cme", argv, timeout)

    @mcp.tool()
    def kali_ldapsearch(target: str, base_dn: str = "", user: str = "", password: str = "",
                        timeout: int = 180) -> str:
        """LDAP 查询（AD 环境摸组织结构、用户、组）。"""
        err = guard(eng, target)
        if err:
            return err
        if not eng.which("ldapsearch"):
            return need(eng, "ldapsearch", "ldap-utils") or ""
        argv = ["ldapsearch", "-H", f"ldap://{target}", "-x"]
        if user:
            argv += ["-D", user, "-w", password or ""]
        argv += ["-b", base_dn or "", "(objectClass=*)", "cn", "distinguishedName"]
        argv += ["-l", "30"]
        return shv(eng, "kali_ldapsearch", argv, timeout)

    @mcp.tool()
    def kali_snmp_walk(target: str, community: str = "public", timeout: int = 120) -> str:
        """SNMP 信息收集（默认 community 试 public）。"""
        err = guard(eng, target)
        if err:
            return err
        binary = eng.which("snmpwalk")
        if not binary:
            return need(eng, "snmpwalk", "snmp") or ""
        return shv(eng, "kali_snmp_walk",
                   [binary, "-v2c", "-c", community, "-t", "5", target, "-On"], timeout)

    @mcp.tool()
    def kali_recon_all(target: str, timeout: int = 900) -> str:
        """一键只读侦察编排：whois → DNS → HTTP/TLS 指纹 → nmap 常见端口 → 结果汇总落盘。

        只做被动/低影响的探测，适合作为一次评估的起点。目标必须在授权范围内。

        Args:
            target: 域名或 IP
            timeout: 总超时
        """
        err = guard(eng, target)
        if err:
            return err
        import time as _t
        import os
        out_dir = os.path.join(eng.artifact_dir, f"recon-{_t.strftime('%Y%m%d-%H%M%S')}")
        os.makedirs(out_dir, exist_ok=True)
        safe = target.replace("/", "_").replace(":", "_")
        steps = []

        def step(name: str, cmd: str) -> None:
            res = eng.run(cmd, min(300, timeout))
            path = os.path.join(out_dir, f"{name}.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(res["output"] or "")
            steps.append((name, res["exit_code"], path, (res["output"] or "").strip()))

        ip = eng.run(f"dig +short {q(target)} A | head -1", 30)["output"].strip()
        step("whois", f"whois {q(target)} 2>/dev/null | head -40" if eng.which("whois") else "echo 'whois 未安装'")
        step("dns", f"dig {q(target)} ANY +short | head -30; dig +short MX {q(target)}; dig +short NS {q(target)}"
             if eng.which("dig") else "echo 'dig 未安装'")
        step("http", f"curl -k -sS -m 20 -D - -o /dev/null -L {q('https://' + target)} 2>&1 | head -30"
             if eng.which("curl") else "echo 'curl 未安装'")
        step("tls", f"echo | openssl s_client -connect {q(target)}:443 -servername {q(target)} 2>/dev/null "
                    f"| openssl x509 -noout -subject -issuer -dates 2>/dev/null" if eng.which("openssl") else "echo 'openssl 未安装'")
        if eng.which("nmap"):
            step("nmap", f"nmap -T4 -sV -Pn --top-ports 100 {q(ip or target)} 2>&1")
        eng.audit("kali_recon_all", f"{target} -> {out_dir}")

        lines = [f"目标: {target}   解析IP: {ip or '未解析'}", f"产物目录: {out_dir}", ""]
        for name, rc, path, body in steps:
            lines.append(f"===== {name} (exit {rc}) =====")
            lines.append((body[:1200] if body else "(无输出)"))
            lines.append("")
        return "\n".join(lines)
