"""网络层工具：接口、路由、连通性、DNS/WHOIS、端口与服务扫描、抓包、TLS 探测。"""

from __future__ import annotations

import re
import shlex

from mcp.server.fastmcp import FastMCP

from ..engine import Engine
from ..toolkit import guard, need, sh, shv
from ..util import q, sanitize_token, strip_scheme

_FLAG = re.compile(r"^-[A-Za-z0-9\-]+$")
_WORDS = re.compile(r"^[-A-Za-z0-9_.,:/=+*?\[\]]+$")


def _flags(text: str) -> str:
    """校验用户传入的 nmap 参数片段（argv 直传，这里只做合法性兜底）。"""
    toks = [t for t in (text or "").split() if t]
    for t in toks:
        if not (_FLAG.match(t) or _WORDS.match(t)):
            raise ValueError(f"不接受的参数片段: {t}")
    return " ".join(toks)


def _target_ok(target: str) -> str:
    t = strip_scheme(target)
    if not t or not _WORDS.match(t):
        raise ValueError(f"目标格式不合法: {target!r}")
    return t


def register(mcp: FastMCP, eng: Engine) -> None:

    @mcp.tool()
    def kali_net_interfaces() -> str:
        """本机网络接口、IP、MAC、状态，以及默认路由与 DNS。"""
        cmd = ("ip -4 -o addr show | awk '{print $2, $3, $4}'; echo '---'; "
               "ip link show | grep -E '^[0-9]+:' | awk '{print $2, $9}'; echo '--- 路由 ---'; "
               "ip route; echo '--- DNS ---'; cat /etc/resolv.conf 2>/dev/null | grep -v '^#'")
        return sh(eng, "kali_net_interfaces", cmd, 60)

    @mcp.tool()
    def kali_net_routes() -> str:
        """路由表 + 邻居缓存（内网资产发现的起点）。"""
        return sh(eng, "kali_net_routes", "ip route show; echo '--- 邻居 ---'; ip neigh show", 60)

    @mcp.tool()
    def kali_ping(target: str, count: int = 4, timeout: int = 25) -> str:
        """ICMP 连通性测试。"""
        t = _target_ok(target)
        return shv(eng, "kali_ping", ["ping", "-c", str(max(1, int(count))), "-W", "2", t], timeout)

    @mcp.tool()
    def kali_traceroute(target: str, max_hops: int = 20, timeout: int = 120) -> str:
        """路由追踪（优先 traceroute，回落 tracepath）。"""
        t = _target_ok(target)
        tool = eng.has("traceroute", "tracepath")
        if not tool:
            return need(eng, "traceroute", "traceroute") or ""
        argv = [tool, t] if tool == "tracepath" else [tool, "-m", str(int(max_hops)), t]
        return shv(eng, "kali_traceroute", argv, timeout)

    @mcp.tool()
    def kali_dns_lookup(domain: str, record: str = "", server: str = "") -> str:
        """DNS 查询：A/AAAA/MX/TXT/NS/CNAME/ANY，可指定 DNS 服务器。

        Args:
            domain: 域名或 IP
            record: 记录类型，留空查全部常用
            server: 指定 DNS，如 8.8.8.8
        """
        d = _target_ok(domain)
        if not eng.which("dig"):
            return need(eng, "dig", "dnsutils") or ""
        types = [record] if record else ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
        parts = []
        for rt in types:
            if not re.fullmatch(r"[A-Za-z0-9]+", rt or ""):
                continue
            at = f"@{server}" if server else ""
            parts.append(f"dig {at} {d} {rt} +short | head -12")
        cmd = "; ".join(f"echo '[{rt}]'; {c}" for rt, c in zip(types, parts))
        return sh(eng, "kali_dns_lookup", cmd, 90)

    @mcp.tool()
    def kali_reverse_dns(ip: str) -> str:
        """IP 反查域名（PTR）。"""
        return sh(eng, "kali_reverse_dns", f"dig +short -x {q(_target_ok(ip))}", 60)

    @mcp.tool()
    def kali_whois(target: str, timeout: int = 90) -> str:
        """WHOIS：域名/IP 注册信息、归属、注册商、时间。"""
        if not eng.which("whois"):
            return need(eng, "whois", "whois") or ""
        return shv(eng, "kali_whois", ["whois", _target_ok(target)], timeout)

    @mcp.tool()
    def kali_arp_scan(interface: str = "", timeout: int = 180) -> str:
        """ARP 扫描发现同网段存活主机（优先 arp-scan，回落 nmap -sn）。"""
        if eng.which("arp-scan"):
            argv = ["arp-scan"] + (["-i", interface] if interface else []) + ["--localnet"]
            return shv(eng, "kali_arp_scan", argv, timeout, sudo=True)
        if eng.which("nmap"):
            subnet = eng.run("ip -4 route | awk '/default/{next} /\\//{print $1; exit}'", 20)["output"].strip()
            return shv(eng, "kali_arp_scan", ["nmap", "-sn", subnet or "192.168.0.0/24"], timeout, sudo=True)
        return "需要 arp-scan 或 nmap：sudo apt install -y arp-scan"

    @mcp.tool()
    def kali_nmap(target: str, ports: str = "", scan: str = "-sV", scripts: str = "",
                  extra: str = "", timeout: int = 600) -> str:
        """nmap 端口/服务扫描（本项目最常用的侦察入口）。

        Args:
            target: IP / 域名 / CIDR，如 10.0.0.0/24
            ports: 端口范围，如 "22,80,443" 或 "1-1000"；留空用 nmap 默认
            scan: 扫描方式参数，如 "-sS"、"-sT"、"-sn"、"-sV -sC"
            scripts: NSE 脚本名，逗号分隔，如 "vulners,http-title"
            extra: 其他 nmap 参数，如 "-T4 -Pn"
            timeout: 超时秒数
        """
        err = guard(eng, target)
        if err:
            return err
        if not eng.which("nmap"):
            return need(eng, "nmap", "nmap") or ""
        t = _target_ok(target)
        p = sanitize_token(ports, r"[0-9,\-]")
        if ports and not p:
            return f"ports 格式不合法: {ports}"
        try:
            argv = ["nmap"] + _flags(scan).split()
            if p:
                argv += ["-p", p]
            if scripts:
                if not re.fullmatch(r"[A-Za-z0-9_,\-]+", scripts):
                    return f"scripts 不合法: {scripts}"
                argv += ["--script", scripts]
            argv += _flags(extra).split() if extra else []
            argv.append(t)
        except ValueError as exc:
            return str(exc)
        return shv(eng, "kali_nmap", argv, timeout, sudo=("-sS" in (scan or "") or "-O" in (extra or "")))

    @mcp.tool()
    def kali_nmap_vuln(target: str, ports: str = "", timeout: int = 900) -> str:
        """nmap 漏洞脚本扫描（NSE vuln/vulners，含 CVE 线索）。"""
        err = guard(eng, target)
        if err:
            return err
        if not eng.which("nmap"):
            return need(eng, "nmap", "nmap") or ""
        t = _target_ok(target)
        argv = ["nmap", "-sV", "--script", "vuln,vulners"]
        p = sanitize_token(ports, r"[0-9,\-]")
        if p:
            argv += ["-p", p]
        argv.append(t)
        return shv(eng, "kali_nmap_vuln", argv, timeout, sudo=True)

    @mcp.tool()
    def kali_masscan(target: str, ports: str = "0-65535", rate: int = 10000, timeout: int = 600) -> str:
        """masscan 高速全端口扫描（比 nmap 快一个数量级，适合大网段）。"""
        err = guard(eng, target)
        if err:
            return err
        if not eng.which("masscan"):
            return need(eng, "masscan", "masscan") or ""
        p = sanitize_token(ports, r"[0-9,\-]")
        if not p:
            return f"ports 不合法: {ports}"
        argv = ["masscan", _target_ok(target), "-p", p, "-rate", str(max(100, int(rate)))]
        return shv(eng, "kali_masscan", argv, timeout, sudo=True)

    @mcp.tool()
    def kali_rustscan(target: str, ports: str = "", timeout: int = 600) -> str:
        """rustscan 快速发现端口（可自动交给 nmap 做服务识别）。"""
        err = guard(eng, target)
        if err:
            return err
        if not eng.which("rustscan"):
            return need(eng, "rustscan", "rustscan") or ""
        argv = ["rustscan", "-a", _target_ok(target)]
        p = sanitize_token(ports, r"[0-9,\-]")
        if p:
            argv += ["-p", p]
        return shv(eng, "kali_rustscan", argv, timeout)

    @mcp.tool()
    def kali_tcpdump(interface: str = "any", capture_filter: str = "", seconds: int = 30,
                     out_file: str = "", read_file: str = "", timeout: int = 120) -> str:
        """抓包或读包：抓 N 秒存 pcap 并给摘要；给 read_file 则直接解析已有 pcap。

        Args:
            interface: 网卡，"any" 表示全部
            capture_filter: BPF 过滤，如 "port 80 or port 443"
            seconds: 抓多久
            out_file: pcap 路径，留空自动生成
            read_file: 已有 pcap，填了就只解析不抓包
        """
        if not eng.which("tcpdump"):
            return need(eng, "tcpdump", "tcpdump") or ""
        if read_file:
            return sh(eng, "kali_tcpdump",
                      f"tcpdump -nr {q(read_file)} 2>/dev/null | head -80; echo '--- 统计 ---'; "
                      f"tcpdump -nr {q(read_file)} 2>/dev/null | wc -l", 120, sudo=True)
        import time as _t
        out_file = out_file or f"/tmp/cap-{_t.strftime('%Y%m%d-%H%M%S')}.pcap"
        filt = f" {capture_filter}" if capture_filter else ""
        cmd = (f"timeout {max(3, int(seconds))} tcpdump -i {shlex.quote(interface)} -w {q(out_file)}{filt} 2>&1 | tail -5; "
               f"echo '--- 摘要 ---'; tcpdump -nr {q(out_file)} 2>/dev/null | head -40; "
               f"echo '--- 包数 ---'; tcpdump -nr {q(out_file)} 2>/dev/null | wc -l; ls -lh {q(out_file)}")
        return sh(eng, "kali_tcpdump", cmd, max(60, int(timeout)), sudo=True)

    @mcp.tool()
    def kali_http_probe(url: str, timeout: int = 40) -> str:
        """HTTP 探测：状态码、响应头、跳转链、服务器指纹、证书信息。

        Args:
            url: http(s)://host[:port][/path]
        """
        err = guard(eng, url)
        if err:
            return err
        if not eng.which("curl"):
            return need(eng, "curl", "curl") or ""
        cmd = (f"curl -k -sS -m {max(5, int(timeout))} -D - -o /dev/null -L --max-redirs 5 {q(url)}")
        return sh(eng, "kali_http_probe", cmd, timeout)

    @mcp.tool()
    def kali_tls_info(host: str, port: int = 443, timeout: int = 60) -> str:
        """TLS/SSL 探测：协议版本、证书主体、签发者、有效期、SAN 列表。"""
        err = guard(eng, host)
        if err:
            return err
        if not eng.which("openssl"):
            return need(eng, "openssl", "openssl") or ""
        h = _target_ok(host)
        cmd = (f"echo | openssl s_client -connect {q(h)}:{int(port)} -servername {q(h)} 2>/dev/null "
               f"| openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null; echo '--- 协议 ---'; "
               f"echo | openssl s_client -connect {q(h)}:{int(port)} 2>/dev/null | grep -E 'Protocol|Cipher' | head -3")
        return sh(eng, "kali_tls_info", cmd, timeout)

    @mcp.tool()
    def kali_banner_grab(host: str, port: int, timeout: int = 30) -> str:
        """端口 banner 抓取（nc 或 bash /dev/tcp 兜底），识别服务版本。"""
        err = guard(eng, host)
        if err:
            return err
        h = _target_ok(host)
        if eng.which("nc"):
            cmd = f"echo '' | nc -w 4 {q(h)} {int(port)} 2>&1 | head -20"
        else:
            cmd = (f"exec 3<>/dev/tcp/{h}/{int(port)} && timeout 5 head -c 400 <&3 2>&1; "
                   f"exec 3<&- 2>/dev/null")
        return sh(eng, "kali_banner_grab", cmd, timeout)
