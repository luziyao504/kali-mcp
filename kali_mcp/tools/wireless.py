"""无线相关：网卡与 AP 扫描、监听模式切换、抓握手包（都需要 root 与兼容网卡）。"""

from __future__ import annotations

import shlex

from mcp.server.fastmcp import FastMCP

from ..engine import Engine
from ..toolkit import need, sh
from ..util import fmt, q, sanitize_token


def register(mcp: FastMCP, eng: Engine) -> None:

    @mcp.tool()
    def kali_wifi_adapters() -> str:
        """列出无线网卡、驱动、chipset、是否支持监听模式（airmon-ng 视角）。"""
        cmd = ("echo '== iw dev =='; iw dev 2>/dev/null | grep -E 'Interface|type|channel'; "
               "echo '== airmon-ng =='; airmon-ng 2>/dev/null; "
               "echo '== rfkill =='; rfkill list 2>/dev/null | head -20; "
               "echo '== nmcli =='; nmcli -t -f DEVICE,TYPE,STATE device 2>/dev/null")
        return sh(eng, "kali_wifi_adapters", cmd, 90, sudo=True)

    @mcp.tool()
    def kali_wifi_scan(interface: str = "wlan0", timeout: int = 120) -> str:
        """扫描周边 AP（SSID/BSSID/信道/加密/信号强度）。"""
        iface = sanitize_token(interface, r"[A-Za-z0-9_\-]") or "wlan0"
        cmd = (f"nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi list iface {q(iface)} 2>/dev/null | head -40; "
               f"echo '--- iw ---'; iw dev {q(iface)} scan 2>/dev/null | grep -E 'SSID|signal|DS Parameter set' | head -60")
        return sh(eng, "kali_wifi_scan", cmd, timeout, sudo=True)

    @mcp.tool()
    def kali_monitor_mode(interface: str = "wlan0", enable: bool = True) -> str:
        """开/关监听模式（airmon-ng start|stop）。开完记得看接口名是否变成 wlan0mon。

        Args:
            interface: 物理网卡名
            enable: True 开启，False 关闭
        """
        iface = sanitize_token(interface, r"[A-Za-z0-9_\-]") or "wlan0"
        if not eng.which("airmon-ng"):
            return need(eng, "airmon-ng", "aircrack-ng") or ""
        action = "start" if enable else "stop"
        cmd = (f"airmon-ng {action} {q(iface)} 2>&1; echo '--- 当前接口 ---'; iw dev 2>/dev/null "
               "| grep -E 'Interface|type'")
        return sh(eng, "kali_monitor_mode", cmd, 120, sudo=True)

    @mcp.tool()
    def kali_airodump(interface: str, out_prefix: str = "/tmp/airodump", seconds: int = 60,
                      bssid: str = "", channel: str = "") -> str:
        """抓包（airodump-ng），可用于捕获 WPA 握手包。

        Args:
            interface: 监听模式接口，如 wlan0mon
            out_prefix: 输出前缀（会生成 .cap/.csv）
            seconds: 抓多久
            bssid: 只抓指定 AP
            channel: 锁定信道，抓握手更快
        """
        iface = sanitize_token(interface, r"[A-Za-z0-9_\-]")
        if not iface:
            return "interface 不合法"
        if not eng.which("airodump-ng"):
            return need(eng, "airodump-ng", "aircrack-ng") or ""
        argv = ["airodump-ng", iface, "-w", out_prefix, "-o", "csv"]
        if bssid:
            argv += ["--bssid", bssid]
        if channel:
            argv += ["-c", sanitize_token(channel, r"[0-9]") or "1"]
        cmd = (f"timeout {max(10, int(seconds))} {' '.join(shlex.quote(a) for a in argv)} 2>&1 | tail -40; "
               f"echo '--- 产物 ---'; ls -lh {q(out_prefix)}* 2>/dev/null")
        return sh(eng, "kali_airodump", cmd, max(60, int(seconds) + 30), sudo=True)

    @mcp.tool()
    def kali_airocrack(handshake_file: str, wordlist: str = "", bssid: str = "") -> str:
        """对着抓到的 .cap 跑 aircrack-ng 恢复 WPA 密钥（需握手包完整）。"""
        if not eng.which("aircrack-ng"):
            return need(eng, "aircrack-ng", "aircrack-ng") or ""
        argv = ["aircrack-ng", handshake_file] + (["-w", wordlist] if wordlist else [])
        if bssid:
            argv += ["--bssid", bssid]
        return fmt(eng.runv(argv, 900))
