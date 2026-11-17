"""凭据类工具：在线爆破（hydra/medusa）、离线破解（john/hashcat）、哈希识别、字典盘点。"""

from __future__ import annotations

import re

from mcp.server.fastmcp import FastMCP

from ..engine import Engine
from ..toolkit import guard, need, sh, shv
from ..util import q


def register(mcp: FastMCP, eng: Engine) -> None:

    @mcp.tool()
    def kali_hydra(target: str, service: str, user: str = "", userlist: str = "",
                   password: str = "", passlist: str = "", port: int = 0,
                   extra: str = "", timeout: int = 900) -> str:
        """hydra 在线认证爆破（ssh/ftp/rdp/http-* 等）。务必确认目标在授权范围内。

        Args:
            target: 目标 IP/域名
            service: ssh / ftp / rdp / smb / mysql / postgres / http-get / http-post-form
            user: 单个用户名
            userlist: 用户名文件
            password: 单个密码
            passlist: 密码字典文件
            port: 非默认端口时填
            extra: 额外参数，如 "-s 2222"、"http-post-form 参数串"
        """
        err = guard(eng, target)
        if err:
            return err
        if not eng.which("hydra"):
            return need(eng, "hydra", "hydra") or ""
        if not service or not re.fullmatch(r"[a-z0-9\-]+", service.lower()):
            return f"service 不合法: {service}"
        argv = ["hydra"]
        if port:
            argv += ["-s", str(int(port))]
        if user:
            argv += ["-l", user]
        if userlist:
            argv += ["-L", userlist]
        if password:
            argv += ["-p", password]
        if passlist:
            argv += ["-P", passlist]
        if extra:
            argv += [t for t in extra.split() if re.fullmatch(r"[-A-Za-z0-9_.,:/=]+", t)]
        argv += [target, service]
        return shv(eng, "kali_hydra", argv, timeout)

    @mcp.tool()
    def kali_medusa(target: str, service: str = "ssh", user: str = "", userlist: str = "",
                    password: str = "", passlist: str = "", timeout: int = 900) -> str:
        """medusa 并行认证爆破（hydra 的替代实现，某些服务上更稳）。"""
        err = guard(eng, target)
        if err:
            return err
        if not eng.which("medusa"):
            return need(eng, "medusa", "medusa") or ""
        argv = ["medusa", "-h", target, "-M", service]
        if user:
            argv += ["-u", user]
        if userlist:
            argv += ["-U", userlist]
        if password:
            argv += ["-p", password]
        if passlist:
            argv += ["-P", passlist]
        argv += ["-t", "4", "-f"]
        return shv(eng, "kali_medusa", argv, timeout)

    @mcp.tool()
    def kali_john(hash_file: str, wordlist: str = "", format_hint: str = "", timeout: int = 900) -> str:
        """John the Ripper 离线破解（自动识别格式，或指定 format）。

        Args:
            hash_file: 哈希文件路径
            wordlist: 字典路径，留空用 John 默认模式
            format_hint: 如 "raw-md5"、"nt"、"sha256crypt"
        """
        if not eng.which("john"):
            return need(eng, "john", "john") or ""
        argv = ["john"]
        if format_hint:
            argv += ["--format=" + format_hint]
        if wordlist:
            argv += ["--wordlist=" + wordlist]
        argv.append(hash_file)
        return shv(eng, "kali_john", argv, timeout)

    @mcp.tool()
    def kali_hashcat(mode: str, hash_file: str, wordlist: str = "", timeout: int = 900) -> str:
        """Hashcat GPU/CPU 破解。

        Args:
            mode: hashcat 的 hash 类型编号，如 "0"(MD5)、"1000"(NTLM)、"22000"(WPA)
            hash_file: 哈希文件
            wordlist: 字典，留空用暴力掩码 -a 3 ?a?a?a?a?a?a
        """
        if not eng.which("hashcat"):
            return need(eng, "hashcat", "hashcat") or ""
        if not re.fullmatch(r"[0-9]+", str(mode)):
            return f"mode 必须是数字编号: {mode}"
        argv = ["hashcat", "-m", str(mode), hash_file]
        if wordlist:
            argv += [wordlist, "-a", "0"]
        else:
            argv += ["-a", "3", "?a?a?a?a?a?a"]
        argv += ["--potfile-disable", "-w", "3"]
        return shv(eng, "kali_hashcat", argv, timeout)

    @mcp.tool()
    def kali_hashid(hash_value: str) -> str:
        """识别哈希类型（拿到一串 hash 不知道是什么算法时用）。"""
        binary = eng.has("hashid", "hash-identifier")
        if not binary:
            return need(eng, "hashid", "hashid") or ""
        return shv(eng, "kali_hashid", [binary, "-m", hash_value], 40)

    @mcp.tool()
    def kali_wordlists(keyword: str = "") -> str:
        """盘点本机字典（seclists / wordlists），找适合当前场景的字典。"""
        cmd = ("echo '== 目录 =='; ls -d /usr/share/wordlists /usr/share/seclists 2>/dev/null; "
               "echo '== 常用字典 =='; ls -lh /usr/share/wordlists/*.txt /usr/share/wordlists/*.gz 2>/dev/null | head -20; "
               "echo '== seclists 大类 =='; ls /usr/share/seclists 2>/dev/null | head -20; "
               "echo '== 压缩字典 =='; find /usr/share/wordlists -name '*.gz' 2>/dev/null | head -10")
        if keyword:
            cmd += f"; echo '== 匹配 {keyword} =='; find /usr/share -iname '*{keyword}*' -name '*.txt' -o -iname '*{keyword}*.gz' 2>/dev/null | head -20"
        return sh(eng, "kali_wordlists", cmd, 90)

    @mcp.tool()
    def kali_crack_zip(zip_file: str, wordlist: str = "", timeout: int = 600) -> str:
        """破解加密 zip（zip2john → john），CTF 与取证常用。"""
        if not eng.which("zip2john") and not eng.which("john"):
            return need(eng, "zip2john", "john") or ""
        tmp_hash = "/tmp/zip2john-" + zip_file.replace("/", "_") + ".txt"
        argv_cmd = f"zip2john {q(zip_file)} > {q(tmp_hash)} 2>/dev/null; head -2 {q(tmp_hash)}"
        pre = eng.run(argv_cmd, 60)
        if not pre["output"].strip():
            return f"提取哈希失败（文件可能未加密）:\n{pre['output']}"
        return sh(eng, "kali_crack_zip",
                  f"john --wordlist={q(wordlist)} {q(tmp_hash)} 2>&1 | tail -15 || "
                  f"john {q(tmp_hash)} 2>&1 | tail -15", timeout)
