"""文件与物料类工具：浏览、读写、查找、归档、传输、临时 HTTP 服务。"""

from __future__ import annotations

import os
import shlex

from mcp.server.fastmcp import FastMCP

from ..engine import Engine
from ..toolkit import sh, table
from ..util import clip, fmt, human_size, perm, q


def register(mcp: FastMCP, eng: Engine) -> None:

    @mcp.tool()
    def kali_list_dir(remote_path: str = ".") -> str:
        """列目录内容（类型/权限/大小/修改时间）。默认当前用户家目录。"""
        try:
            rows = eng.list_dir(remote_path)
        except FileNotFoundError:
            return f"目录不存在: {remote_path}"
        except PermissionError:
            return f"权限不足: {remote_path}（可用 kali_sudo + kali_exec 处理）"
        if not rows:
            return f"{remote_path}: (空目录)"
        import time as _t
        body = table(
            [["d" if r["is_dir"] else "-", r["mode"], "-" if r["is_dir"] else human_size(r["size"]),
              _t.strftime("%Y-%m-%d %H:%M", _t.localtime(r["mtime"])), r["name"]] for r in
             sorted(rows, key=lambda x: (not x["is_dir"], x["name"].lower()))],
            ["类型", "权限", "大小", "修改时间", "名称"],
        )
        return f"{remote_path}  ({len(rows)} 项)\n{body}"

    @mcp.tool()
    def kali_tree(remote_path: str = ".", depth: int = 2, max_entries: int = 120) -> str:
        """目录树概览（限制深度与条目数，避免刷屏）。"""
        cmd = (f"find {q(remote_path)} -maxdepth {max(1, int(depth))} "
               f"\\( -type d -printf '%y %p\\n' -o -printf '%y %p\\n' \\) 2>/dev/null | head -n {max(1, int(max_entries))}")
        return sh(eng, "kali_tree", cmd, 90, artifact=False)

    @mcp.tool()
    def kali_stat(remote_path: str, checksum: bool = False) -> str:
        """看单个文件的详细属性，可选算 sha256。"""
        import time as _t
        st = eng.stat_path(remote_path)
        if not st:
            return f"不存在: {remote_path}"
        rows = [f"path: {remote_path}", f"type: {'dir' if st['is_dir'] else 'file'}",
                f"size: {human_size(st['size'])} ({st['size']} bytes)",
                f"mode: {st['mode']}", f"mtime: {_t.strftime('%Y-%m-%d %H:%M:%S', _t.localtime(st['mtime']))}"]
        if checksum and not st["is_dir"]:
            rows.append(eng.checksum(remote_path)["output"].strip())
        return "\n".join(rows)

    @mcp.tool()
    def kali_read_file(remote_path: str, max_bytes: int = 200_000, offset: int = 0) -> str:
        """读文本文件（分块读，避免一次拉爆上下文）。"""
        try:
            data = eng.read_bytes(remote_path, offset, max_bytes)
        except FileNotFoundError:
            return f"不存在: {remote_path}"
        except PermissionError:
            return f"权限不足: {remote_path}（试试 kali_sudo 'cat {remote_path}'）"
        text = data.decode("utf-8", errors="replace")
        more = ""
        st = eng.stat_path(remote_path)
        if st and offset + len(data) < st["size"]:
            more = f"\n... 还有 {st['size'] - offset - len(data)} 字节，用 offset={offset + len(data)} 继续读"
        return clip(text) + more

    @mcp.tool()
    def kali_write_file(remote_path: str, content: str, append: bool = False, mode: str = "") -> str:
        """写/追加文件（父目录自动创建）。写脚本、payload、字典、配置文件都用它。

        Args:
            remote_path: 目标路径
            content: 文件内容
            append: True 追加
            mode: 写完后 chmod，如 "755"
        """
        try:
            eng.write_bytes(remote_path, content.encode("utf-8"), append)
        except PermissionError:
            return f"权限不足: {remote_path}（用 kali_exec 配合 sudo tee 写系统目录）"
        st = eng.stat_path(remote_path)
        if mode:
            eng.run(f"chmod {shlex.quote(mode)} {q(remote_path)}", 20)
        return f"写入成功: {remote_path}  ({human_size(st['size'] if st else 0)})\n---\n{clip(content[:200])}"

    @mcp.tool()
    def kali_mkdir(remote_path: str, mode: str = "755") -> str:
        """建目录（含多级）。"""
        return fmt(eng.mkdir_p(remote_path, mode))

    @mcp.tool()
    def kali_move(src: str, dst: str, overwrite: bool = False) -> str:
        """移动/重命名。"""
        return fmt(eng.move(src, dst, overwrite))

    @mcp.tool()
    def kali_copy(src: str, dst: str) -> str:
        """复制文件或目录（保留属性）。"""
        return fmt(eng.copy(src, dst))

    @mcp.tool()
    def kali_delete(remote_path: str, recursive: bool = False, backup: bool = True) -> str:
        """删除文件/目录。默认先移到 /tmp/kali-mcp-trash/<时间戳>/ 而非真删。

        Args:
            remote_path: 路径
            recursive: 目录必须 True
            backup: False 才真删（不可恢复）
        """
        res = eng.delete(remote_path, recursive, backup)
        eng.audit("kali_delete", f"{remote_path} recursive={recursive} backup={backup}")
        return fmt(res)

    @mcp.tool()
    def kali_chmod(remote_path: str, mode: str = "644", recursive: bool = False, owner: str = "") -> str:
        """改权限，可同时改属主（owner 形如 "root:root"）。"""
        return fmt(eng.chmod(remote_path, mode, recursive, owner))

    @mcp.tool()
    def kali_find(remote_path: str = ".", name: str = "", size: str = "", mtime: str = "",
                  ftype: str = "", max_results: int = 80) -> str:
        """按名字/大小/时间/类型找文件，例如找 SUID、找配置文件、找备份。

        Args:
            remote_path: 搜索根
            name: 文件名通配，如 "*.conf"
            size: find 语法，如 "+10M"
            mtime: find 语法，如 "-1"（一天内）
            ftype: f/d/l
            max_results: 上限
        """
        parts = [f"find {q(remote_path)}"]
        if name:
            parts.append(f"-iname {q(name)}")
        if ftype in ("f", "d", "l"):
            parts.append(f"-type {ftype}")
        if size:
            parts.append(f"-size {q(size)}")
        if mtime:
            parts.append(f"-mtime {q(mtime)}")
        parts.append(f"-print 2>/dev/null | head -n {max(1, int(max_results))}")
        return sh(eng, "kali_find", " ".join(parts), 90)

    @mcp.tool()
    def kali_grep(pattern: str, remote_path: str = ".", recursive: bool = True,
                  max_results: int = 60, file_glob: str = "", ignore_case: bool = False) -> str:
        """在文件/目录里搜文本或正则（默认忽略二进制）。"""
        res = eng.grep(pattern, remote_path, recursive, max_results, file_glob, ignore_case)
        body = res["output"].strip("\n")
        return f"命中 {len(body.splitlines())} 行\n---\n{clip(body)}" if body else f"无匹配: {pattern!r}"

    @mcp.tool()
    def kali_tail(remote_path: str, lines: int = 100) -> str:
        """看文件末尾（日志、扫描输出）。"""
        return clip(eng.tail(remote_path, lines)["output"].strip()) or "(空)"

    @mcp.tool()
    def kali_head(remote_path: str, lines: int = 50) -> str:
        """看文件开头（配置、报告头部）。"""
        return clip(eng.head(remote_path, lines)["output"].strip()) or "(空)"

    @mcp.tool()
    def kali_checksum(remote_path: str, algo: str = "sha256") -> str:
        """算校验和（md5/sha1/sha256/sha512），下载后核对完整性用。"""
        return eng.checksum(remote_path, algo)["output"].strip()

    @mcp.tool()
    def kali_archive(src: str, dest: str = "", archive_fmt: str = "tar.gz", password: str = "") -> str:
        """打包压缩目录或文件（取证留存、外传前打包）。

        Args:
            src: 源路径
            dest: 输出文件，留空自动命名
            archive_fmt: tar.gz / tar / zip
            password: 目前仅提示用 7z 手动加密；留空即可
        """
        import time as _t
        dest = dest or f"/tmp/{os.path.basename(src.rstrip('/'))}-{_t.strftime('%Y%m%d-%H%M%S')}.{archive_fmt}"
        base = os.path.basename(src.rstrip("/"))
        parent = os.path.dirname(os.path.abspath(src)) or "."
        if archive_fmt == "zip":
            cmd = f"cd {q(parent)} && zip -r {q(dest)} {q(base)}"
        elif archive_fmt == "tar":
            cmd = f"tar -cf {q(dest)} -C {q(parent)} {q(base)}"
        else:
            cmd = f"tar -czf {q(dest)} -C {q(parent)} {q(base)}"
        if password:
            cmd += f" && echo '（密码参数需 7z 手动加密：7z a -p<密码> out.7z {q(base)}）'"
        eng.audit("kali_archive", f"{src} -> {dest} ({archive_fmt})")
        return fmt(eng.run(cmd + f"; ls -lh {q(dest)}", 600))

    @mcp.tool()
    def kali_extract(archive: str, dest: str = "", password: str = "") -> str:
        """解压压缩包（自动识别 tar/zip/7z/rar）。"""
        dest = dest or os.path.dirname(archive) or "."
        cmd = f"mkdir -p {q(dest)} && cd {q(dest)} && "
        if archive.endswith(".zip"):
            cmd += f"unzip -o {q(archive)}"
        elif archive.endswith((".7z", ".rar")):
            tool = eng.has("7z", "7za", "unrar")
            if not tool:
                return "需要 7z/unrar：sudo apt install -y p7zip-full"
            cmd += f"{tool} x -y {q(archive)}"
        else:
            cmd += f"tar -xf {q(archive)}"
        eng.audit("kali_extract", f"{archive} -> {dest}")
        return fmt(eng.run(cmd + f" 2>&1 | tail -20; ls -la {q(dest)} | head -20", 600))

    @mcp.tool()
    def kali_fetch_url(url: str, dest: str = "", timeout: int = 300, insecure: bool = True) -> str:
        """从远端下载文件到 Kali（wget 优先，失败回落 curl）。

        Args:
            url: 下载地址
            dest: 保存路径，留空按 URL 自动命名到 /tmp
            insecure: 忽略证书错误
        """
        if not url.lower().startswith(("http://", "https://", "ftp://")):
            return "只支持 http/https/ftp"
        dest = dest or f"/tmp/{url.split('/')[-1].split('?')[0] or 'download.bin'}"
        flags = "-k " if insecure else ""
        cmd = (f"wget {flags}-q --show-progress -O {q(dest)} {q(url)} 2>&1 || "
               f"curl {('-k ' if insecure else '')}-L -o {q(dest)} {q(url)} 2>&1; "
               f"ls -lh {q(dest)} 2>&1")
        eng.audit("kali_fetch_url", url)
        return fmt(eng.run(cmd, timeout))

    @mcp.tool()
    def kali_serve_http(port: int = 8000, remote_path: str = ".", name: str = "") -> str:
        """起一个临时 HTTP 服务（传 payload、给对方下载文件、配合 SSRF 回连）。

        Args:
            port: 端口
            remote_path: 共享目录
            name: 备注
        """
        cmd = f"cd {q(remote_path)} && python3 -m http.server {int(port)} --bind 0.0.0.0"
        info = eng.job_start(cmd, name or f"http-{port}")
        if not info.get("ok"):
            return f"启动失败: {info.get('output')}"
        eng.audit("kali_serve_http", f"port={port} dir={remote_path}")
        ip = eng.run("hostname -I | awk '{print $1}'", 15)["output"].strip()
        return (f"HTTP 服务已启动\njob_id: {info['job_id']}\n目录: {remote_path}\n"
                f"本机地址: http://{ip}:{port}/   端口: {port}\n"
                f"停止: kali_job_kill job_id={info['job_id']}")
