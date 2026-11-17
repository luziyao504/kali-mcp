"""本机执行引擎：命令、持久 shell、后台任务、文件、审计、产物、笔记、范围。

只做「在 Kali 本机执行」一种后端——这就是 kali-mcp 的定位。
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import time
import uuid

from .util import (
    DEFAULT_TIMEOUT, SHELL_IDLE, MARKER_RE, SENTINEL_CMD,
    clip, decode, human_size, perm, redact, strip_echo, strip_scheme,
)


class Engine:
    def __init__(self, state_dir: str, label: str = "kali@localhost"):
        self.label = label
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.jobs_file = os.path.join(state_dir, "jobs.json")
        self.audit_file = os.path.join(state_dir, "audit.log")
        self.notes_file = os.path.join(state_dir, "notes.json")
        self.scope_file = os.path.join(state_dir, "scope.txt")
        self.artifact_dir = os.path.join(state_dir, "artifacts")
        self.report_dir = os.path.join(state_dir, "reports")
        os.makedirs(self.artifact_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)
        self._proc = None
        self._fd = None
        self._last = 0.0

    # -------------------------------------------------------------- 执行
    @property
    def is_root(self) -> bool:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def run(self, command: str, timeout: int | None = None, sudo: bool = False,
            cwd: str | None = None) -> dict:
        tmo = max(5, int(timeout or DEFAULT_TIMEOUT))
        real = command
        if sudo and not self.is_root:
            pw = os.getenv("KALI_MCP_SUDO_PASS", "")
            if pw:
                blob = base64.b64encode(pw.encode()).decode()
                real = (f"echo {blob} | base64 -d | sudo -S -p '' -H bash -lc {shlex.quote(command)}")
            else:
                real = f"sudo -n -H bash -lc {shlex.quote(command)}"
        started = time.monotonic()
        try:
            proc = subprocess.run(["bash", "-lc", real], capture_output=True, timeout=tmo,
                                  cwd=cwd, text=False)
            return {"exit_code": proc.returncode, "timed_out": False,
                    "output": clip(decode(proc.stdout + proc.stderr)),
                    "elapsed": round(time.monotonic() - started, 2)}
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"") + (exc.stderr or b"")
            return {"exit_code": None, "timed_out": True,
                    "output": clip(decode(out)) + f"\n[超时 {tmo}s，进程已被杀掉]",
                    "elapsed": round(time.monotonic() - started, 2)}

    def runv(self, argv: list[str], timeout: int | None = None, sudo: bool = False) -> dict:
        """参数化执行（不经过 shell），避免注入。sudo 时退回 shell 形式。"""
        if sudo and not self.is_root:
            return self.run(" ".join(shlex.quote(a) for a in argv), timeout, sudo=True)
        tmo = max(5, int(timeout or DEFAULT_TIMEOUT))
        started = time.monotonic()
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=tmo, text=False)
            return {"exit_code": proc.returncode, "timed_out": False,
                    "output": clip(decode(proc.stdout + proc.stderr)),
                    "elapsed": round(time.monotonic() - started, 2)}
        except FileNotFoundError:
            return {"exit_code": 127, "timed_out": False, "elapsed": 0,
                    "output": f"命令不存在: {argv[0]}（可用 kali_install_tool 安装）"}
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"") + (exc.stderr or b"")
            return {"exit_code": None, "timed_out": True,
                    "output": clip(decode(out)) + f"\n[超时 {tmo}s，进程已被杀掉]",
                    "elapsed": round(time.monotonic() - started, 2)}

    def run_sudo(self, command: str, timeout: int | None = None) -> dict:
        return self.run(command, timeout, sudo=True)

    def which(self, binary: str) -> str | None:
        return shutil.which(binary)

    def has(self, *binaries: str) -> str | None:
        for b in binaries:
            if shutil.which(b):
                return b
        return None

    def version_of(self, binary: str) -> str:
        for flag in ("--version", "-V", "-v", "version"):
            res = self.runv([binary, flag], timeout=15)
            line = (res["output"] or "").strip().splitlines()
            if line:
                return line[0][:120]
        return "已安装"

    # -------------------------------------------------------------- 持久 shell
    def _read_until(self, timeout: float):
        import select
        buf = b""
        deadline = time.monotonic() + timeout
        while True:
            r, _, _ = select.select([self._fd], [], [], 0.1)
            if r:
                try:
                    data = os.read(self._fd, 65536)
                except OSError:
                    data = b""
                if data:
                    buf += data
            text = decode(buf)
            if MARKER_RE.search(text):
                return text, True
            if time.monotonic() > deadline:
                return text, False

    def _open_shell(self):
        import pty  # 仅 Unix 有，延迟导入保证 Windows 下也能 import 本包
        master, slave = pty.openpty()
        self._proc = subprocess.Popen(["bash", "-i"], stdin=slave, stdout=slave, stderr=slave,
                                      start_new_session=True, close_fds=True)
        os.close(slave)
        self._fd = master
        time.sleep(0.3)
        os.write(self._fd, (SENTINEL_CMD + "\n").encode())
        _, ok = self._read_until(15)
        if not ok:
            self.shell_close()
            raise RuntimeError("持久 shell 初始化失败")
        self._last = time.monotonic()

    def shell(self, command: str, timeout: int | None = None, reset: bool = False) -> dict:
        tmo = max(5, int(timeout or DEFAULT_TIMEOUT))
        started = time.monotonic()
        if reset:
            self.shell_close()
        if self._fd is None or time.monotonic() - self._last > SHELL_IDLE:
            self.shell_close()
            self._open_shell()
        os.write(self._fd, (command.rstrip("\n") + "\n" + SENTINEL_CMD + "\n").encode())
        text, ok = self._read_until(tmo)
        self._last = time.monotonic()
        if not ok:
            self.shell_close()
            return {"exit_code": None, "timed_out": True, "output": clip(text),
                    "elapsed": round(time.monotonic() - started, 2)}
        m = MARKER_RE.search(text)
        rc = int(m.group(1)) if m else None
        body = text[: m.start()] if m else text
        return {"exit_code": rc, "timed_out": False,
                "output": clip(strip_echo(body, command)),
                "elapsed": round(time.monotonic() - started, 2)}

    def shell_close(self) -> None:
        if self._proc is not None:
            try:
                self._proc.kill()
            except Exception:
                pass
        if self._fd is not None:
            try:
                os.close(self._fd)
            except Exception:
                pass
        self._proc = None
        self._fd = None

    def close(self) -> None:
        self.shell_close()

    # -------------------------------------------------------------- 审计 / 产物
    def audit(self, tool: str, summary: str) -> None:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "tool": tool, "summary": summary[:500]}
        try:
            with open(self.audit_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def history(self, limit: int = 50, tool: str = "") -> str:
        if not os.path.isfile(self.audit_file):
            return "暂无审计记录"
        with open(self.audit_file, "r", encoding="utf-8") as fh:
            rows = [ln.strip() for ln in fh if ln.strip()]
        if tool:
            rows = [r for r in rows if json.loads(r).get("tool") == tool]
        rows = rows[-max(1, int(limit)):]
        if not rows:
            return "无匹配记录"
        out = []
        for r in rows:
            try:
                d = json.loads(r)
                out.append(f"{d.get('ts', '')}  {d.get('tool', ''):<20} {d.get('summary', '')}")
            except Exception:
                out.append(r)
        return "\n".join(out)

    def save_artifact(self, tool: str, text: str, command: str = "") -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        name = f"{stamp}-{tool}-{uuid.uuid4().hex[:6]}.log"
        path = os.path.join(self.artifact_dir, name)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"# tool: {tool}\n# time: {stamp}\n# command: {command}\n")
                fh.write("# " + "-" * 60 + "\n")
                fh.write(redact(text or ""))
        except Exception:
            return ""
        self._prune_artifacts()
        return path

    def _prune_artifacts(self) -> None:
        limit = int(os.getenv("KALI_MCP_ARTIFACT_KEEP", "400"))
        try:
            files = sorted(
                (os.path.join(self.artifact_dir, f) for f in os.listdir(self.artifact_dir)),
                key=os.path.getmtime,
            )
            for old in files[:-limit]:
                os.remove(old)
        except Exception:
            pass

    def artifacts(self, limit: int = 30) -> list[dict]:
        try:
            files = [os.path.join(self.artifact_dir, f) for f in os.listdir(self.artifact_dir)]
        except FileNotFoundError:
            return []
        files.sort(key=os.path.getmtime, reverse=True)
        rows = []
        for p in files[:limit]:
            rows.append({"path": p, "size": human_size(os.path.getsize(p)),
                         "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(p)))})
        return rows

    # -------------------------------------------------------------- 后台任务
    def _load_jobs(self) -> dict:
        try:
            with open(self.jobs_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_jobs(self, jobs: dict) -> None:
        tmp = self.jobs_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(jobs, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, self.jobs_file)

    def job_start(self, command: str, name: str = "", job_dir: str = "/tmp/kali-mcp-jobs") -> dict:
        jid = "j" + uuid.uuid4().hex[:8]
        log_path = f"{job_dir}/{jid}.log"
        cmd = (f"mkdir -p {job_dir} && nohup setsid bash -lc {shlex.quote(command)} "
               f"> {shlex.quote(log_path)} 2>&1 < /dev/null & echo $!")
        res = self.run(cmd, timeout=25)
        time.sleep(0.3)
        pid = None
        for line in (res["output"] or "").splitlines():
            s = line.strip()
            if s.isdigit():
                pid = int(s)
        if pid is None:
            return {"ok": False, "output": res["output"]}
        jobs = self._load_jobs()
        jobs[jid] = {"job_id": jid, "pid": pid, "log": log_path, "name": name,
                     "command": command, "started": time.strftime("%Y-%m-%d %H:%M:%S")}
        self._save_jobs(jobs)
        return {"ok": True, "job_id": jid, "pid": pid, "log": log_path}

    def job_output(self, job_id: str, lines: int = 100) -> str:
        info = self._load_jobs().get(job_id)
        if not info:
            return f"找不到任务 {job_id}"
        pid = int(info["pid"])
        res = self.run(
            f"if kill -0 {pid} 2>/dev/null; then echo '__STATE__:running'; "
            f"else echo '__STATE__:finished'; fi; echo '--- log ---'; "
            f"tail -n {max(1, int(lines))} {shlex.quote(info['log'])} 2>&1",
            timeout=25,
        )
        return f"{job_id} ({(info.get('name') or '未命名')}) pid={pid}\n{clip(res['output']).strip()}"

    def job_list(self) -> str:
        jobs = self._load_jobs()
        if not jobs:
            return "当前没有后台任务"
        pids = " ".join(str(int(v["pid"])) for v in jobs.values())
        res = self.run(
            f"for p in {pids}; do if kill -0 $p 2>/dev/null; then echo \"$p alive\"; "
            'else echo "$p dead"; fi; done',
            timeout=25,
        )
        state = {}
        for line in (res["output"] or "").splitlines():
            parts = line.split()
            if len(parts) == 2:
                state[parts[0]] = parts[1]
        rows = [f"共 {len(jobs)} 个任务"]
        for jid, info in sorted(jobs.items(), key=lambda kv: kv[0], reverse=True):
            rows.append(f"{jid}  pid={info['pid']}  {state.get(str(info['pid']), 'unknown'):<8} "
                        f"{info.get('started', '')}  {(info.get('name') or '-')}  :: "
                        f"{(info.get('command') or '')[:70]}")
        return "\n".join(rows)

    def job_kill(self, job_id: str, force: bool = False) -> str:
        info = self._load_jobs().get(job_id)
        if not info:
            return f"找不到任务 {job_id}"
        pid = int(info["pid"])
        sig = "KILL" if force else "TERM"
        res = self.run(
            f"kill -{sig} -{pid} 2>/dev/null; kill -{sig} {pid} 2>/dev/null; sleep 1; "
            f"if kill -0 {pid} 2>/dev/null; then echo still-running; else echo stopped; fi",
            timeout=25,
        )
        return f"{job_id} SIG{sig} -> {(res['output'] or '').strip() or '已发送信号'}"

    # -------------------------------------------------------------- 文件
    def read_bytes(self, path: str, offset: int = 0, limit: int = 200_000) -> bytes:
        with open(path, "rb") as fh:
            if offset:
                fh.seek(int(offset))
            return fh.read(int(limit))

    def write_bytes(self, path: str, data: bytes, append: bool = False) -> None:
        parent = posixpath.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        with open(path, "ab" if append else "wb") as fh:
            fh.write(data)

    def list_dir(self, path: str) -> list[dict]:
        rows = []
        for item in os.scandir(path):
            st = item.stat(follow_symlinks=False)
            rows.append({"name": item.name, "is_dir": item.is_dir(follow_symlinks=False),
                         "size": st.st_size, "mtime": st.st_mtime, "mode": perm(st.st_mode)})
        return rows

    def stat_path(self, path: str) -> dict | None:
        import stat as statlib
        if not os.path.exists(path):
            return None
        st = os.lstat(path)
        return {"size": st.st_size, "mtime": st.st_mtime, "mode": perm(st.st_mode),
                "is_dir": statlib.S_ISDIR(st.st_mode)}

    def mkdir_p(self, path: str, mode: str = "755") -> dict:
        qp = shlex.quote(path)
        return self.run(f"mkdir -p {qp} && chmod {mode} {qp} && ls -ld {qp}", timeout=20)

    def move(self, src: str, dst: str, overwrite: bool = False) -> dict:
        flag = "-f" if overwrite else "-n"
        return self.run(f"mv {flag} {shlex.quote(src)} {shlex.quote(dst)} 2>&1; echo '---'; "
                        f"ls -ld {shlex.quote(dst)} 2>&1", timeout=40)

    def copy(self, src: str, dst: str) -> dict:
        return self.run(f"cp -a {shlex.quote(src)} {shlex.quote(dst)} 2>&1; echo '---'; "
                        f"ls -ld {shlex.quote(dst)} 2>&1", timeout=90)

    def delete(self, path: str, recursive: bool = False, backup: bool = True,
               trash_dir: str = "/tmp/kali-mcp-trash") -> dict:
        qp = shlex.quote(path)
        check = self.run(f"if [ -d {qp} ] && [ ! -L {qp} ]; then echo dir; elif [ -e {qp} ]; "
                         "then echo file; else echo missing; fi", timeout=20)
        kind = (check["output"].strip().splitlines() or ["missing"])[-1].strip()
        if kind == "missing":
            return {"exit_code": 1, "timed_out": False, "elapsed": 0, "output": f"不存在: {path}"}
        if kind == "dir" and not recursive:
            return {"exit_code": 1, "timed_out": False, "elapsed": 0,
                    "output": f"拒绝执行: {path} 是目录，需要 recursive=True"}
        if backup:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            cmd = (f"mkdir -p {trash_dir}/{stamp} && mv {qp} {trash_dir}/{stamp}/ && "
                   f"echo '已备份到 {trash_dir}/{stamp}/'")
        else:
            cmd = f"rm {'-rf' if recursive else '-f'} {qp} && echo '已直接删除（不可恢复）'"
        return self.run(cmd, timeout=90)

    def chmod(self, path: str, mode: str = "644", recursive: bool = False, owner: str = "") -> dict:
        flag = "-R " if recursive else ""
        res = self.run(f"chmod {flag}{mode} {shlex.quote(path)} 2>&1; ls -ld {shlex.quote(path)}", timeout=40)
        if owner and res["exit_code"] == 0:
            res = self.run_sudo(f"chown {flag}{owner} {shlex.quote(path)} && ls -ld {shlex.quote(path)}", timeout=60)
        return res

    def tail(self, path: str, lines: int = 100) -> dict:
        return self.run(f"tail -n {max(1, int(lines))} {shlex.quote(path)} 2>&1", timeout=40)

    def head(self, path: str, lines: int = 50) -> dict:
        return self.run(f"head -n {max(1, int(lines))} {shlex.quote(path)} 2>&1", timeout=40)

    def grep(self, pattern: str, path: str = ".", recursive: bool = True, max_results: int = 60,
             file_glob: str = "", ignore_case: bool = False) -> dict:
        flags = "-rnI" if recursive else "-nI"
        if ignore_case:
            flags += "i"
        inc = f"--include={shlex.quote(file_glob)} " if file_glob else ""
        return self.run(f"grep {flags} {inc}{shlex.quote(pattern)} {shlex.quote(path)} 2>/dev/null "
                        f"| head -n {max(1, int(max_results))}", timeout=90)

    def find(self, path: str = ".", name: str = "", size: str = "", mtime: str = "",
             ftype: str = "", max_results: int = 80) -> dict:
        parts = [f"find {shlex.quote(path)}"]
        if name:
            parts.append(f"-iname {shlex.quote(name)}")
        if ftype in ("f", "d", "l"):
            parts.append(f"-type {ftype}")
        if size:
            parts.append(f"-size {shlex.quote(size)}")
        if mtime:
            parts.append(f"-mtime {shlex.quote(mtime)}")
        parts.append(f"2>/dev/null | head -n {max(1, int(max_results))}")
        return self.run(" ".join(parts), timeout=90)

    def checksum(self, path: str, algo: str = "sha256") -> dict:
        algo = algo if algo in ("md5", "sha1", "sha256", "sha512") else "sha256"
        return self.run(f"{algo}sum {shlex.quote(path)} 2>&1", timeout=120)

    # -------------------------------------------------------------- 笔记
    def _load_notes(self) -> list:
        try:
            with open(self.notes_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_notes(self, notes: list) -> None:
        tmp = self.notes_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(notes, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, self.notes_file)

    def note_add(self, title: str, detail: str = "", target: str = "", severity: str = "info",
                 tag: str = "") -> dict:
        notes = self._load_notes()
        item = {"id": len(notes) + 1, "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "title": title, "detail": detail, "target": target,
                "severity": severity.lower(), "tag": tag}
        notes.append(item)
        self._save_notes(notes)
        return item

    def note_list(self, severity: str = "", target: str = "") -> str:
        notes = self._load_notes()
        if severity:
            notes = [n for n in notes if n.get("severity") == severity.lower()]
        if target:
            notes = [n for n in notes if target in (n.get("target") or "")]
        if not notes:
            return "暂无记录"
        rows = [f"共 {len(notes)} 条"]
        for n in notes:
            rows.append(f"[{n['id']}] {n['ts']} [{n['severity']:<7}] {n['target'] or '-':<24} "
                        f"{n['title']}" + (f"  | {n['detail'][:120]}" if n.get("detail") else ""))
        return "\n".join(rows)

    def note_clear(self) -> str:
        self._save_notes([])
        return "已清空全部 findings"

    def report(self, title: str = "Kali MCP 行动报告") -> str:
        notes = self._load_notes()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(self.report_dir, f"report-{stamp}.md")
        lines = [f"# {title}", "", f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
                 f"- 主机：{self.label}", f"- 服务：kali-mcp", "",
                 "## Findings", ""]
        if not notes:
            lines.append("_本次未记录 finding。_")
        for n in notes:
            lines.append(f"### {n['id']}. {n['title']}")
            lines.append(f"- 时间：{n['ts']}")
            lines.append(f"- 目标：{n.get('target') or '-'}")
            lines.append(f"- 级别：{n.get('severity')}")
            if n.get("tag"):
                lines.append(f"- 标签：{n['tag']}")
            if n.get("detail"):
                lines += ["", "```", n["detail"], "```"]
            lines.append("")
        lines += ["## 执行审计（最近 40 条）", "", "```", self.history(40), "```", ""]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return path

    # -------------------------------------------------------------- 范围
    def scope(self) -> list[str]:
        try:
            with open(self.scope_file, "r", encoding="utf-8") as fh:
                return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except FileNotFoundError:
            return []

    def scope_set(self, entries: list[str]) -> list[str]:
        cleaned = [e.strip() for e in entries if e.strip()]
        with open(self.scope_file, "w", encoding="utf-8") as fh:
            fh.write("# 授权目标范围，一行一个；留空表示不限制\n")
            for e in cleaned:
                fh.write(e + "\n")
        return cleaned

    def in_scope(self, target: str) -> bool | None:
        """None = 未设置范围（不校验）；True/False = 判定结果。"""
        entries = self.scope()
        if not entries:
            return None
        host = strip_scheme(target)
        try:
            ip = ipaddress.ip_address(host.split(":")[0])
        except ValueError:
            ip = None
        for e in entries:
            if e == "*" or fnmatch.fnmatch(host, e) or host == e:
                return True
            if ip is not None:
                try:
                    if ip in ipaddress.ip_network(e, strict=False):
                        return True
                except ValueError:
                    continue
            if host.endswith("." + e):
                return True
        return False

    def status(self) -> str:
        res = self.run(
            'echo "hostname: $(hostname)"; echo "user: $(whoami)"; '
            'echo "os: $(grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d \'"\')"; '
            'echo "kernel: $(uname -r) $(uname -m)"; '
            'echo "ip: $(hostname -I 2>/dev/null | awk \'{print $1}\')"; '
            'echo "uptime: $(uptime -p 2>/dev/null || uptime)"; '
            'echo "mem: $(free -h 2>/dev/null | sed -n 2p)"; '
            'echo "disk: $(df -h / 2>/dev/null | tail -1)"',
            timeout=30,
        )
        return f"{self.label}\n---\n{res['output'].strip()}"

    def ps(self, top: int = 15, sort_by: str = "cpu") -> dict:
        key = "-%mem" if sort_by.lower().startswith("m") else "-%cpu"
        return self.run(f"ps aux --sort={key} | head -n {max(1, int(top)) + 1}", timeout=30)

    def ports(self) -> dict:
        return self.run_sudo("ss -tulnp", timeout=40)

    def kill_pid(self, pid: int, force: bool = False) -> dict:
        sig = "KILL" if force else "TERM"
        return self.run(f"kill -{sig} {int(pid)} 2>&1; sleep 1; "
                        f"if kill -0 {int(pid)} 2>/dev/null; then echo still-running; else echo stopped; fi",
                        timeout=25)
