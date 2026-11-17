"""系统运维与执行类工具：状态、命令、持久 shell、后台任务、服务、软件包、日志。"""

from __future__ import annotations

import shlex

from mcp.server.fastmcp import FastMCP

from ..engine import Engine
from ..toolkit import sh, table
from ..util import clip, fmt


def register(mcp: FastMCP, eng: Engine) -> None:

    @mcp.tool()
    def kali_status() -> str:
        """查看 Kali 主机状态：主机名/用户/系统/内核/IP/在线时长/内存/磁盘。先调它确认链路可用。"""
        return eng.status()

    @mcp.tool()
    def kali_exec(command: str, timeout: int = 120) -> str:
        """在 Kali 本机执行 shell 命令（一次性会话），返回 exit_code 与输出。

        Args:
            command: 要执行的命令，可直接用管道
            timeout: 超时秒数
        """
        return sh(eng, "kali_exec", command, timeout)

    @mcp.tool()
    def kali_sudo(command: str, timeout: int = 120) -> str:
        """以 root 执行命令（服务非 root 运行时自动 sudo，需配 KALI_MCP_SUDO_PASS）。"""
        return sh(eng, "kali_sudo", command, timeout, sudo=True)

    @mcp.tool()
    def kali_shell(command: str, timeout: int = 120, reset: bool = False) -> str:
        """在持久 shell 里执行命令：cd、export、别名在多次调用之间保留。

        Args:
            command: 命令
            timeout: 超时秒数
            reset: True 重置会话（环境乱了时用）
        """
        eng.audit("kali_shell", command)
        res = eng.shell(command, timeout, reset)
        return fmt(res)

    @mcp.tool()
    def kali_job_start(command: str, name: str = "") -> str:
        """把长任务放到后台跑（nmap 大段扫描、hashcat、监听器、抓包等），立刻返回 job_id。

        Args:
            command: 命令
            name: 备注名
        """
        info = eng.job_start(command, name)
        if not info.get("ok"):
            return f"启动失败: {info.get('output')}"
        eng.audit("kali_job_start", f"{info['job_id']} {name} :: {command}")
        return f"job_id: {info['job_id']}\npid: {info['pid']}\nlog: {info['log']}"

    @mcp.tool()
    def kali_job_output(job_id: str, lines: int = 100) -> str:
        """读后台任务的日志尾部与运行状态。"""
        return eng.job_output(job_id, lines)

    @mcp.tool()
    def kali_job_list() -> str:
        """列出所有后台任务及其存活状态。"""
        return eng.job_list()

    @mcp.tool()
    def kali_job_kill(job_id: str, force: bool = False) -> str:
        """停掉后台任务（force=True 用 SIGKILL）。"""
        eng.audit("kali_job_kill", f"{job_id} force={force}")
        return eng.job_kill(job_id, force)

    @mcp.tool()
    def kali_sysinfo() -> str:
        """系统画像：CPU 型号/核数、负载、内存、磁盘占用、网络接口、开机时间。"""
        cmd = (
            'echo "== CPU =="; lscpu 2>/dev/null | grep -E "^(Model name|CPU\\(s\\)|Thread|Core)" ; '
            'echo "== LOAD =="; uptime; '
            'echo "== MEM =="; free -h; '
            'echo "== DISK =="; df -hT | grep -vE "tmpfs|loop"; '
            'echo "== NET =="; ip -4 -o addr show | awk "{print \\$2, \\$4}"; '
            'echo "== BOOT =="; who -b 2>/dev/null; uptime -s 2>/dev/null; '
            'echo "== TOP5 =="; ps aux --sort=-%mem | head -6'
        )
        return sh(eng, "kali_sysinfo", cmd, 60)

    @mcp.tool()
    def kali_processes(top: int = 15, sort_by: str = "cpu") -> str:
        """资源占用最高的进程。

        Args:
            top: 取前 N 个
            sort_by: "cpu" 或 "mem"
        """
        return fmt(eng.ps(top, sort_by))

    @mcp.tool()
    def kali_ports() -> str:
        """当前监听的 TCP/UDP 端口及对应进程（需要 root 才有进程名）。"""
        res = eng.ports()
        return clip(res["output"].strip()) or "(无监听端口)"

    @mcp.tool()
    def kali_kill_pid(pid: int, force: bool = False) -> str:
        """按 PID 结束进程。"""
        eng.audit("kali_kill_pid", f"{pid} force={force}")
        return fmt(eng.kill_pid(pid, force))

    @mcp.tool()
    def kali_disk(path: str = "/", top: int = 15) -> str:
        """磁盘占用分析：挂载点使用率 + 指定目录下最大的前 N 项。"""
        cmd = (f"df -hT | grep -vE 'tmpfs|loop'; echo '--- 大目录/文件 ---'; "
               f"du -ah {shlex.quote(path)} 2>/dev/null | sort -rh | head -n {max(1, int(top))}")
        return sh(eng, "kali_disk", cmd, 120)

    @mcp.tool()
    def kali_service(action: str, name: str = "") -> str:
        """管理 systemd 服务。

        Args:
            action: list / status / start / stop / restart / enable / disable / failed
            name: 服务名（除 list/failed 外必填）
        """
        act = action.lower().strip()
        if act == "list":
            cmd = "systemctl list-units --type=service --state=running --no-pager | head -40"
        elif act == "failed":
            cmd = "systemctl --failed --no-pager"
        elif act in ("status", "start", "stop", "restart", "enable", "disable"):
            if not name:
                return "缺少 name 参数"
            cmd = f"systemctl {act} {shlex.quote(name)} --no-pager 2>&1; systemctl is-active {shlex.quote(name)}"
            if act in ("start", "stop", "restart", "enable", "disable"):
                return sh(eng, "kali_service", cmd, 60, sudo=True)
        else:
            return "action 只支持 list/failed/status/start/stop/restart/enable/disable"
        return sh(eng, "kali_service", cmd, 60)

    @mcp.tool()
    def kali_logs(unit: str = "", lines: int = 60, since: str = "", grep: str = "") -> str:
        """读 journal 日志。

        Args:
            unit: 服务名，留空读全局
            lines: 行数
            since: 如 "1 hour ago"
            grep: 只看含该关键字的行
        """
        parts = ["journalctl --no-pager", f"-n {max(1, int(lines))}"]
        if unit:
            parts.append(f"-u {shlex.quote(unit)}")
        if since:
            parts.append(f"--since {shlex.quote(since)}")
        cmd = " ".join(parts)
        if grep:
            cmd += f" | grep -i {shlex.quote(grep)}"
        return sh(eng, "kali_logs", cmd, 60, sudo=True)

    @mcp.tool()
    def kali_pkg(action: str, name: str = "") -> str:
        """软件包管理（apt / dpkg）。

        Args:
            action: search / info / installed / install / remove / hold
            name: 包名或关键字
        """
        act = action.lower().strip()
        if act == "search":
            return sh(eng, "kali_pkg", f"apt-cache search {shlex.quote(name)} | head -30", 90)
        if act == "info":
            return sh(eng, "kali_pkg", f"apt-cache show {shlex.quote(name)} 2>/dev/null | head -40", 90)
        if act == "installed":
            cmd = "dpkg -l | awk '$1==\"ii\"{print $2, $3}'"
            if name:
                cmd += f" | grep -i {shlex.quote(name)}"
            return sh(eng, "kali_pkg", cmd, 60)
        if act == "install":
            return sh(eng, "kali_pkg", f"DEBIAN_FRONTEND=noninteractive apt-get install -y {shlex.quote(name)}", 600, sudo=True)
        if act == "remove":
            return sh(eng, "kali_pkg", f"apt-get remove -y {shlex.quote(name)}", 300, sudo=True)
        if act == "hold":
            return sh(eng, "kali_pkg", f"apt-mark hold {shlex.quote(name)}", 60, sudo=True)
        return "action 只支持 search/info/installed/install/remove/hold"

    @mcp.tool()
    def kali_update(upgrade: bool = False) -> str:
        """apt update；upgrade=True 时顺带升级（耗时可能很久，建议放后台）。"""
        cmd = "apt-get update" + (" && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y" if upgrade else "")
        return sh(eng, "kali_update", cmd, 900, sudo=True)

    @mcp.tool()
    def kali_cron_list() -> str:
        """列出当前 crontab 与 /etc/cron.d。"""
        cmd = ("echo '== crontab -l =='; crontab -l 2>&1; echo '== /etc/cron.d =='; "
               "ls -l /etc/cron.d 2>&1; echo '== timers =='; systemctl list-timers --no-pager 2>/dev/null | head -20")
        return sh(eng, "kali_cron_list", cmd, 60, sudo=True)

    @mcp.tool()
    def kali_cron_add(schedule: str, command: str, user: str = "root") -> str:
        """加一条定时任务（写到 /etc/cron.d/kali-mcp-<时间戳>），改完立即生效。

        Args:
            schedule: 五段 cron 表达式，如 "*/5 * * * *"
            command: 要执行的命令
            user: 以哪个用户跑
        """
        if len(schedule.split()) != 5:
            return "schedule 必须是 5 段：分 时 日 月 周"
        import time as _t
        path = f"/etc/cron.d/kali-mcp-{_t.strftime('%Y%m%d%H%M%S')}"
        line = f"{schedule} {user} {command}"
        eng.audit("kali_cron_add", f"{path} :: {line}")
        res = eng.run(f"printf '%s\\n' {shlex.quote(line)} | tee {path} >/dev/null && chmod 644 {path} && cat {path}",
                      timeout=60, sudo=True)
        return fmt(res)

    @mcp.tool()
    def kali_users() -> str:
        """列出系统用户、可登录账户、最近登录记录。"""
        cmd = ("echo '== 用户 =='; awk -F: '$3>=1000 && $7!~/nologin|false/ {print $1, $3, $7}' /etc/passwd; "
               "echo '== 当前登录 =='; who 2>/dev/null; echo '== 最近登录 =='; last -n 10 2>/dev/null | head -12")
        return sh(eng, "kali_users", cmd, 60)

    @mcp.tool()
    def kali_env(keys: str = "") -> str:
        """查看环境变量（可用逗号指定 key，避免把整份环境泄露给模型）。

        Args:
            keys: 如 "PATH,PROXY,http_proxy"，留空则输出全部（已打码）
        """
        from ..util import redact
        if keys:
            names = [k.strip() for k in keys.split(",") if k.strip()]
            cmd = "; ".join(f"echo '{n}=${n}'" for n in names if n.replace('_', '').isalnum())
            res = eng.run(cmd, 20)
            return res["output"].strip() or "(这些变量都没设置)"
        return redact(sh(eng, "kali_env", "env | sort", 20))

    @mcp.tool()
    def kali_docker(action: str = "ps") -> str:
        """Docker 状态管理。

        Args:
            action: ps / images / stats / info / networks / volumes
        """
        if not eng.which("docker"):
            return "未安装 docker（Kali 上可 sudo apt install -y docker.io）"
        act = action.lower().strip()
        cmds = {
            "ps": "docker ps -a --format 'table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}'",
            "images": "docker images",
            "stats": "docker stats --no-stream",
            "info": "docker info 2>&1 | head -30",
            "networks": "docker network ls",
            "volumes": "docker volume ls",
        }
        if act not in cmds:
            return "action 只支持 " + "/".join(cmds)
        return sh(eng, "kali_docker", cmds[act], 90, sudo=not eng.is_root)

    @mcp.tool()
    def kali_history(limit: int = 50, tool: str = "") -> str:
        """查看操作审计记录（谁在什么时间干了什么）。

        Args:
            limit: 最近多少条
            tool: 按工具名过滤
        """
        return eng.history(limit, tool)

    @mcp.tool()
    def kali_artifacts(limit: int = 30) -> str:
        """列出扫描产物（每次执行都落盘一份原始输出，便于复现与取证）。"""
        rows = eng.artifacts(limit)
        if not rows:
            return "暂无产物"
        return table([[r["mtime"], r["size"], r["path"]] for r in rows], ["时间", "大小", "路径"])

    @mcp.tool()
    def kali_artifact_read(path: str, lines: int = 200) -> str:
        """读某个产物文件（配合 kali_artifacts 使用）。"""
        return clip((eng.head(path, lines) or {}).get("output", "")) or "(空)"
