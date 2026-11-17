# kali-mcp

[![CI](https://github.com/luziyao504/kali-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/luziyao504/kali-mcp/actions/workflows/ci.yml)
![tools](https://img.shields.io/badge/tools-114-brightgreen)
![license](https://img.shields.io/badge/license-MIT-blue)

把一整台 **Kali Linux** 包装成一个标准 **MCP Server**：`git clone` → `install.sh` → 客户端填一个 URL，就能用自然语言驱动 Kali 做**系统维护**与**渗透测试**全流程。

- **114 个工具**：执行/文件/任务、侦察/扫描、Web、凭据、利用、内网/AD、无线、取证、报告
- **零公网依赖**：默认监听本机/内网，自带 Bearer Token 鉴权，不需要域名、不需要打洞
- **可交付的工程形态**：systemd 服务、Docker、CI、单测、审计日志、扫描产物留档、Markdown 报告导出
- **安全边界**：授权目标范围（scope）硬校验、危险删除默认进回收站、全量操作审计

> 只用于**你自己拥有或已获得书面授权**的目标。项目本身只做工具封装与编排，不替代授权流程。

---

## 1. 快速开始

```bash
git clone https://github.com/luziyao504/kali-mcp.git
cd kali-mcp
sudo bash install.sh          # 建 venv、装依赖、写 systemd、生成令牌、自检
```

输出会直接打印**令牌**和一段可粘贴的客户端配置：

```
✅ 安装完成
  服务:      kali-mcp (active)，开机自启
  监听:      0.0.0.0:8765   路径 /mcp      ← 绑定地址，不是可访问地址
  令牌:      xxxxxxxx
  本机地址:  http://127.0.0.1:8765/mcp     ← 只在 Kali 本机可用
  内网地址:  http://<Kali内网IP>:8765/mcp  ← 同内网机器用（ip -4 addr show 查）
```

常用运维：

```bash
systemctl status kali-mcp
journalctl -u kali-mcp -f
systemctl restart kali-mcp
sudo bash install.sh --port 9000      # 换端口重装
sudo bash install.sh --uninstall      # 卸载
```

不想装服务、只想前台跑：

```bash
bash run.sh                 # 自动建 .venv、装依赖、监听 127.0.0.1:8765
```

Docker：

```bash
cd docker && docker compose up -d --build
docker logs kali-mcp | grep 令牌     # 首次启动自动生成，或看挂载卷里的 token.txt
```

### 客户端配置

先确定 **URL 里该填哪个地址**，这一步最容易写错：

| 客户端在哪 | URL 填什么 | 说明 |
| --- | --- | --- |
| Kali 本机（同一台机器） | `http://127.0.0.1:8765/mcp` | 走回环，不出网卡；最快最稳 |
| Kali 所在内网的其它机器 | `http://<Kali内网IP>:8765/mcp`，如 `http://192.168.1.50:8765/mcp` | 用 `ip -4 addr show` 查，一般是 `192.168.x.x` / `10.x.x.x` |
| 外网、跨网络、云主机 | 内网 IP **一定不通** | 需要 ZeroTier/WireGuard 之类的 VPN，或 frp/隧道；见下方"跨网络访问" |

> ⚠️ **`0.0.0.0` 不能写进客户端 URL。** 它是服务端"监听所有网卡"的绑定地址（`--host 0.0.0.0`），
> 不是一条可访问的地址。客户端里必须写具体 IP 或域名。
> `127.0.0.1` 只能在同一台 Kali 上用——别的机器访问它，指向的是那台机器自己。

**HTTP 模式（推荐，一个服务多客户端同时用）**

```json
{
  "mcpServers": {
    "kali": {
      "type": "streamableHttp",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer <你的令牌>" }
    }
  }
}
```

把 `127.0.0.1` 换成上表里对应你场景的地址即可。令牌两种传法任选其一（服务端都认）：

- 请求头：`"headers": { "Authorization": "Bearer <你的令牌>" }`
- 写进 URL：`http://127.0.0.1:8765/mcp?token=<你的令牌>`（适合不支持自定义 Header 的客户端）

**跨网络访问（本机不在 Kali 的内网里）**

内网 IP 对外不可达，二选一：

1. **VPN（推荐）**：Kali 和客户端都加入同一 ZeroTier/WireGuard 网络，然后用 VPN 分给 Kali 的地址：
   ```json
   { "url": "http://10.147.20.5:8765/mcp?token=<你的令牌>" }
   ```
2. **隧道**：`cloudflared tunnel --url http://127.0.0.1:8765` 或自建 frp，拿到公网域名后用该域名替换地址。
   注意 `cloudflared` 的临时域名会变、跨境链路可能抖，长期用建议自有域名或 frp。

**stdio 模式（Claude Desktop 这类只支持本地进程的客户端）**

```bash
/opt/kali-mcp/venv/bin/kali-mcp --transport stdio --state-dir /opt/kali-mcp/data
```

```json
{
  "mcpServers": {
    "kali": {
      "command": "/opt/kali-mcp/venv/bin/kali-mcp",
      "args": ["--transport", "stdio", "--state-dir", "/opt/kali-mcp/data"]
    }
  }
}
```

`/health` 用于探活，`POST /mcp` 不带令牌一律 401。

---

## 2. 工具总览（114 个）

| 模块 | 数量 | 代表工具 |
| --- | --- | --- |
| **执行与任务** | 9 | `kali_exec`、`kali_sudo`、`kali_shell`（持久会话，cd/export 跨调用保留）、`kali_job_start/output/list/kill` |
| **系统维护** | 13 | `kali_status`、`kali_sysinfo`、`kali_service`、`kali_logs`、`kali_pkg`、`kali_update`、`kali_disk`、`kali_cron_*`、`kali_users`、`kali_docker`、`kali_kill_pid` |
| **文件与物料** | 16 | `kali_list_dir`、`kali_read_file`、`kali_write_file`、`kali_find`、`kali_grep`、`kali_archive`、`kali_extract`、`kali_fetch_url`、`kali_serve_http`、`kali_checksum` |
| **网络与扫描** | 14 | `kali_nmap`、`kali_nmap_vuln`、`kali_masscan`、`kali_rustscan`、`kali_arp_scan`、`kali_ping`、`kali_traceroute`、`kali_dns_lookup`、`kali_whois`、`kali_tcpdump`、`kali_http_probe`、`kali_tls_info`、`kali_banner_grab` |
| **信息收集** | 11 | `kali_subfinder`、`kali_amass`、`kali_theharvester`、`kali_dns_enum`、`kali_enum4linux`、`kali_smbclient`、`kali_cme`、`kali_ldapsearch`、`kali_snmp_walk`、`kali_recon_all`（一键只读侦察编排） |
| **Web 测试** | 11 | `kali_ffuf`、`kali_gobuster`、`kali_nikto`、`kali_nuclei`、`kali_sqlmap`、`kali_whatweb`、`kali_wafw00f`、`kali_wpscan`、`kali_dalfox`、`kali_http_request` |
| **凭据** | 7 | `kali_hydra`、`kali_medusa`、`kali_john`、`kali_hashcat`、`kali_hashid`、`kali_wordlists`、`kali_crack_zip` |
| **利用** | 7 | `kali_searchsploit`、`kali_msf_search/run/sessions`、`kali_msfvenom`、`kali_listener`、`kali_reverse_shell_snippet` |
| **无线** | 5 | `kali_wifi_scan`、`kali_wifi_adapters`、`kali_monitor_mode`、`kali_airodump`、`kali_airocrack` |
| **元工具与报告** | 12 | `kali_arsenal`（武器库分类盘点）、`kali_doctor`、`kali_tools_check`、`kali_install_tool`、`kali_note_add/list/clear`、`kali_scope_show/set`、`kali_report`、`kali_history`、`kali_artifacts` |

另外还提供 **4 个 MCP Resources**（`kali://host`、`kali://scope`、`kali://notes`、`kali://artifacts`）和 **4 个 Prompts**
（`recon`、`web_assessment`、`internal_pentest`、`hardening`），客户端里可直接选用整套流程模板。

---

## 3. 典型用法

```
# 先确认链路
"帮我看下 kali 的状态和武器库"

# 授权范围（设了之后所有带目标的工具都会先校验）
"把授权范围设成 10.0.0.0/24 和 *.example.com"

# 侦察
"对 example.com 做一轮完整只读侦察，最后给我报告"
"nmap 扫 10.0.0.5 全端口，服务识别打开"

# Web
"对 http://10.0.0.8 先指纹再 ffuf 目录爆破，命中后扩展后缀"
"用 nuclei 打 medium 以上的模板"

# 内网
"扫 10.0.0.0/24 存活主机，然后对 SMB 做枚举"

# 维护
"看看谁在监听端口、有没有意外的 cron、最近登录记录"
"帮我把这个目录打包并算 sha256"
```

模型会自己选择工具、串起流程、写产物、记 finding，最后 `kali_report` 出 Markdown。

---

## 4. 安全设计

| 机制 | 说明 |
| --- | --- |
| **Bearer Token** | 除 `/health` 外全部接口校验，令牌首次启动自动生成（600 权限） |
| **scope 硬校验** | `kali_scope_set` 设了范围后，`nmap/ffuf/hydra/...` 等所有带目标的工具先判定，越界直接拒绝执行 |
| **删除默认可恢复** | `kali_delete` 默认 `mv` 到 `/tmp/kali-mcp-trash/<时间戳>/`，只有显式 `backup=false` 才真删 |
| **全量审计** | 每次工具调用写 `data/audit.log`（时间/工具/摘要），`kali_history` 可查 |
| **产物留档** | 每个扫描的原始输出存 `data/artifacts/<时间>-<工具>-<rand>.log`，自动清理超出 400 份的旧文件 |
| **命令不拼字符串** | 工具参数走 `subprocess` 的 argv 形式（不经 shell），少量 shell 场景统一 `shlex.quote` |

> 注意：服务默认以 **root** 运行（扫描/抓包需要）。若只想跑维护类工具，可用普通用户 + `KALI_MCP_SUDO_PASS`
> 让它按需 sudo；建议监听 `127.0.0.1` 或内网地址，不要直接暴露到公网。

---

## 5. 架构

```
kali-mcp/
├── kali_mcp/
│   ├── engine.py          # 执行引擎：命令/持久 shell/后台任务/文件/审计/产物/笔记/范围
│   ├── toolkit.py         # 工具层封装：依赖检查、scope 校验、产物归档、审计
│   ├── util.py            # 文本清洗、截断、目标解析、打码
│   ├── server.py          # FastMCP 组装、Token 中间件、Resources/Prompts、CLI
│   └── tools/
│       ├── system.py  files.py  net.py  recon.py  web.py
│       ├── creds.py   exploit.py  wireless.py  meta.py
├── install.sh / run.sh           # 一键部署 / 前台运行
├── deploy/kali-mcp.service       # 参考用 systemd 单元
├── docker/                       # Dockerfile + compose
├── tests/test_smoke.py           # 不依赖 Kali 工具的冒烟测试（CI 跑）
├── .github/workflows/ci.yml
└── data/                         # 运行时生成：token、审计、产物、报告（已 gitignore）
```

运行数据全部落在 `--state-dir`（默认 `./data`）：

```
data/
├── token.txt        # 访问令牌
├── audit.log        # 操作审计
├── jobs.json        # 后台任务登记
├── notes.json       # findings
├── scope.txt        # 授权范围
├── artifacts/       # 每次执行的原始输出
└── reports/         # Markdown 报告
```

---

## 6. 常见问题

**工具报「缺少命令」** —— 按提示 `sudo apt install -y <包>`，或直接让它 `kali_install_tool` 装；`kali_arsenal` 会一次性列出全部缺失项。

**sudo 要密码** —— 服务非 root 运行时设置 `KALI_MCP_SUDO_PASS`（写进 systemd `EnvironmentFile`，别写进仓库）。

**抓包/nmap SYN 扫描失败** —— 需要 root 或 `NET_RAW` 能力；Docker 里已加 `cap_add`。

**WAF 挡住扫描** —— 先 `kali_wafw00f` 识别，再降速/换 UA（`kali_nmap` 的 `extra` 可传 `-T2`，`kali_ffuf` 可传 `-t 5`）。

**换令牌** —— 删 `data/token.txt` 后重启服务（会重新生成），或 `--token` 指定；记得同步客户端。

**端口被占** — `sudo bash install.sh --port 9000`。

---

## 7. 开发

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q          # 冒烟测试（不需要真机 Kali 工具）
.venv/bin/ruff check .
bash run.sh                  # 前台跑，改代码即生效
```

加工具只需在 `kali_mcp/tools/<模块>.py` 里写一个带 `@mcp.tool()` 的函数，签名即 schema，
文档字符串即工具说明；缺依赖用 `toolkit.need()`，要校验目标用 `toolkit.guard()`。

## 8. 许可

MIT。使用前请确认你对目标是**合法授权**的，作者不对任何滥用负责。
