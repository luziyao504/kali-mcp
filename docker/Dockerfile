# 把 kali-mcp 跑在容器里（需要有相应工具，基础镜像用官方 Kali）
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    KALI_MCP_BIND=0.0.0.0 \
    KALI_MCP_PORT=8765 \
    KALI_MCP_DATA=/data

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-venv python3-pip \
      nmap curl whois dnsutils net-tools iproute2 tcpdump openssl \
      netcat-traditional gobuster ffuf nikto sqlmap hydra john hashcat \
      smbclient enum4linux exploitdb metasploit-framework 2>/dev/null || true && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN python3 -m venv /app/venv && /app/venv/bin/pip install -q --upgrade pip && /app/venv/bin/pip install -q .

VOLUME ["/data"]
EXPOSE 8765

# 首次启动自动生成令牌：docker logs 里能看到提示，或看 /data/token.txt
CMD ["/app/venv/bin/kali-mcp", "--host", "0.0.0.0", "--port", "8765", "--state-dir", "/data"]
