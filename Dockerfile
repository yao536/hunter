# ===== 阶段 1：构建 Vue 前端 =====
FROM node:20-slim AS frontend
WORKDIR /fe
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build
# 产物在 /fe/../web/dist → /web/dist

# ===== 阶段 2：Python 应用 + 全套安全工具 =====
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 系统工具 + 挖洞常用工具
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget git ca-certificates \
        nmap \
        python3-pip \
        jq dnsutils iputils-ping netcat-openbsd \
        whatweb \
    && rm -rf /var/lib/apt/lists/*

# sqlmap：官方 PyPI 月度版。构建不依赖 git clone GitHub（国内常超时/失败），
# 也比跟踪 master HEAD 稳。pip 会把 sqlmap 装到 PATH，无需再包一层 wrapper。
RUN pip install --no-cache-dir sqlmap

# ProjectDiscovery 工具：nuclei + httpx（从 release 拉二进制，避免装 Go）
# GH_MIRROR 可指定 GitHub 加速前缀（国内网络建议，如 https://ghfast.top/），
# 由 docker-compose 的 build arg 注入；下载失败不阻断构建（仅工具降级，不影响核心）。
ARG TARGETARCH
ARG GH_MIRROR=""
RUN set -eux; \
    NUCLEI_VER=3.3.7; HTTPX_VER=1.6.9; \
    cd /tmp; \
    wget -q -T 60 "${GH_MIRROR}https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip" -O nuclei.zip || true; \
    wget -q -T 60 "${GH_MIRROR}https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip" -O httpx.zip || true; \
    if [ -f nuclei.zip ] || [ -f httpx.zip ]; then \
      apt-get update && apt-get install -y --no-install-recommends unzip; \
    fi; \
    [ -f nuclei.zip ] && unzip -o nuclei.zip nuclei -d /usr/local/bin/; \
    [ -f httpx.zip ] && unzip -o httpx.zip httpx -d /usr/local/bin/; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx 2>/dev/null || true; \
    rm -f /tmp/*.zip; \
    apt-get purge -y unzip 2>/dev/null || true; rm -rf /var/lib/apt/lists/*; \
    echo "[tools] check:"; ls -l /usr/local/bin/nuclei /usr/local/bin/httpx 2>/dev/null || echo "[tools] nuclei/httpx 未安装（网络受限，功能降级）"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 更新 nuclei 模板（失败不阻断构建）
RUN nuclei -update-templates -silent || true

COPY . .

# 拷入前端构建产物（覆盖空的 web/dist）
COPY --from=frontend /web/dist /app/web/dist

# 工作区 + 数据目录（数据目录建议挂卷持久化）
RUN mkdir -p /work /app/data
ENV WORKER_WORK_ROOT=/work \
    DB_PATH=/app/data/hunter.db

EXPOSE 18800

CMD ["sh", "/app/scripts/boot.sh"]
