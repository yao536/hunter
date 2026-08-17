#!/usr/bin/env bash
# =============================================================================
#  Hunter 一键部署向导
#
#  用法：  bash scripts/setup.sh
#
#  流程：  环境预检 → 收集 AI 通道/测绘 Key/访问令牌 → 生成 .env → 构建镜像
#          → 启动服务 → 健康等待 → 输出访问信息
#
#  说明：  首次构建需拉取基础镜像并安装挖洞工具链（nmap/nuclei/sqlmap…），
#          耗时 5~15 分钟属正常。已存在 .env 时可选择保留并跳过采集。
# =============================================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

# ---------- 终端输出 ----------
if [ -t 1 ]; then
  CLR_RST="\033[0m"; CLR_CYN="\033[36m"; CLR_GRN="\033[32m"
  CLR_YLW="\033[33m"; CLR_RED="\033[31m"; CLR_BLD="\033[1m"; CLR_DIM="\033[2m"
else
  CLR_RST=""; CLR_CYN=""; CLR_GRN=""; CLR_YLW=""; CLR_RED=""; CLR_BLD=""; CLR_DIM=""
fi
step() { printf "${CLR_CYN}[>]${CLR_RST} %s\n" "$1"; }
done() { printf "${CLR_GRN}[+]${CLR_RST} %s\n" "$1"; }
note() { printf "${CLR_YLW}[!]${CLR_RST} %s\n" "$1"; }
fail() { printf "${CLR_RED}[x]${CLR_RST} %s\n" "$1" >&2; }

# ---------- 环境预检 ----------
preflight() {
  step "预检 Docker 环境"
  command -v docker >/dev/null 2>&1 || { fail "未找到 docker，请先安装：https://docs.docker.com/engine/install/"; exit 1; }
  docker info >/dev/null 2>&1 || { fail "docker 守护进程未运行或当前用户无权限（可用 sudo 重试）"; exit 1; }
  if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
  else
    fail "未检测到 docker compose（需 Compose v2）"; exit 1
  fi
  done "Docker 就绪：$DC"
}

# ---------- 交互采集 ----------
ask() {  # ask 变量名 提示语 [默认值]
  local __v="$1" __t="$2" __d="${3:-}" __r=""
  if [ -n "$__d" ]; then
    printf "${CLR_BLD}%s${CLR_RST} ${CLR_DIM}[%s]${CLR_RST}: " "$__t" "$__d"
  else
    printf "${CLR_BLD}%s${CLR_RST}: " "$__t"
  fi
  read -r __r </dev/tty || true
  [ -z "$__r" ] && __r="$__d"
  printf -v "$__v" '%s' "$__r"
}
ask_secret() {  # ask_secret 变量名 提示语（不回显）
  local __v="$1" __t="$2" __r=""
  printf "${CLR_BLD}%s${CLR_RST}: " "$__t"
  read -rs __r </dev/tty || true
  echo
  printf -v "$__v" '%s' "$__r"
}
random_token() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 24
  else head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

# ---------- 写 .env ----------
# 目标文件里已存在该键则更新，否则追加
patch_env() {
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  local hit=0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="*) printf '%s=%s\n' "$key" "$val" >> "$tmp"; hit=1 ;;
      *) printf '%s\n' "$line" >> "$tmp" ;;
    esac
  done < .env
  [ "$hit" -eq 0 ] && printf '%s=%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" .env
}

collect_and_write() {
  printf "\n${CLR_CYN}${CLR_BLD}==== 部署参数采集（回车用默认值，密钥不回显）====${CLR_RST}\n"

  # 1. AI 模型通道（必填）
  printf "\n${CLR_YLW}【1/4】AI 模型通道（OpenAI 兼容接口，平台运行核心）${CLR_RST}\n"
  ask LLM_BASE_URL "  base_url" "https://api.deepseek.com/v1"
  ask LLM_MODEL    "  模型名"   "deepseek-chat"
  while :; do
    ask_secret LLM_API_KEY "  API Key（必填，形如 sk-...）"
    [ -n "$LLM_API_KEY" ] && break
    fail "  API Key 不能为空"
  done
  done "模型通道已记录"

  # 2. 资产测绘 Key（推荐）
  printf "\n${CLR_YLW}【2/4】FOFA Key（推荐：自动搜集目标；留空则只能手动录入）${CLR_RST}\n"
  ask_secret FOFA_KEY "  FOFA Key（可留空）"
  [ -n "$FOFA_KEY" ] && done "FOFA 已配置" || note "跳过 FOFA：自动资产搜集不可用，稍后可在设置页补填"

  # 3. 控制台访问令牌
  printf "\n${CLR_YLW}【3/4】控制台访问令牌（强烈建议设置，否则控制台对全网裸奔）${CLR_RST}\n"
  ask AUTO_TOKEN "  自动生成高强度令牌？(Y/n)" "Y"
  case "$AUTO_TOKEN" in
    n|N|no|NO)
      ask_secret HUNTER_API_TOKEN "  自定义令牌（留空=不鉴权，危险）"
      ;;
    *)
      HUNTER_API_TOKEN="$(random_token)"
      done "已生成随机令牌"
      ;;
  esac

  # 4. 对外端口
  printf "\n${CLR_YLW}【4/4】对外访问端口${CLR_RST}\n"
  ask HUNTER_HOST_PORT "  宿主机端口" "18800"

  # 落盘
  step "生成 .env"
  cp .env.example .env
  patch_env LLM_BASE_URL   "$LLM_BASE_URL"
  patch_env LLM_MODEL      "$LLM_MODEL"
  patch_env LLM_API_KEY    "$LLM_API_KEY"
  patch_env FOFA_KEY       "$FOFA_KEY"
  patch_env HUNTER_API_TOKEN "$HUNTER_API_TOKEN"
  grep -q '^HUNTER_HOST_PORT=' .env || printf "\nHUNTER_HOST_PORT=%s\n" "$HUNTER_HOST_PORT" >> .env
  chmod 600 .env 2>/dev/null || true
  done ".env 已生成（权限 600）"
}

# ---------- 构建启动 ----------
launch() {
  printf "\n${CLR_CYN}${CLR_BLD}==== 构建并启动 ====${CLR_RST}\n"
  note "首次构建需编译前端 + 安装工具链，预计 5~15 分钟"
  step "构建镜像"
  $DC up -d --build

  local port
  port="$(grep -E '^HUNTER_HOST_PORT=' .env 2>/dev/null | tail -1 | cut -d= -f2)"
  [ -z "$port" ] && port="18800"

  step "等待服务就绪（最多 60s）"
  local i ready=0
  for i in $(seq 1 30); do
    if curl -fsS --max-time 3 "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 2
  done
  echo
  if [ "$ready" -eq 1 ]; then done "Hunter 已就绪 🎉"; else note "服务已拉起但健康检查未通过，可稍后用日志命令确认"; fi

  summary "$port"
}

summary() {
  local port="$1" token ip
  token="$(grep -E '^HUNTER_API_TOKEN=' .env 2>/dev/null | tail -1 | cut -d= -f2)"
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"; [ -z "$ip" ] && ip="服务器IP"

  printf "\n${CLR_GRN}${CLR_BLD}════════════════════════════════════════════════════════${CLR_RST}\n"
  printf "${CLR_GRN}${CLR_BLD}  Hunter 部署完成${CLR_RST}\n"
  printf "${CLR_GRN}${CLR_BLD}════════════════════════════════════════════════════════${CLR_RST}\n\n"
  printf "  控制台 : ${CLR_CYN}http://%s:%s/${CLR_RST}\n" "$ip" "$port"
  printf "  本机   : ${CLR_CYN}http://127.0.0.1:%s/${CLR_RST}\n" "$port"
  if [ -n "$token" ]; then
    printf "  令牌   : ${CLR_YLW}%s${CLR_RST}\n" "$token"
    printf "           ${CLR_DIM}登录时填入；请妥善保存${CLR_RST}\n"
  else
    printf "  ${CLR_RED}令牌   : 未设置——任何人可访问！请编辑 .env 补 HUNTER_API_TOKEN${CLR_RST}\n"
  fi
  printf "\n  常用命令\n"
  printf "    日志   : %s logs -f hunter\n" "$DC"
  printf "    重启   : %s restart hunter\n" "$DC"
  printf "    停止   : %s down\n" "$DC"
  printf "\n  下一步：打开控制台 → 新建挖掘任务 → 填 FOFA 语法或手动目标 → 启动\n\n"
  printf "  ${CLR_DIM}仅对已获授权的目标使用；个人自用项目，禁止商用。${CLR_RST}\n\n"
}

# ---------- 入口 ----------
main() {
  preflight

  if [ -f .env ]; then
    note "检测到已有 .env"
    ask REGEN "  重新生成？（旧文件将备份，y/N）" "N"
    case "$REGEN" in
      y|Y|yes|YES)
        cp .env ".env.bak.$(date +%Y%m%d_%H%M%S)"
        done "旧配置已备份"
        collect_and_write
        ;;
      *)
        note "保留现有 .env，直接构建启动"
        ;;
    esac
  else
    collect_and_write
  fi

  launch
}

main "$@"
