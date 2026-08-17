#!/usr/bin/env bash
# ============================================================================
#  import-data.sh  ——  从旧部署的数据卷/目录导入数据库到 Hunter 数据卷
#
#  场景：此前用其它部署长期积累的任务 / 目标 / Finding / 复审 / 通杀 / 情报数据
#        存在 Docker 卷或本机目录里。把它的数据库文件导入 Hunter 数据卷后，
#        历史数据直接可用 —— 启动时自动采用（schema 自动补齐，无需迁移）。
#
#  用法（在部署 Hunter 的主机上执行）：
#    bash scripts/import-data.sh                  # 自动探测源 / 目标
#    bash scripts/import-data.sh --from <源卷名>   # 从指定 docker volume 导入
#    bash scripts/import-data.sh --from <目录>    # 从本机目录导入
#    bash scripts/import-data.sh --force          # 覆盖目标卷已有数据（谨慎）
#    bash scripts/import-data.sh --dry-run        # 只打印计划，不真正执行
#
#  参数：
#    --from <卷名|目录>   数据来源：docker volume 名，或本机目录路径
#    --to   <卷名>        Hunter 数据卷名，默认自动探测（含 hunter.db 的卷）
#    --force              目标卷已有数据时仍然覆盖（会先清空！）
#    --dry-run            只打印将要执行的操作
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()  { echo -e "${GREEN}✔${NC} $*"; }
warn(){ echo -e "${YELLOW}!${NC} $*"; }
err() { echo -e "${RED}✘${NC} $*" >&2; }

FROM_SRC=""
TO_VOL=""
FORCE=0
DRY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)  FROM_SRC="$2"; shift 2 ;;
    --to)    TO_VOL="$2";   shift 2 ;;
    --force) FORCE=1;       shift ;;
    --dry-run) DRY=1;       shift ;;
    -h|--help)
      sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) err "未知参数: $1（-h 查看帮助）"; exit 1 ;;
  esac
done

# ---------- 0. 前置检查 ----------
command -v docker >/dev/null 2>&1 || { err "未找到 docker，请先安装 Docker（bash scripts/setup.sh 可一并完成）"; exit 1; }
docker info >/dev/null 2>&1 || { err "docker 不可用，请确认已启动（sudo systemctl start docker）"; exit 1; }

# ---------- 1. 探测源 ----------
SRC_IS_VOL=0
if [[ -n "$FROM_SRC" ]]; then
  if docker volume inspect "$FROM_SRC" >/dev/null 2>&1; then
    SRC_IS_VOL=1
    ok "源：docker volume ${FROM_SRC}"
  elif [[ -d "$FROM_SRC" ]]; then
    ok "源：本机目录 ${FROM_SRC}"
  else
    err "源 ${FROM_SRC} 既不是 docker volume 也不是目录"; exit 1
  fi
else
  # 自动探测：找一个内容里含 *.db 文件的 volume
  for v in $(docker volume ls -q); do
    if docker run --rm -v "${v}:/v:ro" alpine sh -c 'ls /v/*.db >/dev/null 2>&1' 2>/dev/null; then
      SRC_IS_VOL=1; FROM_SRC="$v"; ok "自动探测到源 volume：${FROM_SRC}（内含数据库文件）"; break
    fi
  done
  if [[ -z "$FROM_SRC" ]]; then
    err "未探测到含数据库文件的 volume。请用 --from 指定：卷名或目录"; exit 1
  fi
fi

# ---------- 2. 探测目标卷 ----------
if [[ -z "$TO_VOL" ]]; then
  # 只精确匹配 Hunter 自己的数据卷（hunter_data），避免误匹配 autohunter_* 等旧部署卷名
  TO_VOL=$(docker volume ls -q | grep -ix "hunter_data" | head -n1 || true)
  [[ -z "$TO_VOL" ]] && TO_VOL="hunter_data"
  ok "目标卷：${TO_VOL}（可用 --to 覆盖）"
fi

if docker volume inspect "$TO_VOL" >/dev/null 2>&1; then
  DST_CONTENT=$(docker run --rm -v "${TO_VOL}:/v:ro" alpine ls -A /v 2>/dev/null || true)
  if [[ -n "$DST_CONTENT" && "$FORCE" -eq 0 ]]; then
    err "目标卷 ${TO_VOL} 已有数据（$(echo "$DST_CONTENT" | tr '\n' ' ')）。"
    echo "  → 如确认要覆盖，加 --force 重新执行（会先清空目标卷）"
    exit 1
  fi
  [[ "$FORCE" -eq 1 && -n "$DST_CONTENT" ]] && warn "目标卷已有数据，--force 已开启，将清空后复制"
else
  if [[ "$DRY" -eq 1 ]]; then
    warn "[dry-run] 将创建目标卷 ${TO_VOL}"
  else
    docker volume create "$TO_VOL" >/dev/null
    ok "已创建目标卷 ${TO_VOL}"
  fi
fi

# ---------- 3. 源容器占用检查（WAL 一致性） ----------
if [[ "$SRC_IS_VOL" -eq 1 ]]; then
  RUNNING_SRC=$(docker ps --filter "volume=${FROM_SRC}" -q | head -n1 || true)
  if [[ -n "$RUNNING_SRC" ]]; then
    CN=$(docker ps --filter "volume=${FROM_SRC}" --format '{{.Names}}' | head -n1)
    warn "源卷正被容器占用（${CN}）。强烈建议先停止它再复制，避免复制到不一致的数据："
    echo "    docker stop ${CN}"
    read -r -p "  是否继续？（y 继续 / 其他 取消）" ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || { err "已取消"; exit 1; }
  fi
fi

# ---------- 4. 执行复制 ----------
RUN_PREFIX="docker run --rm"
[[ "$DRY" -eq 1 ]] && RUN_PREFIX="echo [dry-run] docker run --rm"

echo
ok "开始导入： ${FROM_SRC}  →  ${TO_VOL}"
if [[ "$FORCE" -eq 1 ]]; then
  $RUN_PREFIX -v "${TO_VOL}:/dst" alpine sh -c "rm -rf /dst/* 2>/dev/null || true"
fi

if [[ "$SRC_IS_VOL" -eq 1 ]]; then
  # 卷 → 卷：临时容器同时挂源卷(只读)与目标卷，cp 保持权限/属性；shm/wal 一并复制
  $RUN_PREFIX -v "${FROM_SRC}:/src:ro" -v "${TO_VOL}:/dst" alpine sh -c "cp -a /src/. /dst/ && sync"
else
  # 目录 → 卷：本机目录里的数据文件拷进目标卷
  $RUN_PREFIX -v "${FROM_SRC}:/src:ro" -v "${TO_VOL}:/dst" alpine sh -c "cp -a /src/. /dst/ && sync"
fi

if [[ "$DRY" -eq 1 ]]; then
  warn "[dry-run] 结束，未执行真实复制"; exit 0
fi

# ---------- 5. 校验 ----------
DST_LIST=$(docker run --rm -v "${TO_VOL}:/v:ro" alpine ls -A /v 2>/dev/null || true)
DB_FILE=$(echo "$DST_LIST" | grep -E '\.db$' | head -n1 || true)
echo
if [[ -n "$DB_FILE" ]]; then
  SRC_SZ=$(docker run --rm -v "${TO_VOL}:/v:ro" alpine stat -c %s "/v/${DB_FILE}" 2>/dev/null || echo 0)
  ok "导入成功 ✔  数据库文件 ${DB_FILE}（$((SRC_SZ/1024/1024)) MB）已就位"
else
  err "目标卷中未找到数据库文件（*.db），导入可能失败，请检查源数据"
  exit 1
fi

echo
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN} 下一步：${NC}"
echo "  1. 在 Hunter 项目目录执行：  bash scripts/setup.sh   （或 docker compose up -d --build）"
echo "  2. 启动时自动采用该数据库（hunter.db 不存在则自动复制首个 *.db）"
echo "  3. 访问 http://<服务器IP>:18800/ ，用 .env 里的 HUNTER_API_TOKEN 登录"
echo "  4. 控制台应出现历史任务 / 看板统计 / Finding 复审数据"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
