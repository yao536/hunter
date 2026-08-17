#!/bin/sh
# =============================================================================
#  Hunter 容器启动守卫
#  职责：websockets 版本修复 → 拉起 uvicorn → 周期健康探测 → 异常时收集诊断
#        转储并终止自身，触发 Docker restart 策略自动重建（而非僵死挂机）。
# =============================================================================
set -eu

LISTEN_HOST="${HUNTER_HOST:-0.0.0.0}"
LISTEN_PORT="${HUNTER_PORT:-18800}"
PROBE_EVERY="${HUNTER_WATCHDOG_INTERVAL:-20}"
PROBE_TIMEOUT="${HUNTER_WATCHDOG_TIMEOUT:-5}"
MAX_MISSES="${HUNTER_WATCHDOG_MAX_FAILURES:-3}"
BOOT_GRACE="${HUNTER_WATCHDOG_START_GRACE:-20}"
DIAG_SIGNAL="${HUNTER_WATCHDOG_DIAG_SIGNAL:-USR1}"
DIAG_GRACE="${HUNTER_WATCHDOG_DIAG_GRACE:-3}"

dump_file() {
  file="$1"
  if [ -r "$file" ]; then
    echo "----- $file -----" >&2
    cat "$file" >&2 || true
  else
    echo "----- $file (unavailable) -----" >&2
  fi
}

collect_native_diag() {
  kill -0 "$APP_PID" 2>/dev/null || return 0
  echo "[guard] native diagnostics begin pid=$APP_PID" >&2
  dump_file "/proc/$APP_PID/status"
  dump_file "/proc/$APP_PID/wchan"
  dump_file "/proc/$APP_PID/sched"
  if [ -d "/proc/$APP_PID/fd" ]; then
    echo "----- /proc/$APP_PID/fd -----" >&2
    ls -l "/proc/$APP_PID/fd" >&2 || true
  fi
  if [ -d "/proc/$APP_PID/task" ]; then
    echo "----- /proc/$APP_PID/task -----" >&2
    for td in /proc/"$APP_PID"/task/*; do
      tid="${td##*/}"
      echo "[guard] thread tid=$tid" >&2
      dump_file "$td/comm"
      dump_file "$td/status"
      dump_file "$td/wchan"
      dump_file "$td/sched"
      dump_file "$td/stack"
    done
  fi
  echo "[guard] native diagnostics end pid=$APP_PID" >&2
}

# --- 启动前修复：websockets >= 13 ----------------------------------------
# pyppeteer/selenium/undetected-chromedriver 会把 websockets 降到 <13，
# 导致 uvicorn 报 ImportError: cannot import name 'ServerProtocol'。
# 仅在 <13 时修复；高版本不强制降级，避免受限网络里 pip 反复失败拖慢启动。
WS_MAJOR=$(python3 -c "import websockets; print(websockets.__version__.split('.')[0])" 2>/dev/null || echo "0")
if [ "$WS_MAJOR" -lt 13 ] 2>/dev/null; then
  echo "[guard] websockets major=$WS_MAJOR < 13, auto-repairing..." >&2
  pip3 install --quiet 'websockets>=13.0' 2>&1 || pip install --quiet 'websockets>=13.0' 2>&1 || true
  WS_MAJOR=$(python3 -c "import websockets; print(websockets.__version__.split('.')[0])" 2>/dev/null || echo "0")
  echo "[guard] websockets repaired, new major=$WS_MAJOR" >&2
fi

uvicorn app.main:app --host "$LISTEN_HOST" --port "$LISTEN_PORT" &
APP_PID="$!"

stop_app() {
  if kill -0 "$APP_PID" 2>/dev/null; then
    kill -TERM "$APP_PID" 2>/dev/null || true
    sleep 5
    kill -KILL "$APP_PID" 2>/dev/null || true
  fi
}

trap 'stop_app; exit 143' INT TERM

sleep "$BOOT_GRACE" || true
misses=0

while kill -0 "$APP_PID" 2>/dev/null; do
  if curl -fsS --max-time "$PROBE_TIMEOUT" "http://127.0.0.1:$LISTEN_PORT/health" >/dev/null 2>&1; then
    misses=0
  else
    misses=$((misses + 1))
    echo "[guard] health probe miss ${misses}/${MAX_MISSES}" >&2
    if [ "$misses" -ge "$MAX_MISSES" ]; then
      echo "[guard] dumping runtime diagnostics via SIG${DIAG_SIGNAL}" >&2
      kill "-${DIAG_SIGNAL}" "$APP_PID" 2>/dev/null || true
      sleep "$DIAG_GRACE" || true
      collect_native_diag
      echo "[guard] app appears hung; terminating container for Docker restart" >&2
      stop_app
      exit 70
    fi
  fi
  sleep "$PROBE_EVERY" || true
done

wait "$APP_PID"
