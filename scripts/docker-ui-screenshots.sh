#!/usr/bin/env bash
# Build FreeSCP inside a Linux Docker container (Xvfb + optional VNC) and
# capture UI screenshots to the host. Does not use macOS screencapture.
#
# Usage:
#   scripts/docker-ui-screenshots.sh
#   KEEP_VNC=1 scripts/docker-ui-screenshots.sh   # leave VNC up on :5901
#   SKIP_BUILD=1 scripts/docker-ui-screenshots.sh # reuse prior target/ in volume
#
# Screenshots land in tmp/docker-audit/ (repo-relative).
# VNC (when KEEP_VNC=1): vnc://localhost:5901  (password: freescp)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-freescp-ui-audit:local}"
CONTAINER_NAME="${CONTAINER_NAME:-freescp-ui-audit}"
OUT_HOST="${OUT_HOST:-${REPO_ROOT}/tmp/docker-audit}"
CARGO_CACHE_HOST="${CARGO_CACHE_HOST:-${REPO_ROOT}/tmp/docker-cargo-home}"
TARGET_CACHE_HOST="${TARGET_CACHE_HOST:-${REPO_ROOT}/tmp/docker-target}"
KEEP_VNC="${KEEP_VNC:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
VNC_HOST_PORT="${VNC_HOST_PORT:-5901}"
SCREEN_W="${SCREEN_W:-1600}"
SCREEN_H="${SCREEN_H:-900}"
DISPLAY_NUM=99

mkdir -p "${OUT_HOST}" \
  "${CARGO_CACHE_HOST}/registry" \
  "${CARGO_CACHE_HOST}/git" \
  "${TARGET_CACHE_HOST}"

echo "==> Building image ${IMAGE_NAME}"
docker build -t "${IMAGE_NAME}" -f "${REPO_ROOT}/docker/ui-audit/Dockerfile" "${REPO_ROOT}/docker/ui-audit"

# Remove any leftover container from a previous KEEP_VNC run.
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

# Inner capture logic runs as a script mounted into the container.
INNER_SCRIPT="${OUT_HOST}/_inner-capture.sh"
cat >"${INNER_SCRIPT}" <<'INNER'
#!/usr/bin/env bash
set -euo pipefail

export DISPLAY=":${DISPLAY_NUM}"
export LIBGL_ALWAYS_SOFTWARE=1
export GALLIUM_DRIVER=llvmpipe
export WINIT_UNIX_BACKEND=x11
export RUST_BACKTRACE=1
# Avoid Slint/winit trying to talk to a real session bus for anything critical.
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/tmp/dbus-freescp}"

OUT_DIR=/out
LOG="${OUT_DIR}/run.log"
mkdir -p "${OUT_DIR}"
: >"${LOG}"
exec > >(tee -a "${LOG}") 2>&1

echo "=== FreeSCP Docker UI audit $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "uname: $(uname -a)"
echo "DISPLAY=${DISPLAY} LIBGL_ALWAYS_SOFTWARE=${LIBGL_ALWAYS_SOFTWARE}"

# Fresh virtual framebuffer.
pkill -f "Xvfb :${DISPLAY_NUM}" >/dev/null 2>&1 || true
rm -f "/tmp/.X${DISPLAY_NUM}-lock"
Xvfb ":${DISPLAY_NUM}" -screen 0 "${SCREEN_W}x${SCREEN_H}x24" -ac +extension GLX +render -noreset &
XVFB_PID=$!
sleep 1
if ! kill -0 "${XVFB_PID}" 2>/dev/null; then
  echo "ERROR: Xvfb failed to start" >&2
  exit 1
fi
echo "Xvfb pid=${XVFB_PID}"

# Optional lightweight session bus (some GTK/font stacks expect it).
if command -v dbus-daemon >/dev/null 2>&1; then
  dbus-daemon --session --address="${DBUS_SESSION_BUS_ADDRESS}" --nofork --nopidfile &
  sleep 0.3 || true
fi

# VNC for interactive attach (password freescp).
x11vnc -display ":${DISPLAY_NUM}" -forever -shared -rfbport 5900 \
  -passwd freescp -xkb -noxdamage -quiet >/tmp/x11vnc.log 2>&1 &
VNC_PID=$!
echo "x11vnc pid=${VNC_PID} (container :5900)"

cd /work

if [[ "${SKIP_BUILD}" != "1" ]]; then
  echo "==> cargo build -p freescp-app (debug)"
  if ! cargo build -p freescp-app 2>&1 | tee "${OUT_DIR}/build.log"; then
    echo "BUILD FAILED — see ${OUT_DIR}/build.log"
    # Still try a root screenshot of empty desktop for evidence.
    import -window root "${OUT_DIR}/00-xvfb-empty.png" || true
    if [[ "${KEEP_VNC}" == "1" ]]; then
      echo "KEEP_VNC=1 — sleeping so host can attach"
      sleep infinity
    fi
    exit 1
  fi
else
  echo "==> SKIP_BUILD=1 — using existing binary"
fi

BIN="/work/target/debug/freescp-app"
if [[ ! -x "${BIN}" ]]; then
  echo "ERROR: binary missing at ${BIN}" >&2
  ls -la /work/target/debug/ 2>&1 || true
  exit 1
fi

# Isolate config so Start Page always appears (no remembered preference).
export HOME=/tmp/freescp-home
mkdir -p "${HOME}/.config" "${HOME}/.local/share"
rm -rf "${HOME}/.config/freescp" "${HOME}/.local/share/freescp" 2>/dev/null || true

echo "==> Launching freescp-app"
"${BIN}" >"${OUT_DIR}/app-stdout.log" 2>"${OUT_DIR}/app-stderr.log" &
APP_PID=$!
echo "app pid=${APP_PID}"

# Wait for a mapped window (up to ~45s).
WIN_ID=""
for i in $(seq 1 90); do
  if ! kill -0 "${APP_PID}" 2>/dev/null; then
    echo "ERROR: freescp-app exited early"
    cat "${OUT_DIR}/app-stderr.log" || true
    import -window root "${OUT_DIR}/00-after-crash.png" || true
    exit 1
  fi
  WIN_ID="$(xdotool search --onlyvisible --pid "${APP_PID}" 2>/dev/null | head -n1 || true)"
  if [[ -n "${WIN_ID}" ]]; then
    echo "Found window id=${WIN_ID} after ${i}00ms"
    break
  fi
  # Fallback: any FreeSCP-titled window
  WIN_ID="$(xdotool search --onlyvisible --name 'FreeSCP' 2>/dev/null | head -n1 || true)"
  if [[ -n "${WIN_ID}" ]]; then
    echo "Found FreeSCP window id=${WIN_ID} after ${i}00ms"
    break
  fi
  sleep 0.5
done

sleep 1.5
shot() {
  local name="$1"
  echo "  screenshot ${name}"
  import -window root "${OUT_DIR}/${name}.png" || scrot "${OUT_DIR}/${name}.png" || true
  if [[ -n "${WIN_ID}" ]]; then
    import -window "${WIN_ID}" "${OUT_DIR}/${name}-window.png" || true
  fi
}

shot "01-start-page"

# Try to open local two-panel: default mode is two-panel + "No site".
# The Start Page column is vertically centered (~640x content), so the primary
# Open button is mid-window — not near the OS bottom edge. Measured on a
# 1200x700 window the blue Open control sits near (891, 524).
if [[ -n "${WIN_ID}" ]]; then
  xdotool windowfocus --sync "${WIN_ID}" || true
  eval "$(xdotool getwindowgeometry --shell "${WIN_ID}")"
  echo "Window geometry: ${WIDTH}x${HEIGHT}+${X}+${Y}"

  # Settings… first (while Start Page is still up). Centers on 1200x700:
  # Settings ≈ (557,524), Site Manager ≈ (666,524), Quick connect ≈ (793,524).
  SETTINGS_X=$((X + WIDTH * 557 / 1200))
  SETTINGS_Y=$((Y + HEIGHT * 524 / 700))
  echo "Settings click at ${SETTINGS_X},${SETTINGS_Y}"
  xdotool mousemove --sync "${SETTINGS_X}" "${SETTINGS_Y}" click 1
  sleep 1.2
  shot "02-settings-dialog"
  xdotool key Escape || true
  sleep 0.4

  OPEN_X=$((X + WIDTH * 891 / 1200))
  OPEN_Y=$((Y + HEIGHT * 524 / 700))
  echo "Clicking Open at ${OPEN_X},${OPEN_Y}"
  xdotool mousemove --sync "${OPEN_X}" "${OPEN_Y}" click 1
  sleep 1.5
  shot "03-two-panel-local"

  # Fallback: Return often activates the primary button if still on Start Page.
  xdotool key --window "${WIN_ID}" Return || true
  sleep 0.8
  shot "04-after-return"
fi

# Full desktop dump for context.
shot "99-desktop-final"

echo "==> App still running? $(kill -0 "${APP_PID}" 2>/dev/null && echo yes || echo no)"
echo "Screenshots:"
ls -la "${OUT_DIR}"/*.png 2>/dev/null || true

# Stop the app; keep Xvfb/VNC if requested.
kill "${APP_PID}" 2>/dev/null || true
wait "${APP_PID}" 2>/dev/null || true

if [[ "${KEEP_VNC}" == "1" ]]; then
  echo "KEEP_VNC=1 — Xvfb+VNC left up. Attach: vnc://HOST:${VNC_HOST_PORT} password freescp"
  # Re-launch app so VNC shows something useful.
  "${BIN}" >"${OUT_DIR}/app-stdout-vnc.log" 2>"${OUT_DIR}/app-stderr-vnc.log" &
  sleep infinity
else
  kill "${VNC_PID}" 2>/dev/null || true
  kill "${XVFB_PID}" 2>/dev/null || true
  echo "Done — container will exit."
fi
INNER
chmod +x "${INNER_SCRIPT}"

echo "==> Running container ${CONTAINER_NAME}"
DOCKER_ARGS=(
  --name "${CONTAINER_NAME}"
  --rm
  -e "DISPLAY_NUM=${DISPLAY_NUM}"
  -e "SCREEN_W=${SCREEN_W}"
  -e "SCREEN_H=${SCREEN_H}"
  -e "SKIP_BUILD=${SKIP_BUILD}"
  -e "KEEP_VNC=${KEEP_VNC}"
  -e "VNC_HOST_PORT=${VNC_HOST_PORT}"
  -v "${REPO_ROOT}:/work"
  -v "${CARGO_CACHE_HOST}/registry:/usr/local/cargo/registry"
  -v "${CARGO_CACHE_HOST}/git:/usr/local/cargo/git"
  -v "${TARGET_CACHE_HOST}:/work/target"
  -v "${OUT_HOST}:/out"
  -p "${VNC_HOST_PORT}:5900"
)

if [[ "${KEEP_VNC}" == "1" ]]; then
  docker run -d "${DOCKER_ARGS[@]}" "${IMAGE_NAME}" bash /out/_inner-capture.sh
  echo "Container started detached (KEEP_VNC=1)."
  echo "VNC: vnc://localhost:${VNC_HOST_PORT}  password: freescp"
  echo "Follow logs: docker logs -f ${CONTAINER_NAME}"
  echo "Stop when done: docker rm -f ${CONTAINER_NAME}"
else
  docker run "${DOCKER_ARGS[@]}" "${IMAGE_NAME}" bash /out/_inner-capture.sh
  echo ""
  echo "==> Host screenshots in ${OUT_HOST}"
  ls -la "${OUT_HOST}"/*.png 2>/dev/null || echo "(no PNGs produced)"
fi
