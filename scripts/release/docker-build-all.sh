#!/usr/bin/env bash
#
# Host-side driver: builds every FreeSCP release target inside Docker
# (docker/Dockerfile) and drops artifacts into dist/release/.
#
#   scripts/release/docker-build-all.sh                    # all six targets
#   scripts/release/docker-build-all.sh macos-arm64 windows-x86_64
#
# Linux targets always run in a container whose --platform matches the target.
# Prefer a host of the matching architecture (the CI matrix builds
# linux-aarch64 on an arm64 runner); on a mismatched host the container runs
# under QEMU binfmt, which is slow and cannot execute the arm64 AppImage
# tooling. macOS and Windows targets cross-compile, so they run in a container
# of the host's native arch.
#
# Env:
#   IMAGE_NAME   (default freescp-build)   Build image tag
#   FREESCP_VERSION                      Override artifact version

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${IMAGE_NAME:-freescp-build}"
OUT_DIR_REL="dist/release"

ALL_TARGETS=(linux-x86_64 linux-aarch64 macos-x86_64 macos-arm64 windows-x86_64 windows-arm64)

log() { printf '\033[1;34m[release]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[release]\033[0m %s\n' "$*" >&2; exit 1; }

targets=()
if (( $# )); then
  for t in "$@"; do targets+=("$t"); done
else
  targets=("${ALL_TARGETS[@]}")
fi
for t in "${targets[@]}"; do
  case " ${ALL_TARGETS[*]} " in *" $t "*) ;; *) die "unknown target: $t" ;; esac
done

command -v docker >/dev/null 2>&1 || die "docker not found on PATH"

# ---- build image -----------------------------------------------------------
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "Image ${IMAGE} already present; skipping build (pre-built by CI with layer cache)"
else
  log "Building image ${IMAGE} (first run takes a few minutes)"
  docker build -t "$IMAGE" -f "${REPO_DIR}/docker/Dockerfile" "$REPO_DIR"
fi

# ---- host platform ---------------------------------------------------------
server_arch="$(docker version --format '{{.Server.Arch}}')"
case "$server_arch" in
  amd64)  host_platform="linux/amd64"  ;;
  arm64)  host_platform="linux/arm64"  ;;
  *) die "unsupported docker server arch: $server_arch" ;;
esac
log "Host platform: ${host_platform}"

# ---- run one container per target ------------------------------------------
for target in "${targets[@]}"; do
  case "$target" in
    linux-x86_64)  platform="linux/amd64" ;;
    linux-aarch64) platform="linux/arm64" ;;
    *)             platform="$host_platform" ;;
  esac

  if [[ "$platform" != "$host_platform" ]]; then
    log "${target}: running under emulation (${platform}); expect a slow build"
  fi

  log "${target}: building in ${platform} container"
  docker run --rm \
    --platform "$platform" \
    -e FREESCP_TARGET="$target" \
    -e CARGO_HOME=/work/.cargo-home \
    ${FREESCP_VERSION:+-e FREESCP_VERSION="$FREESCP_VERSION"} \
    -v "${REPO_DIR}:/work" \
    "$IMAGE" \
    bash scripts/release/build_target.sh "$target"
done

# ---- combined checksums ----------------------------------------------------
# Only when building the full matrix locally; CI's release job regenerates a
# fresh SHA256SUMS across all downloaded artifacts.
if (( ${#targets[@]} == ${#ALL_TARGETS[@]} )); then
  log "Writing ${OUT_DIR_REL}/SHA256SUMS"
  hash_cmd() {
    command -v sha256sum >/dev/null 2>&1 && { echo "sha256sum"; return; }
    command -v shasum    >/dev/null 2>&1 && { echo "shasum_wrapper"; return; }
    die "need sha256sum or shasum for checksums"
  }
  if [[ "$(hash_cmd)" == "shasum_wrapper" ]]; then
    sha256() { shasum -a 256 "$@"; }
  else
    sha256() { sha256sum "$@"; }
  fi
  (
    cd "$REPO_DIR/$OUT_DIR_REL"
    shopt -s nullglob
    files=( *.AppImage *.zip *.tar.gz )
    if ((${#files[@]})); then
      rm -f SHA256SUMS
      sha256 "${files[@]}" >> SHA256SUMS
    fi
  )
fi

log "All done. Artifacts in ${REPO_DIR}/${OUT_DIR_REL}:"
ls -lh "$REPO_DIR/$OUT_DIR_REL"
