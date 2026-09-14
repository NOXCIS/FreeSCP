#!/usr/bin/env bash

set -euo pipefail

# FreeSCP Linux AppImage packaging script (Rust rewrite)
#
# Mirrors scripts/package_appimage.sh, minus everything Qt-specific: the
# Slint-based freescp-app needs no linuxdeploy-plugin-qt and no Qt plugin
# staging/verification. linuxdeploy still bundles the non-system libraries
# (e.g. libxkbcommon/fontconfig pulled in via ldd) into the AppDir.
#
# Requirements (on your Linux machine):
#   - cargo (stable, see rust-toolchain.toml)
#   - System libs for the Slint build: pkg-config, libxkbcommon-dev,
#     libfontconfig1-dev, libgtk-3-dev, libgl1-mesa-dev, libssl-dev
#   - linuxdeploy and appimagetool in PATH (see optional env vars below;
#     the script can also download the official linuxdeploy AppImage)
#
# Optional env vars:
#   APP_NAME            Default: "FreeSCP"
#   APP_VERSION         Default: "0.9.0" (artifact + AppImage version)
#   LINUXDEPLOY         Path or command name (default: linuxdeploy)
#   APPIMAGETOOL        Path or command name (default: appimagetool)
#   LINUXDEPLOY_DOWNLOAD  Set to 1 (default) to fetch the official linuxdeploy
#                         AppImage when not found in PATH; 0 to require it.
#   APPDIR              Override the staging AppDir path (default: dist/FreeSCP.AppDir)

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${REPO_DIR}/dist"

APP_NAME="${APP_NAME:-FreeSCP}"
APP_VERSION="${APP_VERSION:-0.9.0}"
LINUXDEPLOY="${LINUXDEPLOY:-linuxdeploy}"
APPIMAGETOOL="${APPIMAGETOOL:-appimagetool}"
LINUXDEPLOY_DOWNLOAD="${LINUXDEPLOY_DOWNLOAD:-1}"

APPDIR="${APPDIR:-${DIST_DIR}/${APP_NAME}.AppDir}"

log() { printf "\033[1;34m[pack]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[err ]\033[0m %s\n" "$*"; }
die() { err "$*"; exit 1; }

ensure_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required tool: $1"
}

appimage_arch() {
  local m; m=$(uname -m)
  case "$m" in
    x86_64) echo x86_64 ;;
    aarch64|arm64) echo aarch64 ;;
    *) echo "$m" ;;
  esac
}

# Download the linuxdeploy AppImage when it is not on PATH (mirrors the common
# AppImage CI recipe; LINUXDEPLOY_DOWNLOAD=0 disables this).
ensure_linuxdeploy() {
  if command -v "$LINUXDEPLOY" >/dev/null 2>&1; then
    log "Using linuxdeploy: $LINUXDEPLOY"
    return
  fi
  if [[ "$LINUXDEPLOY_DOWNLOAD" != "1" ]]; then
    die "linuxdeploy not found in PATH (set LINUXDEPLOY or LINUXDEPLOY_DOWNLOAD=1)"
  fi
  local dl="$DIST_DIR/linuxdeploy-x86_64.AppImage"
  if [[ ! -x "$dl" ]]; then
    log "Downloading linuxdeploy (x86_64, continuous release)"
    curl -fL -o "$dl" \
      "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage"
    chmod +x "$dl"
  fi
  LINUXDEPLOY="$dl"
}

# appimagetool ships inside linuxdeploy AppImages/plugins or can be given
# explicitly; keep this helper for completeness (not fetched automatically).
ensure_appimagetool() {
  command -v "$APPIMAGETOOL" >/dev/null 2>&1 \
    || die "appimagetool not found in PATH. Set APPIMAGETOOL=/path/to/appimagetool"
}

prepare_desktop() {
  local dst="$1"
  mkdir -p "$(dirname "$dst")"
  if [[ -f "${REPO_DIR}/assets/linux/freescp.desktop" ]]; then
    # Exec must point at the Rust binary name, not the legacy openscp_hello.
    sed 's#^Exec=.*#Exec=freescp-app#' "${REPO_DIR}/assets/linux/freescp.desktop" > "$dst"
    return
  fi
  cat > "$dst" << 'EOF'
[Desktop Entry]
Type=Application
Name=FreeSCP
GenericName=SFTP Client
Comment=SFTP client focused on simplicity and security
Exec=freescp-app
Icon=freescp
Terminal=false
Categories=Network;FileTransfer;Utility;
Keywords=SFTP;SSH;File;Transfer;Client;
StartupWMClass=FreeSCP
EOF
}

prepare_icon() {
  local src_png_256="${REPO_DIR}/assets/program/icon-freescp-256.png"
  local src_png_large="${REPO_DIR}/assets/program/icon-freescp-2048.png"
  local dst_png="$1"
  mkdir -p "$(dirname "$dst_png")"
  if [[ -f "$src_png_256" ]]; then
    cp "$src_png_256" "$dst_png"
    return
  fi
  if [[ -f "$src_png_large" ]] && command -v convert >/dev/null 2>&1; then
    convert "$src_png_large" -resize 256x256 "$dst_png"
    return
  fi
  if [[ -f "$src_png_large" ]]; then
    die "Missing 256x256 icon asset and ImageMagick 'convert' is unavailable to resize ${src_png_large}"
  fi
  die "No source icon found for AppImage packaging"
}

copy_licenses() {
  if [[ -d "${REPO_DIR}/docs/credits/LICENSES" ]]; then
    local destdir="$APPDIR/usr/share/doc/freescp/licenses"
    mkdir -p "$destdir"
    cp -R "${REPO_DIR}/docs/credits/LICENSES" "$destdir/"
    [[ -f "${REPO_DIR}/docs/credits/CREDITS.md" ]] && cp "${REPO_DIR}/docs/credits/CREDITS.md" "$destdir/"
  fi
}

# Copy full docs directory to the AppDir root (legacy About-dialog parity).
copy_docs() {
  if [[ -d "${REPO_DIR}/docs" ]]; then
    mkdir -p "$APPDIR/docs"
    cp -R "${REPO_DIR}/docs/." "$APPDIR/docs/"
  fi
}

main() {
  mkdir -p "$DIST_DIR"

  log "Building freescp-app (Release)"
  (cd "$REPO_DIR" && cargo build --release -p freescp-app)

  local exe
  exe="${REPO_DIR}/target/release/freescp-app"
  [[ -x "$exe" ]] || die "Built executable not found at: $exe"

  # Prepare AppDir skeleton
  rm -rf "$APPDIR"
  mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"

  # Desktop and icon
  prepare_desktop "$APPDIR/usr/share/applications/freescp.desktop"
  prepare_icon "$APPDIR/usr/share/icons/hicolor/256x256/apps/freescp.png"
  copy_licenses
  copy_docs

  # Ensure tools (linuxdeploy may be downloaded; appimagetool must be present)
  ensure_linuxdeploy
  ensure_appimagetool

  local version arch out_name
  version="${APP_VERSION}"
  arch="$(appimage_arch)"
  out_name="${APP_NAME}-${version}-${arch}.AppImage"

  # Create AppImage (run from dist to keep outputs localized)
  pushd "$DIST_DIR" >/dev/null
  rm -f "$out_name"

  # VERSION env var is used by linuxdeploy/appimagetool for naming
  export VERSION="$version"
  log "Running: $LINUXDEPLOY --appdir $APPDIR -e $exe -d ... --output appimage"
  "$LINUXDEPLOY" --appdir "$APPDIR" \
    -e "$exe" \
    -d "$APPDIR/usr/share/applications/freescp.desktop" \
    -i "$APPDIR/usr/share/icons/hicolor/256x256/apps/freescp.png" \
    --output appimage

  # Rename the produced AppImage to our canonical name if needed
  local produced
  produced=$(ls -1t *.AppImage 2>/dev/null | head -n1 || true)
  if [[ -n "$produced" && "$produced" != "$out_name" ]]; then
    mv -f "$produced" "$out_name"
  fi

  # Generate SHA256
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$out_name" | awk '{print $1}' > "${out_name}.sha256"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$out_name" | awk '{print $1}' > "${out_name}.sha256"
  fi

  popd >/dev/null

  log "Done: ${DIST_DIR}/${out_name}"
}

main "$@"
