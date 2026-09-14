#!/usr/bin/env bash
#
# FreeSCP release build for one target — runs INSIDE the build container
# (see docker/Dockerfile). The host-side driver is
# scripts/release/docker-build-all.sh.
#
# Targets:
#   linux-x86_64   linux-aarch64    (native in a container matching the arch;
#                                    AppImage + tar.gz)
#   macos-x86_64   macos-arm64      (cargo zigbuild cross; zipped .app + CLI)
#   windows-x86_64 windows-arm64    (llvm-mingw gnullvm cross; zipped exes)
#
# Env:
#   FREESCP_VERSION  Override version (default: from Cargo.toml workspace)
#   OUT_DIR          Artifact output dir (default: /work/dist/release)
#   CARGO_TARGET_DIR Cargo target dir (default: /work/.docker-target)
#
# All produced packages are unsigned; macOS/Windows artifacts carry the
# -UNSIGNED marker used by the legacy packaging scripts.

set -euo pipefail

TARGET="${1:-${FREESCP_TARGET:-}}"
REPO_DIR="${FREESCP_REPO_DIR:-/work}"
OUT_DIR="${OUT_DIR:-${REPO_DIR}/dist/release}"
TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_DIR}/.docker-target}"

log() { printf '\033[1;34m[release]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[release]\033[0m %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }

[[ -n "$TARGET" ]] || die "usage: build_target.sh <linux-x86_64|linux-aarch64|macos-x86_64|macos-arm64|windows-x86_64|windows-arm64>"

case "$TARGET" in
  linux-x86_64)    triple=x86_64-unknown-linux-gnu;   arch=x86_64; os=linux ;;
  linux-aarch64)   triple=aarch64-unknown-linux-gnu;  arch=aarch64; os=linux ;;
  macos-x86_64)    triple=x86_64-apple-darwin;        arch=x86_64; os=macos ;;
  macos-arm64)     triple=aarch64-apple-darwin;       arch=arm64;  os=macos ;;
  windows-x86_64)  triple=x86_64-pc-windows-gnullvm;  arch=x86_64; os=windows ;;
  windows-arm64)   triple=aarch64-pc-windows-gnullvm; arch=arm64;  os=windows ;;
  *) die "unknown target: $TARGET" ;;
esac

version() {
  if [[ -n "${FREESCP_VERSION:-}" ]]; then echo "$FREESCP_VERSION"; return; fi
  cargo metadata --quiet --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="freescp-app"))'
}

VERSION="$(version)"
APP_NAME=FreeSCP
DIST="${OUT_DIR}"
mkdir -p "$DIST"

cd "$REPO_DIR"
export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_INCREMENTAL=0

build() {
  log "Building ${os}/${arch} (${triple}) version ${VERSION}"
  local -a cmd
  case "$os" in
    linux)   cmd=(cargo build --release) ;;
    macos)   cmd=(cargo zigbuild --release --target "$triple") ;;
    windows) cmd=(cargo build --release --target "$triple") ;;
  esac
  cmd+=(-p freescp-app -p freescp-cli)

  if [[ "$os" == "windows" ]]; then
    # llvm-mingw names its tools with the mingw triple (x86_64-w64-mingw32-*),
    # not the Rust gnullvm triple. winresource (icon embedding) shells out to
    # "llvm-windres" by default, which builds for the toolchain's default
    # target — the wrong arch on cross hosts — so pin WINDRES/AR to the
    # triple-wrapped tools, which force the correct target.
    local mingw="${triple/-pc-windows-gnullvm/-w64-mingw32}"
    WINDRES="${mingw}-windres" AR="${mingw}-ar" "${cmd[@]}"
  elif [[ "$os" == "macos" ]]; then
    # Vendored C deps (gettext-sys) build Mach-O objects; GNU binutils `ar`
    # writes a corrupt symbol index for them which zig's MachO linker cannot
    # parse. llvm-ar/llvm-ranlib are format-agnostic, so shadow the host
    # binutils tools with them for the duration of the build.
    local shim="/tmp/mac-shims-${triple}"
    mkdir -p "$shim"
    ln -sf "$(command -v llvm-ar)" "$shim/ar"
    ln -sf "$(command -v llvm-ranlib)" "$shim/ranlib"
    PATH="$shim:$PATH" "${cmd[@]}"
  else
    "${cmd[@]}"
  fi

  local exe_ext=""
  [[ "$os" == "windows" ]] && exe_ext=".exe"
  # Native Linux builds go to $TARGET_DIR/release; cross builds include the
  # target-triple directory.
  local rel_dir="${TARGET_DIR}/release"
  [[ "$os" != "linux" ]] && rel_dir="${TARGET_DIR}/${triple}/release"
  [[ -x "${rel_dir}/freescp-app${exe_ext}" ]] \
    || die "freescp-app missing after build: ${rel_dir}/"
  [[ -x "${rel_dir}/freescp${exe_ext}" ]] \
    || die "freescp missing after build: ${rel_dir}/"
}

bin() {
  local rel_dir="${TARGET_DIR}/release"
  [[ "$os" != "linux" ]] && rel_dir="${TARGET_DIR}/${triple}/release"
  echo "${rel_dir}/$1"
}

write_sha256() {
  sha256sum "$1" | awk '{print $1}' > "$1.sha256"
}

# Download an AppImage tool and only accept it if it is a type-2 AppImage for
# the expected machine. The continuous release assets are re-uploaded hourly
# and a truncated/garbage 200 response once slipped through as an executable,
# failing much later with a cryptic "Exec format error" (exit 126).
fetch_tool() {
  local url="$1" out="$2" want_mach="$3"
  local attempt mach_hex
  for attempt in 1 2 3; do
    rm -f "$out"
    curl -fsSL --retry 2 --retry-delay 5 --retry-all-errors -o "$out" "$url" || {
      err "download failed (attempt $attempt/3): $url"; sleep 10; continue; }
    chmod +x "$out"
    if (( $(wc -c < "$out") >= 1000000 )) \
      && [[ "$(head -c4 "$out")" == $'\x7fELF' ]] \
      && [[ "$(dd if="$out" bs=1 skip=8 count=2 2>/dev/null)" == "AI" ]] \
      && mach_hex="$(od -An -tx1 -j18 -N2 "$out" | tr -d ' \n')" \
      && [[ "$mach_hex" == "$want_mach" ]]; then
      return 0
    fi
    err "downloaded file is not a valid $want_mach AppImage (attempt $attempt/3): $(wc -c < "$out") bytes"; sleep 10
  done
  die "could not fetch a valid tool from $url"
}

# ---------------------------------------------------------------- linux ----
package_linux() {
  local src_stage stage tarball appimage
  src_stage="$DIST/FreeSCP-${VERSION}-linux-${arch}"
  stage="$DIST/.stage"
  rm -rf "$src_stage" "$stage"
  mkdir -p "$src_stage" "$stage"

  install -m 755 "$(bin freescp-app)" "$src_stage/freescp-app"
  install -m 755 "$(bin freescp)"    "$src_stage/freescp"
  cp README.md LICENSE "$src_stage/"
  mkdir -p "$src_stage/docs"
  cp -R docs/credits "$src_stage/docs/"

  tarball="$DIST/${APP_NAME}-${VERSION}-linux-${arch}.tar.gz"
  log "Packing $tarball"
  (cd "$DIST" && tar --owner=0 --group=0 -czf "$(basename "$tarball")" "$(basename "$src_stage")")

  # AppImage: linuxdeploy bundles every non-glibc shared library (GTK deps,
  # libxkbcommon, fontconfig, ...) that ldd reports for the GUI binary.
  local mach mach_hex a
  mach="$(uname -m)"; case "$mach" in x86_64) a=x86_64; mach_hex=3e00 ;; aarch64) a=aarch64; mach_hex=b700 ;; *) die "unsupported container arch $mach" ;; esac
  local tools="$DIST/.tools"
  local linuxdeploy="$tools/linuxdeploy-${a}.AppImage"
  local appimagetool="$tools/appimagetool-${a}.AppImage"
  mkdir -p "$tools"
  fetch_tool \
    "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-${a}.AppImage" \
    "$tools/linuxdeploy-${a}.AppImage" "$mach_hex"
  fetch_tool \
    "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-${a}.AppImage" \
    "$tools/appimagetool-${a}.AppImage" "$mach_hex"

  local appdir="$stage/${APP_NAME}.AppDir"
  mkdir -p "$appdir/usr/bin" \
           "$appdir/usr/share/applications" \
           "$appdir/usr/share/icons/hicolor/256x256/apps" \
           "$appdir/usr/share/doc/freescp/licenses" \
           "$appdir/docs"
  install -m 755 "$(bin freescp-app)" "$appdir/usr/bin/freescp-app"
  install -m 755 "$(bin freescp)"     "$appdir/usr/bin/freescp"
  cp assets/linux/freescp.desktop "$appdir/usr/share/applications/freescp.desktop"
  cp assets/program/icon-freescp-256.png "$appdir/usr/share/icons/hicolor/256x256/apps/freescp.png"
  cp -R docs/credits/. "$appdir/usr/share/doc/freescp/licenses/"
  cp -R docs/. "$appdir/docs/"

  appimage="$DIST/${APP_NAME}-${VERSION}-${arch}.AppImage"
  rm -f "$appimage"
  log "Assembling $appimage"
  (cd "$stage" \
    && APPIMAGE_EXTRACT_AND_RUN=1 NO_STRIP=1 VERSION="$VERSION" \
       PATH="$tools:$PATH" \
       "$linuxdeploy" \
         --appdir "$appdir" \
         -e "$appdir/usr/bin/freescp-app" \
         -e "$appdir/usr/bin/freescp" \
         -d "$appdir/usr/share/applications/freescp.desktop" \
         -i "$appdir/usr/share/icons/hicolor/256x256/apps/freescp.png" \
         --output appimage)
  mv "$stage/${APP_NAME}-${VERSION}-${arch}.AppImage" "$appimage"
  rm -rf "$src_stage" "$stage"
}

# ---------------------------------------------------------------- macos ----
render_info_plist() {
  local out="$1"
  sed \
    -e "s#@BUNDLE_IDENTIFIER@#org.freescp.${APP_NAME}#g" \
    -e "s#@PRODUCT_NAME@#${APP_NAME}#g" \
    -e "s#@EXECUTABLE_NAME@#${APP_NAME}#g" \
    -e "s#@ICON_FILE@#${APP_NAME}#g" \
    -e "s#@MINIMUM_SYSTEM_VERSION@#12.0#g" \
    -e "s#@VERSION_SHORT@#${VERSION}#g" \
    -e "s#@VERSION@#${VERSION}#g" \
    -e "s#@CURRENT_YEAR@#$(date +%Y)#g" \
    assets/macos/Info.plist.in > "$out"
  python3 -c "import plistlib,sys; plistlib.load(open(sys.argv[1],'rb'))" "$out" \
    || die "rendered Info.plist is invalid: $out"
}

package_macos() {
  local app="$DIST/.stage/${APP_NAME}.app"
  rm -rf "$DIST/.stage"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

  install -m 755 "$(bin freescp-app)" "$app/Contents/MacOS/${APP_NAME}"
  render_info_plist "$app/Contents/Info.plist"

  [[ -f assets/macos/FreeSCP.icns ]] || die "missing assets/macos/FreeSCP.icns"
  cp assets/macos/FreeSCP.icns "$app/Contents/Resources/${APP_NAME}.icns"
  cp assets/program/icon-freescp-256.png  "$app/Contents/Resources/icon-freescp-256.png"  2>/dev/null || true
  cp assets/program/icon-freescp-2048.png "$app/Contents/Resources/icon-freescp-2048.png" 2>/dev/null || true
  cp -R crates/freescp-app/translations "$app/Contents/Resources/translations"
  mkdir -p "$app/Contents/Resources/licenses" "$app/Contents/Resources/docs"
  cp -R docs/credits/. "$app/Contents/Resources/licenses/"
  cp docs/ABOUT_LIBRARIES_*.txt "$app/Contents/Resources/docs/" 2>/dev/null || true

  local zip_path
  zip_path="$DIST/${APP_NAME}-${VERSION}-macos-${arch}-UNSIGNED.zip"
  log "Packing $zip_path"
  rm -f "$zip_path"
  (cd "$DIST/.stage" && zip -qr -X "$zip_path" "${APP_NAME}.app")
  (cd "$DIST/.stage" && zip -qj "$zip_path" \
    "${TARGET_DIR}/${triple}/release/freescp" \
    "$REPO_DIR/README.md" "$REPO_DIR/LICENSE")
  write_sha256 "$zip_path"
  rm -rf "$DIST/.stage"
}

# -------------------------------------------------------------- windows ----
package_windows() {
  # FreeSCP.exe and freescp.exe differ only by case, which cannot coexist in
  # one directory on case-insensitive filesystems (NTFS, the host mount during
  # Docker builds); ship the CLI under bin/ instead.
  local stage="$DIST/.stage"
  rm -rf "$stage"
  mkdir -p "$stage/bin"

  install -m 644 "$(bin freescp-app.exe)" "$stage/${APP_NAME}.exe"
  install -m 644 "$(bin freescp.exe)"     "$stage/bin/freescp.exe"
  cp README.md LICENSE "$stage/"
  mkdir -p "$stage/docs"
  cp -R docs/credits "$stage/docs/"

  local zip_path
  zip_path="$DIST/${APP_NAME}-${VERSION}-windows-${arch}-UNSIGNED.zip"
  log "Packing $zip_path"
  rm -f "$zip_path"
  (cd "$stage" && zip -qr "$zip_path" .)
  write_sha256 "$zip_path"
  rm -rf "$stage"
}

build
case "$os" in
  linux)   package_linux ;;
  macos)   package_macos ;;
  windows) package_windows ;;
esac

log "Done. Artifacts for ${TARGET}:"
ls -1 "$DIST"/*.AppImage "$DIST"/*.tar.gz "$DIST"/*.zip "$DIST"/*.sha256 2>/dev/null \
  | grep -E "(-${arch}\.|-linux-${arch}\.|-macos-${arch}\.|-windows-${arch}\.)" || true
