#!/usr/bin/env bash

set -euo pipefail

# FreeSCP macOS packaging script (Rust rewrite)
#
# Packages the pure-Rust freescp-app binary into a standalone FreeSCP.app.
# The Rust binary links only against macOS system frameworks, so unlike the
# legacy C++ script (scripts/package_mac.sh) there is no macdeployqt step and
# no third-party dylib bundling (no Qt/libssh2/OpenSSL/tinyxml2).
#
# Pipeline (mirrors the structure of scripts/package_mac.sh):
#   1. cargo build --release -p freescp-app
#   2. Assemble FreeSCP.app (Contents/MacOS, Contents/Resources)
#      - binary          -> Contents/MacOS/FreeSCP
#      - Info.plist      -> Contents/Info.plist (from assets/macos/Info.plist.in)
#      - FreeSCP.icns    -> Contents/Resources/FreeSCP.icns
#      - icon-freescp-256.png -> Contents/Resources/icon-freescp-256.png
#   3. Code-sign (hardened runtime + entitlements) or ad-hoc sign
#   4. Optional notarization via xcrun notarytool (API key method)
#   5. Create DMG via hdiutil (+ optional app ZIP), sha256 sidecars
#
# Configuration via environment variables (same names as the legacy script):
#   APP_NAME               Default: "FreeSCP"
#   BUNDLE_ID              Default: "org.freescp.FreeSCP"
#   VERSION                Default: "0.9.0" (artifact + CFBundleShortVersionString)
#   MINIMUM_SYSTEM_VERSION Default: "12.0"
#   CARGO_BUILD_TARGET     Optional rustc target triple (e.g. aarch64-apple-darwin
#                          when cross-compiling on an x86_64 host); also sets the
#                          artifact arch suffix.
#   PACKAGE_FORMATS        Comma-separated outputs: app,dmg (default: dmg)
#   ENTITLEMENTS_FILE      Default: assets/macos/entitlements.plist
#
# Signing / notarization env vars (identical to the legacy script):
#   APPLE_IDENTITY         Developer ID for signing, e.g. "Developer ID Application: Name (TEAMID)"
#   APPLE_TEAM_ID          Apple Team ID (e.g. ABCDE12345)
#   SKIP_CODESIGN          Set to 1 to skip Developer ID signing (debug/local)
#   DO_ADHOC_SIGN          When SKIP_CODESIGN=1, ad-hoc sign with `codesign -s -` (defaults to 1)
#   APPLE_API_KEY_ID       Notarization API key ID (e.g. ABCDEFGHIJ)
#   APPLE_API_ISSUER_ID    Notarization API issuer UUID
#   APPLE_API_KEY_P8       Contents of AuthKey_<KEYID>.p8 (as a secret)
#   SKIP_NOTARIZATION      Set to 1 to skip notarization
#
# Output (based on PACKAGE_FORMATS):
#   app -> dist/<APP_NAME>-<VERSION>-<ARCH>-UNSIGNED.zip
#   dmg -> dist/<APP_NAME>-<VERSION>-<ARCH>-UNSIGNED.dmg
#   (hash .sha256 alongside each artifact)

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${REPO_DIR}/dist"

APP_NAME="${APP_NAME:-FreeSCP}"
BUNDLE_ID="${BUNDLE_ID:-org.freescp.FreeSCP}"
VERSION="${VERSION:-0.9.0}"
MINIMUM_SYSTEM_VERSION="${MINIMUM_SYSTEM_VERSION:-12.0}"
PACKAGE_FORMATS="${PACKAGE_FORMATS:-dmg}"
ENTITLEMENTS_FILE="${ENTITLEMENTS_FILE:-${REPO_DIR}/assets/macos/entitlements.plist}"

APP_DIR="${DIST_DIR}/${APP_NAME}.app"
CONTENTS_DIR="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"
INFO_PLIST_OUT="${CONTENTS_DIR}/Info.plist"
INFO_PLIST_IN="${REPO_DIR}/assets/macos/Info.plist.in"
ICNS_SRC="${REPO_DIR}/assets/macos/FreeSCP.icns"

# Helpers (mirrors scripts/package_mac.sh)
log() { printf "\033[1;34m[pack]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[err ]\033[0m %s\n" "$*"; }
die() { err "$*"; exit 1; }

ensure_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required tool: $1"
}

normalize_formats() {
  local s="${1// /,}"
  while [[ "$s" == *",,"* ]]; do s="${s//,,/,}"; done
  s="${s#,}"
  s="${s%,}"
  echo "$s"
}

has_format() {
  local needle="$1"
  local haystack
  haystack="$(normalize_formats "${PACKAGE_FORMATS}")"
  [[ ",${haystack}," == *",${needle},"* ]]
}

write_sha256() {
  local artifact="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$artifact" | awk '{print $1}' > "${artifact}.sha256"
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$artifact" | awk '{print $1}' > "${artifact}.sha256"
  fi
}

generate_icns_from_png() {
  local src_png="$1"; local dst_icns="$2"
  ensure_cmd sips
  ensure_cmd iconutil
  local tmp_iconset
  tmp_iconset="$(mktemp -d)"/icon.iconset
  mkdir -p "$tmp_iconset"
  # Required sizes for a macOS iconset
  local sizes=(16 32 64 128 256 512)
  local sz dbl
  for sz in "${sizes[@]}"; do
    sips -z "$sz" "$sz" "$src_png" --out "$tmp_iconset/icon_${sz}x${sz}.png" >/dev/null
    dbl=$((sz*2))
    sips -z "$dbl" "$dbl" "$src_png" --out "$tmp_iconset/icon_${sz}x${sz}@2x.png" >/dev/null
  done
  iconutil -c icns "$tmp_iconset" -o "$dst_icns"
  rm -rf "$(dirname "$tmp_iconset")"
}

arch_suffix() {
  if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    case "$CARGO_BUILD_TARGET" in
      aarch64-*) echo arm64 ;;
      x86_64-*) echo x86_64 ;;
      *) echo "$CARGO_BUILD_TARGET" ;;
    esac
    return
  fi
  case "$(uname -m)" in
    arm64) echo arm64 ;;
    x86_64) echo x86_64 ;;
    *) uname -m ;;
  esac
}

render_info_plist() {
  # Substitute the @VAR@ placeholders of assets/macos/Info.plist.in with
  # package values (the legacy build did this via CMake configure_file).
  [[ -f "$INFO_PLIST_IN" ]] || die "Info.plist template not found: $INFO_PLIST_IN"
  sed \
    -e "s#@BUNDLE_IDENTIFIER@#${BUNDLE_ID}#g" \
    -e "s#@PRODUCT_NAME@#${APP_NAME}#g" \
    -e "s#@EXECUTABLE_NAME@#${APP_NAME}#g" \
    -e "s#@ICON_FILE@#${APP_NAME}#g" \
    -e "s#@MINIMUM_SYSTEM_VERSION@#${MINIMUM_SYSTEM_VERSION}#g" \
    -e "s#@VERSION_SHORT@#${VERSION}#g" \
    -e "s#@VERSION@#${VERSION}#g" \
    -e "s#@CURRENT_YEAR@#$(date +%Y)#g" \
    "$INFO_PLIST_IN" > "$INFO_PLIST_OUT"
  # Strip the CMake how-to comment for cleanliness (optional).
  /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$INFO_PLIST_OUT" >/dev/null 2>&1 \
    || die "Rendered Info.plist is invalid: $INFO_PLIST_OUT"
}

build_release() {
  log "Building freescp-app (Release)" >&2
  local cmd=(cargo build --release -p freescp-app)
  if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    cmd+=(--target "$CARGO_BUILD_TARGET")
  fi
  (cd "$REPO_DIR" && "${cmd[@]}")

  local bin
  if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    bin="${REPO_DIR}/target/${CARGO_BUILD_TARGET}/release/freescp-app"
  else
    bin="${REPO_DIR}/target/release/freescp-app"
  fi
  [[ -x "$bin" ]] || die "Built binary not found at: $bin"
  echo "$bin"
}

sign_item() {
  local path="$1"
  [[ "${SKIP_CODESIGN:-0}" == "1" ]] && { warn "Skipping codesign: $path"; return; }
  [[ -z "${APPLE_IDENTITY:-}" ]] && die "APPLE_IDENTITY is not set"
  codesign --force --timestamp --options runtime \
    --entitlements "$ENTITLEMENTS_FILE" \
    --sign "${APPLE_IDENTITY}" "$path"
}

adhoc_sign_item() {
  local path="$1"
  codesign --force -s - --timestamp=none "$path" 2>/dev/null || true
}

sign_app_bundle() {
  log "Code signing bundle with identity: ${APPLE_IDENTITY}"
  # No nested frameworks/dylibs in a pure-Rust bundle: binary first, then the .app.
  sign_item "$MACOS_DIR/${APP_NAME}"
  sign_item "$APP_DIR"
  codesign --verify --deep --strict --verbose=2 "$APP_DIR"
}

adhoc_sign_bundle() {
  log "Ad-hoc signing bundle (no Developer ID)"
  adhoc_sign_item "$MACOS_DIR/${APP_NAME}"
  adhoc_sign_item "$APP_DIR"
}

create_dmg() {
  # Mirrors scripts/package_mac.sh create_dmg(): staging dir with .app +
  # /Applications symlink, HFS+ UDZO image, retry loop.
  local dmg_path="$1"; local volname="$2"; local src_app="$3"
  local staging
  staging="$(mktemp -d)"
  rm -f "$dmg_path"
  mkdir -p "$staging"
  cp -R "$src_app" "$staging/"
  ln -s /Applications "$staging/Applications"
  ensure_cmd hdiutil
  local attempt=1
  local max_attempts=3
  while (( attempt <= max_attempts )); do
    if hdiutil create -ov -fs HFS+ -volname "$volname" -srcfolder "$staging" -format UDZO -imagekey zlib-level=9 "$dmg_path"; then
      break
    fi
    warn "hdiutil create failed (attempt ${attempt}/${max_attempts})"
    rm -f "$dmg_path"
    if (( attempt == max_attempts )); then
      rm -rf "$staging"
      die "Unable to create DMG after ${max_attempts} attempts"
    fi
    sleep 2
    ((attempt++))
  done
  rm -rf "$staging"
}

create_app_zip() {
  local zip_path="$1"; local src_app="$2"
  rm -f "$zip_path"
  ditto -c -k --sequesterRsrc --keepParent "$src_app" "$zip_path"
}

notarize_and_staple() {
  local dmg="$1"
  [[ "${SKIP_NOTARIZATION:-0}" == "1" ]] && { warn "Skipping notarization"; return; }
  for v in APPLE_TEAM_ID APPLE_API_KEY_ID APPLE_API_ISSUER_ID APPLE_API_KEY_P8; do
    [[ -n "${!v:-}" ]] || die "Missing $v for notarization"
  done
  ensure_cmd xcrun
  local keyfile; keyfile="$(mktemp -t AuthKey).p8"
  chmod 600 "$keyfile"
  printf "%s" "${APPLE_API_KEY_P8}" > "$keyfile"
  log "Submitting for notarization (this may take a few minutes)"
  xcrun notarytool submit "$dmg" \
    --key "$keyfile" \
    --key-id "${APPLE_API_KEY_ID}" \
    --issuer "${APPLE_API_ISSUER_ID}" \
    --team-id "${APPLE_TEAM_ID}" \
    --wait
  rm -f "$keyfile"
  log "Stapling notarization ticket"
  xcrun stapler staple "$dmg"
}

main() {
  mkdir -p "$DIST_DIR"

  # Same auto-local defaults as the legacy script: without Apple credentials,
  # default to skipping signing/notarization (ad-hoc signed, unsigned artifacts).
  if [[ -z "${SKIP_CODESIGN:-}" && -z "${APPLE_IDENTITY:-}" ]]; then
    warn "APPLE_IDENTITY not set; defaulting SKIP_CODESIGN=1 (local/unsigned)"
    SKIP_CODESIGN=1
  fi
  if [[ -z "${SKIP_NOTARIZATION:-}" ]]; then
    missing_notar=()
    for v in APPLE_TEAM_ID APPLE_API_KEY_ID APPLE_API_ISSUER_ID APPLE_API_KEY_P8; do
      [[ -n "${!v:-}" ]] || missing_notar+=("$v")
    done
    if ((${#missing_notar[@]})); then
      warn "Notarization credentials missing (${missing_notar[*]}). Defaulting SKIP_NOTARIZATION=1."
      SKIP_NOTARIZATION=1
    fi
    unset missing_notar
  fi

  local selected_formats
  selected_formats="$(normalize_formats "$PACKAGE_FORMATS")"
  PACKAGE_FORMATS="$selected_formats"
  [[ -n "$PACKAGE_FORMATS" ]] || die "PACKAGE_FORMATS is empty. Use one or more of: app,dmg"
  for fmt in ${PACKAGE_FORMATS//,/ }; do
    case "$fmt" in
      app|dmg) ;;
      *) die "Unsupported PACKAGE_FORMATS entry: '$fmt' (allowed: app,dmg)" ;;
    esac
  done

  local bin arch
  bin="$(build_release)"
  arch="$(arch_suffix)"
  log "Packaging version: ${VERSION} (${arch})"

  # Assemble the bundle from scratch (idempotent).
  rm -rf "$APP_DIR"
  mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

  cp "$bin" "$MACOS_DIR/${APP_NAME}"
  chmod +x "$MACOS_DIR/${APP_NAME}"

  render_info_plist

  if [[ -f "$ICNS_SRC" ]]; then
    cp "$ICNS_SRC" "$RESOURCES_DIR/${APP_NAME}.icns"
  elif [[ -f "${REPO_DIR}/assets/program/icon-freescp-2048.png" ]]; then
    log "No prebuilt icns at ${ICNS_SRC}; generating from icon-freescp-2048.png"
    generate_icns_from_png "${REPO_DIR}/assets/program/icon-freescp-2048.png" \
      "$RESOURCES_DIR/${APP_NAME}.icns"
  else
    die "App icon not found: $ICNS_SRC (and no assets/program/icon-freescp-2048.png to generate it from)"
  fi

  # PNG icons for About-dialog style filesystem fallbacks.
  if [[ -f "${REPO_DIR}/assets/program/icon-freescp-256.png" ]]; then
    cp "${REPO_DIR}/assets/program/icon-freescp-256.png" "$RESOURCES_DIR/icon-freescp-256.png"
  fi
  if [[ -f "${REPO_DIR}/assets/program/icon-freescp-2048.png" ]]; then
    cp "${REPO_DIR}/assets/program/icon-freescp-2048.png" "$RESOURCES_DIR/icon-freescp-2048.png"
  fi

  # Gettext catalogs (translations/{lang}/LC_MESSAGES/freescp-app.mo); the app
  # looks them up in Contents/Resources/translations when not running from the
  # dev tree.
  if [[ -d "${REPO_DIR}/crates/freescp-app/translations" ]]; then
    cp -R "${REPO_DIR}/crates/freescp-app/translations" "$RESOURCES_DIR/translations"
  fi

  # Copy licenses/docs inside the bundle for user visibility (legacy parity).
  if [[ -d "${REPO_DIR}/docs/credits/LICENSES" ]]; then
    mkdir -p "$RESOURCES_DIR/licenses"
    cp -R "${REPO_DIR}/docs/credits/LICENSES" "$RESOURCES_DIR/licenses/"
    [[ -f "${REPO_DIR}/docs/credits/CREDITS.md" ]] && cp "${REPO_DIR}/docs/credits/CREDITS.md" "$RESOURCES_DIR/licenses/"
  fi

  # About-dialog credits text. The app searches docs/ABOUT_LIBRARIES_<LANG>.txt
  # relative to Contents/MacOS/../Resources (settings::docs_search_bases), so
  # ship them in Contents/Resources/docs/.
  if compgen -G "${REPO_DIR}/docs/ABOUT_LIBRARIES_*.txt" > /dev/null; then
    mkdir -p "$RESOURCES_DIR/docs"
    cp "${REPO_DIR}/docs/ABOUT_LIBRARIES_"*.txt "$RESOURCES_DIR/docs/"
  else
    warn "No docs/ABOUT_LIBRARIES_*.txt found; About dialog will use the embedded credits text"
  fi

  # Sign (hardened runtime) — skipped entirely when SKIP_CODESIGN=1
  if [[ "${SKIP_CODESIGN:-0}" != "1" ]]; then
    sign_app_bundle
  else
    if [[ "${DO_ADHOC_SIGN:-1}" == "1" ]]; then
      adhoc_sign_bundle
    else
      warn "SKIP_CODESIGN=1 and DO_ADHOC_SIGN=0: skipping all signing"
    fi
  fi

  local produced=()

  if has_format app; then
    local app_zip_path
    app_zip_path="${DIST_DIR}/${APP_NAME}-${VERSION}-${arch}-UNSIGNED.zip"
    log "Creating app ZIP: $app_zip_path"
    create_app_zip "$app_zip_path" "$APP_DIR"
    write_sha256 "$app_zip_path"
    produced+=("$app_zip_path")
  fi

  if has_format dmg; then
    local dmg_path
    dmg_path="${DIST_DIR}/${APP_NAME}-${VERSION}-${arch}-UNSIGNED.dmg"
    log "Creating DMG: $dmg_path"
    create_dmg "$dmg_path" "$APP_NAME" "$APP_DIR"
    write_sha256 "$dmg_path"
    produced+=("$dmg_path")

    # Notarize and staple — completely skipped when SKIP_NOTARIZATION=1
    if [[ "${SKIP_CODESIGN:-0}" != "1" && "${SKIP_NOTARIZATION:-0}" != "1" ]]; then
      notarize_and_staple "$dmg_path"
    else
      warn "Skipping notarization (SKIP_CODESIGN or SKIP_NOTARIZATION enabled)"
    fi

    local sha
    if [[ -f "${dmg_path}.sha256" ]]; then sha="$(cat "${dmg_path}.sha256")"; else sha="(sha256 not generated)"; fi
    cat << 'EOF'

====================
GitHub Release Notes
====================

This macOS build is unsigned (for testing and advanced users).

Install:
- Open the DMG and drag FreeSCP.app into /Applications
- First launch: Apple may block it because the developer is not identified.

To open it anyway:
- GUI: Right-click FreeSCP.app -> Open -> Open
- Terminal (to remove quarantine):
  xattr -dr com.apple.quarantine /Applications/FreeSCP.app

SHA256 (DMG):
EOF
    echo "${sha}  $(basename "$dmg_path")"
  fi

  log "Done. Produced artifacts:"
  if ((${#produced[@]})); then
    for out in "${produced[@]}"; do
      log "  - $out"
    done
  else
    warn "No artifact generated (PACKAGE_FORMATS=${PACKAGE_FORMATS})"
  fi
}

main "$@"
