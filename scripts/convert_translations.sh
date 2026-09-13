#!/usr/bin/env bash

set -euo pipefail

# Convert Qt Linguist .ts catalogs to Gettext .po for the Slint app
#
# The Rust rewrite's UI (Slint) consumes Gettext .po files via the
# freescp-app i18n wiring (crates/freescp-app/src/i18n.rs + gettext). The
# legacy Qt .ts catalogs in translations/ are converted here so the existing
# Spanish/French/Portuguese translations carry over.
#
# Conversion is done with Qt's lconvert (part of qt6-l10n-tools / qtbase-tools):
#   lconvert -i translations/freescp_es.ts -o crates/freescp-app/translations/es.po
#
# If lconvert is not installed the script prints instructions and exits
# without converting (exit 0: translations are optional for local builds).
#
# Output layout (consumed by the Slint gettext wiring — the domain is the
# package name, `freescp-app`):
#   crates/freescp-app/translations/es/LC_MESSAGES/freescp-app.po (+ .mo)
#   crates/freescp-app/translations/fr/LC_MESSAGES/freescp-app.po (+ .mo)
#   crates/freescp-app/translations/pt/LC_MESSAGES/freescp-app.po (+ .mo)

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_DIR}/translations"
DST_DIR="${REPO_DIR}/crates/freescp-app/translations"

LANGS=(es fr pt)

if ! command -v lconvert >/dev/null 2>&1; then
  cat >&2 <<'MSG'
[warn] lconvert not found; skipping .ts -> .po conversion.
       Install Qt's lconvert tool to generate Gettext catalogs:
         Debian/Ubuntu: sudo apt-get install qt6-l10n-tools
         Homebrew:      brew install qt6
       Then re-run: ./scripts/convert_translations.sh
MSG
  exit 0
fi

if ! command -v msgfmt >/dev/null 2>&1; then
  cat >&2 <<'MSG'
[warn] msgfmt not found; .po files will be written but not compiled to .mo.
       Install gettext to compile catalogs:
         Debian/Ubuntu: sudo apt-get install gettext
         Homebrew:      brew install gettext
MSG
  exit 0
fi

mkdir -p "$DST_DIR"

for lang in "${LANGS[@]}"; do
  src="${SRC_DIR}/freescp_${lang}.ts"
  po_dir="${DST_DIR}/${lang}/LC_MESSAGES"
  po="${po_dir}/freescp-app.po"
  mo="${po_dir}/freescp-app.mo"
  if [[ ! -f "$src" ]]; then
    echo "[warn] missing source catalog: $src (skipping)"
    continue
  fi
  mkdir -p "$po_dir"
  echo "Converting freescp_${lang}.ts -> ${lang}/LC_MESSAGES/freescp-app.po"
  lconvert -i "$src" -o "$po"
  # Qt's PO writer emits `msgctxt "Context|"` for context-only entries, but
  # Slint's runtime looks the context up as plain `Context` (the generated
  # @tr calls use the .slint file name without a trailing separator), so every
  # catalog would miss. Drop the Qt marker before compiling.
  sed -i.bak -E 's/^msgctxt "([^"]*)\|"$/msgctxt "\1"/' "$po"
  rm -f "${po}.bak"
  # The Slint component names double as gettext contexts, but the Rust port
  # does not use exactly the C++ msgid set (widgets the C++ shared between
  # dialogs are repeated in `.slint`), so fill the missing per-component
  # entries from the same source text elsewhere in the catalog.
  python3 "${REPO_DIR}/scripts/po_fill_slint_contexts.py" "$po"
  msgfmt "$po" -o "$mo"
done

echo "Done. Gettext catalogs written to $DST_DIR"
