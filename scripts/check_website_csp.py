#!/usr/bin/env python3
"""Fail if the website gains a script that ``script-src 'none'`` would block.

``website/`` is hand-written static HTML whose only ``<script>`` is the JSON-LD
metadata block. JSON-LD is a *data block*: ``application/ld+json`` is not a
JavaScript MIME type, the HTML parser never prepares it as a script, and CSP's
inline check is therefore never reached. That makes it exempt from
``script-src``, so ``website/_headers`` can use the strongest policy --
``script-src 'none'`` -- instead of a SHA-256 hash that goes stale every time
``index.html`` changes.

This guard keeps the policy honest: it fails when any page under ``website/``
adds a script that would be blocked in production -- executable code, an
external `<script src>`, or an `importmap`/`speculationrules` block (which the
HTML specification also routes through CSP). Remediation is a deliberate policy
change: move the code to an external file and widen ``_headers`` to
``script-src 'self'`` (and update this guard), or drop the script.
"""

from __future__ import annotations

import sys
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEBSITE_DIR = REPO_ROOT / "website"
HEADERS_FILE = WEBSITE_DIR / "_headers"

# <script> types that carry data, are never executed, and are therefore not
# subject to script-src. Anything else -- including a missing type, which means
# classic JavaScript -- is executable.
DATA_BLOCK_TYPES = frozenset(
    {
        "application/json",
        "application/ld+json",
        "text/template",
        "text/x-template",
    }
)

# Not executed as JavaScript, but the HTML specification still routes these
# through CSP's inline check, so `script-src 'none'` blocks them. They must not
# be treated as data blocks.
CSP_GATED_TYPES = frozenset({"importmap", "speculationrules"})


class ScriptTagCollector(HTMLParser):
    """Collect every <script> start tag with the line it appears on."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[int, dict[str, str | None]]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag == "script":
            self.tags.append((self.getpos()[0], dict(attrs)))


def executable_scripts(path: Path) -> list[str]:
    parser = ScriptTagCollector()
    parser.feed(path.read_text(encoding="utf-8"))
    parser.close()

    rel = path.relative_to(REPO_ROOT)
    problems: list[str] = []
    for line, attrs in parser.tags:
        if attrs.get("src"):
            problems.append(
                f"{rel}:{line}: <script src={attrs['src']!r}> would be blocked "
                "by script-src 'none'"
            )
            continue
        # MIME parameters (`text/javascript; charset=utf-8`) do not change the
        # essence, so classify on the part before the first semicolon.
        script_type = (attrs.get("type") or "").split(";", 1)[0].strip().lower()
        if script_type in DATA_BLOCK_TYPES:
            continue
        if script_type in CSP_GATED_TYPES:
            problems.append(
                f"{rel}:{line}: <script type={script_type!r}> is subject to "
                "CSP's script-src and would be blocked by 'none'"
            )
            continue
        shown = script_type or "classic JavaScript (no type attribute)"
        problems.append(
            f"{rel}:{line}: executable <script type={shown!r}> would be "
            "blocked by script-src 'none'"
        )
    return problems


def policy_problems() -> list[str]:
    rel = HEADERS_FILE.relative_to(REPO_ROOT)
    if not HEADERS_FILE.exists():
        return [f"{rel} is missing"]

    csp_lines = [
        line.strip()
        for line in HEADERS_FILE.read_text(encoding="utf-8").splitlines()
        if "Content-Security-Policy:" in line
    ]
    if not csp_lines:
        return [f"{rel} has no Content-Security-Policy header"]
    if not any("script-src 'none'" in line for line in csp_lines):
        return [
            f"{rel} no longer declares script-src 'none'; if that is "
            "deliberate, update this guard too"
        ]
    return []


def main() -> int:
    pages = sorted(WEBSITE_DIR.rglob("*.html"))
    problems = policy_problems()
    for page in pages:
        problems.extend(executable_scripts(page))

    if problems:
        print("Website CSP guard failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nThe policy in website/_headers allows data blocks only.\n"
            "If the script is genuinely needed: move it to an external file,\n"
            "widen the policy to script-src 'self', and update this guard.",
            file=sys.stderr,
        )
        return 1

    print(
        f"Website CSP guard OK: {len(pages)} page(s) ship no executable "
        "scripts, and website/_headers keeps script-src 'none'."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
