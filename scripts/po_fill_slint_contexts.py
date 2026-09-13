#!/usr/bin/env python3
"""Copy translations into the gettext contexts the Slint UI looks up.

Slint derives the gettext context of an ``@tr("...")`` from the name of the
surrounding ``.slint`` component (``MainWindow``, ``SiteManagerDialog``, ...),
and those names match the C++ class names the Qt ``.ts`` catalogs are grouped
by. The msgid sets are not identical though: the Rust port repeated widgets
that the C++ dialogs shared (the site manager reuses the connection fields
instead of embedding ``ConnectionDialog``), so the same English text only
exists under another context and the Slint lookup silently falls back to
English.

For every ``@tr`` in ``crates/freescp-app/ui/*.slint`` this script adds the
missing entry, copying the translation of the same source text from another
context (the most frequent one when contexts disagree). Strings that are
untranslated everywhere are left alone: they keep falling back to the source
text, exactly like the Qt build did with an empty ``msgstr``.

Usage: scripts/po_fill_slint_contexts.py <catalog.po> [...]
"""

import collections
import re
import sys
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
UI_DIR = REPO_DIR / "crates" / "freescp-app" / "ui"

COMPONENT_RE = re.compile(r"(?:export\s+)?(?:component|global)\s+(\w+)")
TRANSLATION_RE = re.compile(r'@tr\(\s*"((?:[^"\\]|\\.)*)"')


def slint_contexts(ui_dir: Path) -> set[tuple[str, str]]:
    """(component, msgid) pairs for every `@tr` in the `.slint` UI files.

    The context is the innermost component the `@tr` sits in; the brace
    tracker mirrors what the Slint compiler generates (verified against the
    `translate(...)` calls in the build output).
    """
    pairs: set[tuple[str, str]] = set()
    for path in sorted(ui_dir.glob("*.slint")):
        text = re.sub(r"//[^\n]*", "", path.read_text())
        stack: list[tuple[str, int]] = []
        depth = 0
        index = 0
        while index < len(text):
            component = COMPONENT_RE.match(text, index)
            if component and (
                index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")
            ):
                stack.append((component.group(1), depth))
                index = component.end()
                continue
            translation = TRANSLATION_RE.match(text, index)
            if translation:
                msgid = unescape_slint(translation.group(1))
                if stack:
                    pairs.add((stack[-1][0], msgid))
                index = translation.end()
                continue
            char = text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                while stack and stack[-1][1] >= depth:
                    stack.pop()
            index += 1
    return pairs


def parse_entries(blocks: list[str]) -> list[dict[str, str]]:
    entries = []
    for block in blocks:
        entry: dict[str, str] = {"context": ""}
        key = None
        for line in block.splitlines():
            if line.startswith("msgctxt "):
                key = "context"
                entry[key] = unquote(line[len("msgctxt ") :])
            elif line.startswith("msgid "):
                key = "msgid"
                entry[key] = unquote(line[len("msgid ") :])
            elif line.startswith("msgstr "):
                key = "msgstr"
                entry[key] = unquote(line[len("msgstr ") :])
            elif line.startswith('"') and key:
                entry[key] += unquote(line)
            else:
                key = None
        if "msgid" in entry:
            entries.append(entry)
    return entries


def unquote(literal: str) -> str:
    """Concatenate the C string literals of one msgid/msgstr value.

    Values are usually wrapped over several physical lines by the PO writer,
    so the caller appends the continuation lines to the value this returns.
    The C escapes are resolved, because gettext compares the msgids after
    unescaping them (the `.slint` side hands over a real newline for a `\\n`).
    """
    value = ""
    for match in re.finditer(r'"((?:[^"\\]|\\.)*)"', literal):
        value += match.group(1)
    return unescape(value)


def unescape(value: str) -> str:
    escapes = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}
    result = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            result.append(escapes.get(value[index + 1], value[index + 1]))
            index += 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


def unescape_slint(value: str) -> str:
    """Resolve the escapes Slint accepts in a string literal (`\\n`, `\\t`,
    `\\"`, `\\\\`), so the msgid matches the catalog's unescaped one."""
    result = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            following = value[index + 1]
            result.append({"n": "\n", "t": "\t"}.get(following, following))
            index += 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


def as_po_string(value: str) -> str:
    """One or more `"..."` lines for a value, wrapped like gettext does."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    if len(escaped) <= 72:
        return f'"{escaped}"'
    lines = []
    rest = escaped
    while len(rest) > 72:
        cut = rest.rfind("\\n", 0, 72)
        if cut == -1:
            cut = rest.rfind(" ", 0, 72)
        if cut == -1:
            cut = 72
        else:
            cut += 2 if rest[cut : cut + 2] == "\\n" else 1
        lines.append(rest[:cut])
        rest = rest[cut:]
    lines.append(rest)
    return "\n".join(f'"{line}"' for line in lines)


def fill(po_path: Path) -> int:
    text = po_path.read_text()
    entries = parse_entries(text.split("\n\n"))
    translations: dict[str, collections.Counter] = {}
    existing: set[tuple[str, str]] = set()
    for entry in entries:
        if entry.get("msgstr"):
            translations.setdefault(entry["msgid"], collections.Counter())[
                entry["msgstr"]
            ] += 1
            existing.add((entry["context"], entry["msgid"]))

    added = []
    for context, msgid in sorted(slint_contexts(UI_DIR)):
        if (context, msgid) in existing:
            continue
        choices = translations.get(msgid)
        if not choices:
            continue  # untranslated everywhere: English fallback, as in Qt
        best = sorted(choices.items(), key=lambda item: (-item[1], item[0]))[0][0]
        added.append(
            f'msgctxt "{context}"\n'
            f"msgid {as_po_string(msgid)}\n"
            f"msgstr {as_po_string(best)}"
        )

    if not added:
        return 0
    if not text.endswith("\n"):
        text += "\n"
    # The `#.` (extracted) comment marks the copies for reviewers.
    body = "\n\n".join(
        "#. Same source text as another catalog entry\n" + block for block in added
    )
    po_path.write_text(text + "\n" + body + "\n")
    return len(added)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    for argument in argv[1:]:
        path = Path(argument)
        count = fill(path)
        print(f"{path}: {count} entries added for Slint contexts")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
