#!/usr/bin/env python3
"""Check the rendering pipeline for defects that only surface at run time.

Both defect classes this catches were found in this repo by hand:

  - a task referencing a variable defined nowhere (`task template:tidy` had
    referenced an undefined TEMPLATE_NODE_CONFIG_FILE for months)
  - a field whose schema default disagrees with the render-time default
    (cluster_svc_cidr was 10.43.0.0/16 in CUE and 10.96.0.0/16 in plugin.py)

Neither is visible by reading a single file, so check them instead of
rediscovering them later.

Usage: check-template-integrity.py [repo-root]
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

# Variables Task provides itself; referencing one is not a defect.
TASK_BUILTINS = {
    "ROOT_DIR", "TASKFILE_DIR", "TASK_DIR", "TASK", "TASK_VERSION", "CLI_ARGS",
    "CLI_FORCE", "CLI_SILENT", "CLI_VERBOSE", "CLI_OFFLINE", "ITEM", "EXIT_CODE",
    "USER_WORKING_DIR", "ALIAS", "TASK_EXE", "CHECKSUM", "TIMESTAMP", "DATE",
}


def taskfiles(root: Path) -> list[Path]:
    found = [root / "Taskfile.yaml"]
    found += sorted((root / ".taskfiles").rglob("Taskfile.yaml"))
    return [f for f in found if f.is_file()]


def declared_vars(path: Path) -> set[str]:
    """Collect names declared under a `vars:` or `env:` block.

    Tracks indentation rather than parsing YAML so this stays dependency-free.
    Handles both mapping form (`vars: {NAME: value}`) and the list form used by
    `requires: vars: [IP]`.
    """
    names: set[str] = set()
    stack: list[tuple[int, str]] = []
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        # list form: `- IP` under `requires: vars:`, or inline `[IP, MODE]`
        if stack and stack[-1][1] == "vars":
            item = re.match(r"^\s*-\s+([A-Z][A-Z0-9_]*)\s*$", line)
            if item:
                names.add(item.group(1))
                continue
        inline = re.match(r"^\s*vars:\s*\[([^\]]*)\]", line)
        if inline:
            names.update(re.findall(r"[A-Z][A-Z0-9_]*", inline.group(1)))
            continue

        m = re.match(r"^(\s*)(?:-\s+)?([A-Za-z_][A-Za-z0-9_]*):", line)
        if not m:
            continue
        indent, key = len(m.group(1)), m.group(2)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if stack and stack[-1][1] in ("vars", "env") and re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            names.add(key)
        stack.append((indent, key))
    return names


def check_dangling_vars(root: Path) -> list[str]:
    files = taskfiles(root)
    if not files:
        return ["no Taskfile.yaml found — wrong repo root?"]

    defined = set(TASK_BUILTINS)
    for f in files:
        defined |= declared_vars(f)

    problems = []
    for f in files:
        for lineno, line in enumerate(f.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for name in re.findall(r"\{\{\s*\.([A-Z][A-Z0-9_]*)", line):
                if name not in defined:
                    rel = f.relative_to(root)
                    problems.append(f"{rel}:{lineno}: {{{{.{name}}}}} is never defined")
    return problems


def cue_defaults(path: Path) -> dict[str, str]:
    """Fields declaring a CUE default, i.e. `field: *"value" | ...`."""
    if not path.is_file():
        return {}
    pattern = re.compile(r'^\s*([a-z_][a-z0-9_]*)\??:\s*\*"([^"]*)"', re.M)
    return {m.group(1): m.group(2) for m in pattern.finditer(path.read_text())}


def plugin_defaults(path: Path) -> dict[str, str | None]:
    """Fields given a render-time default.

    Value is the literal for `setdefault('x', 'literal')`, or None when the
    default is computed — a computed default cannot be compared statically, so
    having one *alongside* a schema default is itself the defect.
    """
    if not path.is_file():
        return {}
    found: dict[str, str | None] = {}
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "setdefault"):
            continue
        if len(node.args) != 2 or not isinstance(node.args[0], ast.Constant):
            continue
        key = node.args[0].value
        value = node.args[1]
        found[key] = value.value if isinstance(value, ast.Constant) else None
    return found


def check_divergent_defaults(root: Path) -> list[str]:
    cue_path = root / ".taskfiles/template/resources/cluster.schema.cue"
    plugin_path = root / "templates/scripts/plugin.py"
    if not cue_path.is_file() or not plugin_path.is_file():
        return [f"missing {cue_path.name} or {plugin_path.name} — wrong repo root?"]

    schema = cue_defaults(cue_path)
    render = plugin_defaults(plugin_path)

    problems = []
    for field in sorted(set(schema) & set(render)):
        want, got = schema[field], render[field]
        if got is None:
            problems.append(
                f"{field}: schema defaults to {want!r} but plugin.py computes a "
                f"default — a field may have only one effective default"
            )
        elif want != got:
            problems.append(
                f"{field}: schema defaults to {want!r} but plugin.py defaults to {got!r}"
            )
    return problems


def check_documented_defaults(root: Path) -> list[str]:
    """Commented-out fields in the sample must show the default actually applied.

    Only literal defaults are checked; a computed default has no single value to
    document, so those lines are skipped rather than guessed at.
    """
    sample = root / "cluster.sample.yaml"
    plugin_path = root / "templates/scripts/plugin.py"
    if not sample.is_file() or not plugin_path.is_file():
        return []

    render = plugin_defaults(plugin_path)
    problems = []
    for lineno, line in enumerate(sample.read_text().splitlines(), 1):
        m = re.match(r'^#\s*([a-z_][a-z0-9_]*):\s*"([^"]*)"', line)
        if not m:
            continue
        field, shown = m.group(1), m.group(2)
        # `# field: ""` is the sample's idiom for "optional, no value shown" —
        # it documents absence, not a default of empty string.
        if shown == "":
            continue
        actual = render.get(field)
        if actual is not None and shown != actual:
            problems.append(
                f"cluster.sample.yaml:{lineno}: {field} is documented as {shown!r} "
                f"but omitting it yields {actual!r}"
            )
    return problems


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()

    checks = (
        ("dangling task variables", check_dangling_vars),
        ("divergent defaults", check_divergent_defaults),
        ("documented defaults", check_documented_defaults),
    )

    failed = False
    for label, check in checks:
        problems = check(root)
        if problems:
            failed = True
            print(f"FAIL  {label}", file=sys.stderr)
            for p in problems:
                print(f"        {p}", file=sys.stderr)
        else:
            print(f"ok    {label}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
