#!/usr/bin/env python3
"""Check the rendering pipeline for defects that only surface at run time.

Both defect classes this catches were found in this repo by hand:

  - a task referencing a variable defined nowhere (`task template:tidy` had
    referenced an undefined TEMPLATE_NODE_CONFIG_FILE for months)
  - a field whose schema default disagrees with the render-time default
    (cluster_svc_cidr was 10.43.0.0/16 in CUE and 10.96.0.0/16 in plugin.py)
  - a `db_storage_class` naming a class this cluster will not install
    (ferry133/jg-cluster-template#1)

None is visible by reading a single file, so check them instead of
rediscovering them later.

Three outcomes, not two: `ok`, `FAIL`, and `skip` for a check whose subject is
not present. A check that cannot see what it is checking must not print the same
word as one that looked and found nothing wrong.

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


# Storage classes this repository installs, and what has to be true for each.
# Anything not named here is left alone: a cluster may have a CSI class this
# repo has never heard of, and refusing those would be wrong more often than the
# bug it prevents (ferry133/jg-cluster-template#1).
#
# `local-path` needs no entry — local-path-provisioner is a base app everywhere.


class CannotCheck(Exception):
    """The check's subject is not present, so nothing was measured.

    Distinct from finding no problems. Raised rather than returning an empty
    list because those two print the same word otherwise, which is the defect
    this file exists to catch.
    """


def top_level(path: Path) -> dict[str, str]:
    """Top-level `key: value` scalars from a cluster.yaml, as raw strings.

    Regex rather than a YAML parser to stay dependency-free, like the rest of
    this file. Only column-zero keys are collected, so nested mappings and list
    items cannot be mistaken for top-level fields, and commented lines are
    ignored. Values keep their raw text — quote stripping and boolean
    interpretation are the caller's business, and doing them here would hide
    the difference between `false` and `"false"`.
    """
    found: dict[str, str] = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^([a-z_][a-z0-9_]*):[ \t]*(.*?)[ \t]*$", line)
        if m and not m.group(1).startswith("#"):
            found[m.group(1)] = strip_comment(m.group(2))
    return found


def strip_comment(value: str) -> str:
    """Drop a trailing `# ...` the way YAML does.

    Not cosmetic. A real cluster.yaml in this fleet carries
    `storage_backend: "local-path"   # single node, no NAS`, and without this the
    value compares unequal to every name it should match — which would fail a
    correct configuration and, worse, would have looked like the check working.
    Found by running against the live repos rather than against the fixture list,
    which had no commented values in it because none were imagined.
    """
    v = value.strip()
    if v[:1] in ('"', "'"):
        end = v.find(v[0], 1)
        return v if end == -1 else v[:end + 1]
    return v.split(" #", 1)[0].split("\t#", 1)[0].strip()


def unquote(raw: str) -> str:
    return raw.strip().strip('"').strip("'")


def yaml_bool(raw: str) -> bool | None:
    """`true`/`false` only. None for anything else, including YAML 1.1's
    `yes`/`no`/`on`/`off` — guessing at those here would be a second opinion
    about what the renderer does, and two opinions is the divergence this file
    checks for elsewhere."""
    v = unquote(raw).lower()
    return True if v == "true" else False if v == "false" else None


def check_db_storage_class(root: Path) -> tuple[list[str], list[str]]:
    """`db_storage_class` must name a class this cluster will actually have.

    The schema accepts any non-empty string and plugin.py only `setdefault`s it,
    so `db_storage_class: "longhorn"` on a cluster without Longhorn renders, vets
    clean, and leaves a PVC `Pending` forever. There is no failure signal: the
    Kustomization goes Ready, and the symptom is one pod that never starts.

    Deliberately mirrors plugin.py's derivation rather than restating the rule.
    The issue that asked for this described it as "replicated_storage: true OR
    storage_backend: replicated", and that is not what the renderer does: an
    explicit `replicated_storage: false` wins over `storage_backend:
    "replicated"`, so that combination installs no Longhorn. A check that
    disagreed with the renderer in that corner would pass exactly the config
    that breaks.
    """
    cfg_path = root / "cluster.yaml"
    if not cfg_path.is_file():
        raise CannotCheck(
            "no cluster.yaml here — this is the template repo, which has no "
            "cluster to check. In a per-user repo `task configure` requires it, "
            "so this cannot be the silent-skip case"
        )

    cfg = top_level(cfg_path)
    problems: list[str] = []
    warnings: list[str] = []

    # Absent means plugin.py's setdefault applies, which is local-path.
    db_class = unquote(cfg.get("db_storage_class", "local-path"))
    backend = unquote(cfg.get("storage_backend", ""))

    if db_class == "longhorn":
        if "replicated_storage" in cfg:
            declared = yaml_bool(cfg["replicated_storage"])
            if declared is None:
                warnings.append(
                    f"replicated_storage is {cfg['replicated_storage']!r}, which "
                    "this check reads as neither true nor false, so whether "
                    "Longhorn is installed was not determined here. "
                    "`task configure` runs `cue vet` after this and will reject it"
                )
                installed = None
            else:
                installed = declared
        else:
            installed = backend == "replicated"

        if installed is False:
            missing = (
                "replicated_storage is declared false, which overrides "
                f"storage_backend: {backend!r}"
                if yaml_bool(cfg.get("replicated_storage", "")) is False
                else f"neither replicated_storage: true nor storage_backend: "
                     f'"replicated" is set (storage_backend is {backend!r})'
            )
            problems.append(
                f"db_storage_class is \"longhorn\" but {missing}, so no Longhorn "
                "is installed. The database PVC would sit Pending forever with "
                "every Kustomization reporting Ready"
            )

    elif db_class == "sc-nas":
        if backend != "nfs":
            problems.append(
                f'db_storage_class is "sc-nas" but storage_backend is {backend!r}, '
                "so nfs-client-provisioner is suspended and nothing provides that "
                "class. The database PVC would sit Pending forever"
            )
        else:
            warnings.append(
                'db_storage_class is "sc-nas": the database is on NFS, which is '
                "never a correct answer for something that needs fsync durability "
                "and file locking. This is the un-migrated state, not a choice — "
                "see fleet-ops docs/operations/db-storage-migration.md"
            )

    return problems, warnings


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


def check_dangling_vars(root: Path) -> tuple[list[str], list[str]]:
    files = taskfiles(root)
    if not files:
        return ["no Taskfile.yaml found — wrong repo root?"], []

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
    return problems, []


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


def check_divergent_defaults(root: Path) -> tuple[list[str], list[str]]:
    cue_path = root / ".taskfiles/template/resources/cluster.schema.cue"
    plugin_path = root / "templates/scripts/plugin.py"
    if not cue_path.is_file() or not plugin_path.is_file():
        return [f"missing {cue_path.name} or {plugin_path.name} — wrong repo root?"], []

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
    return problems, []


def check_documented_defaults(root: Path) -> tuple[list[str], list[str]]:
    """Commented-out fields in the sample must show the default actually applied.

    Only literal defaults are checked; a computed default has no single value to
    document, so those lines are skipped rather than guessed at.
    """
    sample = root / "cluster.sample.yaml"
    plugin_path = root / "templates/scripts/plugin.py"
    # Raise, do not return clean. This check used to `return [], []` when either
    # file was missing, which prints `ok` — the same word as a sample that was
    # read and found correct. Measured three ways: present-and-correct → ok,
    # present-and-wrong → FAIL, ABSENT → ok. Two of those three are the same
    # word for different facts, which is the thing this file's own docstring
    # forbids in its opening paragraph.
    #
    # It is not hypothetical. `jg-janncotcc` deleted its cluster.sample.yaml on
    # purpose ("only a maintainer reads this, and this is the customer's repo"),
    # and removing it from the other user repos is under consideration. Every
    # one of them would print `ok documented defaults` forever afterwards.
    missing = [f.name for f in (sample, plugin_path) if not f.is_file()]
    if missing:
        raise CannotCheck(
            f"{', '.join(missing)} not here — nothing to compare. A user repo "
            "may drop cluster.sample.yaml deliberately; the template repo never "
            "should, so an absent sample HERE is a finding, not a skip"
        )

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
    return problems, []


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()

    checks = (
        ("dangling task variables", check_dangling_vars),
        ("divergent defaults", check_divergent_defaults),
        ("documented defaults", check_documented_defaults),
        ("db_storage_class is installable", check_db_storage_class),
    )

    failed = False
    for label, check in checks:
        try:
            problems, warnings = check(root)
        except CannotCheck as why:
            # Not "ok": nothing was measured. Not a failure either, when the
            # subject is absent by design rather than by accident.
            print(f"skip  {label} — {why}")
            continue

        if problems:
            failed = True
            print(f"FAIL  {label}", file=sys.stderr)
            for problem in problems:
                print(f"        {problem}", file=sys.stderr)
        else:
            print(f"ok    {label}")
        for warning in warnings:
            print(f"warn  {label}")
            print(f"        {warning}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
