#!/usr/bin/env python3
"""Report how a per-user cluster repo's templates differ from this one.

Every cluster repo carries its own copy of `templates/` and `.taskfiles/`.
Copies drift: someone edits a shared file to solve a local problem, and from
then on that repo silently stops receiving improvements to it. Worse, the edit
outlives its reason — jg-jiahd carried a cloudflare-tunnel patch for three weeks
after jg-base adopted exactly those values as the default, and nothing said so.

So this reports three things, and the third is the one people forget:

  DRIFTED    the file differs — an exception, or an edit nobody wrote down
  BEHIND     the file is missing locally — this repo will not get the feature
  EXTRA      the file exists only locally — a whole addition to account for
  MODE       same bytes, different permission bit

MODE is here because content equality was not enough and the gap had already
cost something. makejinja renders with `copy_metadata = true`, so a template's
mode lands on its output: jcom's `.sops.yaml.j2` was byte-identical to this
repo's and mode 755 against 644, which flipped the rendered `.sops.yaml` to 755
on every `task configure`. This script reported `ok` throughout, because bytes
were all it read — a clean result from a check that was not looking.

Usage:  ./scripts/check-template-drift.py <cluster-repo> [template-repo]
Exit 0 if the cluster matches, 1 if anything drifted or is missing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Compared verbatim. Rendered output lives elsewhere and legitimately differs.
TRACKED = ("templates", ".taskfiles", "scripts")

# Local by definition — every cluster fills these in for itself.
IGNORE_NAMES = {"__pycache__", ".DS_Store"}


def files_under(root: Path) -> set[Path]:
    found: set[Path] = set()
    for tracked in TRACKED:
        base = root / tracked
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if any(part in IGNORE_NAMES for part in path.parts):
                continue
            found.add(path.relative_to(root))
    return found


def diff_size(a: Path, b: Path) -> int:
    result = subprocess.run(
        ["diff", "-u", str(a), str(b)], capture_output=True, text=True
    )
    return sum(
        1
        for line in result.stdout.splitlines()
        if line[:1] in "+-" and not line.startswith(("+++", "---"))
    )


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cluster = Path(sys.argv[1]).expanduser().resolve()
    template = Path(sys.argv[2] if len(sys.argv) > 2 else ".").expanduser().resolve()
    if not cluster.is_dir():
        sys.exit(f"not a directory: {cluster}")

    theirs, ours = files_under(cluster), files_under(template)
    drifted = sorted(
        (p, diff_size(template / p, cluster / p))
        for p in theirs & ours
        if (template / p).read_bytes() != (cluster / p).read_bytes()
    )
    # Only for files whose bytes match — a drifted file's mode is noise next to
    # its content, and reporting both would double-count one divergence.
    mode_only = sorted(
        p
        for p in theirs & ours
        if (template / p).read_bytes() == (cluster / p).read_bytes()
        and ((template / p).stat().st_mode & 0o111) != ((cluster / p).stat().st_mode & 0o111)
    )
    behind = sorted(ours - theirs)
    extra = sorted(theirs - ours)

    print(f"cluster:  {cluster}")
    print(f"template: {template}")
    print(f"compared: {len(theirs & ours)} shared files\n")

    for label, rows in (
        ("DRIFTED", [(p, f"{n} changed lines") for p, n in drifted]),
        ("BEHIND ", [(p, "missing locally") for p in behind]),
        ("EXTRA  ", [(p, "not in template") for p in extra]),
        (
            "MODE   ",
            [
                (
                    p,
                    f"same bytes, {(template / p).stat().st_mode & 0o777:o}"
                    f" here vs {(cluster / p).stat().st_mode & 0o777:o} there",
                )
                for p in mode_only
            ],
        ),
    ):
        for path, note in rows:
            print(f"  {label}  {path}  ({note})")

    total = len(drifted) + len(behind) + len(extra) + len(mode_only)
    if not total:
        print("ok — this cluster's templates match the template repo")
        return 0

    print(f"\n{total} file(s) diverge.")
    print("Each DRIFTED file is either a declared per-cluster exception or an")
    print("undeclared edit. Check both directions: an exception whose reason")
    print("upstream has since adopted is dead weight that still reads as current.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
