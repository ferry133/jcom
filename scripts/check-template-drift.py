#!/usr/bin/env python3
"""Report how a per-user cluster repo's templates differ from this one.

Every cluster repo carries its own copy of `templates/`, `.taskfiles/`
and `scripts/` — all three, see TRACKED. The docstring said two of them
until 2026-08-30, and the missing one is where every guard lives, so a
reader checking whether guards are covered here read "no".
Copies drift: someone edits a shared file to solve a local problem, and from
then on that repo silently stops receiving improvements to it. Worse, the edit
outlives its reason — jg-jiahd carried a cloudflare-tunnel patch for three weeks
after jg-base adopted exactly those values as the default, and nothing said so.

So this reports three things, and the third is the one people forget:

  DRIFTED    the file differs — and, since 2026-08-30 (`#54`), whether it is
             *stale* or *edited*: the cluster's bytes are looked up in this
             repo's history for that path, so a copy that is simply an older
             template version says so and names the commit it came from
  BEHIND     the file is missing locally — this repo will not get the feature
  EXTRA      the file exists only locally — a whole addition to account for
  MODE       same bytes, different permission bit

MODE is here because content equality was not enough and the gap had already
cost something. makejinja renders with `copy_metadata = true`, so a template's
mode lands on its output: jcom's `.sops.yaml.j2` was byte-identical to this
repo's and mode 755 against 644, which flipped the rendered `.sops.yaml` to 755
on every `task configure`. This script reported `ok` throughout, because bytes
were all it read — a clean result from a check that was not looking.

Usage:  ./scripts/check-template-drift.py <cluster-repo> <template-repo>

Exit 0 if the cluster matches, 1 if anything drifted or is missing, and 2 if it
could not compare -- today that means the two paths resolved to the same repo,
which was reported as `ok` until 2026-08-28. Three outcomes, because with two
"did not compare" lands in whichever bucket the reader is already expecting.

[template-repo] still defaults to the current directory, but a default that
resolves to the cluster is now refused rather than answered.
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


def git(template: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(template), *args], capture_output=True, text=True
    )


def stale_or_edited(template: Path, rel: Path, cluster_file: Path) -> str:
    """Is the cluster's copy an older version of this file, or an edited one?

    `#54`: this report used to say only that the bytes differ, and left the
    reader to decide between "a declared per-cluster exception" and "nobody
    synced it". Measured 2026-08-30 across the fleet — four different versions
    of `check-template-integrity.py` in circulation and two repos without the
    file at all — that distinction is the whole question, and nothing was
    answering it.

    It is answerable without asking anyone: git already stores every version
    this repo has ever had. If the cluster's bytes hash to a blob this path
    held at some commit, the copy is that version — stale, not edited. If they
    hash to nothing in that path's history, somebody changed it locally.

    Returns a phrase to append to the DRIFTED row. Never guesses: when the
    template is not a git repo, or git fails, it says so rather than implying
    the file was edited — "could not look" and "edited" are different answers
    and only one of them is a finding.
    """
    blob = git(template, "hash-object", str(cluster_file))
    if blob.returncode != 0:
        return "could not hash it — is the template a git repo?"
    want = blob.stdout.strip()

    log = git(template, "log", "--format=%H %ad", "--date=short", "--", str(rel))
    if log.returncode != 0:
        return "could not read this path's history"
    # How far back it is comes from the position in this list, not from
    # `rev-list --count <sha>..HEAD`. That count was tried first and printed
    # `0 change(s) behind` for a file whose bytes differ — because history
    # simplification drops merge commits from a path's log, so the count can be
    # zero while the content is not. A number that reads "up to date" next to a
    # row that exists because the file is not is worse than no number.
    #
    # The index needs no ancestry arithmetic: this log is already newest-first,
    # so the number of entries passed before the match IS the number of
    # recorded versions newer than the cluster's.
    for newer, line in enumerate(log.stdout.splitlines()):
        sha, _, date = line.partition(" ")
        got = git(template, "rev-parse", f"{sha}:{rel}")
        if got.returncode != 0 or got.stdout.strip() != want:
            continue
        if newer == 0:
            # It matched the newest commit touching this path, yet the bytes
            # differ from what is on disk here. The difference is the
            # template's own working tree, not the cluster.
            return (
                f"matches template {sha[:7]} ({date}), the newest commit for this"
                " path — the difference is uncommitted work in the TEMPLATE"
            )
        return (
            f"stale: this is template {sha[:7]} ({date}), "
            f"{newer} newer version(s) of this file since"
        )
    return "edited locally: these bytes are no version this path ever had"


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cluster = Path(sys.argv[1]).expanduser().resolve()
    defaulted = len(sys.argv) <= 2
    template = Path(sys.argv[2] if not defaulted else ".").expanduser().resolve()
    if not cluster.is_dir():
        sys.exit(f"not a directory: {cluster}")

    # Refuse to compare a repo with itself, and exit 2 rather than 0.
    #
    # Measured 2026-08-28: run from inside a cluster repo as
    # `check-template-drift.py .`, both paths resolve to that repo, every shared
    # file is byte-identical to itself, and this printed
    # `ok -- this cluster's templates match`. A fleet-ops session used that to
    # start refuting a real 21-file drift report before catching it.
    #
    # The `template:` line was already printed and named the same directory, so
    # the information was on screen and still missed -- which is the argument
    # for refusing rather than warning. **A self-comparison cannot fail**, so
    # its `ok` carries no information, and an `ok` that cannot fail is
    # indistinguishable from one that passed.
    #
    # Exit 2, not 0 and not 1: this is the third outcome. 0 means "compared,
    # matched", 1 means "compared, diverged", and 2 means "did not compare".
    # Collapsing it into 0 is exactly how "I could not measure" gets filed under
    # "passed".
    if cluster == template:
        how = "the default (current directory)" if defaulted else "argv[2]"
        sys.stderr.write(
            f"refusing to compare {cluster} with itself\n"
            f"  template path came from {how}\n"
            f"  a repo always matches itself, so the result would be `ok` no\n"
            f"  matter how far this cluster has drifted\n"
            f"  pass the template repo explicitly:\n"
            f"      {Path(sys.argv[0]).name} {sys.argv[1]} <path-to-jg-cluster-template>\n"
        )
        return 2

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
        # 0o100 (owner execute), NOT 0o111.
        #
        # Measured 2026-08-28: git records exactly two file modes, `100644` and
        # `100755` — the owner-execute bit and nothing else. Group and other
        # execute are not stored, so what lands in a working tree for those bits
        # is decided by the umask at checkout time, not by the repo.
        #
        # `& 0o111` therefore compared two checkout environments and called the
        # answer a repo difference. It fired for `scripts/lib/common.sh` at
        # 700 vs 755 while `git ls-files -s` said `100755` on BOTH sides — the
        # same file, no divergence, one row of noise. Cloning either side again
        # can change the answer without anything in either repo changing.
        #
        # That is the same class as the self-comparison fixed in the commit
        # before this one: **a result decided by the environment reads exactly
        # like a result that measured something.**
        #
        # The case this check exists for survives the narrowing. The docstring's
        # example is `.sops.yaml.j2` at 755 against 644, and that IS the
        # owner-execute bit — `100755` vs `100644`, recorded by git, propagated
        # to the rendered output by makejinja's `copy_metadata = true`.
        and ((template / p).stat().st_mode & 0o100) != ((cluster / p).stat().st_mode & 0o100)
    )
    behind = sorted(ours - theirs)
    extra = sorted(theirs - ours)

    print(f"cluster:  {cluster}")
    print(f"template: {template}")
    print(f"compared: {len(theirs & ours)} shared files\n")

    for label, rows in (
        (
            "DRIFTED",
            [
                (p, f"{n} changed lines; "
                    + stale_or_edited(template, p, cluster / p))
                for p, n in drifted
            ],
        ),
        ("BEHIND ", [(p, "missing locally") for p in behind]),
        ("EXTRA  ", [(p, "not in template") for p in extra]),
        (
            "MODE   ",
            [
                (
                    p,
                    # Cluster first, then template — every other row in this
                    # report reads "what is true of the cluster", and MODE used
                    # to print the template's mode labelled `here`. Measured
                    # 2026-08-28 against jcom: it said `755 here vs 700 there`
                    # while the cluster was 700 and the template 755. Reversed.
                    #
                    # Said as executable/not rather than as an octal triple: the
                    # octal implies git carries three digits of precision. It
                    # carries one bit.
                    "same bytes, executable in the cluster but not in the"
                    " template"
                    if (cluster / p).stat().st_mode & 0o100
                    else "same bytes, executable in the template but not in the"
                    " cluster",
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
    print("Each DRIFTED row says which kind it is. `stale` means nobody synced")
    print("this repo — no judgement needed, and the named commit says how far")
    print("back it is. `edited locally` is the one that needs a reason, and an")
    print("exception whose reason upstream has since adopted is dead weight that")
    print("still reads as current.")
    print("Nothing here applies anything: `stale` and a deliberate exception are")
    print("told apart by this report, not by a copy that would overwrite both.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
