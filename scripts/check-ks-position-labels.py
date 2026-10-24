#!/usr/bin/env python3
"""Assert the `# enabled:` / `# disabled:` comment in ks.yaml renders the truth.

That comment sits above every Kustomization patch in a per-user repo's
`kubernetes/flux/cluster/ks.yaml`. It is the only place that file says what
this cluster turned on and why, and it is read by someone asking why a thing
is missing -- so a label that says the opposite of the truth is worse than no
label: **a wrong comment reads exactly like a measured fact.**

jgct#94 was that, in production: the template asked `position == 'enabled'`
and let every other position name fall through to "disabled (…pruned)", which
announced `claudecode-db` -- the always-on explicit-memory database, position
`app` -- as disabled and about to be pruned, three lines above its own
`suspend: false`. Nothing went red. Nothing could: it is a comment.

What this checks, and the order matters:

  1. every position maps to the label its directory earns (empty -> pruned),
  2. an UNKNOWN position raises rather than being labelled by fallthrough,
     which is the bug class itself,
  3. the two vocabularies are disjoint, so the answer cannot depend on which
     `if` runs first,
  4. every position literal that ks.yaml.j2 can put in the tuple is classified
     -- read out of the template, not out of the author's memory, because a
     fixture written from memory omits exactly the entry nobody remembered,
  5. and the template actually USES the filter. Without this the filter can be
     perfect while the render still runs the old ternary: two things that have
     to agree, with only one of them tested.

What it CANNOT see, stated because a silent gap reads like coverage: whether
`./<basepath>/<position>/` really renders no resources. Those directories live
in ferry133/jg-base, not here. This guard checks the vocabulary is complete
and honest; it cannot check the vocabulary is *right* about jg-base's tree.

Exit 0 if everything matches, 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "templates" / "config" / "kubernetes" / "flux" / "cluster" / "ks.yaml.j2"


def load_plugin():
    """Import templates/scripts/plugin.py without a real makejinja.

    Bytecode is disabled deliberately. This guard exists to be run against a
    MUTATED plugin.py -- that is how anyone shows it can still tell right from
    wrong -- and CPython accepts a cached .pyc when the source mtime (one-second
    resolution) AND size still match. A minimal mutation is exactly the shape
    that matches both: swap a word for one of equal length, restore within the
    same second, and the stale bytecode is served. Measured here on 2026-09-09,
    where a reverted mutation kept failing and a subsequent one reported the
    PREVIOUS mutation's result; reproduced deterministically on 2026-09-10 by
    aligning the two. Both directions are dangerous, and the quiet one is a
    negative control that passes for a reason that no longer exists.
    """
    sys.dont_write_bytecode = True
    importlib.invalidate_caches()
    mj = types.ModuleType("makejinja")
    pl = types.ModuleType("makejinja.plugin")

    class _Base:
        def __init__(self, *a, **k):
            pass

    pl.Plugin, pl.Data, pl.Filters, pl.Functions = _Base, dict, list, list
    mj.plugin = pl
    sys.modules.setdefault("makejinja", mj)
    sys.modules.setdefault("makejinja.plugin", pl)
    spec = importlib.util.spec_from_file_location(
        "_plugin", ROOT / "templates" / "scripts" / "plugin.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# (position, must the label say "pruned")
CASES = [
    ("enabled", False),
    ("disabled", True),
    ("app", False),      # claudecode-db: always on, and jgct#94's victim
    # A row here is a claim about a directory in ferry133/jg-base, so a
    # position that is retired there loses its row in the same commit that
    # drops it from plugin.py's vocabulary. Removing only one side fails this
    # file, naming the position -- which is deliberate, see the except below.
    # ('nfs', False) and ('none', True) sat here until 2026-09-10, retired with
    # the NFS backup CronJob by ferry133/jg-base#82 (B).
]


def positions_in_template(text: str) -> tuple[set[str], set[str]]:
    """Position literals ks.yaml.j2 can put in the third tuple slot.

    Each `_enabled.append((name, basepath, position, why))` spans several
    lines and the position may be a conditional, so take every quoted literal
    on the lines between the basepath and the `why`. Over-collecting is safe
    here (an extra name only makes the check stricter); under-collecting is
    not, which is why this reads the file instead of listing what I remember.
    """
    found: set[str] = set()
    computed: set[str] = set()
    for block in re.findall(r"_enabled\.append\(\((.*?)\)\)", text, re.S):
        lines = [ln.strip() for ln in block.strip().split("\n")]
        # 0 = name, 1 = basepath, then the position expression, then `why`.
        for line in lines[2:]:
            if line.startswith("'") and len(line) > 60:
                break  # into the prose of `why`
            literals = re.findall(r"'([a-z0-9_-]{1,20})'", line)
            if literals:
                found.update(literals)
            elif re.fullmatch(r"[a-z_][a-z0-9_]*,", line):
                # A bare variable: `nas_backup,`. Its values are decided in
                # plugin.py, so no literal exists here to scrape. Named rather
                # than skipped -- an entry this function cannot see would
                # otherwise make the coverage line read as if it covered
                # everything.
                computed.add(line.rstrip(","))
    return found, computed


def main() -> int:
    plugin = load_plugin()
    label = plugin.ks_position_label
    failed = 0

    for position, wants_pruned in CASES:
        try:
            got = label(position)
        except KeyError as e:
            # Reached when the two sides of the coupling above disagree --
            # in practice, half of a position being retired. A traceback reads
            # like the guard broke; it did not, it is holding the line.
            print(f"FAIL  {position!r} is in CASES but plugin.py no longer "
                  f"classifies it.")
            print(f"        If you are retiring it, delete its row here too — "
                  f"do not put the name back.")
            print(f"        If you are not, it needs classifying: {str(e)[:100]}")
            failed += 1
            continue
        says_pruned = "pruned" in got
        if says_pruned == wants_pruned:
            print(f"PASS  {position!r} -> {got!r}")
        else:
            print(f"FAIL  {position!r} -> {got!r}")
            print(f"        expected a label that {'does' if wants_pruned else 'does NOT'}"
                  f" mention pruning")
            failed += 1

    # Negative control. This is the actual defect: a name the table does not
    # know must not come back labelled anyway. A guard that only checks the
    # five known names passes just as well against the broken ternary.
    try:
        got = label("sideways")
    except KeyError as e:
        msg = str(e)
        if "sideways" in msg and "plugin.py" in msg:
            print("PASS  an unknown position aborts the render and names itself")
        else:
            print(f"FAIL  unknown position raised, but the message does not say which\n"
                  f"        one or where to fix it: {msg[:120]}")
            failed += 1
    else:
        print(f"FAIL  an unknown position came back labelled {got!r} instead of raising —")
        print("      that fallthrough IS jgct#94: every unclassified name gets")
        print("      whichever label happens to be the else branch.")
        failed += 1

    overlap = plugin.EMPTY_POSITIONS & plugin.LIVE_POSITIONS
    if overlap:
        print(f"FAIL  {sorted(overlap)} is in both vocabularies, so the label depends")
        print("      on which branch is written first, not on what the directory holds.")
        failed += 1
    else:
        print("PASS  the two vocabularies are disjoint")

    # Coverage, read out of the protected thing rather than recalled.
    text = TEMPLATE.read_text()
    known = plugin.EMPTY_POSITIONS | plugin.LIVE_POSITIONS
    used, computed = positions_in_template(text)
    if not used:
        print("FAIL  found no position literals in ks.yaml.j2 — the scraper stopped")
        print("      matching, and an empty fixture passes every coverage check.")
        failed += 1
    else:
        missing = sorted(used - known)
        if missing:
            print(f"FAIL  ks.yaml.j2 can emit {missing}, which plugin.py classifies")
            print("      as neither empty nor live. Rendering would abort — add them.")
            failed += 1
        else:
            print(f"PASS  every position literal in ks.yaml.j2 is classified "
                  f"({sorted(used)})")
            if computed:
                print(f"      note: {sorted(computed)} supply a position at render time,"
                      f" so no\n            literal exists here to check — those are"
                      f" covered by the raise, not\n            by this line")

    # And the template has to be asking the filter at all.
    if "ks_position_label" in text:
        print("PASS  ks.yaml.j2 renders the label through the filter")
    else:
        print("FAIL  ks.yaml.j2 does not mention ks_position_label — the filter can")
        print("      be correct while the rendered comment still comes from the old")
        print("      inline conditional, and this file would not notice.")
        failed += 1

    print("\n(not checked here: whether ./<basepath>/<position>/ really renders no")
    print(" resources — those directories are in ferry133/jg-base, not this repo)")

    print()
    if failed:
        print(f"{failed} check(s) failed.")
        print("A wrong label in ks.yaml does not go red anywhere; it is read as a")
        print("statement of fact by whoever is asking where their app went.")
        return 1
    print(f"ok — {len(CASES)} positions labelled correctly, unknown ones abort,")
    print("     and the template is wired to the filter")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
