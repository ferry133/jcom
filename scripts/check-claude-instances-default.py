#!/usr/bin/env python3
"""Assert what an unset `claude_code_always_on` renders to, per instance count.

Since 2026-09-06 the standing way in is jg-base's static im instance, and
claude_instances (default []) names EXTRA instances only — "im" in it is
refused outright, because the base HelmRelease already owns that object name.
The always_on default still has to hit three different answers for the
extras, and two of them are easy to get wrong in a way nothing reports:

  exactly one instance -> that one          (a renamed/extra terminal the
                                             cluster clearly wants standing)
  more than one        -> [] and say so     (picking one would be a guess --
                                             the #57 lesson, kept)
  zero instances       -> [] and say NOTHING (the DEFAULT now; a guard that
                                             flags correct input is worse
                                             than none -- jg-base#18)

The stderr note is asserted in BOTH directions. Asserting only that it fires
leaves the case it must NOT fire on invisible, which is how the zero-instance
false alarm survived review twice.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_plugin():
    """Import templates/scripts/plugin.py without a real makejinja."""
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


BASE = dict(
    cluster_name="rendertest",
    node_cidr="10.9.1.0/24",
    cluster_svc_cidr="10.96.0.0/12",
    bootstrap_distro="talos",
    deployment_profile="full",
    claudecode_auth0=False,
    ttyd_credential="ops:placeholder-not-a-real-credential",
)

# (name, extra cluster.yaml fields, expected always_on, expect stderr note)
CASES = [
    ("neither declared -- the ordinary new cluster (base im is the way in)",
     {}, [], False),
    ("one extra instance, always_on unset -> kept",
     {"claude_instances": ["ops"]}, ["ops"], False),
    ("POSITIVE CONTROL: always_on declared empty stays empty",
     {"claude_instances": ["ops"], "claude_code_always_on": []}, [], False),
    ("more than one extra -> refuse to pick, and say so",
     {"claude_instances": ["cc", "ops"]}, [], True),
    ("ZERO instances declared explicitly -- must NOT be flagged (jg-base#18)",
     {"claude_instances": []}, [], False),
    ("jg-jiahd post-migration: one extra kept standing",
     {"claude_instances": ["cc"], "claude_code_always_on": ["cc"]},
     ["cc"], False),
]


def main() -> int:
    plugin = load_plugin()
    failed = 0

    for name, extra, expected, expect_note in CASES:
        data = dict(BASE, **extra)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                plugin.Plugin(data).data()
            got = data["claude_code_always_on"]
        except Exception as e:  # noqa: BLE001
            print(f"FAIL  {name}\n        render raised {type(e).__name__}: {e}")
            failed += 1
            continue
        noted = "claude_code_always_on is unset" in err.getvalue()
        if got != expected:
            print(f"FAIL  {name}\n        expected {expected}, got {got!r}")
            failed += 1
        elif noted != expect_note:
            print(f"FAIL  {name}\n        stderr note: expected "
                  f"{'one' if expect_note else 'none'}, got "
                  f"{'one' if noted else 'none'}")
            failed += 1
        else:
            print(f"PASS  {name}\n        always_on = {got!r}"
                  f"{'  (+ note)' if noted else ''}")

    # A name that is not an instance renders no replicas and no error, which is
    # indistinguishable from a cluster that was never given a way in.
    data = dict(BASE, claude_instances=["ops"], claude_code_always_on=["cc"])
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            plugin.Plugin(data).data()
    except KeyError:
        print("PASS  always_on naming a non-instance is refused")
    else:
        print("FAIL  always_on naming a non-instance was accepted —")
        print("      it renders nothing and reports nothing.")
        failed += 1

    # "im" now names jg-base's static instance; a rendered twin would have two
    # Flux Kustomizations fighting over one HelmRelease, apply by apply. This
    # is exactly jg-jiahd/jcom's pre-migration cluster.yaml, so the refusal is
    # also what forces their migration edit to be deliberate.
    data = dict(BASE, claude_instances=["cc", "im"],
                claude_code_always_on=["im"])
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            plugin.Plugin(data).data()
    except KeyError as e:
        if "jg-base" in str(e):
            print("PASS  'im' in claude_instances is refused, naming jg-base")
        else:
            print(f"FAIL  'im' was refused but for the wrong reason: {e}")
            failed += 1
    else:
        print("FAIL  'im' in claude_instances was accepted — that renders a")
        print("      twin of the base HelmRelease under the same name.")
        failed += 1

    # A default that returns the same list for every instance count is not being
    # computed from the instance count. Same guard as check-node-dns-path.py.
    answers = set()
    for _, extra, _, _ in CASES:
        d = dict(BASE, **extra)
        with contextlib.redirect_stderr(io.StringIO()):
            plugin.Plugin(d).data()
        answers.add(tuple(d["claude_code_always_on"]))
    if len(answers) < 2:
        print("\nFAIL  every case produced the same always_on — a value that "
              "never varies\n      is not being derived from anything.")
        failed += 1

    print(f"\n{'FAIL' if failed else 'ok'} claude_code_always_on default "
          f"({len(CASES) + 3} assertions, {failed} failed)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
