#!/usr/bin/env python3
"""Assert what an unset `claude_code_always_on` renders to, per instance count.

A cluster handed over with 0 replicas has no way in, and Step 5's "the instance
actually answers" assertion then fails with a 503 (jg-cluster-template#57). The
default that fixes that has to hit three different answers, and two of them are
easy to get wrong in a way nothing reports:

  exactly one instance -> that one          (the ordinary handover)
  more than one        -> [] and say so     (picking one would be a guess:
                                             jg-jiahd and jcom both declare
                                             ["cc","im"] and both run **im**)
  zero instances       -> [] and say NOTHING (claude_instances: [] is a legal,
                                             deliberate "no web terminal"; a
                                             guard that flags correct input is
                                             worse than none -- jg-base#18)

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
    ("neither declared -- the ordinary new cluster",
     {}, ["im"], False),
    ("instances renamed, always_on unset",
     {"claude_instances": ["ops"]}, ["ops"], False),
    ("POSITIVE CONTROL: always_on declared empty stays empty",
     {"claude_code_always_on": []}, [], False),
    ("more than one instance -> refuse to pick, and say so",
     {"claude_instances": ["cc", "im"]}, [], True),
    ("ZERO instances is legal -- must NOT be flagged (jg-base#18)",
     {"claude_instances": []}, [], False),
    ("jg-jiahd / jcom as they are today -- untouched",
     {"claude_instances": ["cc", "im"], "claude_code_always_on": ["im"]},
     ["im"], False),
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
    data = dict(BASE, claude_instances=["ops"], claude_code_always_on=["im"])
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            plugin.Plugin(data).data()
    except KeyError:
        print("PASS  always_on naming a non-instance is refused")
    else:
        print("FAIL  always_on naming a non-instance was accepted —")
        print("      it renders nothing and reports nothing.")
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
          f"({len(CASES) + 2} assertions, {failed} failed)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
