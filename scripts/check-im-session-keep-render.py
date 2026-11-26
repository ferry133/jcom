#!/usr/bin/env python3
"""im_session_keep renders IM_SESSION_KEEP: "1" into cluster-secrets and nothing else; absent or false renders nothing.

jgct#276. On real makejinja renders of the fixtures check-tenant-render.py
maintains:

1. **Not asked, no change**: no fixture -- nor the im-on fixture with an
   explicit `im_session_keep: false` -- renders IM_SESSION_KEEP. With
   `--against <ref>` each is byte-identical to the template at <ref>.
2. **Asked** (on im/enabled and on im/netdev): cluster-secrets carries
   IM_SESSION_KEEP with the string "1"; the only file that differs from the
   same cluster without the field is cluster-secrets; and within it the only
   key that differs is that one. In particular ks.yaml is byte-identical, so
   claude-code-im's patch and the list it sits in are what they were -- the
   field never writes `spec.patches` (the trap recorded on jgct#276).
3. **Asked together with chamber deliver**: both keys are there, and adding
   the field to a deliver cluster still changes cluster-secrets alone. The
   two fields are independent (plugin.py, chamber point 3).
4. **Refusals**: true on im/disabled, for its own reason. cue vet refuses a
   value that is not a boolean and accepts true.

What this does NOT check: that jg-base's im reads IM_SESSION_KEEP. That is a
line in another repository (ferry133/jg-base#277). Against a jg-base without
it every case here passes and the key is read by nothing.

Exit 0 pass, 1 fail, 2 could not measure. A failure wins.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tr = _load("tr", "check-tenant-render.py")
nr = _load("nr", "check-netdev-render.py")

CS = tr.CS
KEY = "IM_SESSION_KEEP"
# The fixture with the base im on (the field on im/disabled is refused).
BASE = "appliance-instances-auth0"
DISABLED = "appliance-minimal"


def fixture(name: str) -> dict:
    f = next((f for n, f, _ in tr.FIXTURES if n == name), None)
    if f is None:
        raise tr.CannotMeasure(f"fixture {name!r} is gone from check-tenant-render.py")
    return dict(f)


def cs_data(files: dict[str, bytes]) -> dict:
    for d in tr.docs(files[CS]):
        if tr.ident(d) == ("Secret", "cluster-secrets"):
            return d.get("stringData") or {}
    return {}


def check_absent(name: str, files: dict[str, bytes]) -> list[str]:
    hits = sorted(n for n, b in files.items() if KEY.encode() in b)
    return [f"[{name}] not asked, yet {KEY} is in {hits}"] if hits else []


def check_asked(label: str, without: dict[str, bytes], files: dict[str, bytes]) -> list[str]:
    bad = []
    got = cs_data(files).get(KEY)
    if got != "1":
        bad.append(f"[{label}] {KEY} is {got!r}, expected the string '1'")
    stray = [d for d in tr.diff_names(without, files) if d != f"differs: {CS}"]
    if stray:
        bad.append(f"[{label}] the field changed more than cluster-secrets: {stray}")
    before, after = cs_data(without), cs_data(files)
    moved = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    if moved != [KEY]:
        bad.append(f"[{label}] keys that differ in cluster-secrets: {moved}, expected ['{KEY}']")
    elsewhere = sorted(n for n, b in files.items() if n != CS and KEY.encode() in b)
    if elsewhere:
        bad.append(f"[{label}] {KEY} is also in {elsewhere}")
    return bad


REFUSALS = [
    # (name, fixture builder, reason substring)
    ("keep-on-disabled", lambda: dict(fixture(DISABLED), im_session_keep=True),
     "there is no session to keep"),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tree", type=Path, default=ROOT)
    ap.add_argument("--against", metavar="REF")
    args = ap.parse_args()
    failures: list[str] = []
    passed = 0
    refusals = 0
    try:
        base = fixture(BASE)
        with tempfile.TemporaryDirectory(prefix="im-session-keep-render.") as tmp:
            key = Path(tmp) / "age.key"
            subprocess.run([tr.tool("age-keygen"), "-o", str(key)], capture_output=True, check=True)
            ref_tree = None
            if args.against:
                ref_tree = Path(tmp) / "ref"
                ref_tree.mkdir()
                tr.checkout(args.against, ref_tree)

            def render(f):
                return tr.render(args.tree, f, [], key)

            # 1. not asked
            population = [(n, f, nodes) for n, f, nodes in tr.FIXTURES]
            population.append(("explicit-false", dict(base, im_session_keep=False), []))
            for name, fx, nodes in population:
                try:
                    files = tr.render(args.tree, fx, nodes, key)
                    # The ref predates the field, so the explicit-false case is
                    # compared against the ref's render of the plain fixture.
                    plain = {k: v for k, v in fx.items() if k != "im_session_keep"}
                    before = tr.render(ref_tree, plain, nodes, key) if ref_tree else None
                except RuntimeError as e:
                    failures.append(f"[{name}] render failed: {e}")
                    continue
                bad = check_absent(name, files)
                if before is not None:
                    bad += [f"[{name}] differs from {args.against}: {d}"
                            for d in tr.diff_names(before, files)]
                failures += bad
                if not bad:
                    passed += 1
                    print(f"ok  [{name}] no {KEY} in any rendered file"
                          + (f"; byte-identical to {args.against}" if before is not None else ""))

            # 2. asked, on both positions that have an im
            netdev = dict(base, **nr.READER)
            for pos_label, pos_base in (("enabled", base), ("netdev", netdev)):
                label = f"keep-{pos_label}"
                bad = check_asked(label, render(pos_base), render(dict(pos_base, im_session_keep=True)))
                failures += bad
                if not bad:
                    passed += 1
                    print(f"ok  [{label}] {KEY}='1' in cluster-secrets; it is the only key and "
                          "the only file that differs, ks.yaml included")

            # 3. independent of chamber
            deliver = dict(base, chamber_mode="deliver")
            both = render(dict(deliver, im_session_keep=True))
            bad = check_asked("keep-with-deliver", render(deliver), both)
            if cs_data(both).get("CHAMBER_MODE") != "deliver":
                bad.append("[keep-with-deliver] CHAMBER_MODE is not deliver beside the field")
            if KEY in cs_data(render(deliver)):
                bad.append(f"[keep-with-deliver] chamber deliver alone rendered {KEY}")
            failures += bad
            if not bad:
                passed += 1
                print(f"ok  [keep-with-deliver] both keys present; deliver alone renders no {KEY}; "
                      "the field still changes cluster-secrets alone")

            # 4. refusals
            for name, build, reason in REFUSALS:
                try:
                    render(build())
                except RuntimeError as e:
                    msg = str(e)
                    if reason not in msg:
                        failures.append(f"[{name}] refused, but not for its own reason "
                                        f"(no {reason!r}): {msg[-200:]}")
                    else:
                        refusals += 1
                        print(f"ok  [{name}] refused: {reason!r}")
                    continue
                failures.append(f"[{name}] rendered; it must be refused ({reason!r})")
            for name, fx, accept in (
                ("vet-true", dict(base, im_session_keep=True), True),
                ("vet-not-bool", dict(base, im_session_keep="1"), False),
            ):
                problem = tr.vet(args.tree, fx, [])
                if (problem is None) != accept:
                    failures.append(f"[{name}] cue vet {'refused' if problem else 'accepted'} it"
                                    + (f": {problem}" if problem else ""))
                else:
                    refusals += 1
                    print(f"ok  [{name}] cue vet {'accepts' if accept else 'refuses'}")
    except tr.CannotMeasure as e:
        if failures:
            print("\n".join("FAIL " + f for f in failures))
            return 1
        print(f"COULD NOT MEASURE: {e}")
        return 2
    except RuntimeError as e:
        failures.append(f"a good scenario failed to render (guard or template defect): {e}")
    if failures:
        print("\n".join("FAIL " + f for f in failures))
        return 1
    print(f"PASS -- {passed} render cases and {refusals} refusal/vet cases"
          + (f", the not-asked ones byte-identical to {args.against}" if args.against else "")
          + f". Not checked here: that jg-base reads {KEY}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
