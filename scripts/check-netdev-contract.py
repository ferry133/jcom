#!/usr/bin/env python3
"""check-netdev-render.py's copy of the netdev contract still matches jg-base.

jgct#249. check-netdev-render.py asserts the render against its own table of
Secret names, Secret keys and cluster-secrets keys. That table is a copy of
ferry133/jg-base's kubernetes/apps/base/claudecode/claude-code/im/netdev/
netdev-mcp.yaml, and a copy that drifts keeps its guard green while the
sidecar reads a file that is not there (`reader credential: missing`, a
visible state -- but on a cluster, after delivery). This reads jg-base's file
and derives the same table from it:

  - Secrets: every persistence entry whose volumeSpec.secret names one, and
    the netdev-mcp mount path it is given;
  - keys: every netdev-mcp env value under that mount path (`<path>/<key>`);
  - cluster-secrets keys: every substitution name netdev-mcp's env reads,
    less CLUSTER_NAME, which every cluster already carries.

Then it requires the copy to be equal, both directions. jg-base comes from
`--base`, else `$JG_BASE_DIR` (the template CI clones it), else `../jg-base`.

Exit 0 equal, 1 different, 2 could not measure (no jg-base, no overlay, or
the reader found nothing -- a reader that finds nothing would otherwise
"match" an empty table).
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("nr", ROOT / "scripts" / "check-netdev-render.py")
nr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nr)
tr = nr.tr

OVERLAY = "kubernetes/apps/base/claudecode/claude-code/im/netdev/netdev-mcp.yaml"
ALWAYS_THERE = {"CLUSTER_NAME"}


def derive(text: str) -> tuple[dict[str, list[str]], set[str]]:
    hr = next(d for d in tr.docs(text.encode()) if d.get("kind") == "HelmRelease")
    values = hr["spec"]["values"]
    env = values["controllers"]["im"]["containers"]["netdev-mcp"]["env"]
    strings = {k: v for k, v in env.items() if isinstance(v, str)}
    secrets: dict[str, list[str]] = {}
    for vol in (values.get("persistence") or {}).values():
        name = ((vol.get("volumeSpec") or {}).get("secret") or {}).get("secretName")
        if not name:
            continue
        mounts = ((vol.get("advancedMounts") or {}).get("im") or {}).get("netdev-mcp") or []
        keys = []
        for m in mounts:
            prefix = m["path"].rstrip("/") + "/"
            keys += [v[len(prefix):] for v in strings.values() if v.startswith(prefix)]
        secrets[name] = sorted(keys)
    subst = set()
    for v in strings.values():
        subst |= set(re.findall(r"\$\{([A-Z0-9_]+)", v))
    return secrets, subst - ALWAYS_THERE


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", type=Path,
                    default=Path(os.environ.get("JG_BASE_DIR") or ROOT.parent / "jg-base"))
    args = ap.parse_args()
    path = args.base / OVERLAY
    try:
        if not path.is_file():
            raise tr.CannotMeasure(f"{path} not found (jg-base from --base, $JG_BASE_DIR or ../jg-base)")
        secrets, subst = derive(path.read_text())
    except tr.CannotMeasure as e:
        print(f"COULD NOT MEASURE: {e}")
        return 2
    except (KeyError, StopIteration) as e:
        print(f"COULD NOT MEASURE: {OVERLAY} no longer has the shape this reader expects ({e!r})")
        return 2
    # Reader control: the shape must have yielded something on every axis.
    if not secrets or not subst or not all(secrets.values()):
        print(f"COULD NOT MEASURE: read {len(secrets)} Secret(s), {len(subst)} substitution(s), "
              f"keys {secrets} -- the reader is blind, not the contract empty")
        return 2
    bad = []
    copy = {k: sorted(v) for k, v in nr.SECRETS.items()}
    if copy != secrets:
        bad.append(f"Secrets: jg-base {secrets}, check-netdev-render.py {copy}")
    want = set(nr.CS_READER + nr.CS_WRITER)
    if subst != want:
        bad.append(f"cluster-secrets keys: jg-base reads {sorted(subst)}, "
                   f"check-netdev-render.py expects {sorted(want)}")
    if bad:
        print("\n".join("FAIL " + b for b in bad))
        return 1
    print(f"PASS -- {len(secrets)} Secrets with their keys and {len(subst)} cluster-secrets keys "
          f"match {args.base.name}/{OVERLAY}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
