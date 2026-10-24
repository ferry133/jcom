#!/usr/bin/env python3
"""The optional apps come from ferry133/jg-extras, and nothing else moved.

jgct#217 (fleet-ops root `split-extras-repo` D1/D3/D6). The extras loop in
ks.yaml.j2 changed one field — `sourceRef.name: jg-base` -> `jg-extras` — and
the template gained `GitRepository jg-extras` plus its deploy-key Secret.
Three things can go quietly wrong, and each is asserted on a real makejinja
render of the fixtures check-tenant-render.py already maintains:

1. **A cluster without extras is untouched**: no `GitRepository jg-extras`, no
   deploy-key Secret file, no `extras-*` Kustomization (appliance-minimal).
2. **A cluster with extras is wired, and both halves exist**: exactly one
   `GitRepository jg-extras` (url/ref as rendered from extras_repo_*), whose
   `secretRef.name` is the name of a Secret that IS rendered — the jgct#56
   shape was a credential nothing referenced, or a reference to nothing,
   which reads as `unable to list remote` only after delivery. The Secret
   carries `identity` and a `known_hosts` equal to the root sync's. Every
   `extras-<app>` Kustomization points at `jg-extras` with
   `path: ./kubernetes/apps/extras/<ns>/<app>`, one per `extras_from_repo`
   entry, and `GitRepository jg-base` is unchanged.
3. **On demand (`--against <ref>`)**: against the template at <ref>, each
   fixture's render differs ONLY by GitRepository jg-extras, the deploy-key
   Secret file, and the extras Kustomizations' sourceRef.name. Not in CI for
   the reason check-tenant-render.py gives: an unrelated change is supposed
   to move the render.

Exit 0 pass, 1 fail, 2 could not measure. A failure wins.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("tr", ROOT / "scripts" / "check-tenant-render.py")
tr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tr)

KS = "kubernetes/flux/cluster/ks.yaml"
SECRET_FILE = "kubernetes/components/sops/jg-extras-deploy-key.sops.yaml"
NOW_BASE = {"claudecode/claude-code", "monitoring/daily-check",
            "storage/local-path-provisioner", "default/echo"}


def by_kind_name(files: dict[str, bytes], path: str) -> dict[tuple[str, str], dict]:
    return {(d.get("kind", ""), d.get("metadata", {}).get("name", "")): d
            for d in (tr.docs(files[path]) if path in files else [])}


def check_render(name: str, fixture: dict, files: dict[str, bytes], hosts: list[str]) -> list[str]:
    bad: list[str] = []
    if tr.KS not in files:
        return [f"[{name}] {KS} not rendered"]
    objs = by_kind_name(files, KS)
    extras = [e for e in (fixture.get("extras") or []) if e not in NOW_BASE]
    repo = objs.get(("GitRepository", "jg-extras"))
    ks_extras = {k[1]: v for k, v in objs.items() if k[0] == "Kustomization" and k[1].startswith("extras-")}
    base = objs.get(("GitRepository", "jg-base"))
    if base is None or base.get("spec", {}).get("url") != fixture.get("base_repo_url", "https://github.com/ferry133/jg-base"):
        bad.append(f"[{name}] GitRepository jg-base missing or its url changed")
    if not extras:
        if repo is not None:
            bad.append(f"[{name}] no extras, yet GitRepository jg-extras is rendered")
        if SECRET_FILE in files:
            bad.append(f"[{name}] no extras, yet {SECRET_FILE} is rendered")
        if ks_extras:
            bad.append(f"[{name}] no extras, yet {sorted(ks_extras)} are rendered")
        return bad
    if repo is None:
        return bad + [f"[{name}] extras {extras} but no GitRepository jg-extras"]
    spec = repo.get("spec", {})
    want_url = fixture.get("extras_repo_url", "ssh://git@github.com/ferry133/jg-extras.git")
    if spec.get("url") != want_url:
        bad.append(f"[{name}] GitRepository jg-extras url {spec.get('url')!r}, expected {want_url!r}")
    kind = fixture.get("extras_repo_ref_kind", "branch")
    if spec.get("ref") != {kind: fixture.get("extras_repo_ref", "main")}:
        bad.append(f"[{name}] GitRepository jg-extras ref {spec.get('ref')!r}")
    ref_name = (spec.get("secretRef") or {}).get("name")
    secrets = by_kind_name(files, SECRET_FILE)
    sec = secrets.get(("Secret", ref_name or ""))
    if not ref_name:
        bad.append(f"[{name}] GitRepository jg-extras has no secretRef — a private repo cannot be cloned")
    elif sec is None:
        bad.append(f"[{name}] secretRef {ref_name!r} names no Secret in {SECRET_FILE} "
                   f"(rendered: {sorted(k[1] for k in secrets)})")
    else:
        if sec.get("metadata", {}).get("namespace") != "flux-system":
            bad.append(f"[{name}] Secret {ref_name} is not in flux-system")
        sd = sec.get("stringData", {})
        if sorted(sd) != ["identity", "known_hosts"]:
            bad.append(f"[{name}] Secret {ref_name} keys {sorted(sd)}, expected identity, known_hosts")
        if "placeholder-jg-extras-ro" not in sd.get("identity", ""):
            bad.append(f"[{name}] Secret {ref_name} identity is not jg-extras.deploy.key")
        if [l.strip() for l in sd.get("known_hosts", "").splitlines() if l.strip()] != hosts:
            bad.append(f"[{name}] Secret {ref_name} known_hosts differs from bootstrap's")
    want = {f"extras-{e.split('/')[1]}": e for e in extras}
    if sorted(ks_extras) != sorted(want):
        bad.append(f"[{name}] extras Kustomizations {sorted(ks_extras)}, expected {sorted(want)}")
    for k, extra in want.items():
        d = ks_extras.get(k, {}).get("spec", {})
        if d.get("sourceRef") != {"kind": "GitRepository", "name": "jg-extras", "namespace": "flux-system"}:
            bad.append(f"[{name}] {k} sourceRef {d.get('sourceRef')!r}, expected jg-extras")
        if d.get("path") != f"./kubernetes/apps/extras/{extra}":
            bad.append(f"[{name}] {k} path {d.get('path')!r}, expected ./kubernetes/apps/extras/{extra}")
    return bad


def against(name: str, before: dict[str, bytes], now: dict[str, bytes]) -> list[str]:
    """Only GitRepository jg-extras, the Secret file and sourceRef.name may differ."""
    bad = []
    for d in tr.diff_names(before, now):
        path = d.split(": ", 1)[1]
        if path not in (KS, SECRET_FILE):
            bad.append(f"[{name}] differs from the reference outside the allowed set: {d}")
    if SECRET_FILE in before:
        bad.append(f"[{name}] the reference already has {SECRET_FILE}")
    old = tr.docs(before[KS])
    new = []
    for d in tr.docs(now[KS]):
        if (d.get("kind"), d.get("metadata", {}).get("name")) == ("GitRepository", "jg-extras"):
            continue
        d = copy.deepcopy(d)
        if d.get("kind") == "Kustomization" and d["metadata"]["name"].startswith("extras-"):
            if (d.get("spec", {}).get("sourceRef") or {}).get("name") == "jg-extras":
                d["spec"]["sourceRef"]["name"] = "jg-base"
        new.append(d)
    if new != old:
        bad.append(f"[{name}] {KS} differs from the reference beyond jg-extras + sourceRef.name "
                   f"({len(new)} vs {len(old)} documents after normalising)")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tree", type=Path, default=ROOT)
    ap.add_argument("--against", metavar="REF")
    args = ap.parse_args()
    failures: list[str] = []
    try:
        hosts = tr.bootstrap_known_hosts(args.tree)
        if len(hosts) < 3:
            raise tr.CannotMeasure(f"{tr.BOOTSTRAP_KEY}: {len(hosts)} known_hosts lines, expected 3")
        with tempfile.TemporaryDirectory(prefix="extras-src.") as tmp:
            key = Path(tmp) / "age.key"
            subprocess.run([tr.tool("age-keygen"), "-o", str(key)], capture_output=True, check=True)
            ref_tree = None
            if args.against:
                ref_tree = Path(tmp) / "ref"
                ref_tree.mkdir()
                tr.checkout(args.against, ref_tree)
            seen_with, seen_without = 0, 0
            for name, fixture, nodes in tr.FIXTURES:
                problem = tr.vet(args.tree, fixture, nodes)
                if problem:
                    failures.append(f"[{name}] fixture fails cue vet (guard defect):\n{problem}")
                    continue
                try:
                    files = tr.render(args.tree, fixture, nodes, key)
                    before = tr.render(ref_tree, fixture, nodes, key) if ref_tree else None
                except RuntimeError as e:
                    failures.append(f"[{name}] render failed: {e}")
                    continue
                has = bool([e for e in (fixture.get("extras") or []) if e not in NOW_BASE])
                seen_with += has
                seen_without += not has
                bad = check_render(name, fixture, files, hosts)
                if before is not None:
                    bad += against(name, before, files)
                failures += bad
                if not bad:
                    print(f"ok  [{name}] " + ("extras from jg-extras, secretRef resolves"
                                              if has else "no extras, no jg-extras objects")
                          + (f"; vs {args.against}: only the allowed lines" if before is not None else ""))
            # Positive control on the population: both shapes must be exercised.
            if not (seen_with and seen_without):
                failures.append(f"fixtures exercise with-extras={seen_with}, without={seen_without}; "
                                f"both must be >0 (guard defect)")
    except tr.CannotMeasure as e:
        if failures:
            print("\n".join("FAIL " + f for f in failures))
            return 1
        print(f"COULD NOT MEASURE: {e}")
        return 2
    if failures:
        print("\n".join("FAIL " + f for f in failures))
        return 1
    print(f"PASS -- {len(tr.FIXTURES)} fixtures: extras come from jg-extras with a resolving "
          f"secretRef; clusters without extras unchanged"
          + (f"; each render differs from {args.against} only by the allowed lines" if args.against else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
