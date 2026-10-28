#!/usr/bin/env python3
"""Every namespace the platform deploys into is in `#ReservedNamespaces`.

jgct#235 (fleet-ops standalone-app-repos 3.10). `cluster.schema.cue` keeps a
hand-written list of namespaces a tenant may not declare, because a tenant is
bound to `tenant-admin` in every namespace it declares and `tenant-admin` can
read Secrets. The list was enumerated once, on 2026-10-18. The day jg-base or
jg-extras adds a namespace, the list is one short **and nothing says so**: the
tenant is accepted and lands in a platform namespace.

So this reads both repos and compares. Two repos, not one: since
split-extras-repo the extras (linebot, homebridge, ...) live in ferry133/
jg-extras, and jg-base#214 deleted jg-base's copy. Reading jg-base alone would
drop every extras namespace, and that looks exactly like "no new namespace".

What counts as a namespace the platform uses, from each YAML document under
`kubernetes/` in each repo:

  - `kind: Namespace`               -> `metadata.name`
  - any object                      -> `metadata.namespace`
  - Flux Kustomization/HelmRelease  -> `spec.targetNamespace`
  - kustomize `kustomization.yaml`  -> top-level `namespace`

Parsed with yq, not grepped: the first baseline on #235 used
`grep -A3 'kind: Namespace'`, which cannot see a `name:` further down, and
it printed the same 0 a correct reading prints. A value that still holds a
Flux `${VAR}` is not a name yet; those are counted and printed, not compared.

Where the repos come from: `--base`/`--extras`, else `$JG_BASE_DIR`/
`$JG_EXTRAS_DIR`, else siblings of this checkout (`../jg-base`,
`../jg-extras`) — the same sibling convention check-private-repo-chain.py
uses. Files are the ones `git ls-files` tracks, so a stray untracked file in
a working copy is not a namespace. Each repo's HEAD is printed, because a
reading against a stale sibling looks the same as a reading against main.

Exit 0 ok, 1 a namespace is not reserved, 2 could not measure (a repo is
missing, yq is missing, the list cannot be read, or a repo yields no
namespace at all). A failure wins: one repo missing does not hide a gap
found in the other.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / ".taskfiles" / "template" / "resources" / "cluster.schema.cue"


def reserved(schema: Path) -> list[str] | None:
    """The list as CUE evaluates it, not as a regex reads the file."""
    cue = shutil.which("cue")
    if not cue or not schema.is_file():
        return None
    p = subprocess.run([cue, "eval", str(schema), "-e", "#ReservedNamespaces",
                        "--out", "json"], capture_output=True, text=True)
    if p.returncode != 0:
        print(p.stderr.strip())
        return None
    value = json.loads(p.stdout)
    return value if isinstance(value, list) else None


def documents(yq: str, path: Path):
    p = subprocess.run([yq, "eval-all", "-o=json", "-I=0", ".", str(path)],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"yq could not parse {path}: {p.stderr.strip()}")
    for line in p.stdout.splitlines():
        line = line.strip()
        if line and line != "null":
            yield json.loads(line)


def namespaces_in(doc) -> list[tuple[str, str]]:
    """(value, where) pairs this document puts objects into."""
    if not isinstance(doc, dict):
        return []
    out = []
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
    if doc.get("kind") == "Namespace" and meta.get("name"):
        out.append((meta["name"], "kind: Namespace"))
    if meta.get("namespace"):
        out.append((meta["namespace"], "metadata.namespace"))
    if spec.get("targetNamespace"):
        out.append((spec["targetNamespace"], "spec.targetNamespace"))
    if (str(doc.get("apiVersion", "")).startswith("kustomize.config.k8s.io/")
            and doc.get("namespace")):
        out.append((doc["namespace"], "kustomization namespace"))
    return [(str(v), w) for v, w in out]


def scan(repo: Path, yq: str):
    """{namespace: first file it was seen in}, unresolved count, HEAD."""
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True).stdout.strip() or "?"
    files = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "--", "kubernetes/*.yaml", "kubernetes/*.yml"],
        capture_output=True, text=True).stdout.split()
    found: dict[str, str] = {}
    unresolved = 0
    for rel in files:
        for doc in documents(yq, repo / rel):
            for value, where in namespaces_in(doc):
                if "${" in value:
                    unresolved += 1
                    continue
                found.setdefault(value, f"{rel} ({where})")
    return found, unresolved, head, len(files)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", type=Path,
                    default=Path(os.environ.get("JG_BASE_DIR") or ROOT.parent / "jg-base"))
    ap.add_argument("--extras", type=Path,
                    default=Path(os.environ.get("JG_EXTRAS_DIR") or ROOT.parent / "jg-extras"))
    ap.add_argument("--schema", type=Path, default=SCHEMA)
    args = ap.parse_args(argv)

    cannot: list[str] = []
    yq = shutil.which("yq")
    names = reserved(args.schema)
    if names is None:
        print(f"?     cannot tell: #ReservedNamespaces not readable from {args.schema} "
              "(is `cue` on PATH?)")
        return 2
    if not yq:
        print("?     cannot tell: `yq` is not on PATH")
        return 2
    allowed = set(names)

    missing: list[tuple[str, str, str]] = []
    for label, repo in (("jg-base", args.base), ("jg-extras", args.extras)):
        if not (repo / ".git").exists() or not (repo / "kubernetes").is_dir():
            cannot.append(f"{label}: no checkout with kubernetes/ at {repo}")
            continue
        try:
            found, unresolved, head, nfiles = scan(repo, yq)
        except RuntimeError as e:
            cannot.append(f"{label}: {e}")
            continue
        if not found:
            cannot.append(f"{label} @ {head}: {nfiles} tracked YAML files under "
                          "kubernetes/ and not one namespace in them")
            continue
        print(f"      {label} @ {head}: {nfiles} files, {len(found)} namespaces, "
              f"{unresolved} values still holding ${{VAR}} (not compared)")
        for ns, where in sorted(found.items()):
            if ns not in allowed:
                missing.append((label, ns, where))

    for label, ns, where in missing:
        print(f"FAIL  {label}: namespace '{ns}' is not in #ReservedNamespaces")
        print(f"      first seen in {where}")
    if missing:
        print("      A tenant may declare it today and be bound to tenant-admin in")
        print(f"      it. Add it to #ReservedNamespaces in {SCHEMA.relative_to(ROOT)}.")
    for line in cannot:
        print(f"?     cannot tell: {line}")
    if missing:
        return 1
    if cannot:
        return 2
    print(f"ok    every namespace in jg-base and jg-extras is among the "
          f"{len(allowed)} reserved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
