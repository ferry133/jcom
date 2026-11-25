#!/usr/bin/env python3
"""registry_pull_secrets renders one dockerconfigjson Secret per namespace and its Kustomization; nothing else moves.

jgct#272 (first use: jg-extras#23, the private ghcr.io/ferry133/freepbx). On
real makejinja renders of the fixtures check-tenant-render.py maintains:

1. **Absent, no change**: no fixture renders the registry-pull directory or
   Kustomization registry-pull-secrets; an empty list renders what an absent
   field renders. With `--against <ref>` each is byte-identical to the
   template at <ref> (not in CI, for check-tenant-render.py's reason).
2. **Two entries, three Secrets**: one entry with two namespaces and one with
   one. Each Secret has type kubernetes.io/dockerconfigjson and exactly the
   key `.dockerconfigjson`; that value parses as JSON whose only registry is
   the entry's, whose username and password are the entry's, and whose `auth`
   decodes to `username:token`. Kustomization registry-pull-secrets applies
   ./kubernetes/registry-pull with sops after cluster-apps-base; the
   directory's kustomization lists the one file; neither token is in any
   other file; nothing outside ks.yaml and the two new files differs from the
   render without the field.
3. **Refusals**, each for its own reason and with no token or username in the
   message: the same Secret twice in one namespace, a token with whitespace in
   it, a username with a colon. cue vet refuses a registry with a scheme, a
   bad Secret name and an empty namespace list, and accepts the good scenario.

What this does not measure: sops encrypting the file, Flux applying it, and a
kubelet pulling with the result.

Exit 0 pass, 1 fail, 2 could not measure. A failure wins.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("tr", ROOT / "scripts" / "check-tenant-render.py")
tr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tr)

KS = tr.KS
SECRET = "kubernetes/registry-pull/registry-pull.sops.yaml"
KZ = "kubernetes/registry-pull/kustomization.yaml"
KS_NAME = "registry-pull-secrets"
TOKEN_A = "placeholder-pull-token-a"
TOKEN_B = "placeholder-pull-token-b"
USER_A = "fixture-user-a"
USER_B = "fixture-user-b"
A = dict(name="ghcr-pull", registry="ghcr.io", username=USER_A, token=TOKEN_A,
         namespaces=["freepbx", "default"])
B = dict(name="other-pull", registry="registry.example:5000", username=USER_B,
         token=TOKEN_B, namespaces=["default"])
SENSITIVE = (TOKEN_A, TOKEN_B, USER_A, USER_B)


def pull_ks(files: dict[str, bytes]) -> dict | None:
    return {tr.ident(d): d for d in tr.docs(files.get(KS, b""))}.get(("Kustomization", KS_NAME))


def check_rendered(quiet: dict[str, bytes], files: dict[str, bytes]) -> list[str]:
    bad = []
    ks = pull_ks(files)
    if ks is None:
        bad.append(f"no Kustomization {KS_NAME} -- nothing would apply the Secrets")
    else:
        spec = ks.get("spec") or {}
        if spec.get("path") != "./kubernetes/registry-pull":
            bad.append(f"{KS_NAME} path {spec.get('path')!r}")
        if (spec.get("decryption") or {}).get("provider") != "sops":
            bad.append(f"{KS_NAME} does not decrypt with sops")
        if [d.get("name") for d in spec.get("dependsOn") or []] != ["cluster-apps-base"]:
            bad.append(f"{KS_NAME} does not depend on cluster-apps-base alone")
        if spec.get("postBuild"):
            bad.append(f"{KS_NAME} has postBuild: a `$` in a token would be substituted")
    listed = next((d.get("resources") or [] for d in tr.docs(files.get(KZ, b""))), [])
    if listed != ["registry-pull.sops.yaml"]:
        bad.append(f"{KZ} lists {listed}, expected ['registry-pull.sops.yaml']")
    secrets = [d for d in tr.docs(files.get(SECRET, b"")) if d.get("kind") == "Secret"]
    got = sorted((d["metadata"]["name"], d["metadata"].get("namespace")) for d in secrets)
    want = sorted([(e["name"], ns) for e in (A, B) for ns in e["namespaces"]])
    if got != want:
        bad.append(f"Secrets rendered {got}, expected {want}")
    by_name = {A["name"]: A, B["name"]: B}
    for d in secrets:
        who = f"Secret {d['metadata']['name']} in {d['metadata'].get('namespace')}"
        entry = by_name.get(d["metadata"]["name"])
        if entry is None:
            continue
        if d.get("type") != "kubernetes.io/dockerconfigjson":
            bad.append(f"{who}: type {d.get('type')!r}")
        sd = d.get("stringData") or {}
        if sorted(sd) != [".dockerconfigjson"]:
            bad.append(f"{who}: keys {sorted(sd)}, expected ['.dockerconfigjson']")
            continue
        try:
            auths = json.loads(sd[".dockerconfigjson"])["auths"]
        except (ValueError, KeyError, TypeError):
            bad.append(f"{who}: .dockerconfigjson is not JSON with an `auths` object")
            continue
        if sorted(auths) != [entry["registry"]]:
            bad.append(f"{who}: registries {sorted(auths)}, expected [{entry['registry']!r}]")
            continue
        a = auths[entry["registry"]]
        if a.get("username") != entry["username"] or a.get("password") != entry["token"]:
            bad.append(f"{who}: username or password is not the entry's")
        try:
            decoded = base64.b64decode(a.get("auth", ""), validate=True).decode()
        except ValueError:
            decoded = None
        if decoded != f"{entry['username']}:{entry['token']}":
            bad.append(f"{who}: `auth` does not decode to the entry's username:token")
    for tok in (TOKEN_A, TOKEN_B):
        elsewhere = sorted(n for n, b in files.items() if n != SECRET and tok.encode() in b)
        if elsewhere:
            bad.append(f"a token is also in {elsewhere}")
    allowed = {f"differs: {KS}", f"only in second: {SECRET}", f"only in second: {KZ}"}
    stray = [d for d in tr.diff_names(quiet, files) if d not in allowed]
    if stray:
        bad.append(f"the field changed more than its three files: {stray}")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tree", type=Path, default=ROOT)
    ap.add_argument("--against", metavar="REF")
    args = ap.parse_args()
    failures: list[str] = []
    base = next((f for n, f, _ in tr.FIXTURES if n == tr.TENANT_BASE), None)
    refusals = 0
    try:
        if base is None:
            raise tr.CannotMeasure(f"fixture {tr.TENANT_BASE!r} is gone from check-tenant-render.py")
        with tempfile.TemporaryDirectory(prefix="registry-pull-render.") as tmp:
            key = Path(tmp) / "age.key"
            subprocess.run([tr.tool("age-keygen"), "-o", str(key)], capture_output=True, check=True)
            ref_tree = None
            if args.against:
                ref_tree = Path(tmp) / "ref"
                ref_tree.mkdir()
                tr.checkout(args.against, ref_tree)

            def render(f):
                return tr.render(args.tree, f, [], key)

            # 1. absent (every fixture), and an empty list
            for name, fixture, nodes in tr.FIXTURES:
                try:
                    files = tr.render(args.tree, fixture, nodes, key)
                    before = tr.render(ref_tree, fixture, nodes, key) if ref_tree else None
                except RuntimeError as e:
                    failures.append(f"[{name}] render failed: {e}")
                    continue
                bad = []
                if SECRET in files or KZ in files:
                    bad.append(f"[{name}] no registry_pull_secrets, yet kubernetes/registry-pull rendered")
                if pull_ks(files) is not None:
                    bad.append(f"[{name}] no registry_pull_secrets, yet Kustomization {KS_NAME} rendered")
                if before is not None:
                    bad += [f"[{name}] differs from {args.against}: {d}"
                            for d in tr.diff_names(before, files)]
                failures += bad
                if not bad:
                    print(f"ok  [{name}] no registry-pull directory, no {KS_NAME}"
                          + (f"; byte-identical to {args.against}" if before is not None else ""))
            quiet = render(base)
            diff = tr.diff_names(quiet, render(dict(base, registry_pull_secrets=[])))
            if diff:
                failures.append(f"[empty-list] an empty list changed the render: {diff}")
            else:
                print("ok  [empty-list] an empty list renders what an absent field renders")

            # 2. two entries, three Secrets
            files = render(dict(base, registry_pull_secrets=[A, B]))
            bad = [f"[two-entries] {b}" for b in check_rendered(quiet, files)]
            failures += bad
            if not bad:
                print(f"ok  [two-entries] 3 Secrets of type dockerconfigjson, each `auth` decodes to its "
                      f"entry's username:token; {KS_NAME} applies them; nothing else moved")

            # 3. refusals
            for name, entries, reason in (
                ("same-secret-twice", [A, dict(B, name=A["name"])], "is declared twice"),
                ("token-with-space", [dict(A, token=TOKEN_A + " x")], "token must be one token"),
                ("username-with-colon", [dict(A, username=USER_A + ":x")], "without a colon"),
            ):
                try:
                    render(dict(base, registry_pull_secrets=entries))
                except RuntimeError as e:
                    msg = str(e)
                    leaked = [s for s in SENSITIVE if s in msg]
                    if reason not in msg:
                        failures.append(f"[{name}] refused, but not for its own reason "
                                        f"(no {reason!r}): {msg[-200:]}")
                    elif leaked:
                        failures.append(f"[{name}] refused, and the message carries a token or username")
                    else:
                        refusals += 1
                        print(f"ok  [{name}] refused: {reason!r}")
                    continue
                failures.append(f"[{name}] rendered; it must be refused ({reason!r})")
            for name, entries, accept in (
                ("vet-good", [A, B], True),
                ("vet-registry-with-scheme", [dict(A, registry="https://ghcr.io")], False),
                ("vet-bad-secret-name", [dict(A, name="Ghcr_Pull")], False),
                ("vet-no-namespace", [dict(A, namespaces=[])], False),
            ):
                problem = tr.vet(args.tree, dict(base, registry_pull_secrets=entries), [])
                if (problem is None) != accept:
                    failures.append(f"[{name}] cue vet {'refused' if problem else 'accepted'} it"
                                    + (f": {problem}" if problem else ""))
                else:
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
    print(f"PASS -- {len(tr.FIXTURES)} renders without the field unchanged"
          + (f" (byte-identical to {args.against})" if args.against else "")
          + f"; an empty list is quiet; two entries render 3 Secrets and {KS_NAME} only; "
          f"{refusals} refusals each for its own reason; 4 cue vet verdicts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
