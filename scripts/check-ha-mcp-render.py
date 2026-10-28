#!/usr/bin/env python3
"""ha_im_token renders HA_MCP_URL and Secret ha-im-token, derived from the ha_app tenant or the HA extra; nothing else moves.

jgct#237 (fleet-ops im-home-automation 3.1/3.2; jg-base#221/#232). On real
makejinja renders of the fixtures check-tenant-render.py maintains:

1. **No HA, no change**: no fixture renders HA_MCP_URL, the ha-mcp directory
   or Kustomization claude-code-ha-mcp-secret -- nor does a vendor tenant
   without ha_app, or the default/home-assistant extra without a token. With
   `--against <ref>` each is byte-identical to the template at <ref> (not in
   CI, for check-tenant-render.py's reason).
2. **ha_app without a token changes nothing**: the HA tenant's render equals
   the same tenant without `ha_app`, file for file -- the first render, before
   HA has minted a token, must be the quiet one.
3. **A token, for each of the two HA sources** (an ha_app tenant; the extra on
   a cluster with no app_repos at all, so no tenants directory): HA_MCP_URL is
   `https://<ha_app>.<tenant>.<domain>/api/mcp` or `https://ha.<domain>/api/mcp`;
   Kustomization claude-code-ha-mcp-secret applies ./kubernetes/ha-mcp with
   sops after cluster-apps-base; that directory's kustomization lists
   ha-im-token.sops.yaml; Secret ha-im-token is in `claudecode` with exactly
   `token`, carrying the fixture's value; the token is in no other file; and
   nothing outside cluster-secrets, ks.yaml and the two new files differs
   from the token-less render.
4. **Refusals**, each with its own token and no credential in the message:
   a token with no HA, a token with both an ha_app tenant and the extra, a
   token on two lines. cue vet refuses a bad label and two ha_app tenants,
   and accepts the good scenario.

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
_spec = importlib.util.spec_from_file_location("tr", ROOT / "scripts" / "check-tenant-render.py")
tr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tr)

CS = tr.CS
KS = tr.KS
SECRET = "kubernetes/ha-mcp/ha-im-token.sops.yaml"
HKZ = "kubernetes/ha-mcp/kustomization.yaml"
KS_NAME = "claude-code-ha-mcp-secret"
TOKEN = "placeholder-ha-im-token"
HA = dict(name="homeauto", repository="fixture/home-automation", kind="vendor")
EXTRA = "default/home-assistant"
WANT_TENANT_URL = "https://ha.homeauto.{domain}/api/mcp"
WANT_EXTRA_URL = "https://ha.{domain}/api/mcp"


def cs_data(files: dict[str, bytes]) -> dict:
    for d in tr.docs(files[CS]):
        if tr.ident(d) == ("Secret", "cluster-secrets"):
            return d.get("stringData") or {}
    return {}


def scenario(base: dict, ha_app: bool, token: bool, **extra) -> dict:
    repo = dict(HA, ha_app="ha") if ha_app else dict(HA)
    f = dict(base, app_repos=[repo], **extra)
    if token:
        f["ha_im_token"] = TOKEN
    return f


def with_extra(base: dict, token: bool) -> dict:
    f = dict(base, extras=list(base.get("extras") or []) + [EXTRA])
    f.pop("app_repos", None)
    if token:
        f["ha_im_token"] = TOKEN
    return f


def ha_ks(files: dict[str, bytes]) -> dict | None:
    return {tr.ident(d): d for d in tr.docs(files.get(KS, b""))}.get(("Kustomization", KS_NAME))


def check_token(label: str, quiet: dict[str, bytes], files: dict[str, bytes], want: str) -> list[str]:
    bad = []
    url = cs_data(files).get("HA_MCP_URL")
    if url != want:
        bad.append(f"[{label}] HA_MCP_URL {url!r}, expected {want!r}")
    ks = ha_ks(files)
    if ks is None:
        bad.append(f"[{label}] no Kustomization {KS_NAME} -- nothing would apply the Secret")
    else:
        spec = ks.get("spec") or {}
        if spec.get("path") != "./kubernetes/ha-mcp":
            bad.append(f"[{label}] {KS_NAME} path {spec.get('path')!r}")
        if (spec.get("decryption") or {}).get("provider") != "sops":
            bad.append(f"[{label}] {KS_NAME} does not decrypt with sops")
        if [d.get("name") for d in spec.get("dependsOn") or []] != ["cluster-apps-base"]:
            bad.append(f"[{label}] {KS_NAME} does not depend on cluster-apps-base alone")
    listed = next((d.get("resources") or [] for d in tr.docs(files.get(HKZ, b""))), [])
    if listed != ["ha-im-token.sops.yaml"]:
        bad.append(f"[{label}] {HKZ} lists {listed}, expected ['ha-im-token.sops.yaml']")
    sec = {tr.ident(d): d for d in tr.docs(files.get(SECRET, b""))}.get(("Secret", "ha-im-token"))
    if sec is None:
        bad.append(f"[{label}] Secret ha-im-token not rendered in {SECRET}")
    else:
        if sec.get("metadata", {}).get("namespace") != "claudecode":
            bad.append(f"[{label}] Secret ha-im-token not in claudecode")
        sd = sec.get("stringData") or {}
        if sorted(sd) != ["token"]:
            bad.append(f"[{label}] Secret ha-im-token keys {sorted(sd)}, expected ['token']")
        elif sd["token"] != TOKEN:
            bad.append(f"[{label}] Secret ha-im-token does not carry the fixture's token")
    elsewhere = sorted(n for n, b in files.items() if n != SECRET and TOKEN.encode() in b)
    if elsewhere:
        bad.append(f"[{label}] the token is also in {elsewhere}")
    allowed = {f"differs: {CS}", f"differs: {KS}", f"only in second: {SECRET}", f"only in second: {HKZ}"}
    stray = [d for d in tr.diff_names(quiet, files) if d not in allowed]
    if stray:
        bad.append(f"[{label}] the token changed more than its four files: {stray}")
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
        with tempfile.TemporaryDirectory(prefix="ha-mcp-render.") as tmp:
            key = Path(tmp) / "age.key"
            subprocess.run([tr.tool("age-keygen"), "-o", str(key)], capture_output=True, check=True)
            ref_tree = None
            if args.against:
                ref_tree = Path(tmp) / "ref"
                ref_tree.mkdir()
                tr.checkout(args.against, ref_tree)

            def render(f):
                return tr.render(args.tree, f, [], key)

            # 1. no HA (the four fixtures, and a vendor tenant without ha_app)
            population = [(n, f, nodes) for n, f, nodes in tr.FIXTURES]
            population.append(("tenant-no-ha", scenario(base, False, False), []))
            population.append(("extra-no-token", with_extra(base, False), []))
            for name, fixture, nodes in population:
                try:
                    files = tr.render(args.tree, fixture, nodes, key)
                    before = tr.render(ref_tree, fixture, nodes, key) if ref_tree else None
                except RuntimeError as e:
                    failures.append(f"[{name}] render failed: {e}")
                    continue
                bad = []
                if "HA_MCP_URL" in cs_data(files):
                    bad.append(f"[{name}] no HA, yet cluster-secrets has HA_MCP_URL")
                if SECRET in files or HKZ in files:
                    bad.append(f"[{name}] no HA, yet kubernetes/ha-mcp rendered")
                if ha_ks(files) is not None:
                    bad.append(f"[{name}] no HA, yet Kustomization {KS_NAME} rendered")
                if before is not None:
                    bad += [f"[{name}] differs from {args.against}: {d}"
                            for d in tr.diff_names(before, files)]
                failures += bad
                if not bad:
                    print(f"ok  [{name}] no HA_MCP_URL, no ha-mcp directory, no {KS_NAME}"
                          + (f"; byte-identical to {args.against}" if before is not None else ""))

            # 2. ha_app alone is quiet
            plain = render(scenario(base, False, False))
            quiet = render(scenario(base, True, False))
            diff = tr.diff_names(plain, quiet)
            if diff:
                failures.append(f"[ha-app-no-token] ha_app without a token changed the render: {diff}")
            else:
                print("ok  [ha-app-no-token] ha_app without a token renders exactly what the tenant renders without it")

            # 3. a token, for each HA source
            domain = base["cloudflare_domain"]
            for label, quiet_f, files_f, want in (
                ("ha-tenant", scenario(base, True, False), scenario(base, True, True),
                 WANT_TENANT_URL.format(domain=domain)),
                ("ha-extra", with_extra(base, False), with_extra(base, True),
                 WANT_EXTRA_URL.format(domain=domain)),
            ):
                files = render(files_f)
                bad = check_token(label, render(quiet_f), files, want)
                if label == "ha-extra" and any(n.startswith("kubernetes/tenants/") for n in files):
                    bad.append("[ha-extra] the extra-only scenario rendered a tenants directory; "
                               "it no longer tests a cluster without one")
                failures += bad
                if not bad:
                    print(f"ok  [{label}] HA_MCP_URL={want}; {KS_NAME} applies ha-im-token in claudecode, "
                          "carrying the token; nothing else moved")

            # 4. refusals
            for name, fixture, token in (
                ("token-no-ha", scenario(base, False, True), "nor is the default/home-assistant extra listed"),
                ("token-both", dict(scenario(base, True, True),
                                    extras=list(base.get("extras") or []) + [EXTRA]),
                 "im takes one Home Assistant"),
                ("token-two-lines", dict(scenario(base, True, False), ha_im_token=TOKEN + "\nx"),
                 "spans more than one line"),
            ):
                try:
                    render(fixture)
                except RuntimeError as e:
                    msg = str(e)
                    if token not in msg:
                        failures.append(f"[{name}] refused, but not for its own reason "
                                        f"(no {token!r}): {msg[-200:]}")
                    elif TOKEN in msg:
                        failures.append(f"[{name}] refused, and the message carries the token")
                    else:
                        refusals += 1
                        print(f"ok  [{name}] refused: {token!r}")
                    continue
                failures.append(f"[{name}] rendered; it must be refused ({token!r})")
            two = dict(base, app_repos=[dict(HA, ha_app="ha"),
                                        dict(name="other", repository="fixture/other",
                                             kind="vendor", ha_app="ha")])
            for name, fixture, accept in (
                ("vet-ha", scenario(base, True, True), True),
                ("vet-bad-label", dict(base, app_repos=[dict(HA, ha_app="Ha.x")]), False),
                ("vet-two-ha-apps", two, False),
            ):
                problem = tr.vet(args.tree, fixture, [])
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
    print(f"PASS -- {len(tr.FIXTURES) + 2} renders without HA unchanged"
          + (f" (byte-identical to {args.against})" if args.against else "")
          + f"; ha_app alone quiet; a token renders URL, Secret and {KS_NAME} only, "
          "for the tenant and for the extra; "
          f"{refusals} refusals each for its own reason; 3 cue vet verdicts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
