#!/usr/bin/env python3
"""A recorded UniFi console selects im/netdev and renders its Secrets; nothing else moves.

jgct#249, the jgct half of ferry133/jg-base#222. On real makejinja renders:

1. **No console, no change**: every fixture check-tenant-render.py maintains
   renders no `kubernetes/netdev/` file, no `claude-code-netdev-secrets`
   Kustomization, none of the four netdev keys in cluster-secrets, and keeps
   claude-code-im off `im/netdev`. With `--against <ref>` each fixture's
   render is also byte-identical to the template at <ref> (not in CI, for the
   reason check-tenant-render.py gives: an unrelated change is supposed to
   move the render).
2. **Reader** (console recorded, no write fields): claude-code-im's patch
   path is `.../im/netdev`; Kustomization claude-code-netdev-secrets applies
   `./kubernetes/netdev` with sops decryption after cluster-apps-base; that
   directory's kustomization lists exactly unifi-reader, every listed file is
   rendered and nothing unlisted is; Secret unifi-reader is in `claudecode`
   with exactly `ca.crt` and `reader-key`, carrying the fixture's values;
   cluster-secrets has UNIFI_CONTROLLER_URL and none of the writer's keys.
3. **Writer** (all five write fields, and a site): the same, plus
   unifi-operator (`operator` = user and password on two lines) and
   im-fac-ticket (`token`), and IM_FAC_TICKET_REPO / NETDEV_OUTSIDE_PROBES /
   UNIFI_SITE in cluster-secrets, the probes joined by commas.
4. **Refusals**: each half-set or malformed input fails the render with ITS
   OWN reason (a distinct token per case: one red that every case shares
   cannot tell them apart), and no fixture credential appears in the message.
   cue vet refuses the formats it owns (http URL, two probes, a comma in a
   probe) and accepts both good scenarios.

The key names are this guard's copy of jg-base's contract. Whether that copy
still matches jg-base is check-netdev-contract.py's question, not this one's.

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

KS = tr.KS
CS = tr.CS
NETDEV_DIR = "kubernetes/netdev/"
NETDEV_KS = "claude-code-netdev-secrets"
IM_BASE = "./kubernetes/apps/base/claudecode/claude-code/im"

# jg-base im/netdev/netdev-mcp.yaml (checked against jg-base by
# check-netdev-contract.py).
SECRETS = {
    "unifi-reader": ["ca.crt", "reader-key"],
    "unifi-operator": ["operator"],
    "im-fac-ticket": ["token"],
}
WRITER_SECRETS = ("unifi-operator", "im-fac-ticket")
CS_READER = ("UNIFI_CONTROLLER_URL", "UNIFI_SITE")
CS_WRITER = ("IM_FAC_TICKET_REPO", "NETDEV_OUTSIDE_PROBES")

# The scenarios sit on the fixture that has the base im on: a console on an
# im/disabled cluster is refused (case auth0-off below).
BASE = "appliance-instances-auth0"
CA = ("-----BEGIN CERTIFICATE-----\nplaceholder-unifi-ca\n"
      "-----END CERTIFICATE-----\n")
READER = dict(
    unifi_controller_url="https://192.0.2.1",
    unifi_ca_cert=CA,
    unifi_reader_key="placeholder-unifi-reader",
)
PROBES = ["https://api.github.com/zen",
          "https://minio.example.invalid/minio/health/live",
          "192.0.2.53:53"]
WRITER = dict(
    READER,
    unifi_site="placeholder-site",
    unifi_operator_user="placeholder-op-user",
    unifi_operator_password="placeholder-op-pass",
    im_fac_ticket_repo="example/fac-tickets",
    im_fac_ticket_token="placeholder-fac-token",
    netdev_outside_probes=PROBES,
)
CREDENTIALS = ("placeholder-unifi-reader", "placeholder-op-user",
               "placeholder-op-pass", "placeholder-fac-token")


def drop(d: dict, *keys: str) -> dict:
    return {k: v for k, v in d.items() if k not in keys}


# (case, cluster.yaml additions over BASE, token the refusal must contain)
REFUSALS = [
    ("writer-without-reader", drop(WRITER, *READER), "no UniFi console"),
    ("reader-missing-key", drop(READER, "unifi_reader_key"), "is missing unifi_reader_key"),
    ("writer-half", drop(WRITER, "im_fac_ticket_token"), "is missing im_fac_ticket_token"),
    ("auth0-off", dict(READER, claudecode_auth0=False,
                       ttyd_credential="ops:placeholder-not-a-real-credential",
                       claude_instances=[]), "claudecode_auth0 is"),
    ("ca-not-pem", dict(READER, unifi_ca_cert="placeholder-not-pem"), "BEGIN CERTIFICATE"),
    ("key-two-lines", dict(READER, unifi_reader_key="placeholder-unifi-reader\nx"),
     "span more than one line"),
    ("probes-repeat", dict(WRITER, netdev_outside_probes=[PROBES[0], PROBES[0], PROBES[2]]),
     "exactly three DIFFERENT"),
]
# (case, additions, expected cue vet verdict: True = accepted)
VETS = [
    ("vet-reader", READER, True),
    ("vet-writer", WRITER, True),
    ("vet-http", dict(READER, unifi_controller_url="http://192.0.2.1"), False),
    ("vet-two-probes", dict(WRITER, netdev_outside_probes=PROBES[:2]), False),
    ("vet-comma-probe", dict(WRITER, netdev_outside_probes=[PROBES[0] + ",x", *PROBES[1:]]), False),
    # jgct#252: the server parses the port at import, so a non-numeric one crashloops it
    ("vet-bad-port", dict(WRITER, netdev_outside_probes=["https://host:abc/x", *PROBES[1:]]), False),
    ("vet-numeric-port", dict(WRITER, netdev_outside_probes=["https://host:9000/x", *PROBES[1:]]), True),
]


def objs(files: dict[str, bytes], path: str) -> dict[tuple[str, str], dict]:
    return {tr.ident(d): d for d in (tr.docs(files[path]) if path in files else [])}


def im_path(files: dict[str, bytes]) -> str | None:
    """spec.path of the claude-code-im patch in the root sync's patches."""
    for d in tr.docs(files[KS]):
        for p in (d.get("spec") or {}).get("patches") or []:
            if (p.get("target") or {}).get("name") != "claude-code-im":
                continue
            body = tr.yq_value(p.get("patch", ""))
            return ((body or {}).get("spec") or {}).get("path")
    return None


def cs_data(files: dict[str, bytes]) -> dict:
    for d in tr.docs(files[CS]):
        if tr.ident(d) == ("Secret", "cluster-secrets"):
            return d.get("stringData") or {}
    return {}


def check_absent(name: str, files: dict[str, bytes]) -> list[str]:
    bad = []
    stray = sorted(p for p in files if p.startswith(NETDEV_DIR))
    if stray:
        bad.append(f"[{name}] no console, yet {stray} rendered")
    if ("Kustomization", NETDEV_KS) in objs(files, KS):
        bad.append(f"[{name}] no console, yet Kustomization {NETDEV_KS} rendered")
    keys = sorted(set(cs_data(files)) & set(CS_READER + CS_WRITER))
    if keys:
        bad.append(f"[{name}] no console, yet cluster-secrets has {keys}")
    path = im_path(files)
    if path is not None and path.endswith("/netdev"):
        bad.append(f"[{name}] no console, yet claude-code-im's path is {path}")
    return bad


def check_present(name: str, files: dict[str, bytes], writer: bool, fixture: dict) -> list[str]:
    bad = []
    path = im_path(files)
    if path != f"{IM_BASE}/netdev":
        bad.append(f"[{name}] claude-code-im path {path!r}, expected {IM_BASE}/netdev")
    ks = objs(files, KS).get(("Kustomization", NETDEV_KS))
    if ks is None:
        bad.append(f"[{name}] no Kustomization {NETDEV_KS}")
    else:
        spec = ks.get("spec", {})
        want = {"path": "./kubernetes/netdev", "prune": True,
                "decryption": {"provider": "sops"},
                "sourceRef": {"kind": "GitRepository", "name": "flux-system",
                              "namespace": "flux-system"},
                "dependsOn": [{"name": "cluster-apps-base"}]}
        for k, v in want.items():
            if spec.get(k) != v:
                bad.append(f"[{name}] {NETDEV_KS} spec.{k} = {spec.get(k)!r}, expected {v!r}")
        if "postBuild" in spec:
            bad.append(f"[{name}] {NETDEV_KS} has postBuild: a credential would be substituted")
    want_secrets = [s for s in SECRETS if writer or s not in WRITER_SECRETS]
    kz_path = NETDEV_DIR + "kustomization.yaml"
    listed = []
    for d in tr.docs(files.get(kz_path, b"")):
        listed = d.get("resources") or []
    if sorted(listed) != sorted(f"{s}.sops.yaml" for s in want_secrets):
        bad.append(f"[{name}] {kz_path} lists {listed}, expected {want_secrets}")
    rendered = sorted(p[len(NETDEV_DIR):] for p in files if p.startswith(NETDEV_DIR))
    if rendered != sorted(listed + ["kustomization.yaml"]):
        bad.append(f"[{name}] {NETDEV_DIR} holds {rendered}, but the kustomization lists {listed}"
                   " -- an unlisted file is never applied, a listed missing one fails the build")
    values = {
        ("unifi-reader", "ca.crt"): fixture["unifi_ca_cert"],
        ("unifi-reader", "reader-key"): fixture["unifi_reader_key"],
        ("unifi-operator", "operator"):
            f"{fixture.get('unifi_operator_user')}\n{fixture.get('unifi_operator_password')}\n",
        ("im-fac-ticket", "token"): fixture.get("im_fac_ticket_token"),
    }
    for s in want_secrets:
        sec = objs(files, f"{NETDEV_DIR}{s}.sops.yaml").get(("Secret", s))
        if sec is None:
            bad.append(f"[{name}] Secret {s} not rendered")
            continue
        if sec.get("metadata", {}).get("namespace") != "claudecode":
            bad.append(f"[{name}] Secret {s} not in claudecode")
        sd = sec.get("stringData") or {}
        if sorted(sd) != sorted(SECRETS[s]):
            bad.append(f"[{name}] Secret {s} keys {sorted(sd)}, expected {SECRETS[s]}")
            continue
        for k in SECRETS[s]:
            if sd[k] != values[(s, k)]:
                bad.append(f"[{name}] Secret {s} key {k} does not carry the fixture's value")
    cs = cs_data(files)
    want_cs = {"UNIFI_CONTROLLER_URL": fixture["unifi_controller_url"]}
    if fixture.get("unifi_site"):
        want_cs["UNIFI_SITE"] = fixture["unifi_site"]
    if writer:
        want_cs["IM_FAC_TICKET_REPO"] = fixture["im_fac_ticket_repo"]
        want_cs["NETDEV_OUTSIDE_PROBES"] = ",".join(fixture["netdev_outside_probes"])
    got_cs = {k: cs[k] for k in CS_READER + CS_WRITER if k in cs}
    if got_cs != want_cs:
        bad.append(f"[{name}] cluster-secrets netdev keys {sorted(got_cs)} differ from "
                   f"{sorted(want_cs)} (or a value does)")
    leaked = [c for c in CREDENTIALS if c.encode() in files[CS]]
    if leaked:
        bad.append(f"[{name}] a credential is in cluster-secrets ({len(leaked)} of them)")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tree", type=Path, default=ROOT)
    ap.add_argument("--against", metavar="REF")
    args = ap.parse_args()
    failures: list[str] = []
    base = next((f for n, f, _ in tr.FIXTURES if n == BASE), None)
    try:
        if base is None:
            raise tr.CannotMeasure(f"fixture {BASE!r} is gone from check-tenant-render.py")
        with tempfile.TemporaryDirectory(prefix="netdev-render.") as tmp:
            key = Path(tmp) / "age.key"
            subprocess.run([tr.tool("age-keygen"), "-o", str(key)], capture_output=True, check=True)
            ref_tree = None
            if args.against:
                ref_tree = Path(tmp) / "ref"
                ref_tree.mkdir()
                tr.checkout(args.against, ref_tree)

            # 1. no console
            for name, fixture, nodes in tr.FIXTURES:
                try:
                    files = tr.render(args.tree, fixture, nodes, key)
                    before = tr.render(ref_tree, fixture, nodes, key) if ref_tree else None
                except RuntimeError as e:
                    failures.append(f"[{name}] render failed: {e}")
                    continue
                bad = check_absent(name, files)
                if before is not None:
                    bad += [f"[{name}] differs from {args.against}: {d}"
                            for d in tr.diff_names(before, files)]
                failures += bad
                if not bad:
                    print(f"ok  [{name}] no console: no netdev objects, im not on im/netdev"
                          + (f"; byte-identical to {args.against}" if before is not None else ""))

            # 2-3. reader, writer
            for name, add, writer in (("reader", READER, False), ("writer", WRITER, True)):
                fixture = dict(base, **add)
                try:
                    files = tr.render(args.tree, fixture, [], key)
                except RuntimeError as e:
                    failures.append(f"[{name}] render failed (guard or template defect): {e}")
                    continue
                bad = check_present(name, files, writer, fixture)
                failures += bad
                if not bad:
                    print(f"ok  [{name}] im/netdev, {NETDEV_KS} after cluster-apps-base, "
                          f"Secrets {[s for s in SECRETS if writer or s not in WRITER_SECRETS]} "
                          "with the fixture's values, cluster-secrets keys as expected")

            # 4. refusals, each with its own reason
            for name, add, token in REFUSALS:
                fixture = dict(base, **add)
                try:
                    tr.render(args.tree, fixture, [], key)
                except RuntimeError as e:
                    msg = str(e)
                    if token not in msg:
                        failures.append(f"[{name}] refused, but not for its own reason "
                                        f"(no {token!r} in the message): {msg[-200:]}")
                    elif any(c in msg for c in CREDENTIALS):
                        failures.append(f"[{name}] refused, and the message carries a credential")
                    else:
                        print(f"ok  [{name}] refused: {token!r}")
                    continue
                failures.append(f"[{name}] rendered; it must be refused ({token!r})")
            for name, add, accept in VETS:
                problem = tr.vet(args.tree, dict(base, **add), [])
                if (problem is None) != accept:
                    failures.append(f"[{name}] cue vet {'refused' if problem else 'accepted'} it, "
                                    f"expected {'accept' if accept else 'refuse'}"
                                    + (f": {problem}" if problem else ""))
                else:
                    print(f"ok  [{name}] cue vet {'accepts' if accept else 'refuses'}")
    except tr.CannotMeasure as e:
        if failures:
            print("\n".join("FAIL " + f for f in failures))
            return 1
        print(f"COULD NOT MEASURE: {e}")
        return 2
    if failures:
        print("\n".join("FAIL " + f for f in failures))
        return 1
    print(f"PASS -- {len(tr.FIXTURES)} fixtures without a console unchanged"
          + (f" (byte-identical to {args.against})" if args.against else "")
          + f"; reader and writer render im/netdev and their Secrets; "
          f"{len(REFUSALS)} refusals each for its own reason; {len(VETS)} cue vet verdicts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
