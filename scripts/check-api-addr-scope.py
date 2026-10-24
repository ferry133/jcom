#!/usr/bin/env python3
"""`cluster_api_addr` is required on the talos provisioning path and nowhere else.

jgct#188. `full` + `omni` clusters were being asked for a LAN address that
nothing reads: the schema's own reason ("the API is reached through the Omni
proxy") is a fact about `provisioning_path`, and it was attached to
`deployment_profile`.

**Why a guard and not just the schema change.** The acceptance of PR #193 found
that nothing asserted the new behaviour — the existing suite proved there was no
regression, which is a different claim. It also found that the reviewer could
not build a valid `talos` fixture (their base was an omni cluster, so switching
the path hit `nodes: list.MinItems(1)` first and the real message was buried).
**So the case they could not measure is the one this file measures**, and it
carries the `nodes` list that makes it reachable.

Three outcomes: `cue` missing exits 2 (cannot measure), not 0.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = ROOT / ".taskfiles/template/resources/cluster.schema.cue"

# Fabricated values: TEST-NET-1 addresses, an `.invalid` domain, FAKE- strings.
# `cue vet` echoes values it rejects, so a fixture built from a real cluster.yaml
# would print credentials into CI output.
BASE = """\
---
deployment_profile: "full"
provisioning_path: "{path}"
storage_backend: "local-path"
db_storage_class: "local-path"
extras: []
single_node: false
accept_node_pinning: true
cluster_svc_cidr: "10.96.0.0/12"
cloudflare_domain: "fixture-not-real.invalid"
cloudflare_token: "FAKE-TOKEN-FIXTURE"
github_webhook_token: "FAKE-WEBHOOK"
repository_name: "fixture/fixture-repo"
cluster_name: "fixture"
node_cidr: "192.0.2.0/24"
cluster_gateway_addr: "192.0.2.11"
cluster_dns_gateway_addr: "192.0.2.12"
cloudflare_gateway_addr: "192.0.2.13"
{api}{nodes}"""

API_LINE = 'cluster_api_addr: "192.0.2.10"\n'
TALOS_NODES = 'nodes:\n  - name: "n1"\n    address: "192.0.2.21"\n'
OMNI_NODES = "nodes: []\n"


def fixture(path: str, with_api: bool) -> str:
    return BASE.format(
        path=path,
        api=API_LINE if with_api else "",
        nodes=TALOS_NODES if path == "talos" else OMNI_NODES,
    )


def vet(text: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as d:
        f = pathlib.Path(d) / "merged.yaml"
        f.write_text(text)
        r = subprocess.run(["cue", "vet", str(f), str(SCHEMA)],
                           capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout + r.stderr


def main() -> int:
    if shutil.which("cue") is None:
        print("huh   cue not on PATH — CANNOT MEASURE (this is not a pass)")
        return 2
    if not SCHEMA.is_file():
        print(f"huh   {SCHEMA} not found — wrong repo root?")
        return 2

    failed = False

    def case(label: str, text: str, want_ok: bool, must_name: str = "") -> None:
        nonlocal failed
        rc, out = vet(text)
        ok = rc == 0
        named = any(l.startswith(f"{must_name}:") for l in out.splitlines()) if must_name else True
        if ok == want_ok and named:
            print(f"PASS  {label}")
            return
        failed = True
        print(f"FAIL  {label}")
        print(f"        rc={rc} (wanted {'0' if want_ok else 'non-zero'})"
              + (f", message names {must_name}: {named}" if must_name else ""))
        for line in out.splitlines()[:4]:
            print(f"        | {line}")

    # The finding: omni does not need it.
    case("omni + full, no cluster_api_addr, passes", fixture("omni", False), True)
    # Positive control for that pass: the same fixture must still be rejected
    # when something else is wrong, or "passes" only means the harness is blind.
    case("omni + full, two gateways equal, is rejected",
         fixture("omni", False).replace('cluster_dns_gateway_addr: "192.0.2.12"',
                                        'cluster_dns_gateway_addr: "192.0.2.11"'),
         False)
    # The half the reviewer could not build, and the reason the fix needed the
    # three `!=cluster_api_addr` clauses moved: before #188 the message named
    # the other three fields and never the missing one.
    case("talos + full, no cluster_api_addr, is rejected AND names it",
         fixture("talos", False), False, must_name="cluster_api_addr")
    # Declaring it on omni stays allowed — every full+omni repo that exists has
    # a value there, and rejecting it would fail their next `task configure`.
    case("omni + full, cluster_api_addr declared, still passes",
         fixture("omni", True), True)
    case("talos + full, cluster_api_addr declared, passes", fixture("talos", True), True)

    print("ok — cluster_api_addr is required on talos only" if not failed
          else "5 case(s) checked, some failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
