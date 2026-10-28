#!/usr/bin/env python3
"""What `cluster.schema.cue` accepts and refuses under `app_repos`.

jgct#214 task 3.1 (fleet-ops root `standalone-app-repos`, spec requirement
"cluster.yaml declares app repos"). The schema is the first of the tenant
boundaries the root relies on: an entry that gets past it is rendered, and the
render is what Flux applies with a ServiceAccount bound into those namespaces.
So each refusal below is asserted, and each refusal that the spec says must
NAME something (the unknown field, the namespace) is asserted to name it —
a rejection for some other reason reads exactly like the right one.

Cell 0 is the unmutated fixture and must pass; without it a broken harness
(no schema, a fixture the schema rejects for an unrelated reason) would make
every refusal below look caught.

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
# would print credentials into CI output. Same base as check-api-addr-scope.py.
BASE = """\
---
deployment_profile: "full"
provisioning_path: "omni"
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
nodes: []
"""

VENDOR = """\
  - name: "acme"
    repository: "fixture/acme-app"
    kind: "vendor"
"""

AGENT_FULL = """\
  - name: "im-apps"
    repository: "fixture/im-apps"
    kind: "agent"
    namespaces: ["im-apps", "im-apps-db"]
    branch: "main"
    quota: {cpu: "2", memory: "4Gi", pods: 20}
    grants: {baseline: true, lan_ip: 2}
    lan_ip_range: {start: "192.0.2.200", stop: "192.0.2.201"}
"""


def with_repos(entries: str) -> str:
    return BASE + "app_repos:\n" + entries


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

    results: list[bool] = []

    def case(label: str, text: str, want_ok: bool, must_name: str = "") -> None:
        rc, out = vet(text)
        ok = rc == 0
        named = must_name in out if must_name else True
        good = ok == want_ok and named
        results.append(good)
        if good:
            print(f"PASS  {label}")
            return
        print(f"FAIL  {label}")
        print(f"        rc={rc} (wanted {'0' if want_ok else 'non-zero'})"
              + (f", output contains {must_name!r}: {named}" if must_name else ""))
        for line in out.splitlines()[:6]:
            print(f"        | {line}")

    # 0: the harness itself. Everything after this is a mutation of BASE.
    case("0  no app_repos, passes", BASE, True)
    case("   app_repos: [], passes", BASE + "app_repos: []\n", True)
    case("   one minimal vendor entry, passes", with_repos(VENDOR), True)
    case("   vendor + fully-specified agent, passes",
         with_repos(VENDOR + AGENT_FULL), True)
    case("   lan_ip: 0 without a range, passes",
         with_repos(VENDOR + '    grants: {lan_ip: 0}\n'), True)

    # The spec's scenarios, by name. `must_name` is the CUE path (and, where the
    # spec says the message names a value, that value): a bare word like
    # "namespace" would also match "namespaces" and every unrelated message.
    case("pod_security is refused AND named (the level is derived)",
         with_repos(VENDOR + '    pod_security: "privileged"\n'),
         False, must_name="app_repos.0.pod_security: field not allowed")
    case("two entries claiming one namespace are refused",
         with_repos(VENDOR + AGENT_FULL.replace('["im-apps", "im-apps-db"]',
                                                '["im-apps", "acme"]')),
         False, must_name='_app_repos_check.namespaces: invalid value ["acme","im-apps","acme"]')

    # The rest of the boundary.
    case("duplicate name is refused",
         with_repos(VENDOR + VENDOR.replace("acme-app", "other-app")
                    .replace('kind: "vendor"', 'kind: "vendor"\n    namespaces: ["other"]')),
         False, must_name="_app_repos_check.name:")
    case("a second agent is refused (one im-apps-write-key, one IM_APPS_REPO)",
         with_repos(AGENT_FULL + AGENT_FULL.replace('["im-apps", "im-apps-db"]',
                                                    '["till", "till-db"]')
                    .replace("fixture/im-apps", "fixture/till")),
         False, must_name="_app_repos_check.agents:")
    # Root task 3.11: im's own instructions name `tenant-im-apps`.
    case("an agent not named im-apps is refused, naming the required name",
         with_repos(AGENT_FULL.replace('name: "im-apps"', 'name: "shop"')),
         False, must_name='app_repos.0.name: conflicting values "im-apps" and "shop"')
    case("a vendor named anything else still passes (the rule is agent-only)",
         with_repos(VENDOR.replace('"acme"', '"shop"')), True)
    case("lan_ip > 0 without lan_ip_range is refused AND names it",
         with_repos(VENDOR + '    grants: {lan_ip: 1}\n'),
         False, must_name="app_repos.0.lan_ip_range: field is required")
    # grants.l2 (jg-base#187): the range is required with the grant, the
    # interface is a Linux name, and lan_routed_cidrs takes CIDRs only.
    L2 = '    grants: {l2: true}\n    l2_network: {interface: "enp1s0", start: "192.0.2.20", stop: "192.0.2.21"}\n'
    case("l2 with l2_network and lan_routed_cidrs passes",
         BASE + 'lan_routed_cidrs: ["198.51.100.0/24"]\napp_repos:\n' + VENDOR + L2, True)
    case("l2 without l2_network is refused AND names it",
         with_repos(VENDOR + '    grants: {l2: true}\n'),
         False, must_name="app_repos.0.l2_network: field is required")
    case("l2: false without l2_network passes",
         with_repos(VENDOR + '    grants: {l2: false}\n'), True)
    case("an interface name with a quote is refused (it lands in CNI JSON)",
         with_repos(VENDOR + L2.replace('"enp1s0"', '"en\'p1"')),
         False, must_name="app_repos.0.l2_network.interface: invalid value")
    case("an interface name longer than 15 characters is refused",
         with_repos(VENDOR + L2.replace('"enp1s0"', '"enp1s0enp1s0enp1"')),
         False, must_name="app_repos.0.l2_network.interface: invalid value")
    case("a non-CIDR lan_routed_cidrs entry is refused",
         BASE + 'lan_routed_cidrs: ["198.51.100.1"]\napp_repos: []\n',
         False, must_name="lan_routed_cidrs.0")
    # grants.public (jgct#250): a bool, nothing required beside it.
    case("public: true passes",
         with_repos(VENDOR + '    grants: {public: true}\n'), True)
    case("public as a string is refused AND names it",
         with_repos(VENDOR + '    grants: {public: "yes"}\n'),
         False, must_name="app_repos.0.grants.public")
    # grants.devices (jg-base#188): class -> positive count.
    case("devices {serial: 1} passes",
         with_repos(VENDOR + '    grants: {devices: {serial: 1}}\n'), True)
    case("devices as the old list shape is refused",
         with_repos(VENDOR + '    grants: {devices: ["/dev/ttyUSB0"]}\n'),
         False, must_name="app_repos.0.grants.devices")
    case("a device count of 0 is refused (leave the class out instead)",
         with_repos(VENDOR + '    grants: {devices: {serial: 0}}\n'),
         False, must_name="app_repos.0.grants.devices.serial")
    case("a reserved namespace is refused AND named",
         with_repos(VENDOR + '    namespaces: ["acme", "claudecode"]\n'),
         False, must_name='invalid value "claudecode"')
    case("a reserved name (default namespace) is refused",
         with_repos(VENDOR.replace('"acme"', '"flux-system"')),
         False, must_name='app_repos.0.name: invalid value "flux-system"')
    case("an unknown kind is refused",
         with_repos(VENDOR.replace('"vendor"', '"partner"')),
         False, must_name="app_repos.0.kind:")
    case("repository without owner/ is refused",
         with_repos(VENDOR.replace("fixture/acme-app", "acme-app")),
         False, must_name="app_repos.0.repository: invalid value")
    case("a non-DNS-label name is refused",
         with_repos(VENDOR.replace('"acme"', '"Acme_1"')),
         False, must_name='app_repos.0.name: invalid value "Acme_1"')
    case("a negative lan_ip is refused",
         with_repos(VENDOR + '    grants: {lan_ip: -1}\n'),
         False, must_name="app_repos.0.grants.lan_ip: invalid value -1")
    case("an unknown grant is refused AND named",
         with_repos(VENDOR + '    grants: {privileged: true}\n'),
         False, must_name="app_repos.0.grants.privileged: field not allowed")
    case("an unknown entry field (typo) is refused AND named",
         with_repos(VENDOR + '    namespace: ["acme"]\n'),
         False, must_name="app_repos.0.namespace: field not allowed")
    case("an empty namespaces list is refused",
         with_repos(VENDOR + '    namespaces: []\n'),
         False, must_name="app_repos.0.namespaces:")

    passed = sum(results)
    print(f"ok — {passed}/{len(results)} app_repos schema cases as expected"
          if all(results) else
          f"{len(results) - passed}/{len(results)} app_repos schema case(s) FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
