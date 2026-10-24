#!/usr/bin/env python3
"""A cluster without `app_repos` renders exactly as it did before tenants existed.

fleet-ops `standalone-app-repos` (jgct#214) adds tenants to this template: a
schema field, plugin derivations, a loop in `ks.yaml.j2`, a new
`kubernetes/tenants/` tree. Every cluster in the fleet today has no tenants, and
every one of them would be re-rendered by the next `task configure`. So the
first thing that has to hold -- before any tenant object is right -- is that the
tenant code is invisible to a cluster that does not use it.

That is asserted two ways, because the useful one cannot run in CI:

1. **Always (CI):** for each fixture, the render with `app_repos` absent is
   byte-identical to the render with `app_repos: []`, and neither contains a
   tenant object (a `kubernetes/tenants/` path, a Kustomization named
   `cluster-tenants` or `tenant-*`, or a `jg.tenant` label). This survives
   every future PR, because it compares the template with itself.

2. **On demand (`--against <ref>`):** each fixture rendered with the template
   at `<ref>` and with this tree, compared byte for byte. That is the real
   "nothing changed for existing clusters" reading, and every jgct#214 PR
   pastes it. It is NOT in CI: an unrelated template change is *supposed* to
   change the render, and a guard that fires on correct input gets switched off.

3. **Always (CI), from task 3.3:** one fixture rendered WITH two tenants
   (a vendor and a multi-namespace agent), and the Flux objects in `ks.yaml`
   asserted field by field: one `cluster-tenants`; per tenant a ServiceAccount,
   a GitRepository on its own deploy key, and a Kustomization that runs as
   `tenant-<name>`, decrypts with `tenant-<name>-sops-age` and has **no**
   `postBuild` (cluster-secrets is every credential the cluster has). Every
   other document in `ks.yaml` and every other file must equal the tenant-free
   render, so adding a tenant cannot change anything that is not the tenant.
   No ClusterRoleBinding anywhere may name a tenant ServiceAccount. Without
   this part, "identical when absent" would also be what a tenant loop that
   never renders looks like. Three scenarios (root task 3.7): the main one
   (a vendor, the `im-apps` agent with two namespaces and a LAN grant, a
   host_network vendor), vendors only (no agent object may appear), and the
   commented example in cluster.sample.yaml — operators copy it, so it must
   pass cue vet and render. Every tenant's known_hosts must equal the root
   sync's (bootstrap/github-deploy-key), so a host-key rotation cannot update
   one copy.

The fixtures are four complete, `cue vet`-valid inputs chosen to walk different
branches (profile, provisioning path, storage, extras, claude instances, auth0,
repository visibility). A fixture that fails `cue vet` is a defect in this
guard, not in the template -- it would be testing a cluster nobody can render
(`~/.claude/CLAUDE.md`: a fixture can invent a value a cluster cannot produce).
Addresses are RFC 5737 documentation ranges: this repo is public.

Each render runs the real makejinja on a private copy of the template inputs,
with placeholder credential files and a throwaway age key generated per run.
Nothing is written outside a temporary directory.

Exit 0 pass, 1 fail, 2 could not measure (a tool is missing). A failure wins
over "could not measure": a red result found before a tool went missing is
still red.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent

# What a render reads from the repo. Everything else (scripts/, .github/, docs)
# cannot affect the output, so it is not copied.
TEMPLATE_INPUTS = ["templates", "makejinja.toml", "trello-notifier.sample.yaml"]
SCHEMA = ".taskfiles/template/resources/cluster.schema.cue"

_COMMON = dict(
    storage_backend="nfs",
    node_cidr="192.0.2.0/24",
    cluster_svc_cidr="10.96.0.0/12",
    cloudflare_domain="example.com",
    cloudflare_token="placeholder-not-a-real-token",
    repository_name="example/rendertest",
    cluster_name="rendertest",
)

# An appliance is local-path only and must declare its off-site backup and
# that its age key is escrowed (schema, `deployment_profile == "appliance"`).
_APPLIANCE = dict(
    deployment_profile="appliance",
    provisioning_path="omni",
    storage_backend="local-path",
    age_key_escrowed=True,
    backup_r2_bucket="placeholder",
    backup_r2_endpoint="https://example.invalid",
    backup_r2_access_key_id="placeholder",
    backup_r2_secret_access_key="placeholder",
)

_TALOS_NODES = [
    dict(name=f"node-{i}", address=f"192.0.2.{10 + i}", controller=True,
         disk="/dev/sda", mac_addr=f"02:00:00:00:00:0{i}",
         schematic_id="0" * 64)
    for i in (1, 2, 3)
]

# (name, cluster.yaml, nodes)
FIXTURES: list[tuple[str, dict, list]] = [
    ("appliance-minimal", dict(
        _COMMON, **_APPLIANCE,
        claudecode_auth0=False,
        ttyd_credential="ops:placeholder-not-a-real-credential",
    ), []),
    ("appliance-instances-auth0", dict(
        _COMMON, **_APPLIANCE,
        claude_instances=["cc"],
        claudecode_auth0_domain="example.invalid",
        claudecode_auth0_client_id="placeholder",
        claudecode_auth0_client_secret="placeholder",
        claudecode_allowed_emails="ops@example.invalid",
        extras=["default/postgres"],
    ), []),
    ("full-talos-private", dict(
        _COMMON,
        deployment_profile="full",
        provisioning_path="talos",
        storage_backend="replicated",
        repository_visibility="private",
        accept_node_pinning=True,
        cluster_api_addr="192.0.2.100",
        cluster_gateway_addr="192.0.2.101",
        cluster_dns_gateway_addr="192.0.2.102",
        cloudflare_gateway_addr="192.0.2.103",
        claudecode_auth0=False,
        ttyd_credential="ops:placeholder-not-a-real-credential",
        extras=["default/postgres", "default/mqtt"],
    ), _TALOS_NODES),
    ("full-omni-extras", dict(
        _COMMON,
        deployment_profile="full",
        provisioning_path="omni",
        cluster_api_addr="192.0.2.100",
        cluster_gateway_addr="192.0.2.101",
        cluster_dns_gateway_addr="192.0.2.102",
        cloudflare_gateway_addr="192.0.2.103",
        nas_server="192.0.2.50",
        nas_path="/volume1/placeholder",
        accept_node_pinning=True,
        claudecode_auth0=False,
        ttyd_credential="ops:placeholder-not-a-real-credential",
        extras=["default/postgres", "default/mariadb", "freepbx/freepbx"],
    ), []),
]

_PLACEHOLDERS = {
    "cloudflare-tunnel.json": json.dumps({
        "AccountTag": "placeholder", "TunnelSecret": "cGxhY2Vob2xkZXI=",
        "TunnelID": "00000000-0000-0000-0000-000000000000"}),
    "github-deploy.key": "placeholder-not-a-key\n",
    # jg-extras deploy key (jgct#217): carries only the marker line
    # plugin.py's extras_deploy_key() checks for. Never a real key.
    "jg-extras.deploy.key": "-----BEGIN OPENSSH PRIVATE KEY-----\nplaceholder-jg-extras-ro\n"
                            "-----END OPENSSH PRIVATE KEY-----\n",
    "github-push-token.txt": "placeholder-not-a-token\n",
    "auth0.json": json.dumps({
        "domain": "example.invalid", "client_id": "placeholder",
        "client_secret": "placeholder", "allowed_emails": ["ops@example.invalid"]}),
}


class CannotMeasure(Exception):
    pass


def tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise CannotMeasure(f"`{name}` not on PATH (run under `mise exec --`)")
    return path


def dump_yaml(obj) -> str:
    # JSON is YAML; it keeps this guard free of a yaml dependency for writing.
    return json.dumps(obj, indent=2) + "\n"


def stage(tree: Path, work: Path, fixture: dict, nodes: list, age_key: Path) -> None:
    for name in TEMPLATE_INPUTS:
        src = tree / name
        if src.is_dir():
            shutil.copytree(src, work / name, symlinks=True)
        else:
            shutil.copy2(src, work / name)
    shutil.copy2(work / "trello-notifier.sample.yaml", work / "trello-notifier.yaml")
    (work / "cluster.yaml").write_text(dump_yaml(fixture))
    (work / "nodes.yaml").write_text(dump_yaml({"nodes": nodes}))
    shutil.copy2(age_key, work / "age.key")
    for name, body in _PLACEHOLDERS.items():
        (work / name).parent.mkdir(parents=True, exist_ok=True)
        (work / name).write_text(body)
    # Tenant key files for part 3 (plugin.py tenant_key()), one set per
    # declared tenant so any scenario renders. Fakes carrying only the marker
    # line tenant_key() checks for, plus a per-name token tenant_objects()
    # uses to tell which file landed in which Secret. Never real keys.
    for repo in fixture.get("app_repos") or []:
        n = repo["name"]
        keys = {"age": f"# placeholder\nAGE-SECRET-KEY-1PLACEHOLDER{n.upper()}\n",
                "deploy": f"-----BEGIN OPENSSH PRIVATE KEY-----\nplaceholder-{n}-ro\n"
                          f"-----END OPENSSH PRIVATE KEY-----\n"}
        if repo.get("kind") == "agent":
            keys["write"] = (f"-----BEGIN OPENSSH PRIVATE KEY-----\nplaceholder-{n}-rw\n"
                             f"-----END OPENSSH PRIVATE KEY-----\n")
        (work / "tenants").mkdir(exist_ok=True)
        for kind, body in keys.items():
            (work / "tenants" / f"{n}.{kind}.key").write_text(body)


def render(tree: Path, fixture: dict, nodes: list, age_key: Path) -> dict[str, bytes]:
    with tempfile.TemporaryDirectory(prefix="tenant-render.") as tmp:
        work = Path(tmp)
        stage(tree, work, fixture, nodes, age_key)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        proc = subprocess.run([tool("makejinja"), "--output", "./out/"],
                              cwd=work, env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            tail = "\n".join(proc.stderr.strip().splitlines()[-3:])
            raise RuntimeError(f"makejinja exited {proc.returncode}:\n{tail}")
        out = work / "out"
        files = {str(p.relative_to(out)): p.read_bytes()
                 for p in sorted(out.rglob("*")) if p.is_file()}
        if not files:
            raise RuntimeError("makejinja exited 0 but rendered no files")
        return files


def vet(tree: Path, fixture: dict, nodes: list) -> str | None:
    """Return None if the fixture is valid, else cue's first lines."""
    merged = dict(fixture, nodes=nodes)
    with tempfile.TemporaryDirectory(prefix="tenant-vet.") as tmp:
        cfg = Path(tmp) / "merged.yaml"
        cfg.write_text(dump_yaml(merged))
        proc = subprocess.run([tool("cue"), "vet", str(cfg), str(tree / SCHEMA)],
                              capture_output=True, text=True)
    if proc.returncode == 0:
        return None
    return "\n".join(proc.stderr.strip().splitlines()[:4])


def tenant_traces(files: dict[str, bytes]) -> list[str]:
    found = []
    for path, body in files.items():
        if path.startswith("kubernetes/tenants/") or "/tenants/" in path:
            found.append(f"{path}: a tenants/ path")
            continue
        text = body.decode("utf-8", "replace")
        for needle in ("name: cluster-tenants", "name: tenant-", "jg.tenant",
                       "IM_APPS_REPO", "im-apps-write-key"):
            if needle in text:
                found.append(f"{path}: contains `{needle}`")
    return found


def diff_names(a: dict[str, bytes], b: dict[str, bytes]) -> list[str]:
    out = [f"only in first: {p}" for p in sorted(a.keys() - b.keys())]
    out += [f"only in second: {p}" for p in sorted(b.keys() - a.keys())]
    out += [f"differs: {p}" for p in sorted(a.keys() & b.keys()) if a[p] != b[p]]
    return out


def checkout(ref: str, dest: Path) -> None:
    git = tool("git")
    archive = subprocess.run([git, "-C", str(ROOT), "archive", ref, "--", *TEMPLATE_INPUTS],
                             capture_output=True)
    if archive.returncode != 0:
        raise CannotMeasure(f"git archive {ref}: {archive.stderr.decode().strip()}")
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive.stdout, check=True)


# Part 3. Built on full-omni-extras: a narrowed shared pool (three declared
# gateway addresses) so a lan_ip grant is legal, and `full` so it is not
# refused as an appliance.
TENANT_BASE = "full-omni-extras"
TENANTS = [
    dict(name="acme", repository="fixture/acme-app", kind="vendor"),
    dict(name="im-apps", repository="fixture/im-apps", kind="agent",
         namespaces=["im-apps", "im-apps-db"], branch="prod",
         grants=dict(baseline=True, lan_ip=1),
         lan_ip_range=dict(start="192.0.2.200", stop="192.0.2.200")),
    # host_network: PSA privileged, the granted label, no `world` (root 3.7).
    dict(name="edge", repository="fixture/edge-app", kind="vendor",
         grants=dict(host_network=True)),
]
# A cluster with vendors only renders no agent objects at all: no
# im-apps-write-key file, no IM_APPS_REPO (root 3.7).
VENDOR_ONLY = [TENANTS[0]]
SAMPLE = "cluster.sample.yaml"
BOOTSTRAP_KEY = "templates/config/bootstrap/github-deploy-key.sops.yaml.j2"


def sample_example(tree: Path) -> list[dict]:
    """The commented `app_repos:` example in cluster.sample.yaml, uncommented.

    Operators copy it, so it must be a config the schema accepts and the
    template renders. Its `10.9.x.` placeholders become TEST-NET-1.
    """
    lines = (tree / SAMPLE).read_text().splitlines()
    if "# app_repos:" not in lines:
        raise RuntimeError(f"{SAMPLE} has no `# app_repos:` example")
    start = lines.index("# app_repos:")
    block = []
    for line in lines[start:]:
        if not line.startswith("#"):
            break
        block.append(line[2:])
    text = "\n".join(block).replace("10.9.x.", "192.0.2.")
    proc = subprocess.run([tool("yq"), "-o=json", "."], input=text.encode(),
                          capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{SAMPLE} example does not parse: {proc.stderr.decode().strip()}")
    return json.loads(proc.stdout)["app_repos"]


def bootstrap_known_hosts(tree: Path) -> list[str]:
    """known_hosts as the root sync's deploy key carries it — the copy the
    tenant Secrets must equal, or a GitHub host-key rotation updates one."""
    text = (tree / BOOTSTRAP_KEY).read_text()
    return [l.strip() for l in text.splitlines() if l.strip().startswith("github.com ")]
KS = "kubernetes/flux/cluster/ks.yaml"
CS = "kubernetes/components/sops/cluster-secrets.sops.yaml"
TD = "kubernetes/tenants/"


def docs(body: bytes) -> list[dict]:
    """Every YAML document as a dict, via yq (CI's python has no PyYAML)."""
    proc = subprocess.run([tool("yq"), "-o=json", "-I=0", "."], input=body,
                          capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"yq could not parse: {proc.stderr.decode().strip()}")
    out = [json.loads(l) for l in proc.stdout.decode().splitlines() if l.strip()]
    return [d for d in out if isinstance(d, dict)]


def ident(d: dict) -> tuple[str, str]:
    return d.get("kind", ""), d.get("metadata", {}).get("name", "")


def tenant_objects(files: dict[str, bytes], tenants: list[dict],
                   known_hosts: list[str]) -> list[str]:
    """What cluster-tenants applies (task 3.4), asserted per object."""
    bad: list[str] = []
    rendered = {p[len(TD):]: b for p, b in files.items() if p.startswith(TD)}
    lan = [t for t in tenants if (t.get("grants") or {}).get("lan_ip")]
    agents = [t for t in tenants if t["kind"] == "agent"]
    want_files = {"kustomization.yaml", "namespaces.yaml", "rbac.yaml", "quota.yaml",
                  "networkpolicy.yaml", "tenant-git-auth.sops.yaml",
                  "tenant-sops-age.sops.yaml"}
    if lan:
        want_files.add("lb-pools.yaml")
    if agents:
        want_files.add("im-apps-write-key.sops.yaml")
    if set(rendered) != want_files:
        bad.append(f"{TD}: files {sorted(rendered)}, expected {sorted(want_files)}")
        return bad
    kz = docs(rendered["kustomization.yaml"])
    if len(kz) != 1 or sorted(kz[0].get("resources", [])) != sorted(want_files - {"kustomization.yaml"}):
        bad.append(f"{TD}kustomization.yaml: resources do not list exactly the rendered files")
    objs: dict[tuple[str, str, str], dict] = {}
    for f, body in rendered.items():
        if f == "kustomization.yaml":
            continue
        for d in docs(body):
            key = (d.get("kind", ""), d.get("metadata", {}).get("namespace", ""),
                   d.get("metadata", {}).get("name", ""))
            if key in objs:
                bad.append(f"{TD}{f}: duplicate {key}")
            objs[key] = d

    def get(kind, ns, name):
        o = objs.pop((kind, ns, name), None)
        if o is None:
            bad.append(f"{kind} {ns}/{name}: not rendered")
        return o or {}

    def eq(label, got, want):
        if got != want:
            bad.append(f"{label} = {got!r}, expected {want!r}")

    q_default = {"cpu": "4", "memory": "8Gi", "pods": 50}
    for t in tenants:
        g = t.get("grants") or {}
        level = ("privileged" if g.get("host_network") else
                 "baseline" if g.get("baseline") else "restricted")
        nss = t.get("namespaces", [t["name"]])
        q = dict(q_default, **(t.get("quota") or {}))
        for ns in nss:
            labels = get("Namespace", "", ns).get("metadata", {}).get("labels", {})
            want = {"pod-security.kubernetes.io/enforce": level, "jg.tenant": t["name"]}
            if g.get("host_network"):
                want["jg.tenant-privileged"] = "granted"
            if g.get("lan_ip"):
                want["jg.tenant-lan-ip"] = "granted"
            eq(f"Namespace/{ns} labels", labels, want)
            rb = get("RoleBinding", ns, f"tenant-{t['name']}")
            eq(f"RoleBinding {ns} roleRef", rb.get("roleRef"),
               {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                "name": "tenant-admin"})
            eq(f"RoleBinding {ns} subjects", rb.get("subjects"),
               [{"kind": "ServiceAccount", "name": f"tenant-{t['name']}",
                 "namespace": "flux-system"}])
            eq(f"ResourceQuota {ns}", get("ResourceQuota", ns, "tenant-quota").get("spec"),
               {"hard": {"requests.cpu": str(q["cpu"]), "requests.memory": str(q["memory"]),
                         "pods": str(q["pods"]),
                         "services.loadbalancers": str(g.get("lan_ip", 0)),
                         "services.nodeports": "0"}})
            lr = get("LimitRange", ns, "tenant-defaults")
            eq(f"LimitRange {ns} type", [l.get("type") for l in lr.get("spec", {}).get("limits", [])],
               ["Container"])
            np = get("CiliumNetworkPolicy", ns, "tenant-ingress").get("spec", {})
            eq(f"CiliumNetworkPolicy {ns} endpointSelector", np.get("endpointSelector"), {})
            ing = np.get("ingress") or [{}, {}]
            eq(f"CiliumNetworkPolicy {ns} namespaces",
               sorted(ing[0].get("fromEndpoints", [{}])[0].get("matchExpressions", [{}])[0]
                      .get("values", [])), sorted(nss + ["network"]))
            eq(f"CiliumNetworkPolicy {ns} entities", ing[1].get("fromEntities") if len(ing) > 1 else None,
               ["host", "world"] if g.get("lan_ip") else ["host"])
            if "egress" in np or "egressDeny" in np:
                bad.append(f"CiliumNetworkPolicy {ns}: restricts egress (spec says it must not)")
        sa = get("Secret", "flux-system", f"tenant-{t['name']}-git-auth").get("stringData", {})
        eq(f"tenant-{t['name']}-git-auth keys", sorted(sa), ["identity", "known_hosts"])
        got_hosts = [l.strip() for l in sa.get("known_hosts", "").splitlines() if l.strip()]
        if got_hosts != known_hosts:
            bad.append(f"tenant-{t['name']}-git-auth known_hosts differs from {BOOTSTRAP_KEY}")
        if f"placeholder-{t['name']}-ro" not in sa.get("identity", ""):
            bad.append(f"tenant-{t['name']}-git-auth identity is not tenants/{t['name']}.deploy.key")
        age = get("Secret", "flux-system", f"tenant-{t['name']}-sops-age").get("stringData", {})
        eq(f"tenant-{t['name']}-sops-age keys", sorted(age), ["age.agekey"])
        if f"PLACEHOLDER{t['name'].upper()}" not in age.get("age.agekey", ""):
            bad.append(f"tenant-{t['name']}-sops-age is not tenants/{t['name']}.age.key")
        if g.get("lan_ip"):
            pool = get("CiliumLoadBalancerIPPool", "", f"tenant-{t['name']}").get("spec", {})
            eq(f"pool tenant-{t['name']} blocks", pool.get("blocks"), [t["lan_ip_range"]])
            # The namespace half is what a tenant cannot forge (fleet-ops-96's
            # finding on #221): the label alone lets another tenant draw here.
            eq(f"pool tenant-{t['name']} selector", pool.get("serviceSelector"),
               {"matchLabels": {"jg.tenant": t["name"]},
                "matchExpressions": [{"key": "io.kubernetes.service.namespace",
                                      "operator": "In", "values": nss}]})
        if t["kind"] == "agent":
            wk = get("Secret", "claudecode", "im-apps-write-key").get("stringData", {})
            eq("im-apps-write-key keys", sorted(wk), ["identity"])
            if f"placeholder-{t['name']}-rw" not in wk.get("identity", ""):
                bad.append("im-apps-write-key identity is not the agent's write key")
    # Anything left over was not asked for: an extra object is how a
    # ClusterRole or a second binding would arrive.
    for k, o in objs.items():
        bad.append(f"{TD}: unexpected object {k}")
    return bad


def tenant_shape(with_t: dict[str, bytes], without: dict[str, bytes],
                 tenants: list[dict], known_hosts: list[str]) -> list[str]:
    bad: list[str] = []
    if KS not in with_t:
        return [f"{KS} not rendered"]
    # Nothing but ks.yaml (and, from task 3.4, kubernetes/tenants/) may differ.
    for d in diff_names(without, with_t):
        path = d.split(": ", 1)[1]
        if path not in (KS, CS) and not path.startswith("kubernetes/tenants/"):
            bad.append(f"adding tenants changed a non-tenant file: {d}")
    # cluster-secrets may gain exactly one key, IM_APPS_REPO, for the agent.
    cs_with, cs_without = docs(with_t[CS]), docs(without[CS])
    if len(cs_with) != 1 or len(cs_without) != 1:
        bad.append(f"{CS}: expected one document on each side")
    else:
        added = {k: v for k, v in cs_with[0].get("stringData", {}).items()
                 if k not in cs_without[0].get("stringData", {})}
        agents = [t for t in tenants if t["kind"] == "agent"]
        want_added = {"IM_APPS_REPO": agents[0]["repository"]} if agents else {}
        if added != want_added:
            bad.append(f"{CS}: keys added by tenants = {added}, expected {want_added}")
        rest = dict(cs_with[0], stringData={k: v for k, v in cs_with[0]["stringData"].items()
                                             if k not in added})
        if rest != cs_without[0]:
            bad.append(f"{CS}: tenants changed something other than the added key")
    bad += tenant_objects(with_t, tenants, known_hosts)
    got = docs(with_t[KS])
    base = docs(without[KS])
    tenant_names = {f"tenant-{t['name']}" for t in tenants} | {"cluster-tenants"}
    rest = [d for d in got if ident(d)[1] not in tenant_names]
    if rest != base:
        bad.append(f"{KS}: the non-tenant documents differ from the tenant-free render "
                   f"({len(rest)} vs {len(base)} documents)")
    by = {}
    for d in got:
        by.setdefault(ident(d), []).append(d)

    def one(kind, name):
        found = by.get((kind, name), [])
        if len(found) != 1:
            bad.append(f"{kind}/{name}: {len(found)} rendered, expected 1")
            return {}
        if found[0].get("metadata", {}).get("namespace") != "flux-system":
            bad.append(f"{kind}/{name}: not in flux-system")
        return found[0]

    def want(obj, path, expected, label):
        cur = obj
        for k in path:
            cur = cur.get(k) if isinstance(cur, dict) else None
        if cur != expected:
            bad.append(f"{label} .{'.'.join(path)} = {cur!r}, expected {expected!r}")

    ct = one("Kustomization", "cluster-tenants")
    if ct:
        lbl = "Kustomization/cluster-tenants"
        want(ct, ["spec", "path"], "./kubernetes/tenants", lbl)
        want(ct, ["spec", "prune"], True, lbl)
        want(ct, ["spec", "sourceRef", "name"], "flux-system", lbl)
        want(ct, ["spec", "dependsOn"], [{"name": "cluster-apps-base"}], lbl)
        # The cluster key decrypts the platform's own tenant Secrets.
        want(ct, ["spec", "decryption"], {"provider": "sops"}, lbl)
    for t in tenants:
        n = f"tenant-{t['name']}"
        one("ServiceAccount", n)
        g = one("GitRepository", n)
        if g:
            lbl = f"GitRepository/{n}"
            want(g, ["spec", "url"], f"ssh://git@github.com/{t['repository']}.git", lbl)
            want(g, ["spec", "ref"], {"branch": t.get("branch", "main")}, lbl)
            want(g, ["spec", "secretRef", "name"], f"{n}-git-auth", lbl)
        k = one("Kustomization", n)
        if k:
            lbl = f"Kustomization/{n}"
            want(k, ["spec", "serviceAccountName"], n, lbl)
            # The seed kustomization.yaml sits at the tenant repo root (root
            # task 5.1); a deeper path would apply nothing and stay Ready.
            want(k, ["spec", "path"], "./", lbl)
            want(k, ["spec", "decryption"],
                 {"provider": "sops", "secretRef": {"name": f"{n}-sops-age"}}, lbl)
            want(k, ["spec", "sourceRef"],
                 {"kind": "GitRepository", "name": n, "namespace": "flux-system"}, lbl)
            want(k, ["spec", "prune"], True, lbl)
            want(k, ["spec", "dependsOn"], [{"name": "cluster-tenants"}], lbl)
            for forbidden in ("postBuild", "targetNamespace", "kubeConfig"):
                if forbidden in k.get("spec", {}):
                    bad.append(f"{lbl} has spec.{forbidden}")
    # No ClusterRoleBinding, in any rendered file, may name a tenant SA.
    for path, body in with_t.items():
        if not path.endswith((".yaml", ".yml")):
            continue
        for d in docs(body):
            if d.get("kind") == "ClusterRoleBinding":
                for s in d.get("subjects") or []:
                    if str(s.get("name", "")).startswith("tenant-"):
                        bad.append(f"{path}: ClusterRoleBinding/{ident(d)[1]} names {s.get('name')}")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tree", type=Path, default=ROOT,
                    help="template tree to check (default: this repo)")
    ap.add_argument("--against", metavar="REF",
                    help="also compare each fixture's render with the template at REF")
    args = ap.parse_args()

    failures: list[str] = []
    try:
        for name, fixture, nodes in FIXTURES:
            problem = vet(args.tree, fixture, nodes)
            if problem:
                failures.append(f"[{name}] fixture fails cue vet (guard defect):\n{problem}")
        if failures:
            raise RuntimeError("fixtures invalid")

        with tempfile.TemporaryDirectory(prefix="tenant-key.") as tmp:
            key = Path(tmp) / "age.key"
            proc = subprocess.run([tool("age-keygen"), "-o", str(key)],
                                  capture_output=True, text=True)
            if proc.returncode != 0 or not key.is_file():
                raise CannotMeasure(f"age-keygen failed: {proc.stderr.strip()}")

            ref_tree = None
            if args.against:
                ref_tree = Path(tmp) / "ref"
                ref_tree.mkdir()
                checkout(args.against, ref_tree)

            for name, fixture, nodes in FIXTURES:
                try:
                    absent = render(args.tree, fixture, nodes, key)
                    empty = render(args.tree, dict(copy.deepcopy(fixture), app_repos=[]),
                                   nodes, key)
                    before = (render(ref_tree, fixture, nodes, key)
                              if ref_tree is not None else None)
                except RuntimeError as e:
                    failures.append(f"[{name}] render failed: {e}")
                    continue
                diffs = diff_names(absent, empty)
                if diffs:
                    failures.append(f"[{name}] `app_repos` absent vs `[]` differ:\n  "
                                    + "\n  ".join(diffs))
                for label, files in (("absent", absent), ("[]", empty)):
                    traces = tenant_traces(files)
                    if traces:
                        failures.append(f"[{name}] tenant objects with `app_repos` {label}:\n  "
                                        + "\n  ".join(traces))
                line = f"[{name}] {len(absent)} files rendered; absent == []"
                if before is not None:
                    diffs = diff_names(before, absent)
                    if diffs:
                        failures.append(f"[{name}] render differs from {args.against}:\n  "
                                        + "\n  ".join(diffs))
                    else:
                        line += f"; identical to {args.against} ({len(before)} files)"
                if not any(f.startswith(f"[{name}]") for f in failures):
                    print("ok  " + line)

            # Part 3: the shape of a render that HAS tenants.
            base = next((f for f in FIXTURES if f[0] == TENANT_BASE), None)
            if base is None:
                failures.append(f"[with-tenants] base fixture {TENANT_BASE} not found (guard defect)")
            else:
                _, fixture, nodes = base
                hosts = bootstrap_known_hosts(args.tree)
                if len(hosts) < 3:
                    failures.append(f"[with-tenants] {BOOTSTRAP_KEY}: {len(hosts)} known_hosts "
                                    f"lines found, expected 3 (guard defect)")
                try:
                    example = sample_example(args.tree)
                except RuntimeError as e:
                    failures.append(f"[sample-example] {e}")
                    example = None
                scenarios = [("with-tenants", TENANTS), ("vendor-only", VENDOR_ONLY)]
                if example is not None:
                    scenarios.append(("sample-example", example))
                without = None
                for label, tenants in scenarios:
                    with_t = dict(copy.deepcopy(fixture), app_repos=copy.deepcopy(tenants))
                    problem = vet(args.tree, with_t, nodes)
                    if problem:
                        what = ("the example operators copy fails cue vet"
                                if label == "sample-example" else
                                "fixture fails cue vet (guard defect)")
                        failures.append(f"[{label}] {what}:\n{problem}")
                        continue
                    try:
                        got = render(args.tree, with_t, nodes, key)
                        if without is None:
                            without = render(args.tree, fixture, nodes, key)
                    except RuntimeError as e:
                        failures.append(f"[{label}] render failed: {e}")
                        continue
                    bad = tenant_shape(got, without, tenants, hosts)
                    if bad:
                        failures.append(f"[{label}] " + "\n  ".join(bad))
                    else:
                        print(f"ok  [{label}] {len(tenants)} tenant(s) on {TENANT_BASE}: "
                              f"every tenant object as declared, nothing else changed")
    except CannotMeasure as e:
        if failures:
            print("\n".join("FAIL " + f for f in failures))
            print(f"(also could not finish: {e})")
            return 1
        print(f"COULD NOT MEASURE: {e}")
        return 2
    except RuntimeError as e:
        if str(e) != "fixtures invalid":
            raise

    if failures:
        print("\n".join("FAIL " + f for f in failures))
        return 1
    print(f"PASS -- {len(FIXTURES)} fixtures: no tenant object and no byte change "
          f"when `app_repos` is absent or empty; with tenants, only tenant objects"
          + (f"; each render identical to {args.against}" if args.against else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
