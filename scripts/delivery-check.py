#!/usr/bin/env python3
"""Executable form of the provisioning runbook's assertions — §7.1a.

`fleet-ops docs/operations/provision-customer-cluster.md` is a document made almost
entirely of checks, executed by a person, with nothing behind them. This runs
the ones a machine can run, so that 7.2 has real assertions to execute and 7.3
has something an agent can run identically.

The design rule every check here obeys
--------------------------------------
**A check that cannot discriminate reads identically to a check that passed.**
So each check below either carries a positive control, or refuses to report a
pass. Concretely, that means:

  - Absence is never reported as good on its own. `NotFound`, "no output" and
    "no rows" are also what asking the wrong question looks like, so something
    that must be present is asserted in the same breath.
  - Nothing trusts a tool's own account of itself where a checksum, a digest or
    a delegation record is available instead.
  - A check pinned to one path is treated as not having looked. `cluster.yaml`
    leaked at `config.gen/cluster.yaml` past a rule and a check both naming
    `/cluster.yaml`.

Every subcommand exits 0 on pass, 1 on fail, and 2 when it could not tell —
which is deliberately not the same as a pass.

Usage
-----
  delivery-check.py escrow       --escrowed-key PATH [--sops-yaml PATH]
  delivery-check.py repo-hygiene [--dir PATH] [--deep]
  delivery-check.py dns          --domain DOMAIN [--token-env VAR]
  delivery-check.py flux         --kubeconfig PATH --expect-sha SHA
  delivery-check.py lan          --domain DOMAIN --expect-addr ADDR
  delivery-check.py gateway      --node ADDR [--talosconfig PATH] [--routes-json PATH]
  delivery-check.py deploy-key   --repo OWNER/NAME [--pubkey PATH]
  delivery-check.py tunnel-cert  --domain DOMAIN [--cert PATH] [--token-env VAR]
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.request

PASS, FAIL, UNKNOWN = 0, 1, 2

# Reused verbatim from the runbook's history scan, and from
# delivery-ticket.py's comment guard. One list, three call sites: three
# divergent lists would mean the strictest one defines the real policy and
# nobody knows which it is.
SECRET_FIELDS = (
    "cloudflare_token",
    "claudecode_auth0_client_secret",
    "backup_r2_secret_access_key",
    "ttyd_credential",
    "claudecode_postgres_password",
)


def ok(msg: str) -> None:
    print(f"PASS  {msg}")


def bad(msg: str) -> None:
    print(f"FAIL  {msg}")


def huh(msg: str) -> None:
    print(f"?     {msg}")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# ---------------------------------------------------------------- escrow (0)

def check_escrow(args) -> int:
    """The escrowed copy IS this cluster's key, not merely a file of that name.

    A truncated copy reads exactly like a good one — same name, same rough
    size, present. Only the public half derived from the copy identifies the
    material, which is why this derives rather than compares filenames.
    """
    if not shutil.which("age-keygen"):
        huh("age-keygen not installed — cannot derive the public half")
        return UNKNOWN
    if not os.path.exists(args.escrowed_key):
        bad(f"escrowed key not found at {args.escrowed_key}")
        return FAIL

    r = run(["age-keygen", "-y", args.escrowed_key])
    if r.returncode != 0:
        bad(f"age-keygen could not read {args.escrowed_key} as a key — "
            "a truncated or partial copy does exactly this")
        return FAIL
    derived = r.stdout.strip()

    try:
        sops_text = open(args.sops_yaml).read()
    except FileNotFoundError:
        huh(f"{args.sops_yaml} not found — nothing to compare against")
        return UNKNOWN

    recipients = re.findall(r"age1[a-z0-9]{20,}", sops_text)
    if not recipients:
        huh(f"no age recipient in {args.sops_yaml}; cannot compare")
        return UNKNOWN

    if derived in recipients:
        ok(f"escrowed copy derives {derived[:16]}…, which is a recipient in "
           f"{args.sops_yaml}")
        print("      Record this as: compared, public halves match verbatim.")
        print("      Not 'escrowed' — that word is what jgt-appliance's unchecked")
        print("      age_key_escrowed: true was written on.")
        return PASS

    bad("the escrowed copy is a valid age key but NOT this cluster's")
    print(f"      derived from copy: {derived[:16]}…")
    print(f"      .sops.yaml expects: {', '.join(r[:16] + '…' for r in recipients)}")
    print("      Delete it from the escrow store — a wrong key in an escrow slot")
    print("      is worse than an empty one, because it will be trusted.")
    return FAIL


# ---------------------------------------------------- repository hygiene (3)

def check_repo_hygiene(args) -> int:
    d = args.dir
    if run(["git", "-C", d, "rev-parse", "--git-dir"]).returncode != 0:
        huh(f"{d} is not a git repository")
        return UNKNOWN

    failed = False

    # 1. Is the protection IN the repo, or only on this machine?
    #
    # This is first because it is the one that would have caught jg-jiahd, and
    # because `git check-ignore` cannot: it measures the workstation running
    # it, which is also the workstation doing the verifying. jg-jiahd has no
    # .gitignore in HEAD at all, ~/.gitignore_global ignores .gitignore itself
    # so it never reaches `git add`, and check-ignore reports .gitignore:18 and
    # looks healthy. Eleven credential-bearing blobs landed behind that.
    tracked = run(["git", "-C", d, "ls-files", "--error-unmatch", ".gitignore"])
    if tracked.returncode != 0:
        bad(".gitignore is NOT tracked — protection exists only on this machine")
        print("      A fresh clone has no ignore rule at all. `git check-ignore`")
        print("      will still say everything is fine, because it reads the")
        print("      working copy.")
        print("      Fix: git add -f .gitignore && git commit  (the global ignore")
        print("      list contains .gitignore, so a plain `git add` will not do it)")
        failed = True
    else:
        head_ignore = run(["git", "-C", d, "show", "HEAD:.gitignore"]).stdout
        if re.search(r"cluster\.yaml", head_ignore):
            ok(".gitignore is tracked and HEAD's copy names cluster.yaml")
        else:
            bad(".gitignore is tracked but HEAD's copy has no cluster.yaml rule")
            failed = True

    # 2. Any path, not just the expected one.
    hist = run(["git", "-C", d, "log", "--all", "--oneline", "--", "*cluster.yaml"])
    offenders = [l for l in hist.stdout.splitlines() if l.strip()]
    if offenders:
        bad(f"a *cluster.yaml path appears in history ({len(offenders)} commits)")
        print("      Rotate the credentials; untracking does not unpublish them.")
        failed = True
    else:
        ok("no *cluster.yaml at any path in --all history")

    # 3. Positive control for check 2.
    #
    # An empty result from `git log` is also what a wrong pathspec, an empty
    # repo or a broken invocation produces. Asserting that the same command
    # shape finds something that must exist separates "nothing there" from
    # "not looking".
    control = run(["git", "-C", d, "log", "--all", "--oneline", "--", "*.md"])
    if not control.stdout.strip():
        huh("positive control found no *.md in history either — the history "
            "query itself may not be working, so the clean result above proves "
            "nothing")
        return UNKNOWN
    ok("positive control: the same query shape does find *.md in history")

    # 4. By content, because the next leak is at a name nobody predicted.
    if args.deep:
        # Positive control first: a clean deep scan and a deep scan that cannot
        # recognise a credential produce the same empty list.
        if not _scan_blob_for_secrets(_SCAN_CONTROL):
            huh("deep scan cannot recognise a credential in its own control "
                "sample, so finding none in this history proves nothing")
            return UNKNOWN
        found = _scan_history_for_secrets(d)
        if found:
            bad(f"credential-shaped content in {len(found)} historical blob(s)")
            for path, sha in found[:10]:
                print(f"      {path}  ({sha[:12]})")
            failed = True
        else:
            ok("deep scan: control sample recognised, and no credential fields "
               "with real values in any blob")
    else:
        print("      (skipped the content scan; pass --deep. It is slow, and is")
        print("       a once-per-repo check rather than once-per-delivery.)")

    return FAIL if failed else PASS


_SECRET_LINE = re.compile(
    r"(?im)^\s*(" + "|".join(SECRET_FIELDS) + r")\s*:\s*(.+)$"
)


def _is_real_credential(value: str) -> bool:
    """Does this right-hand side look like a live secret rather than a placeholder?

    The case-insensitive field match above is deliberate: the rendered Secret
    spells the same fields in UPPER CASE, and a plaintext render is exactly the
    leak worth catching. But that breadth is what makes the SOPS exclusion
    mandatory — `kubernetes/components/sops/cluster-secrets.sops.yaml` is
    *supposed* to be committed, with every one of these fields present and
    encrypted, so without it the scan FAILs on the correct state of every
    cluster repo. Measured on jg-janncotcc 2026-08-22: five fields matched, all
    five values began `ENC[`, and the whole delivery reported a leak.

    That is the failure this file exists to prevent, pointed at itself: a guard
    that fires on the correct input gets switched off, and a switched-off guard
    reads exactly like a passing one — the same reasoning as the placeholder
    exemptions in `delivery-ticket.py`.
    """
    v = value.split("#", 1)[0].strip().strip("\"'").strip()
    if not v or len(v) < 8:
        return False
    if v.startswith(("<", "${", "$(")):          # documentation, not a value
        return False
    if v.startswith(("ENC[", "ENC(")):           # SOPS ciphertext — meant to be here
        return False
    if "change" in v.lower() or set(v.lower()) == {"x"}:
        return False
    return True


def _scan_blob_for_secrets(text: str) -> list[str]:
    """Field names in this blob whose value looks like a live credential."""
    return [f for f, value in _SECRET_LINE.findall(text) if _is_real_credential(value)]


# A blob shaped like the thing being looked for. If the scan cannot find a
# credential here, its silence on real history means nothing — see the
# positive control on the path query above.
_SCAN_CONTROL = "stringData:\n  cloudflare_token: 0123456789abcdef0123456789abcdef01234567\n"


def _scan_history_for_secrets(d: str) -> list[tuple[str, str]]:
    listing = run(["git", "-C", d, "rev-list", "--all", "--objects"]).stdout
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in listing.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        sha, path = parts
        if sha in seen or not path.endswith((".yaml", ".yml")):
            continue
        seen.add(sha)
        blob = run(["git", "-C", d, "cat-file", "blob", sha])
        if blob.returncode != 0:
            continue
        if _scan_blob_for_secrets(blob.stdout):
            hits.append((path, sha))
    return hits


# ------------------------------------------------------------------- dns (2)

def _doh(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.load(r)
    return sorted({a["data"].rstrip(".").lower() for a in data.get("Answer", [])
                   if a.get("type") == 2})


def check_dns(args) -> int:
    """Cloudflare's zone must be the zone the domain is actually delegated to.

    /user/tokens/verify says "valid and active" for a token belonging to an
    entirely different account, and GET /zones returns HTTP 200 with an empty
    result for a token pasted from the wrong field. Neither separates anything,
    so this compares nameservers as sets against the live delegation.

    DoH rather than dig on purpose: an appliance gateway transparently
    redirects all outbound UDP/53, so `dig @1.1.1.1` is answered by the cluster
    and even `dig @192.0.2.1` answers. HTTPS on 443 is immune.
    """
    try:
        cf_ns_live = _doh(f"https://cloudflare-dns.com/dns-query?name={args.domain}&type=NS")
        google_ns_live = _doh(f"https://dns.google/resolve?name={args.domain}&type=NS")
    except Exception as e:  # noqa: BLE001 — any network failure is "cannot tell"
        huh(f"could not reach a DoH resolver: {e}")
        return UNKNOWN

    if not cf_ns_live and not google_ns_live:
        bad(f"{args.domain} has no NS records at either resolver — the domain is "
            "not delegated anywhere")
        return FAIL

    if cf_ns_live != google_ns_live:
        huh("the two resolvers disagree on the delegation; retry before acting")
        print(f"      cloudflare-dns: {', '.join(cf_ns_live) or '(none)'}")
        print(f"      dns.google:     {', '.join(google_ns_live) or '(none)'}")
        return UNKNOWN
    ok(f"live delegation agrees across two resolvers: {', '.join(cf_ns_live)}")

    token = os.environ.get(args.token_env or "CLOUDFLARE_TOKEN", "")
    if not token:
        huh(f"${args.token_env or 'CLOUDFLARE_TOKEN'} not set — checked the "
            "delegation only, NOT that your token sees this zone. That is the "
            "half that catches a same-named zone in an abandoned account.")
        return UNKNOWN

    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/zones?name={args.domain}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            payload = json.load(r)
    except Exception as e:  # noqa: BLE001
        huh(f"Cloudflare API call failed: {e}")
        return UNKNOWN

    results = payload.get("result") or []
    if not results:
        bad(f"the token returned HTTP 200 with an EMPTY zone list for "
            f"{args.domain}")
        print("      Not a 403 — a well-formed empty answer, which is what a")
        print("      token from another account (an R2 key, say) produces.")
        print("      external-dns filters against this list and logs nothing.")
        return FAIL

    zone = results[0]
    zone_ns = sorted(n.rstrip(".").lower() for n in zone.get("name_servers", []))
    status = zone.get("status")

    if zone_ns != cf_ns_live:
        bad("the zone your token sees is NOT the zone this domain resolves to")
        print(f"      token's zone nameservers: {', '.join(zone_ns)}")
        print(f"      live delegation:          {', '.join(cf_ns_live)}")
        print(f"      zone status: {status}")
        print("      This is the same-name-different-zone case: an abandoned")
        print("      account's copy holds complete, correct-looking records for")
        print("      hostnames that are NXDOMAIN worldwide.")
        return FAIL

    if status != "active":
        bad(f"nameservers match but zone status is {status!r}, not 'active'")
        return FAIL

    ok(f"token's zone matches the live delegation and is active")

    # ---- and: do the records in it belong to a cluster that still exists? ----
    #
    # "im.<domain> resolves" passes just as happily on records left behind by a
    # cluster that was dropped. Both cases look identical from outside: proxied
    # A records at Cloudflare's edge and HTTP 530, because a tunnel hostname
    # with no connector answers exactly like one whose cluster has not booted
    # yet. Measured on janncot.cc 2026-08-23: six external-dns records still
    # pointed at the dropped jg-appliance's tunnel while the repo held
    # credentials for a different, freshly created one.
    #
    # external-dns will usually adopt them — same owner id — but "usually" is
    # not what a delivery gate is for, and if it does not, the symptom is
    # indistinguishable from "not bootstrapped yet" forever.
    creds = pathlib.Path(args.tunnel_credentials)
    if not creds.is_file():
        huh(f"{creds} not found — checked the delegation and the token, NOT "
            "whether this zone still holds a dropped cluster's records. That "
            "is the half that stops a later DNS assertion from passing on a "
            "corpse.")
        return UNKNOWN
    try:
        local_tunnel = json.loads(creds.read_text()).get("TunnelID", "")
    except Exception as e:  # noqa: BLE001
        huh(f"could not read a TunnelID out of {creds}: {e}")
        return UNKNOWN
    if not local_tunnel:
        huh(f"{creds} has no TunnelID field")
        return UNKNOWN

    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/zones/{zone['id']}"
        "/dns_records?per_page=100",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            records = json.load(r).get("result") or []
    except Exception as e:  # noqa: BLE001
        huh(f"could not list the zone's DNS records: {e}")
        return UNKNOWN

    tunnel_backed = [r for r in records
                     if str(r.get("content", "")).endswith(".cfargotunnel.com")]
    if not tunnel_backed:
        ok("no tunnel-backed records in the zone: a later DNS assertion has "
           "nothing to inherit, so whatever appears will be this cluster's")
        return PASS

    foreign = [r for r in tunnel_backed
               if r["content"].split(".")[0] != local_tunnel]
    if foreign:
        bad("this zone holds tunnel records pointing at a DIFFERENT tunnel "
            "than the one this repo has credentials for")
        print(f"      this repo's tunnel: {local_tunnel[:8]}…")
        for r in foreign:
            print(f"      {r['name']} -> {r['content'][:8]}….cfargotunnel.com")
        print("      Delete them before bootstrapping. Left in place, "
              "'<host> resolves' passes")
        print("      on a dropped cluster's leftovers and cannot fail.")
        return FAIL

    ok(f"every tunnel record in the zone points at this repo's tunnel "
       f"({local_tunnel[:8]}…)")
    return PASS


# ------------------------------------------------------------------ flux (3)

def check_flux(args) -> int:
    """Flux has fetched the commit — before any absence is interpreted.

    Containment and a stalled Flux emit identical NotFound. Until the cluster
    is provably at the pushed revision, "not deployed yet" is unreadable.
    """
    if not shutil.which("kubectl"):
        huh("kubectl not installed")
        return UNKNOWN
    r = run(["kubectl", "--kubeconfig", args.kubeconfig, "get", "gitrepository",
             "-A", "-o", "json"])
    if r.returncode != 0:
        huh(f"could not query the cluster: {r.stderr.strip().splitlines()[:1]}")
        return UNKNOWN

    items = json.loads(r.stdout).get("items", [])
    if not items:
        bad("no GitRepository objects at all — Flux is not installed or not "
            "reconciling; every absence you observe next would be meaningless")
        return FAIL

    matched = False
    for it in items:
        name = it["metadata"]["name"]
        conds = {c["type"]: c["status"] for c in it.get("status", {}).get("conditions", [])}
        rev = (it.get("status", {}).get("artifact") or {}).get("revision", "")
        ready = conds.get("Ready") == "True"
        has_sha = args.expect_sha in rev
        line = f"{name}: ready={conds.get('Ready')} revision={rev or '(none)'}"
        if ready and has_sha:
            ok(line)
            matched = True
        else:
            print(f"      {line}")
    if matched:
        return PASS
    bad(f"no GitRepository is Ready at a revision containing {args.expect_sha}")
    print("      Do not read any 'the resource is absent' result until this passes.")
    return FAIL


# ------------------------------------------------------------------- lan (4)

def check_lan(args) -> int:
    """Internal names resolve, AND forwarding still works.

    The second half is the control. A cluster answering NXDOMAIN for everything
    looks like a correct configuration if you only test the one name you care
    about — and a client accepts NXDOMAIN and never asks the secondary.
    """
    if not shutil.which("nslookup"):
        huh("nslookup not installed")
        return UNKNOWN

    internal = f"internal.{args.domain}"
    r = run(["nslookup", internal])
    got = re.findall(r"^Address:\s*([0-9.]+)", r.stdout, re.M)
    got = [a for a in got if not a.endswith("#53")]

    if args.expect_addr not in got:
        bad(f"{internal} did not resolve to {args.expect_addr} (got: "
            f"{', '.join(got) or 'nothing'})")
        print("      If nothing: the DHCP lease may not have renewed. Reconnect")
        print("      the client and retry BEFORE changing anything.")
        return FAIL
    ok(f"{internal} -> {args.expect_addr}")

    ctl = run(["nslookup", "github.com"])
    ctl_addrs = [a for a in re.findall(r"^Address:\s*([0-9.]+)", ctl.stdout, re.M)
                 if not a.endswith("#53")]
    if not ctl_addrs:
        bad("positive control failed: github.com does not resolve through this "
            "resolver")
        print("      k8s-gateway is not forwarding. Internal names work and")
        print("      everything else on the LAN is broken — which is a worse")
        print("      outcome than the one this step was guarding against.")
        return FAIL
    ok("positive control: github.com resolves, so forwarding works")
    return PASS


# --------------------------------------------------- default gateway (5)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _merged_config(root: pathlib.Path):
    """cluster.yaml unified with nodes.yaml, the way `task configure` does it."""
    if not shutil.which("yq"):
        return None, "yq is not on PATH — run this under `mise exec`"
    files = [root / "cluster.yaml"]
    if (root / "nodes.yaml").is_file():
        files.append(root / "nodes.yaml")
    if not files[0].is_file():
        return None, f"{files[0]} not here — run this inside a cluster repo"
    r = run(["yq", "eval-all", "-o=json", ". as $i ireduce ({}; . * $i)",
             *[str(f) for f in files]])
    if r.returncode != 0:
        return None, f"yq could not read the config: {r.stderr.strip()[:140]}"
    try:
        return json.loads(r.stdout), None
    except json.JSONDecodeError as e:
        return None, f"the merged config did not decode as JSON: {e}"


def _shipped_gateway(root: pathlib.Path):
    """(address, provenance, error). provenance is "declared" or "assumed".

    The address comes from the real `Plugin.data()`, never from a second copy
    of the `.1` rule. `#32` cost the whole fleet its ability to render because
    this file's neighbour held a copy of one value plugin.py owns, and the copy
    stayed behind when the original changed.
    """
    raw, err = _merged_config(root)
    if err:
        return None, None, err
    provenance = "declared" if "node_default_gateway" in raw else "assumed"
    loader = root / "scripts" / "check-node-dns-path.py"
    if not loader.is_file():
        return None, None, f"{loader} not here — it owns the makejinja stub"
    try:
        spec = importlib.util.spec_from_file_location("_cndp", loader)
        cndp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cndp)
        data = cndp.load_plugin().Plugin(dict(raw)).data()
    except Exception as e:  # a real repo has auth0.json; a bare one does not
        return None, provenance, f"could not render the config: {type(e).__name__}: {str(e)[:140]}"
    return data.get("node_default_gateway"), provenance, None


def _route_docs(args):
    """Whatever talosctl says, as a list of decoded JSON documents."""
    if args.routes_json:
        f = pathlib.Path(args.routes_json)
        if not f.is_file():
            return None, f"{f} not here"
        text = f.read_text()
    else:
        if not shutil.which("talosctl"):
            return None, "talosctl is not on PATH"
        cmd = ["talosctl"]
        if args.talosconfig:
            cmd += ["--talosconfig", args.talosconfig]
        cmd += ["-n", args.node, "get", "routes", "-o", "json"]
        r = run(cmd, timeout=args.timeout)
        if r.returncode != 0:
            return None, f"talosctl failed: {(r.stderr or r.stdout).strip()[:200]}"
        text = r.stdout
    docs, dec, i = [], json.JSONDecoder(), 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        try:
            doc, end = dec.raw_decode(text, i)
        except json.JSONDecodeError as e:
            return None, f"talosctl output did not decode as JSON at offset {i}: {e}"
        docs.append(doc)
        i = end
    return docs, None


def check_gateway(args) -> int:
    """The nodes' real default route, against the one this repo ships.

    `#49`: `node_default_gateway` defaults to `.1` of `node_cidr`, which is an
    assumption about someone else's LAN. It is invisible when wrong — configure
    succeeds, `cue vet` passes, the cluster boots, and nothing leaves the LAN —
    and it is invisible when right for the wrong reason, because the operator's
    own LANs are all `.1`, so the assumed string and the measured one match on
    every cluster this lab can test.

    Positive control, per this file's rule: a node always has routes. Zero
    routes back is what asking the wrong question looks like, not a node
    without a gateway, so it reports UNKNOWN rather than a missing default.

    Two default routes are not resolved by picking one — same rule as multiple
    candidate subnets for `node_cidr`.
    """
    shipped, provenance, err = _shipped_gateway(REPO_ROOT)
    if err:
        huh(f"cannot tell what this repo ships: {err}")
        return UNKNOWN

    docs, err = _route_docs(args)
    if err:
        huh(f"cannot measure the node's routes: {err}")
        print(f"      This repo would ship {shipped} ({provenance}). Unverified.")
        return UNKNOWN

    if not docs:
        huh("talosctl returned no routes at all")
        print("      Every node has routes, so this is the wrong question being")
        print("      asked — wrong node, wrong resource name, or no permission —")
        print("      not a node without a default gateway.")
        return UNKNOWN

    specs = [d.get("spec", d) for d in docs]
    if not any("gateway" in sp for sp in specs):
        keys = sorted({k for sp in specs if isinstance(sp, dict) for k in sp})
        huh(f"no route carries a `gateway` key across {len(docs)} routes")
        print(f"      Keys seen: {', '.join(keys) or 'none'}")
        print("      The selector below expects `gateway` and `dst`. If talosctl")
        print("      names them differently, fix the two names here — do not")
        print("      loosen this into picking whatever is first.")
        return UNKNOWN

    defaults = [
        sp for sp in specs
        if isinstance(sp, dict) and sp.get("gateway") and not sp.get("dst")
    ]
    # node_default_gateway is `net.IPv4` in cluster.schema.cue, so an IPv6
    # default route is not a second candidate for it — it is a different
    # question. Measured 2026-08-30 on a real 145-route capture from a jg-jiahd
    # node: 110 of them inet6, one of those with an empty dst (no gateway, so
    # it never reached this line). A node that does have an IPv6 default
    # gateway would have made the count two and this check would have refused
    # to choose — a false alarm on a healthy dual-stack node, which is the
    # failure mode that gets guards switched off.
    #
    # `family` absent is kept rather than dropped: an unknown shape should
    # widen the answer into "cannot tell", never narrow it into a confident one.
    other = sorted({sp["gateway"] for sp in defaults
                    if sp.get("family") not in (None, "", "inet4")})
    found = sorted({sp["gateway"] for sp in defaults
                    if sp.get("family") in (None, "", "inet4")})
    if other:
        print(f"      ({len(other)} non-IPv4 default route(s) not compared: "
              f"{', '.join(other)} — node_default_gateway is IPv4)")

    if not found:
        huh(f"{len(docs)} routes, none of them a default route")
        print("      A default route is one with a gateway and no destination.")
        return UNKNOWN
    if len(found) > 1:
        huh(f"{len(found)} default routes: {', '.join(found)}")
        print("      Refusing to pick. Which one the node uses depends on metric")
        print("      and interface, and guessing here would ship a number that")
        print("      looks measured. Decide on the node, then declare it.")
        return UNKNOWN

    measured = found[0]
    if measured != shipped:
        bad(f"this repo ships {shipped} ({provenance}); the node routes via {measured}")
        print("      Set node_default_gateway in cluster.yaml to the measured")
        print("      value and re-run `task configure`. Left alone, the cluster")
        print("      comes up and nothing reaches the internet.")
        return FAIL

    if provenance == "assumed":
        ok(f"default route {measured} — matches, but cluster.yaml does not say so")
        print("      Declare it anyway: it is right by coincidence today, and")
        print("      the next node_cidr change silently moves it.")
        return PASS
    ok(f"default route {measured} — declared in cluster.yaml and measured on the node")
    return PASS


# ------------------------------------------------- deploy key (6)

def check_deploy_key(args) -> int:
    """The deploy key exists locally AND GitHub has it.

    `#56`: `task init` runs `ssh-keygen` and the template renders the private
    half into a Secret, so every artefact a person would look at is present —
    and `gh api repos/<repo>/keys` was empty on jg-janncotcc. Nothing in either
    repo registers the public half, and on a PUBLIC repo nothing ever notices,
    because Flux clones anonymously. It surfaces only when the repo goes
    private, as `GitRepository READY=False` during a provisioning run.

    Registering is a runbook step (fleet-ops), not something this repo should
    do behind an operator's back — a write to someone's GitHub account is not a
    side effect of a check. Detecting it is this repo's half.

    Positive control: the local public key is compared to what GitHub returns,
    so a repo carrying somebody else's key is a finding rather than a pass.
    "The list is not empty" would accept exactly that.
    """
    pub = pathlib.Path(args.pubkey)
    if not pub.is_file():
        huh(f"{pub} is not here — run `task init` in the cluster repo first")
        return UNKNOWN
    if not shutil.which("gh"):
        huh("gh is not on PATH")
        return UNKNOWN

    # ssh-keygen writes "<type> <base64> <comment>"; GitHub returns and compares
    # the first two fields only, so the comment must not take part.
    local = " ".join(pub.read_text().split()[:2])

    r = run(["gh", "api", f"repos/{args.repo}/keys", "--jq", ".[].key"])
    if r.returncode != 0:
        huh(f"could not list deploy keys: {r.stderr.strip()[:160]}")
        print("      Not reporting a missing key: no answer and an empty answer")
        print("      are different, and only one of them is a finding.")
        return UNKNOWN

    remote = [" ".join(k.split()[:2]) for k in r.stdout.splitlines() if k.strip()]
    if local in remote:
        ok(f"{args.repo} carries this repo's deploy key ({len(remote)} key(s) registered)")
        return PASS

    if not remote:
        bad(f"{args.repo} has no deploy keys at all")
    else:
        bad(f"{args.repo} has {len(remote)} deploy key(s), none of them this one")
    print("      Register it:")
    print(f"        gh api -X POST repos/{args.repo}/keys \\")
    print(f"          -f title='flux' -f key=\"$(cat {pub})\" -F read_only=true")
    print("      Until then a private repo cannot be synced: Flux authenticates")
    print("      with the matching private half and GitHub will refuse it.")
    return FAIL


# ------------------------------------------------ tunnel cert (7)

CERT_BLOCK = re.compile(
    r"-----BEGIN ARGO TUNNEL TOKEN-----(.*?)-----END ARGO TUNNEL TOKEN-----", re.S
)


def _cert_binding(cert: pathlib.Path) -> tuple[dict, str | None]:
    """The accountID/zoneID a cloudflared cert is bound to.

    The file is a base64 JSON blob with exactly three keys: `accountID`,
    `zoneID` and `apiToken`. **The third is a credential.** Only the first two
    are ever returned, and nothing here formats the parsed object as a whole —
    a check that leaks the secret it is validating is a worse trade than the
    check is worth.
    """
    try:
        text = cert.read_text()
    except OSError as e:
        return {}, f"could not read it: {e}"
    m = CERT_BLOCK.search(text)
    if not m:
        return {}, "no ARGO TUNNEL TOKEN block in it — is this a cloudflared cert?"
    try:
        payload = json.loads(base64.b64decode("".join(m.group(1).split())))
    except Exception as e:  # noqa: BLE001 — malformed is "cannot tell", not a finding
        return {}, f"the token block did not decode: {type(e).__name__}"
    if not isinstance(payload, dict):
        return {}, "the token block is not an object"
    return (
        {k: payload.get(k) for k in ("accountID", "zoneID") if payload.get(k)},
        None,
    )


def check_tunnel_cert(args) -> int:
    """Which Cloudflare account `cloudflared tunnel login` actually bound to.

    Nothing checks this today, and every downstream step passes when it is
    wrong: `cloudflared tunnel create` succeeds, `cloudflare-tunnel.json` is
    written, `task configure` renders. The cluster comes up and the tunnel
    answers **1033**.

    Measured 2026-09-02 (`#63`): re-running the runbook's Step 2 opened a
    browser already signed in as the operator, while the account being
    authorised had to be the customer's. The authorisation page even lists a
    `Moved` remnant of the old account with the right name and an `Active`
    plan. What stopped it was a person reading the screen.

    So this is the after-the-fact half. It cannot prevent clicking Authorize in
    the wrong window — nothing measured that day could — it catches it before
    the cert is used for anything.

    The filename is never evidence. `fleet-ops docs/deploy/manual.md` Stage 4
    says so, and the fixture that proves it is called `cert.pem.for.janncot`
    while being bound to the operator's own account.
    """
    cert = pathlib.Path(args.cert).expanduser()
    if not cert.is_file():
        huh(f"{cert} is not here")
        print("      That is also the state right before `cloudflared tunnel")
        print("      login` — absent and wrong are different answers, so this")
        print("      reports neither pass nor fail.")
        return UNKNOWN

    binding, err = _cert_binding(cert)
    if err:
        huh(f"{cert}: {err}")
        return UNKNOWN
    if "accountID" not in binding or "zoneID" not in binding:
        huh(f"{cert} carries {sorted(binding) or 'nothing'} — expected accountID and zoneID")
        return UNKNOWN

    token = os.environ.get(args.token_env or "CLOUDFLARE_TOKEN", "")
    if not token:
        huh(f"${args.token_env or 'CLOUDFLARE_TOKEN'} not set — cannot ask "
            "Cloudflare which account owns this domain")
        print(f"      The cert is bound to account {binding['accountID']},")
        print(f"      zone {binding['zoneID']}. Compare by hand, or set the token.")
        return UNKNOWN

    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/zones?name={args.domain}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = json.load(r)
    except Exception as e:  # noqa: BLE001
        huh(f"could not query Cloudflare: {e}")
        return UNKNOWN

    zones = body.get("result") or []
    if len(zones) != 1:
        huh(f"Cloudflare returned {len(zones)} zones named {args.domain}")
        print("      Zero means this token cannot see the zone — which is itself")
        print("      a finding, but not the one this check makes. More than one")
        print("      is ambiguous and picking would invent an answer.")
        return UNKNOWN

    want_zone = zones[0].get("id")
    want_account = (zones[0].get("account") or {}).get("id")
    got_zone, got_account = binding["zoneID"], binding["accountID"]

    wrong = []
    if got_account != want_account:
        wrong.append(("account", got_account, want_account))
    if got_zone != want_zone:
        wrong.append(("zone", got_zone, want_zone))

    if not wrong:
        ok(f"{cert.name} is bound to the account and zone that own {args.domain}")
        print(f"      account {got_account}  zone {got_zone}")
        return PASS

    bad(f"{cert.name} is bound to the wrong Cloudflare account for {args.domain}")
    for what, got, want in wrong:
        print(f"      {what}: cert says {got}")
        print(f"      {' ' * len(what)}  {args.domain} belongs to {want}")
    print("      Re-run `cloudflared tunnel login` in a browser signed in as the")
    print("      account that owns this domain, and check the window before")
    print("      authorising. A tunnel built on this cert answers 1033 and")
    print("      nothing before that point complains.")
    return FAIL


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("escrow")
    e.add_argument("--escrowed-key", required=True)
    e.add_argument("--sops-yaml", default=".sops.yaml")
    e.set_defaults(func=check_escrow)

    h = sub.add_parser("repo-hygiene")
    h.add_argument("--dir", default=".")
    h.add_argument("--deep", action="store_true", help="scan every blob's content")
    h.set_defaults(func=check_repo_hygiene)

    d = sub.add_parser("dns")
    d.add_argument("--domain", required=True)
    d.add_argument("--token-env", default="CLOUDFLARE_TOKEN")
    d.add_argument("--tunnel-credentials", default="cloudflare-tunnel.json")
    d.set_defaults(func=check_dns)

    f = sub.add_parser("flux")
    f.add_argument("--kubeconfig", required=True)
    f.add_argument("--expect-sha", required=True)
    f.set_defaults(func=check_flux)

    l = sub.add_parser("lan")
    l.add_argument("--domain", required=True)
    l.add_argument("--expect-addr", required=True)
    l.set_defaults(func=check_lan)

    g = sub.add_parser("gateway")
    g.add_argument("--node", help="node address talosctl should ask")
    g.add_argument("--talosconfig")
    g.add_argument("--routes-json",
                   help="a captured `talosctl get routes -o json`, instead of asking a node")
    g.add_argument("--timeout", type=int, default=30)
    g.set_defaults(func=check_gateway)

    k = sub.add_parser("deploy-key")
    k.add_argument("--repo", required=True, help="OWNER/NAME on GitHub")
    k.add_argument("--pubkey", default="github-deploy.key.pub")
    k.set_defaults(func=check_deploy_key)

    t = sub.add_parser("tunnel-cert")
    t.add_argument("--domain", required=True)
    t.add_argument("--cert", default="~/.cloudflared/cert.pem")
    t.add_argument("--token-env", default="CLOUDFLARE_TOKEN")
    t.set_defaults(func=check_tunnel_cert)

    args = p.parse_args()
    if args.cmd == "gateway" and not args.node and not args.routes_json:
        p.error("gateway needs --node, or --routes-json to read a capture")
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
