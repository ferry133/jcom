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
"""

from __future__ import annotations

import argparse
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

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
