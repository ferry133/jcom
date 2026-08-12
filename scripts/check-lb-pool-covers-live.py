#!/usr/bin/env python3
"""Check the rendered LoadBalancer pool covers every address currently assigned.

Run this BEFORE pushing a narrowed pool. "Did anything break after narrowing?"
is the wrong question: Cilium does not revoke an address when the pool that
supplied it goes away, so a missing address looks fine until the Service is next
recreated — a Helm upgrade or a node event, days later, with nothing connecting
cause to effect. See openspec/changes/deployment-profiles/design.md D26.

Usage:  KUBECONFIG=… SOPS_AGE_KEY_FILE=… ./scripts/check-lb-pool-covers-live.py [repo]
Exit 0 if every assigned address is covered, 1 otherwise.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
from pathlib import Path

SECRETS = "kubernetes/components/sops/cluster-secrets.sops.yaml"


def rendered_blocks(repo: Path) -> str:
    out = subprocess.run(
        ["sops", "-d", str(repo / SECRETS)], capture_output=True, text=True
    )
    if out.returncode != 0:
        sys.exit(f"could not decrypt {SECRETS}: {out.stderr.strip()}")
    blocks = "[]"
    for line in out.stdout.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "LB_POOL_BLOCKS":
            blocks = value.strip().strip("'\"") or "[]"
    return blocks


def covered_addresses(blocks: str) -> set[ipaddress.IPv4Address]:
    covered: set[ipaddress.IPv4Address] = set()
    for block in json.loads(blocks):
        if "cidr" in block:
            covered |= set(ipaddress.ip_network(block["cidr"]).hosts())
            continue
        lo = int(ipaddress.ip_address(block["start"]))
        hi = int(ipaddress.ip_address(block["stop"]))
        covered |= {ipaddress.ip_address(n) for n in range(lo, hi + 1)}
    return covered


def assigned_addresses() -> list[tuple[str, str]]:
    jsonpath = (
        "{range .items[*]}{.metadata.namespace}/{.metadata.name}="
        "{.status.loadBalancer.ingress[0].ip}{'\\n'}{end}"
    ).replace("'", '"')
    out = subprocess.run(
        ["kubectl", "get", "svc", "-A", "--field-selector",
         "spec.type=LoadBalancer", "-o", f"jsonpath={jsonpath}"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        sys.exit(f"kubectl failed: {out.stderr.strip()}")
    rows = []
    for line in filter(None, (l.strip() for l in out.stdout.splitlines())):
        name, _, ip = line.rpartition("=")
        if ip:
            rows.append((name, ip))
    return rows


def main() -> int:
    repo = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    covered = covered_addresses(rendered_blocks(repo))
    print(f"pool covers {len(covered)} address(es): "
          f"{', '.join(sorted(str(a) for a in covered))}\n")
    missing = []
    for name, ip in assigned_addresses():
        hit = ipaddress.ip_address(ip) in covered
        print(f"  {'ok  ' if hit else 'MISS'}  {name:38} {ip}")
        if not hit:
            missing.append((name, ip))

    if missing:
        print(f"\nFAIL — {len(missing)} assigned address(es) not in the pool.")
        print("Applying this would leave them working until the Service is next")
        print("recreated, then silently unassign it. Add them and re-render.")
        print("If instead you are deliberately moving a Service to a new")
        print("address (lan_shared_addr), confirm the NEW address is listed")
        print("above — this check only knows where Services are today.")
        return 1
    print("\nok — every assigned address is covered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
