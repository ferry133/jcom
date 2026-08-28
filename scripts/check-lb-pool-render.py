#!/usr/bin/env python3
"""Assert what `lb_pool_blocks` renders to, per deployment profile.

Exists because of ferry133/jg-cluster-template#10, whose defect was not a wrong
value but an **unreachable branch**: the appliance case sat behind `if addrs:`,
and `lan_shared_addr` back-filled two of the three fields `addrs` is built from.
So the branch stopped executing the moment an operator followed
fleet-ops docs/operations/router-dns.md and declared the shared address — and nothing in
the source looked wrong, because the branch was still there.

An unreachable branch is invisible to review and to every check that reads the
rendered output of *some other* profile. The only thing that catches it is
asserting the value for each profile, which is what this does.

It exercises the real Plugin.data() rather than a copy of its logic. A
reimplementation here would drift, and the copy that drifts is the one that
keeps passing.

Exit 0 if every case matches, 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_plugin():
    """Import templates/scripts/plugin.py without a real makejinja."""
    mj = types.ModuleType("makejinja")
    pl = types.ModuleType("makejinja.plugin")

    class _Base:
        def __init__(self, *a, **k):
            pass

    pl.Plugin, pl.Data, pl.Filters, pl.Functions = _Base, dict, list, list
    mj.plugin = pl
    sys.modules.setdefault("makejinja", mj)
    sys.modules.setdefault("makejinja.plugin", pl)
    spec = importlib.util.spec_from_file_location(
        "_plugin", ROOT / "templates" / "scripts" / "plugin.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# claudecode_auth0 is off in every case so the render does not require an
# auth0.json; it has nothing to do with the pool.
BASE = dict(
    cluster_name="rendertest",
    node_cidr="10.9.1.0/24",
    bootstrap_distro="talos",
    claudecode_auth0=False,
    ttyd_credential="ops:placeholder-not-a-real-credential",
)

CASES = [
    # (name, extra cluster.yaml fields, expected lb_pool_blocks)
    (
        "appliance with lan_shared_addr declared  (#10)",
        dict(deployment_profile="appliance", lan_shared_addr="10.9.1.254"),
        [],
    ),
    (
        "appliance with nothing declared",
        dict(deployment_profile="appliance"),
        [],
    ),
    (
        "full profile with addresses declared",
        dict(deployment_profile="full",
             cluster_gateway_addr="10.9.1.10",
             cluster_dns_gateway_addr="10.9.1.11"),
        [{"start": "10.9.1.10", "stop": "10.9.1.10"},
         {"start": "10.9.1.11", "stop": "10.9.1.11"}],
    ),
    (
        "full profile with nothing declared falls back to the node CIDR",
        dict(deployment_profile="full"),
        [{"cidr": "10.9.1.0/24"}],
    ),
    (
        "prosumer sharing an address still declares its own pool",
        dict(deployment_profile="prosumer", lan_shared_addr="10.9.1.254"),
        [{"start": "10.9.1.254", "stop": "10.9.1.254"}],
    ),
]


def main() -> int:
    plugin = load_plugin()
    failed = 0
    for name, extra, expected in CASES:
        data = dict(BASE, **extra)
        try:
            plugin.Plugin(data).data()
            got = json.loads(data["lb_pool_blocks"])
        except Exception as e:  # noqa: BLE001
            print(f"FAIL  {name}\n        render raised {type(e).__name__}: {e}")
            failed += 1
            continue
        if got == expected:
            print(f"PASS  {name}\n        {json.dumps(got)}")
        else:
            print(f"FAIL  {name}\n        expected {json.dumps(expected)}"
                  f"\n        got      {json.dumps(got)}")
            failed += 1

    print()
    if failed:
        print(f"{failed} case(s) failed.")
        print("An appliance emitting a NON-empty pool is #10 returning: it will")
        print("overlap lan-address-probe's discovered pool, Cilium will disable")
        print("the whole discovered pool with PoolConflict=True, and every LAN")
        print("name in the cluster domain goes NXDOMAIN while the public tunnel")
        print("keeps answering — which is why nobody notices.")
        return 1
    print(f"ok — {len(CASES)} cases match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
