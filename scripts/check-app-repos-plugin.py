#!/usr/bin/env python3
"""What plugin.py does to `app_repos` entries (jgct#214 task 3.2).

The schema (task 3.1, `check-app-repos-schema.py`) decides which entries are
well-formed. This decides what a well-formed entry becomes: the defaults the
templates will read, the PSA level derived from its grants, and the refusals
that only plugin.py can make because they need a value plugin.py derives —
chiefly `lb_pool_blocks`, which a tenant LAN pool must not overlap (Cilium
reports an overlap as PoolConflict and the narrower pool never allocates, with
no other symptom: jg-base networks.yaml 2026-08-12, jgct#10).

It runs the real Plugin.data(), not app_repos() alone, so the ordering
(app_repos after lb_pool_blocks) is under test too. Loader copied from
check-lb-pool-render.py, including its no-bytecode rule.

A refusal is asserted by the text it must contain, not by "it raised": the
reader of a refusal has to be told which ranges collide, and a raise for some
other reason (a KeyError on a field the fixture forgot) reads exactly like the
right one.

Exit 0 if every case matches, 1 otherwise.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_plugin():
    """Import templates/scripts/plugin.py without a real makejinja."""
    # No bytecode: these guards get run against a MUTATED plugin.py to show
    # they can still tell right from wrong, and CPython accepts a cached .pyc
    # when the source mtime (one-second resolution) AND size still match. A
    # minimal mutation is exactly the shape that matches both -- swap a word
    # for one of equal length, restore within the same second, and the stale
    # bytecode is served. Both directions have been seen; the quiet one is a
    # negative control that passes for a reason that no longer exists
    # (jgct#96, reproduced deterministically 2026-09-10).
    sys.dont_write_bytecode = True
    importlib.invalidate_caches()
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


# TEST-NET-1 addresses throughout. claudecode_auth0 is off so the render does
# not need an auth0.json. Two declared gateway addresses narrow the shared pool
# to 192.0.2.10 and 192.0.2.11.
BASE = dict(
    cluster_name="rendertest",
    node_cidr="192.0.2.0/24",
    bootstrap_distro="talos",
    claudecode_auth0=False,
    ttyd_credential="ops:placeholder-not-a-real-credential",
    deployment_profile="full",
    cluster_gateway_addr="192.0.2.10",
    cluster_dns_gateway_addr="192.0.2.11",
)


def vendor(**kw):
    return dict(dict(name="acme", repository="fixture/acme-app", kind="vendor"), **kw)


def lan(n, start, stop, **kw):
    return vendor(grants=dict(lan_ip=n), lan_ip_range=dict(start=start, stop=stop), **kw)


def render(extra):
    data = copy.deepcopy(dict(BASE, **extra))
    plugin = load_plugin()
    plugin.Plugin(data).data()
    return data


def main() -> int:
    # data() derives two secrets from ./age.key. Render from a temp dir holding
    # a throwaway key of its own rather than from the repo root: this works
    # standalone as well as under ci-checks.py (which writes one at the root),
    # and never writes a key file into a checkout.
    if shutil.which("age-keygen") is None:
        print("huh   age-keygen not on PATH — CANNOT MEASURE (this is not a pass)")
        return 2
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["age-keygen", "-o", os.path.join(d, "age.key")],
                       check=True, capture_output=True)
        cwd = os.getcwd()
        os.chdir(d)
        try:
            return run_cases()
        finally:
            os.chdir(cwd)


def run_cases() -> int:
    results: list[bool] = []

    def report(label, good, detail=""):
        results.append(good)
        print(f"{'PASS' if good else 'FAIL'}  {label}")
        if detail and not good:
            print(f"        {detail}")

    def accepts(label, extra, check):
        try:
            data = render(extra)
        except Exception as e:  # noqa: BLE001
            report(label, False, f"render raised {type(e).__name__}: {e}")
            return
        ok, detail = check(data)
        report(label, ok, detail)

    def refuses(label, extra, *must_contain):
        try:
            render(extra)
        except Exception as e:  # noqa: BLE001
            msg = str(e)
            missing = [m for m in must_contain if m not in msg]
            report(label, not missing,
                   f"raised, but the message lacks {missing}: {msg}")
            return
        report(label, False, "rendered; expected a refusal")

    def entry(data, i=0):
        return data["app_repos"][i]

    def expect(data, i, **want):
        got = {k: entry(data, i).get(k) for k in want}
        return got == want, f"expected {want}, got {got}"

    # 0: the harness and the absent case.
    accepts("0  no app_repos: renders, app_repos is []", {},
            lambda d: (d["app_repos"] == [], f"app_repos={d.get('app_repos')!r}"))

    # Defaults.
    accepts("a minimal entry gets branch, namespaces, quota, grants, restricted",
            {"app_repos": [vendor()]},
            lambda d: expect(d, 0, branch="main", namespaces=["acme"],
                             quota={"cpu": "4", "memory": "8Gi", "pods": 50},
                             grants={"lan_ip": 0, "devices": {}}, psa_level="restricted",
                             device_quota={"serial": 0}))
    accepts("a partial quota keeps what it set and fills the rest",
            {"app_repos": [vendor(quota={"cpu": "2"})]},
            lambda d: expect(d, 0, quota={"cpu": "2", "memory": "8Gi", "pods": 50}))
    accepts("declared branch and namespaces are kept",
            {"app_repos": [vendor(branch="prod", namespaces=["a1", "a2"])]},
            lambda d: expect(d, 0, branch="prod", namespaces=["a1", "a2"]))

    # PSA derivation (design D9).
    accepts("baseline grant -> baseline",
            {"app_repos": [vendor(grants={"baseline": True})]},
            lambda d: expect(d, 0, psa_level="baseline"))
    accepts("host_network grant -> privileged",
            {"app_repos": [vendor(grants={"host_network": True})]},
            lambda d: expect(d, 0, psa_level="privileged"))
    accepts("host_network beats baseline -> privileged",
            {"app_repos": [vendor(grants={"host_network": True, "baseline": True})]},
            lambda d: expect(d, 0, psa_level="privileged"))
    accepts("grants set to false -> restricted",
            {"app_repos": [vendor(grants={"host_network": False, "baseline": False,
                                          "l2": False})]},
            lambda d: expect(d, 0, psa_level="restricted"))

    # LAN pools.
    accepts("lan_ip 2 in a disjoint range renders",
            {"app_repos": [lan(2, "192.0.2.200", "192.0.2.201")]},
            lambda d: expect(d, 0, psa_level="restricted"))
    accepts("a range ending one below the shared pool renders (boundary)",
            {"app_repos": [lan(1, "192.0.2.9", "192.0.2.9")]},
            lambda d: (True, ""))
    refuses("a range overlapping the narrowed shared pool is refused, naming both",
            {"app_repos": [lan(2, "192.0.2.11", "192.0.2.12")]},
            "192.0.2.11-192.0.2.12", "192.0.2.10-192.0.2.10, 192.0.2.11-192.0.2.11",
            "PoolConflict")
    # Both ends of the interval test: the case above overlaps at the range's
    # FIRST address, this one at its LAST.
    refuses("a range whose last address is the shared pool's first is refused",
            {"app_repos": [lan(1, "192.0.2.5", "192.0.2.10")]},
            "192.0.2.5-192.0.2.10", "PoolConflict")
    refuses("on the whole-node_cidr pool any LAN range is refused, naming it",
            {"cluster_gateway_addr": None, "cluster_dns_gateway_addr": None,
             "app_repos": [lan(1, "192.0.2.200", "192.0.2.200")]},
            "192.0.2.200-192.0.2.200", "192.0.2.0/24")
    refuses("two tenants' ranges overlapping are refused, naming both",
            {"app_repos": [lan(2, "192.0.2.200", "192.0.2.201"),
                           lan(1, "192.0.2.201", "192.0.2.201", name="other",
                               repository="fixture/other")]},
            "app_repos[other]", "app_repos[acme]", "192.0.2.200-192.0.2.201")
    refuses("a range smaller than lan_ip is refused",
            {"app_repos": [lan(3, "192.0.2.200", "192.0.2.201")]},
            "holds 2 address(es)", "grants.lan_ip is 3")
    refuses("a range with stop below start is refused",
            {"app_repos": [lan(1, "192.0.2.201", "192.0.2.200")]},
            "stop is below start")
    refuses("lan_ip on an appliance is refused",
            {"deployment_profile": "appliance",
             "app_repos": [lan(1, "192.0.2.200", "192.0.2.200")]},
            "appliance", "discovered at runtime")

    # grants.l2 (jg-base#187, jgct#240). The shared pool is 192.0.2.10-11 and
    # the assumed gateway .1, so .20-.21 is clear of everything.
    def l2(start, stop, iface="enp1s0", **kw):
        return vendor(grants={"l2": True},
                      l2_network=dict(interface=iface, start=start, stop=stop), **kw)
    ROUTED = {"lan_routed_cidrs": ["198.51.100.0/24"]}

    def nads(d, i=0):
        return [(n["name"], json.loads(n["config"])) for n in entry(d, i)["l2_nads"]]

    def l2_ok(d):
        got = nads(d)
        want_names = ["lan-192-0-2-20", "lan-192-0-2-21"]
        conf = got[0][1] if got else {}
        plugins = conf.get("plugins", [])
        cfg = plugins[0] if plugins else {}
        ok = ([n for n, _ in got] == want_names
              and conf.get("name") == want_names[0] and "type" not in conf
              and [p.get("type") for p in plugins] == ["macvlan", "sbr"]
              and cfg.get("master") == "enp1s0"
              and cfg.get("ipam", {}).get("addresses") == [{"address": "192.0.2.20/24"}]
              and cfg.get("ipam", {}).get("routes") == [{"dst": "198.51.100.0/24",
                                                         "gw": "192.0.2.1"}]
              and "gateway" not in cfg.get("ipam", {}))
        return ok, f"got {got}"
    accepts("l2 renders one NAD per address as a macvlan+sbr conflist, routes via the gateway, no default route",
            dict(ROUTED, app_repos=[l2("192.0.2.20", "192.0.2.21")]), l2_ok)
    accepts("l2 with lan_routed_cidrs [] renders NADs with no routes",
            {"lan_routed_cidrs": [], "app_repos": [l2("192.0.2.20", "192.0.2.20")]},
            lambda d: (nads(d)[0][1]["plugins"][0]["ipam"]["routes"] == [], f"got {nads(d)}"))
    accepts("l2 leaves the PSA level alone (restricted)",
            dict(ROUTED, app_repos=[l2("192.0.2.20", "192.0.2.20")]),
            lambda d: expect(d, 0, psa_level="restricted"))
    accepts("no l2 tenant: lan_routed_cidrs is not required and l2_nads absent",
            {"app_repos": [vendor()]},
            lambda d: ("l2_nads" not in entry(d), f"entry={entry(d)}"))
    refuses("l2 without l2_network is refused",
            dict(ROUTED, app_repos=[vendor(grants={"l2": True})]),
            "grants.l2 is set without l2_network")
    refuses("l2_network without the grant is refused",
            dict(ROUTED, app_repos=[vendor(l2_network=dict(
                interface="enp1s0", start="192.0.2.20", stop="192.0.2.20"))]),
            "l2_network is set but grants.l2 is not")
    refuses("l2 without lan_routed_cidrs is refused, saying [] is the way out",
            {"app_repos": [l2("192.0.2.20", "192.0.2.20")]},
            "lan_routed_cidrs is not set", "or [] if there is none")
    refuses("a lan_routed_cidrs entry overlapping node_cidr is refused",
            {"lan_routed_cidrs": ["192.0.2.0/25"],
             "app_repos": [l2("192.0.2.20", "192.0.2.20")]},
            "192.0.2.0/25 overlaps node_cidr 192.0.2.0/24")
    refuses("overlapping lan_routed_cidrs entries are refused, naming both",
            {"lan_routed_cidrs": ["198.51.100.0/24", "198.51.100.128/25"],
             "app_repos": [l2("192.0.2.20", "192.0.2.20")]},
            "198.51.100.0/24 and 198.51.100.128/25 overlap")
    refuses("a lan_routed_cidrs entry with host bits is refused",
            {"lan_routed_cidrs": ["198.51.100.7/24"],
             "app_repos": [l2("192.0.2.20", "192.0.2.20")]},
            "198.51.100.7/24", "host bits")
    refuses("a gateway outside node_cidr is refused",
            dict(ROUTED, node_default_gateway="203.0.113.1",
                 app_repos=[l2("192.0.2.20", "192.0.2.20")]),
            "node_default_gateway 203.0.113.1 is outside node_cidr")
    refuses("an l2 range outside node_cidr is refused",
            dict(ROUTED, app_repos=[l2("203.0.113.20", "203.0.113.20")]),
            "not inside node_cidr 192.0.2.0/24")
    refuses("an l2 range holding the gateway is refused",
            dict(ROUTED, app_repos=[l2("192.0.2.1", "192.0.2.2")]),
            "includes node_default_gateway 192.0.2.1")
    refuses("an l2 range holding the broadcast address is refused",
            dict(ROUTED, app_repos=[l2("192.0.2.250", "192.0.2.255")]),
            "broadcast")
    refuses("an l2 range holding a node is refused, naming it",
            dict(ROUTED, nodes=[{"name": "n1", "address": "192.0.2.30"}],
                 app_repos=[l2("192.0.2.29", "192.0.2.31")]),
            "includes node n1 (192.0.2.30)")
    refuses("an l2 range overlapping the shared pool is refused (first address)",
            dict(ROUTED, app_repos=[l2("192.0.2.11", "192.0.2.12")]),
            "overlaps lb_pool_blocks")
    refuses("an l2 range overlapping the shared pool is refused (last address)",
            dict(ROUTED, app_repos=[l2("192.0.2.5", "192.0.2.10")]),
            "overlaps lb_pool_blocks")
    refuses("an l2 range overlapping another tenant's lan_ip_range is refused",
            dict(ROUTED, app_repos=[lan(1, "192.0.2.200", "192.0.2.200"),
                                    l2("192.0.2.200", "192.0.2.200", name="other",
                                       repository="fixture/other")]),
            "app_repos[other].l2_network", "app_repos[acme].lan_ip_range")
    refuses("a lan_ip_range overlapping an earlier tenant's l2 range is refused",
            dict(ROUTED, app_repos=[l2("192.0.2.200", "192.0.2.200"),
                                    lan(1, "192.0.2.200", "192.0.2.200", name="other",
                                        repository="fixture/other")]),
            "app_repos[other].lan_ip_range", "app_repos[acme].l2_network")
    refuses("two tenants' l2 ranges overlapping are refused",
            dict(ROUTED, app_repos=[l2("192.0.2.20", "192.0.2.21"),
                                    l2("192.0.2.21", "192.0.2.22", name="other",
                                       repository="fixture/other")]),
            "app_repos[other].l2_network", "app_repos[acme].l2_network")
    refuses("an l2 range wider than 16 addresses is refused",
            dict(ROUTED, app_repos=[l2("192.0.2.20", "192.0.2.36")]),
            "holds 17 addresses", "at most 16")
    refuses("an l2 range with stop below start is refused",
            dict(ROUTED, app_repos=[l2("192.0.2.21", "192.0.2.20")]),
            "stop is below start")
    accepts("on an appliance an l2 range below the probe window renders",
            dict(ROUTED, deployment_profile="appliance",
                 app_repos=[l2("192.0.2.19", "192.0.2.19")]),
            lambda d: ([n for n, _ in nads(d)] == ["lan-192-0-2-19"], f"got {nads(d)}"))
    refuses("on an appliance an l2 range touching the probe window is refused",
            dict(ROUTED, deployment_profile="appliance",
                 app_repos=[l2("192.0.2.195", "192.0.2.200")]),
            "192.0.2.200-192.0.2.254", "lan-address-probe")

    # grants.devices (jg-base#188): a class -> count map, every class quoted
    # in the quota (0 without the grant), and only classes jg-base advertises.
    accepts("devices {serial: 2} -> device_quota serial 2, PSA unchanged",
            {"app_repos": [vendor(grants={"devices": {"serial": 2}})]},
            lambda d: expect(d, 0, device_quota={"serial": 2}, psa_level="restricted"))
    accepts("no devices grant -> device_quota serial 0 (the second fence)",
            {"app_repos": [vendor(grants={"baseline": True})]},
            lambda d: expect(d, 0, device_quota={"serial": 0}))
    refuses("a device class jg-base does not advertise is refused, listing what exists",
            {"app_repos": [vendor(grants={"devices": {"zigbee": 1}})]},
            "grants.devices names zigbee", "it has: serial")

    # tenant_key(): the file-name contract with the provisioning skill.
    def key_case(label, files, kind, must, forbid=""):
        import tempfile as _t
        with _t.TemporaryDirectory() as d:
            for name, body in files.items():
                (Path(d) / name).write_text(body)
            try:
                load_plugin().tenant_key("acme", kind, directory=d)
            except Exception as e:  # noqa: BLE001
                msg = str(e)
                ok = must in msg and not (forbid and forbid in msg)
                report(label, ok, f"message: {msg}")
                return
            report(label, False, "returned; expected a refusal")

    key_case("tenant_key: a missing file is refused, naming the path",
             {}, "deploy", "acme.deploy.key not found")
    key_case("tenant_key: a public half under the private name is refused, "
             "without echoing it",
             {"acme.deploy.key": "ssh-ed25519 AAAAC3NzaFAKEPUBLIC acme\n"},
             "deploy", "does not look like a private deploy key", forbid="AAAAC3NzaFAKEPUBLIC")
    key_case("tenant_key: an age public key is refused",
             {"acme.age.key": "age1fakepublicrecipient\n"}, "age",
             "does not look like a private age key", forbid="age1fakepublic")
    try:
        import tempfile as _t
        with _t.TemporaryDirectory() as d:
            (Path(d) / "acme.write.key").write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n")
            got = load_plugin().tenant_key("acme", "write", directory=d)
        report("tenant_key: a well-formed write key is returned stripped",
               got.startswith("-----BEGIN") and got.endswith("-----"), f"got {got!r}")
    except Exception as e:  # noqa: BLE001
        report("tenant_key: a well-formed write key is returned stripped", False, str(e))

    passed = sum(results)
    print(f"ok — {passed}/{len(results)} app_repos plugin cases as expected"
          if all(results) else
          f"{len(results) - passed}/{len(results)} app_repos plugin case(s) FAILED")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
