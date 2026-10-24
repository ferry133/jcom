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
                             grants={"lan_ip": 0}, psa_level="restricted"))
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

    # Grants with no platform component yet.
    refuses("l2 is refused, naming the missing component",
            {"app_repos": [vendor(grants={"l2": True})]},
            "grants.l2", "jg-base#187", "task 8.1")
    refuses("devices is refused, naming the missing component",
            {"app_repos": [vendor(grants={"devices": ["/dev/ttyUSB0"]})]},
            "grants.devices", "jg-base#188", "task 8.2")

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
