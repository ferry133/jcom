#!/usr/bin/env python3
"""Assert the two-tenant split in front of claude-code (jgct#84).

Ruled by ferry133 2026-09-06: `im` is the factory's support agent, so it uses
the factory's Auth0. That splits one set of values into two, and every way of
getting the split wrong is a gate defect on a root shell with cluster-admin
that the tunnel publishes to the internet:

  factory  auth0.json (gitignored, factory-supplied) -> FACTORY_AUTH0_DOMAIN /
           _CLIENT_ID / _CLIENT_SECRET / FACTORY_ALLOWED_EMAILS. Required on
           every cluster whenever OIDC is on, because every cluster ships the
           base im. Missing file, or an empty allowlist, must FAIL THE RENDER --
           fail-closed at the door instead reads like a broken cluster from
           outside (measured 2026-09-06: a 403 nobody could attribute).

  customer cluster.yaml's claudecode_auth0_* -- required only when the cluster
           names its own instances in claude_instances, and never inherited
           from auth0.json. Inheriting would put a customer's terminal behind
           the factory gate: the mirror image of the defect jgct#64 closed.

The cases below are the two-way version of that: the values must be present
when they are needed, ABSENT-tolerant when they are not, and the two tenants
must not be mixed. A test that only checked the happy path would pass on a
plugin that put everyone behind one tenant, which is the state #84 exists to end.

age_key is stubbed: these cases chdir into a fixture directory (auth0.json is
read relative to the cluster directory), which puts the real age.key out of
reach. The derivations it feeds are covered by check-claudecode-postgres-derive.py.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FACTORY = {
    "domain": "factory.example.auth0.com",
    "client_id": "factory-client-id",
    "client_secret": "factory-client-secret-not-real",
    "allowed_emails": "ops-a@factory.example,ops-b@factory.example",
}
CUSTOMER = {
    "claudecode_auth0_domain": "customer.example.auth0.com",
    "claudecode_auth0_client_id": "customer-client-id",
    "claudecode_auth0_client_secret": "customer-client-secret-not-real",
    "claudecode_allowed_emails": "owner@customer.example",
}

BASE = dict(
    cluster_name="rendertest",
    node_cidr="10.9.1.0/24",
    cluster_svc_cidr="10.96.0.0/12",
    bootstrap_distro="talos",
    deployment_profile="full",
)


def load_plugin():
    """Import templates/scripts/plugin.py without a real makejinja or age.key."""
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
    mod.age_key = lambda *a, **k: "jgct-factory-auth-check-fixed-key"
    return mod


def resolved(plugin, auth0_json: dict | None, **cluster):
    """Run data() in a fixture directory, optionally holding an auth0.json."""
    data = dict(BASE, **cluster)
    with tempfile.TemporaryDirectory() as tmp:
        if auth0_json is not None:
            (Path(tmp) / "auth0.json").write_text(json.dumps(auth0_json))
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                plugin.Plugin(data).data()
        finally:
            os.chdir(cwd)
    return data


def resolved_or(plugin, label, auth0_json, **cluster):
    """resolved(), but a raise becomes a reported failure rather than a
    traceback: a check that dies on the first wrong plugin says less about the
    other cases than one that runs them all."""
    try:
        return resolved(plugin, auth0_json, **cluster)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL  {label}\n        render raised {type(e).__name__}: "
              f"{str(e)[:160]}")
        return None


def expect_error(plugin, label, kinds, needle, auth0_json, **cluster):
    try:
        resolved(plugin, auth0_json, **cluster)
    except kinds as e:
        if needle in str(e):
            print(f"PASS  {label}")
            return 0
        print(f"FAIL  {label}\n        raised {type(e).__name__} without "
              f"{needle!r}: {e}")
        return 1
    print(f"FAIL  {label}\n        no error raised")
    return 1


GUARD = ROOT / "scripts" / "check-claudecode-auth.py"
COMPLETE = json.dumps(FACTORY)
NO_LIST = json.dumps(dict(FACTORY, allowed_emails=""))


def run_guard(auth0_json: str | None, cluster_yaml: str) -> tuple[int, str]:
    """Run check-claudecode-auth.py over a fixture cluster directory.

    That guard is in ci-checks.py's SKIP list -- it takes a cluster.yaml, and a
    bare checkout has none -- so until this, rewriting it was unverified by
    anything that runs on its own. It is the SECOND step of `:configure:` and
    the render is tenth, so its message is what an operator acts on: leaving it
    unexercised means the words that reach a human are the ones nothing checks.
    """
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        if auth0_json is not None:
            (d / "auth0.json").write_text(auth0_json)
        (d / "cluster.yaml").write_text(cluster_yaml)
        r = subprocess.run([sys.executable, str(GUARD), str(d / "cluster.yaml")],
                           capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr


def check_guard() -> int:
    """The same two-tenant rule, as the operator meets it."""
    failed = 0
    base = "cluster_name: t\nclaude_instances: []\n"
    cases = [
        ("guard: factory file present, no own instances -> ok",
         COMPLETE, base, 0, ""),
        ("guard: auth0.json absent -> refused",
         None, base, 1, "auth0.json is not in"),
        ("guard: empty allowed_emails -> refused",
         NO_LIST, base, 1, "allowed_emails"),
        ("guard: claudecode_auth0_shared -> refused",
         COMPLETE, base + "claudecode_auth0_shared: true\n", 1, "REFUSED"),
        ("guard: own instance without customer tenant -> refused",
         COMPLETE, 'cluster_name: t\nclaude_instances: ["cc"]\n', 1,
         "CUSTOMER instances"),
        ("guard: own instance with customer tenant -> ok",
         COMPLETE,
         'cluster_name: t\nclaude_instances: ["cc"]\n'
         "claudecode_auth0_domain: c.auth0.com\n"
         "claudecode_auth0_client_id: ci\n"
         "claudecode_auth0_client_secret: cs\n"
         "claudecode_allowed_emails: owner@c.example\n", 0, ""),
    ]
    for label, auth0_json, cluster_yaml, want_rc, needle in cases:
        rc, out = run_guard(auth0_json, cluster_yaml)
        if rc != want_rc:
            print(f"FAIL  {label}\n        exit {rc}, wanted {want_rc}: "
                  f"{out.strip()[:160]}")
            failed += 1
        elif needle and needle not in out:
            print(f"FAIL  {label}\n        exit {rc} as wanted but the message "
                  f"never says {needle!r}: {out.strip()[:160]}")
            failed += 1
        else:
            print(f"PASS  {label}")
    return failed


def main() -> int:
    plugin = load_plugin()
    failed = 0

    # 1. The ordinary cluster: factory file present, no instances of its own.
    d = resolved_or(plugin, "factory tenant from auth0.json", FACTORY,
                    claude_instances=[])
    if d is None:
        failed += 1
        d = {}
    got = {k: d.get(f"factory_auth0_{k}") for k in
           ("domain", "client_id", "client_secret")}
    want = {k: FACTORY[k] for k in ("domain", "client_id", "client_secret")}
    if got != want:
        print(f"FAIL  factory OIDC values not taken from auth0.json\n"
              f"        got {got}")
        failed += 1
    elif d.get("factory_allowed_emails") != FACTORY["allowed_emails"]:
        print(f"FAIL  factory allowlist not taken from auth0.json: "
              f"{d.get('factory_allowed_emails')!r}")
        failed += 1
    else:
        print("PASS  factory tenant (4 values) comes from auth0.json")

    # 2. ...and it does NOT demand a customer tenant it has no instance for.
    if any(d.get(k) for k in CUSTOMER):
        print("FAIL  customer values appeared on a cluster that declared none — "
              "auth0.json leaked into the customer fields")
        failed += 1
    else:
        print("PASS  no instances -> customer tenant neither required nor "
              "inherited")

    # 3. Missing auth0.json fails the render (not a blank gate).
    failed += expect_error(
        plugin, "auth0.json absent -> render error",
        (FileNotFoundError, KeyError), "auth0.json", None, claude_instances=[])

    # 4. Present but with no allowlist: the door that admits nobody.
    no_list = dict(FACTORY, allowed_emails="")
    failed += expect_error(
        plugin, "empty allowed_emails -> render error",
        (KeyError, FileNotFoundError), "allowed_emails", no_list,
        claude_instances=[])

    # 5. The retired flag is refused, not ignored.
    failed += expect_error(
        plugin, "claudecode_auth0_shared -> refused",
        KeyError, "claudecode_auth0_shared", FACTORY,
        claude_instances=[], claudecode_auth0_shared=True)

    # 6. A cluster WITH its own instance must declare the customer tenant.
    failed += expect_error(
        plugin, "extra instance without customer tenant -> render error",
        KeyError, "claudecode_auth0_domain", FACTORY,
        claude_instances=["cc"])

    # 7. With both declared, the two tenants stay apart. This is the assertion
    #    a one-tenant plugin fails: it would answer the factory values here.
    d = resolved_or(plugin, "both tenants declared", FACTORY,
                    claude_instances=["cc"], **CUSTOMER)
    if d is None:
        failed += 1
        d = {}
    # Assert the factory half is PRESENT before comparing: `None != customer`
    # would also read as "distinct", so a plugin that derives no factory values
    # at all would pass this case vacuously — the undiscriminating shape.
    if d.get("factory_auth0_domain") != FACTORY["domain"]:
        print(f"FAIL  factory domain missing/wrong with both declared: "
              f"{d.get('factory_auth0_domain')!r}")
        failed += 1
    elif d.get("claudecode_auth0_domain") != CUSTOMER["claudecode_auth0_domain"]:
        print(f"FAIL  customer domain was overwritten: "
              f"{d.get('claudecode_auth0_domain')!r}")
        failed += 1
    elif d.get("factory_auth0_domain") == d.get("claudecode_auth0_domain"):
        print("FAIL  factory and customer tenants resolved to the same value — "
              "the split is not real")
        failed += 1
    elif d.get("factory_allowed_emails") == d.get("claudecode_allowed_emails"):
        print("FAIL  factory and customer allowlists are the same value — the "
              "customer's people would open the factory agent's door")
        failed += 1
    else:
        print("PASS  both declared -> tenants stay distinct")

    # 8. claudecode_auth0: false needs no auth0.json at all — OIDC is off, and
    #    demanding the factory file there would block the basic-auth escape
    #    hatch that exists for clusters which cannot accept the Auth0 trade.
    try:
        resolved(plugin, None, claude_instances=[], claudecode_auth0=False,
                 ttyd_credential="ops:placeholder-not-a-real-credential")
    except Exception as e:  # noqa: BLE001
        print(f"FAIL  claudecode_auth0:false still demanded auth0.json: "
              f"{type(e).__name__}: {e}")
        failed += 1
    else:
        print("PASS  claudecode_auth0:false -> auth0.json not required")

    failed += check_guard()

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
