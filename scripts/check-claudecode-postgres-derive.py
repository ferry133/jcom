#!/usr/bin/env python3
"""Assert how explicit-memory PostgreSQL creds are derived (jgct#85).

Since 2026-09-06 postgres ships from jg-base as a base app and cluster.yaml no
longer carries the password or the URL. plugin.py derives both:

  claudecode_postgres_password  HMAC(age.key, "claudecode-postgres:<cluster>"),
                                hex — cluster.yaml may override to rotate.
  claude_code_database_url      DERIVED from that password, never a field:
                                postgresql://claudecode:<pw>@postgres.claudecode.svc/claudecode

Four things this checks, and each is a way the change fails silently:

  hex output          the password goes into a URL; base64url's -/_/= would need
                      percent-encoding and a URL parser would trip. hex never does.
  URL carries THE pw  a URL composed from a different value than the password in
                      cluster-secrets is two truths that drift (jg-base#73's whole
                      reason for composing here, not in jg-base).
  override wins       rotation has to have an exit; a default that clobbered an
                      explicit value would make rotation impossible.
  extras render error listing claudecode/postgres as an extra makes the user repo
                      and base fight over one Kustomization name — must abort.

age_key is stubbed to a fixed string: this tests the DERIVATION, deterministically,
without a real age.key (a bare checkout has none). The value is not a real secret.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import re
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


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
    return mod


BASE = dict(
    cluster_name="rendertest",
    node_cidr="10.9.1.0/24",
    cluster_svc_cidr="10.96.0.0/12",
    bootstrap_distro="talos",
    deployment_profile="full",
    claudecode_auth0=False,
    ttyd_credential="ops:placeholder-not-a-real-credential",
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXPECT_URL = ("postgresql://claudecode:{pw}"
              "@postgres.claudecode.svc/claudecode")


def resolved(plugin, **extra):
    data = dict(BASE, **extra)
    with contextlib.redirect_stderr(io.StringIO()):
        plugin.Plugin(data).data()
    return data


def main() -> int:
    plugin = load_plugin()
    failed = 0

    # 1. Derived password is hex; URL is composed from exactly that password.
    d = resolved(plugin)
    pw = d.get("claudecode_postgres_password")
    url = d.get("claude_code_database_url")
    if not (isinstance(pw, str) and HEX64.match(pw)):
        print(f"FAIL  password not 64-char hex: {pw!r}")
        failed += 1
    else:
        print(f"PASS  password is 64-char hex")
    if url != EXPECT_URL.format(pw=pw):
        print(f"FAIL  URL is not composed from the password\n"
              f"        got {url!r}")
        failed += 1
    else:
        print(f"PASS  URL carries the derived password, expected form")

    # 2. cluster.yaml override wins (rotation exit) and the URL follows it.
    d = resolved(plugin, claudecode_postgres_password="rotated-value-123")
    if d.get("claudecode_postgres_password") != "rotated-value-123":
        print(f"FAIL  override ignored: {d.get('claudecode_postgres_password')!r}")
        failed += 1
    elif "rotated-value-123" not in (d.get("claude_code_database_url") or ""):
        print(f"FAIL  URL did not follow the override: "
              f"{d.get('claude_code_database_url')!r}")
        failed += 1
    else:
        print("PASS  override wins and the URL follows it")

    # 3. extras listing claudecode/postgres aborts the render.
    try:
        resolved(plugin, extras=["claudecode/postgres"])
    except KeyError as e:
        if "claudecode/postgres" in str(e):
            print("PASS  extras claudecode/postgres -> render error")
        else:
            print(f"FAIL  wrong KeyError: {e}")
            failed += 1
    else:
        print("FAIL  extras claudecode/postgres did NOT abort")
        failed += 1

    # 4. Discriminating power: the password is a function of cluster_name, so
    #    two names must not derive the same value (a constant would pass 1-3).
    a = resolved(plugin, cluster_name="alpha").get("claudecode_postgres_password")
    b = resolved(plugin, cluster_name="bravo").get("claudecode_postgres_password")
    if a == b:
        print("FAIL  two cluster names derived the SAME password — not keyed "
              "on cluster_name")
        failed += 1
    else:
        print("PASS  distinct cluster names derive distinct passwords")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
