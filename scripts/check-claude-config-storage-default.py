#!/usr/bin/env python3
"""Assert what an unset `claudecode_config_storage_class` renders to (#76).

Since 2026-09-05 the default is `db_storage_class` — the block tier. The
ruling: claude's auto memory (~/.claude PVC) and explicit memory (PostgreSQL)
never live on NFS. The default could only change AFTER every cluster from
before the ruling migrated and wrote its class into cluster.yaml, because
`storageClassName` is immutable: on an unmigrated cluster the new default
renders a PVC the cluster cannot accept, and the only symptom is a pod that
never starts while every Kustomization reads Ready.

Three answers matter, and the third is the one a happy-path test misses:

  unset, NFS cluster    -> db_storage_class (block), while the workspace PVC
                           stays on default_storage_class (NFS) — the two
                           tiers must decouple, that is the whole point
  unset, db declared    -> follows db_storage_class
  explicitly named      -> kept verbatim. An explicit value is how a cluster
                           RECORDS where its immutable PVC actually is; a
                           default that clobbered it would silently re-render
                           the one PVC that must not move.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
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


BASE = dict(
    cluster_name="rendertest",
    node_cidr="10.9.1.0/24",
    cluster_svc_cidr="10.96.0.0/12",
    bootstrap_distro="talos",
    deployment_profile="full",
    claudecode_auth0=False,
    ttyd_credential="ops:placeholder-not-a-real-credential",
)

# (name, extra cluster.yaml fields, expected claudecode_config_storage_class)
CASES = [
    ("NFS cluster, nothing declared -> block tier, not the NFS class",
     {"storage_backend": "nfs"}, "local-path"),
    ("NFS cluster, db tier declared -> config follows it",
     {"storage_backend": "nfs", "db_storage_class": "longhorn"}, "longhorn"),
    ("explicit record survives -- a not-yet-moved cluster stays where it is",
     {"storage_backend": "nfs", "claudecode_config_storage_class": "sc-nas"},
     "sc-nas"),
    ("bare single-node cluster -- unchanged by #76",
     {}, "local-path"),
]


def main() -> int:
    plugin = load_plugin()
    failed = 0
    answers = set()

    for name, extra, expected in CASES:
        data = dict(BASE, **extra)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                plugin.Plugin(data).data()
            got = data["claudecode_config_storage_class"]
        except Exception as e:  # noqa: BLE001
            print(f"FAIL  {name}\n        render raised {type(e).__name__}: {e}")
            failed += 1
            continue
        answers.add(got)
        if got != expected:
            print(f"FAIL  {name}\n        expected {expected!r}, got {got!r}")
            failed += 1
        else:
            print(f"PASS  {name}\n        config class = {got!r}")

    # The decoupling assertion — acceptance 2 of #76 at the logic level. The
    # workspace PVC takes default_storage_class verbatim (instances j2, the
    # claude-workspace block), so this pair IS "config moves to block, bulk
    # stays on NFS". If the two are equal on an NFS cluster, the default is
    # still following the axis #76 exists to leave.
    data = dict(BASE, storage_backend="nfs")
    with contextlib.redirect_stderr(io.StringIO()):
        plugin.Plugin(data).data()
    if data["default_storage_class"] != "sc-nas":
        print("FAIL  NFS control broke: default_storage_class is "
              f"{data['default_storage_class']!r}, the fixture no longer "
              "tests an NFS cluster at all")
        failed += 1
    elif data["claudecode_config_storage_class"] == data["default_storage_class"]:
        print("FAIL  on an NFS cluster the config PVC still lands on the NFS")
        print("      class — config and bulk did not decouple")
        failed += 1
    else:
        print("PASS  NFS cluster: config "
              f"{data['claudecode_config_storage_class']!r} != workspace "
              f"{data['default_storage_class']!r} — tiers decoupled")

    # A check whose cases all render the same value is not measuring the
    # declared inputs. Same guard as check-claude-instances-default.py.
    if len(answers) < 2:
        print(f"FAIL  every case rendered {answers!r} — the fixture has no")
        print("      discriminating power over the inputs it claims to vary")
        failed += 1

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
