#!/usr/bin/env python3
"""Assert what the unset claude-code storage-class fields render to (#76, #191).

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

`claudecode_workspace_storage_class` (#191) is the other half and the axis is
the opposite one: the workspace is bulk, so its default FOLLOWS
default_storage_class, and the field exists so a cluster deploying Longhorn can
stop it following. Two answers matter there, and the second is the point:

  unset                 -> default_storage_class verbatim. This is what the
                           template did before the field existed, so an
                           existing cluster renders byte-identically.
  explicitly named      -> kept verbatim EVEN WHEN the backend says otherwise.
                           A cluster flipping storage_backend to "replicated"
                           with the workspace pinned to "local-path" is the
                           whole reason #191 exists: the PVC is bound and
                           storageClassName is immutable, so following the
                           backend wedges the HelmRelease for good.
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

# (name, extra cluster.yaml fields, expected claudecode_workspace_storage_class)
# The default follows the bulk tier -- the opposite axis from the config PVC
# above -- so every backend is listed rather than sampled: the three answers
# differ, and one case would read the same whether the field followed
# default_storage_class, db_storage_class, or a hardcoded 'local-path'.
WORKSPACE_CASES = [
    ("unset, local-path cluster -> follows bulk",
     {}, "local-path"),
    ("unset, NFS cluster -> follows bulk onto the NAS class",
     {"storage_backend": "nfs"}, "sc-nas"),
    ("unset, replicated cluster -> follows bulk onto longhorn",
     {"storage_backend": "replicated"}, "longhorn"),
    ("PINNED while the backend moves -- #191's whole case: the bound PVC stays"
     " where it is and the helm upgrade does not hit an immutable field",
     {"storage_backend": "replicated",
      "claudecode_workspace_storage_class": "local-path"}, "local-path"),
    ("pinned value is not confused with the block tier either",
     {"storage_backend": "replicated", "db_storage_class": "longhorn",
      "claudecode_workspace_storage_class": "sc-nas"}, "sc-nas"),
]


INSTANCES_J2 = (ROOT / "templates" / "config" / "kubernetes" / "apps" / "base"
                / "claudecode" / "claude-code" / "instances"
                / "helmrelease.yaml.j2")

# Which variable each volume's storageClass must name in the template. Every
# case above measures plugin.py's resolved data, and NONE of them reads the
# template — so reverting the template line to `default_storage_class` was
# caught by nothing: the field still resolved, all cells still passed, and the
# value simply stopped arriving. Measured 2026-09-23 before this function
# existed. The defence has to be on the other side of the render.
TEMPLATE_EXPECTED = {
    "claude-config": "claudecode_config_storage_class",
    "claude-workspace": "claudecode_workspace_storage_class",
}


def check_template_consumes_the_fields() -> int:
    """Assert the two claude PVC blocks name the two fields, in the template.

    Blocks are found by their volume key and then by the next `storageClass:`
    line, not by a single regex over the whole file: a pattern narrow enough to
    match one line is also narrow enough to miss it after a reindent, and a miss
    reads as zero findings, i.e. as a pass.
    """
    if not INSTANCES_J2.exists():
        print(f"FAIL  template not found: {INSTANCES_J2}")
        print("      This is 'cannot measure', and it is counted as a failure")
        print("      on purpose — a moved file must not read as coverage.")
        return 1

    lines = INSTANCES_J2.read_text().splitlines()
    found: dict[str, str | None] = {}
    for i, line in enumerate(lines):
        key = line.strip().rstrip(":")
        if line.strip().endswith(":") and key in TEMPLATE_EXPECTED:
            found[key] = None
            for nxt in lines[i + 1:i + 8]:
                s = nxt.strip()
                if s.startswith("storageClass:"):
                    found[key] = s.split(":", 1)[1].strip()
                    break
                if s.endswith(":") and not s.startswith("#"):
                    break  # next mapping key — this block has no storageClass

    failed = 0
    missing = sorted(set(TEMPLATE_EXPECTED) - set(found))
    if missing:
        print(f"FAIL  template: no volume block named {missing} — the parse")
        print("      found nothing to check, which is not the same as nothing")
        print("      being wrong. Blocks seen: " + repr(sorted(found)))
        return 1

    for key, want in sorted(TEMPLATE_EXPECTED.items()):
        got = found[key]
        if got is None:
            print(f"FAIL  template: {key} block has no storageClass line")
            failed += 1
        elif want not in got:
            print(f"FAIL  template: {key} storageClass is {got!r}, which does")
            print(f"      not name {want} — the field resolves but never")
            print("      reaches the render")
            failed += 1
        else:
            print(f"PASS  template: {key} storageClass names {want}")
    return failed


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

    ws_answers = set()
    for name, extra, expected in WORKSPACE_CASES:
        data = dict(BASE, **extra)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                plugin.Plugin(data).data()
            got = data["claudecode_workspace_storage_class"]
        except Exception as e:  # noqa: BLE001
            print(f"FAIL  {name}\n        render raised {type(e).__name__}: {e}")
            failed += 1
            continue
        ws_answers.add(got)
        if got != expected:
            print(f"FAIL  {name}\n        expected {expected!r}, got {got!r}")
            failed += 1
        else:
            print(f"PASS  {name}\n        workspace class = {got!r}")

    # The decoupling assertion — acceptance 2 of #76 at the logic level. Read
    # off the workspace FIELD since #191, not off default_storage_class: the two
    # are equal when nothing is declared, so asserting against the default would
    # keep passing after the field stopped following it, which is the one change
    # this pair exists to notice.
    #
    # `.get` and not `[…]` on the two claude fields: a missing key here used to
    # abort the script, and everything below this point then never ran while the
    # cells above had already printed their FAILs — a red that hid a red.
    data = dict(BASE, storage_backend="nfs")
    with contextlib.redirect_stderr(io.StringIO()):
        plugin.Plugin(data).data()
    if "claudecode_workspace_storage_class" not in data:
        print("FAIL  decoupling: nothing resolved "
              "claudecode_workspace_storage_class at all")
        failed += 1
    elif data["default_storage_class"] != "sc-nas":
        print("FAIL  NFS control broke: default_storage_class is "
              f"{data['default_storage_class']!r}, the fixture no longer "
              "tests an NFS cluster at all")
        failed += 1
    elif data["claudecode_config_storage_class"] == \
            data["claudecode_workspace_storage_class"]:
        print("FAIL  on an NFS cluster the config PVC still lands on the NFS")
        print("      class — config and bulk did not decouple")
        failed += 1
    else:
        print("PASS  NFS cluster: config "
              f"{data['claudecode_config_storage_class']!r} != workspace "
              f"{data['claudecode_workspace_storage_class']!r} — tiers decoupled")

    # An unset workspace class must still be default_storage_class verbatim —
    # #191 acceptance 1, stated as "an existing cluster renders byte-identically".
    # Separate from the cases above on purpose: those compare against a literal
    # this file chose, and a literal cannot notice the two fields drifting apart.
    for backend, in (("local-path",), ("nfs",), ("replicated",)):
        data = dict(BASE, storage_backend=backend)
        with contextlib.redirect_stderr(io.StringIO()):
            plugin.Plugin(data).data()
        if data.get("claudecode_workspace_storage_class") != data["default_storage_class"]:
            print(f"FAIL  {backend}: unset workspace class is "
                  f"{data['claudecode_workspace_storage_class']!r}, not "
                  f"{data['default_storage_class']!r} — an existing cluster "
                  "that names nothing would re-render its bound PVC")
            failed += 1
        else:
            print(f"PASS  {backend}: unset workspace class == "
                  f"default_storage_class ({data['default_storage_class']!r})")

    failed += check_template_consumes_the_fields()

    # A check whose cases all render the same value is not measuring the
    # declared inputs. Same guard as check-claude-instances-default.py.
    # Two sets, not one: the config cases could stay varied while every
    # workspace case collapsed onto a single answer, and a combined set would
    # read as coverage.
    for label, seen, least in (("config", answers, 2),
                               ("workspace", ws_answers, 3)):
        if len(seen) < least:
            print(f"FAIL  every {label} case rendered {seen!r} — fewer than "
                  f"{least} distinct answers, so the fixture has no")
            print("      discriminating power over the inputs it claims to vary")
            failed += 1

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
