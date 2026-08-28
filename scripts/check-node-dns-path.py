#!/usr/bin/env python3
"""Assert what `node_dns_path` derives to, per node_dns_servers shape.

daily-check probes `internal.<domain>` through the node's ordinary resolution
path and raises an alarm when it fails. This flag decides whether that probe
runs at all, so both ways of getting it wrong are silent:

  stuck `lan`     a cluster whose nodes point at 1.1.1.1 alarms every morning
                  while its LAN is perfectly healthy — Cloudflare will not
                  serve the RFC1918 answer (deployment-profiles D29), so the
                  probe can never pass there. A permanently red row trains the
                  reader to ignore the channel carrying seventeen other checks.

  stuck `public`  the probe never runs anywhere. Since jg-base#16 that at least
                  prints an explicit "not measured" row rather than nothing,
                  but nothing about the router is being watched.

Neither shows up in a rendered manifest, because the value is computed before
rendering and only ever appears as one word.

The first case below is the one this file exists for. It used to expect the
opposite answer: the derivation read `node_dns_servers` BEFORE plugin.py's own
`setdefault(...)` and called unset "LAN", while the case right after it asserted
`public` for the identical machine config. Measured 2026-08-23: jg-jiahd, jcom,
jg-janncotcc and jgt-talos-accept all rendered `nameservers: [1.1.1.1, 1.0.0.1]`,
and no cluster.yaml in the fleet set the field — so the branch that said "LAN"
described no cluster that existed.

It exercises the real Plugin.data() rather than a copy of its logic. A
reimplementation here would drift, and the copy that drifts is the one that
keeps passing.

**2026-08-27 — that rule was written here and then broken here**
(`ferry133/jg-cluster-template#32`). This file did not reimplement the logic,
but it did hold a copy of one *value* the logic owns: the default itself, spelled
`["1.1.1.1", "1.0.0.1"]` in a case named "the applied default spelled out" and
again in the self-agreement assertion at the bottom. `#29` changed the default in
plugin.py to `[node_default_gateway]` and the copy here stayed. The two then
contradicted each other, and because this guard sits on the `task configure`
chain, **every cluster repo synced to main stopped being able to render at all** —
including `jg-jiahd`, which was only trying to pick up an unrelated fix.

So the fix is not to write the new default in these two places. It is to stop
holding the value: the self-agreement assertion below now reads the applied
default back out of `Plugin.data()`, which is the one spelling that cannot go
stale. What stays hard-coded is the *policy* — unset must put the nodes on the
LAN — because that is the thing worth failing over if someone changes it back.

Note what this guard got right, because the temptation when it fires is to
loosen it: it refused loudly instead of letting a contradictory default render
quietly, and `#29` exists precisely because both ways of being wrong here are
silent. The cost was one `exit 201`. Do not fix it by relaxing an assertion.

Exit 0 if every case matches, 1 otherwise.
"""

from __future__ import annotations

import importlib.util
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

CASES = [
    # (name, extra cluster.yaml fields, expected node_dns_path)
    (
        # The POLICY, not a restatement of the default's literal value: a
        # cluster nobody configured must end up watching its own LAN. `#29`
        # moved the default here because a node on a public resolver cannot
        # resolve `internal.<domain>` at all — Cloudflare does not serve the
        # RFC1918 answer — which takes the `im` rescue terminal with it.
        # If someone puts a public resolver back, this is the case that fires.
        "unset — the shipped default must put the nodes on the LAN's own resolver",
        dict(),
        "lan",
    ),
    (
        # Not "the applied default" any more; that role belongs to the
        # self-agreement assertion at the bottom, which reads it from
        # plugin.py. This is now just the public-resolver shape, kept because
        # the derivation has to be able to answer `public` at all.
        "public resolvers spelled out",
        dict(node_dns_servers=["1.1.1.1", "1.0.0.1"]),
        "public",
    ),
    (
        # Since 2026-08-27 this is the same machine config as the unset case
        # above — BASE's node_cidr makes .1 the gateway, and the gateway is now
        # the default. Kept, and said out loud so nobody reads it as independent
        # coverage: what it still asserts is that spelling the default out
        # explicitly agrees with leaving it out, which is the small version of
        # the assertion at the bottom of this file.
        "router as resolver — the default written out by hand",
        dict(node_dns_servers=["10.9.1.1"]),
        "lan",
    ),
    (
        "the cluster's own k8s-gateway",
        dict(node_dns_servers=["10.9.1.254"]),
        "lan",
    ),
    (
        "192.168/16 and 172.16/12 are LAN too",
        dict(node_dns_servers=["192.168.1.1", "172.20.0.1"]),
        "lan",
    ),
    (
        "one public entry is enough to make the probe meaningless",
        dict(node_dns_servers=["10.9.1.1", "8.8.8.8"]),
        "public",
    ),
    (
        "never a YAML boolean — jg-base#16 took daily-check down over exactly this",
        dict(node_dns_servers=["10.9.1.1"]),
        "lan",
    ),
]

# Values a YAML 1.1 parser would read as something other than a string. The
# consuming Secret in jg-base puts this straight into stringData, and kustomize
# does not preserve the quotes around the placeholder, so any of these takes the
# whole Secret down — no daily-check, no dead-man ping.
NOT_A_STRING = {
    "true", "True", "TRUE", "false", "False", "FALSE",
    "yes", "Yes", "YES", "no", "No", "NO",
    "on", "On", "ON", "off", "Off", "OFF",
    "null", "Null", "NULL", "~", "",
}


def main() -> int:
    plugin = load_plugin()
    failed = 0
    for name, extra, expected in CASES:
        data = dict(BASE, **extra)
        try:
            plugin.Plugin(data).data()
            got = data["node_dns_path"]
        except Exception as e:  # noqa: BLE001
            print(f"FAIL  {name}\n        render raised {type(e).__name__}: {e}")
            failed += 1
            continue
        if got == expected:
            print(f"PASS  {name}\n        node_dns_path = {got!r}")
        else:
            print(f"FAIL  {name}\n        expected {expected}, got {got!r}")
            failed += 1

    # Both stuck values pass a same-answer suite, so require the two answers to
    # actually differ across the cases above.
    answers = set()
    for _, extra, _ in CASES:
        d = dict(BASE, **extra)
        plugin.Plugin(d).data()
        answers.add(d["node_dns_path"])
    if len(answers) < 2:
        print("\nFAIL  the derivation returned the same answer for every case —")
        print("      a value that never varies is not being computed from anything.")
        failed += 1

    # Whatever it derives has to survive the trip through kustomize + Flux into
    # a stringData field. A value a YAML parser re-types is not a value.
    bad = sorted(a for a in answers if a in NOT_A_STRING)
    if bad:
        print(f"\nFAIL  derived {bad}, which YAML does not read as a string —")
        print("      stringData rejects it and daily-check does not deploy at all")
        print("      (ferry133/jg-base#16).")
        failed += 1

    # The bug this file was rewritten for: unset and the spelled-out default are
    # the same machine config, so they must be the same answer. Asserting each
    # separately is what let them disagree for as long as they did.
    #
    # The second operand is READ BACK from plugin.py rather than written here.
    # Writing it here is what broke this file on 2026-08-27: the value was
    # copied, `#29` changed the original, and the copy went on asserting the old
    # world. Whatever the default becomes, this compares unset against exactly
    # that.
    d_unset = dict(BASE)
    plugin.Plugin(d_unset).data()
    applied = list(d_unset["node_dns_servers"])
    d_explicit = dict(BASE, node_dns_servers=list(applied))
    plugin.Plugin(d_explicit).data()
    print(f"applied default = {applied!r}  (read from plugin.py, not copied here)")
    if d_unset["node_dns_path"] != d_explicit["node_dns_path"]:
        print("\nFAIL  unset derived {!r} but the default it applies derived {!r} —".format(
            d_unset["node_dns_path"], d_explicit["node_dns_path"]))
        print("      those are the same machine config, so that is a contradiction.")
        failed += 1

    # `#29`'s reasoning, not just its outcome. It chose ONE private entry, and
    # both halves of that carry weight:
    #
    #   more than one   `all(is_private)` derives `public` the moment a public
    #                   fallback is added, which switches check 18 back off —
    #                   and CoreDNS's forward plugin picks among upstreams at
    #                   random by default, so internal names would resolve on
    #                   roughly half of queries, with the failures negatively
    #                   cached. Intermittent is worse than absent.
    #
    #   not private     a node that cannot resolve internal names cannot reach
    #                   anything the cluster publishes to itself.
    #
    # Neither of those is visible in a rendered manifest, and neither would be
    # caught by the case table above: a two-entry default still derives a legal
    # answer. Asserting the SHAPE of the default is the only place it shows up.
    if len(applied) != 1:
        print(f"\nFAIL  the applied default has {len(applied)} entries: {applied!r}")
        print("      #29 chose exactly one on purpose. A second upstream makes")
        print("      internal names resolve intermittently (CoreDNS forwards at")
        print("      random by default) and, if it is public, flips this very")
        print("      derivation to 'public' and switches check 18 off.")
        failed += 1
    elif d_unset["node_dns_path"] != "lan":
        print(f"\nFAIL  the applied default {applied!r} does not derive 'lan'.")
        print("      A cluster nobody configured would then watch nothing, and")
        print("      its nodes would not resolve internal names at all.")
        failed += 1

    print()
    if failed:
        print(f"{failed} case(s) failed.")
        print("Stuck `lan` alarms daily on a healthy LAN; stuck `public` means")
        print("nothing here watches the router at all.")
        return 1
    print(f"ok — {len(CASES)} cases match; the derivation varies, stays a string,")
    print("     and agrees with itself about the default")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
