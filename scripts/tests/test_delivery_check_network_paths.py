#!/usr/bin/env python3
"""Tests for delivery-check.py's `gateway`, `lan` and `flux` — #104 (4), batch 2b-1.

Run: python3 .github/workflows/run-tests.py

These three read a node's routes, a resolver's answers and a cluster's Flux
objects. Each had none of its branches exercised, and each has a state where
**a false alarm is the expensive direction** rather than a false pass — which is
the failure mode that gets guards switched off, and a switched-off guard reads
exactly like a passing one.

The two properties worth the most here are both "do not cry wolf":

- `gateway` must not count an **IPv6** default route as a second candidate for
  `node_default_gateway` (which is `net.IPv4` in cluster.schema.cue). Measured
  2026-08-30 on a real 145-route capture from a jg-jiahd node: 110 were inet6. A
  dual-stack node with an IPv6 default route would otherwise make the count two
  and the check would refuse to choose — on a healthy node.
- `lan` must not read nslookup's **server** line (`Address: <resolver>#53`) as an
  answer. A resolver whose own address happens to equal `--expect-addr` would
  otherwise pass while resolving nothing.

What is stubbed, and what is not:

- `gateway`: the route parsing is REAL (`--routes-json` is a supported input, so
  the test writes a file rather than faking talosctl). Only `_shipped_gateway` is
  patched, because what this repo would ship depends on a rendered config and is
  a different subject — the tests here are about selecting a default route.
- `lan` and `flux`: fake `nslookup` / `kubectl` on PATH, same shape as #117's
  tests. Nothing reaches a resolver or a cluster.
"""

from __future__ import annotations

# See the note in test_delivery_check_repo_hygiene.py: this stops the SUBJECT's
# bytecode being cached, which is what feeds a stale `.pyc` to a negative control
# (jgct#96). This module's own `.pyc` is written before this line runs; only
# `python3 -B` or the runner covers that.
import sys

sys.dont_write_bytecode = True

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)


def capture(fn, *a) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*a)
    return rc, buf.getvalue()


@contextlib.contextmanager
def fake_bin(name: str, body: str):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / name
        p.write_text(f"#!/bin/sh\n{body}\n")
        p.chmod(0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = d + os.pathsep + old
        try:
            yield pathlib.Path(d)
        finally:
            os.environ["PATH"] = old


@contextlib.contextmanager
def no_tool_on_path():
    """An empty PATH dir only — `shutil.which` must find nothing."""
    with tempfile.TemporaryDirectory() as d:
        old = os.environ["PATH"]
        os.environ["PATH"] = d
        try:
            yield
        finally:
            os.environ["PATH"] = old


# ---------------------------------------------------------------- gateway (5)

def route(gateway: str | None = None, dst: str = "", family: str | None = "inet4"):
    spec: dict = {"dst": dst}
    if gateway is not None:
        spec["gateway"] = gateway
    if family is not None:
        spec["family"] = family
    return {"spec": spec}


@contextlib.contextmanager
def routes(*docs, shipped="192.168.1.1", provenance="declared", err=None):
    """A routes file plus a patched `_shipped_gateway`."""
    with tempfile.TemporaryDirectory() as d:
        f = pathlib.Path(d) / "routes.json"
        f.write_text("\n".join(json.dumps(doc) for doc in docs))
        args = types.SimpleNamespace(routes_json=str(f), talosconfig=None,
                                     node="n1", timeout=30)
        with mock.patch.object(dc, "_shipped_gateway",
                               return_value=(shipped, provenance, err)):
            yield args


class TestGateway(unittest.TestCase):
    def test_the_declared_gateway_matching_the_node_passes(self):
        with routes(route("192.168.1.1"), route("10.0.0.9", dst="10.0.0.0/24")) as args:
            rc, out = capture(dc.check_gateway, args)
        self.assertEqual(rc, dc.PASS, out)
        self.assertIn("declared in cluster.yaml and measured", out)

    def test_a_match_that_was_never_declared_still_says_so(self):
        """`#49`: right by coincidence today, and the next node_cidr change moves
        it silently. Passing quietly here would lose that."""
        with routes(route("192.168.1.1"), provenance="assumed") as args:
            rc, out = capture(dc.check_gateway, args)
        self.assertEqual(rc, dc.PASS, out)
        self.assertIn("does not say so", out)

    def test_a_mismatch_is_a_finding(self):
        with routes(route("192.168.9.254")) as args:
            rc, out = capture(dc.check_gateway, args)
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("the node routes via 192.168.9.254", out)

    def test_an_ipv6_default_route_is_not_a_second_candidate(self):
        """The false-alarm case. One IPv4 default and one IPv6 default is a
        healthy dual-stack node, not an ambiguity to refuse."""
        with routes(route("192.168.1.1"),
                    route("fe80::1", family="inet6")) as args:
            rc, out = capture(dc.check_gateway, args)
        self.assertEqual(rc, dc.PASS, out)
        self.assertIn("not compared", out)

    def test_two_ipv4_default_routes_refuse_to_pick(self):
        with routes(route("192.168.1.1"), route("192.168.1.2")) as args:
            rc, out = capture(dc.check_gateway, args)
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("Refusing to pick", out)

    def test_a_route_without_a_family_field_is_still_compared(self):
        """An unknown shape must widen the answer, never narrow it: dropping a
        familyless route would mean reporting "no default route" on a node that
        has one."""
        with routes(route("192.168.1.1", family=None)) as args:
            rc, out = capture(dc.check_gateway, args)
        self.assertEqual(rc, dc.PASS, out)

    def test_zero_routes_is_the_wrong_question_not_a_missing_gateway(self):
        with routes() as args:
            rc, out = capture(dc.check_gateway, args)
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("wrong question", out)

    def test_routes_without_a_gateway_key_report_the_shape_change(self):
        """If talosctl renames the field, the answer is "cannot tell" plus the
        keys actually seen — not "this node has no default gateway"."""
        with routes({"spec": {"destination": "0.0.0.0/0", "via": "192.168.1.1"}}) as args:
            rc, out = capture(dc.check_gateway, args)
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("no route carries a `gateway` key", out)

    def test_not_knowing_what_this_repo_ships_is_cannot_measure(self):
        with routes(route("192.168.1.1"), shipped=None,
                    err="could not render the config: KeyError: 'auth0'") as args:
            rc, out = capture(dc.check_gateway, args)
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("cannot tell what this repo ships", out)


# -------------------------------------------------------------------- lan (4)

def nslookup_output(server: str, answers: list[str]) -> str:
    """What nslookup actually prints: the server's own address carries `#53`."""
    lines = [f"Server:\t\t{server}", f"Address:\t{server}#53", ""]
    for a in answers:
        lines += ["Non-authoritative answer:", "Name:\tinternal.example.com",
                  f"Address: {a}"]
    return "\n".join(lines) + "\n"


class TestLan(unittest.TestCase):
    def _args(self):
        return types.SimpleNamespace(domain="example.com", expect_addr="10.9.1.50")

    def test_resolution_plus_a_working_control_passes(self):
        body = (f"case \"$1\" in\n"
                f"  internal.example.com) cat <<'EOF'\n{nslookup_output('10.9.1.53', ['10.9.1.50'])}EOF\n"
                f"  ;;\n"
                f"  *) cat <<'EOF'\n{nslookup_output('10.9.1.53', ['140.82.121.4'])}EOF\n"
                f"  ;;\nesac")
        with fake_bin("nslookup", body):
            rc, out = capture(dc.check_lan, self._args())
        self.assertEqual(rc, dc.PASS, out)
        self.assertIn("positive control", out)

    def test_the_resolvers_own_address_is_not_an_answer(self):
        """`Address: 10.9.1.50#53` is the server, not a result. Counting it would
        pass this check on a resolver that resolved nothing — and the resolver's
        address being the expected one is exactly the plausible coincidence."""
        body = f"cat <<'EOF'\n{nslookup_output('10.9.1.50', [])}EOF"
        with fake_bin("nslookup", body):
            rc, out = capture(dc.check_lan, self._args())
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("did not resolve", out)

    def test_the_wrong_address_is_a_finding(self):
        body = f"cat <<'EOF'\n{nslookup_output('10.9.1.53', ['10.9.1.99'])}EOF"
        with fake_bin("nslookup", body):
            rc, out = capture(dc.check_lan, self._args())
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("10.9.1.99", out)

    def test_internal_names_working_while_forwarding_is_broken_is_a_finding(self):
        """The control's whole purpose: a cluster answering NXDOMAIN for
        everything else looks correct if you only test the name you care about,
        and the client never asks the secondary."""
        body = (f"case \"$1\" in\n"
                f"  internal.example.com) cat <<'EOF'\n{nslookup_output('10.9.1.53', ['10.9.1.50'])}EOF\n"
                f"  ;;\n"
                f"  *) cat <<'EOF'\n{nslookup_output('10.9.1.53', [])}EOF\n"
                f"  ;;\nesac")
        with fake_bin("nslookup", body):
            rc, out = capture(dc.check_lan, self._args())
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("positive control failed", out)

    def test_without_nslookup_it_cannot_measure(self):
        with no_tool_on_path():
            rc, out = capture(dc.check_lan, self._args())
        self.assertEqual(rc, dc.UNKNOWN, out)


# ------------------------------------------------------------------- flux (3)

def gitrepo(name: str, ready: str, revision: str) -> dict:
    return {"metadata": {"name": name},
            "status": {"conditions": [{"type": "Ready", "status": ready}],
                       "artifact": {"revision": revision}}}


class TestFlux(unittest.TestCase):
    """`#117` already covers the hang and the empty-list case; these are the
    branches that decide whether a *present* Flux is at the pushed commit."""

    def _args(self, kubeconfig: str, sha="deadbee"):
        return types.SimpleNamespace(kubeconfig=kubeconfig, expect_sha=sha)

    @contextlib.contextmanager
    def _kubectl(self, items: list[dict], rc: int = 0):
        payload = json.dumps({"items": items}).replace("'", "")
        body = (f"printf '%s' '{payload}'" if rc == 0
                else f"echo 'the server could not find the requested resource' >&2; exit {rc}")
        with fake_bin("kubectl", body) as d:
            kubeconfig = d / "kubeconfig"
            kubeconfig.write_text("unused by the fake\n")
            yield str(kubeconfig)

    def test_ready_at_the_pushed_revision_passes(self):
        with self._kubectl([gitrepo("flux-system", "True", "main@sha1:deadbeef")]) as kc:
            rc, out = capture(dc.check_flux, self._args(kc))
        self.assertEqual(rc, dc.PASS, out)

    def test_ready_at_a_different_revision_is_a_finding(self):
        """The dangerous one: Flux is healthy, so every dashboard is green — it
        just has not fetched the commit whose absence is about to be read as
        "not deployed yet"."""
        with self._kubectl([gitrepo("flux-system", "True", "main@sha1:cafe1234")]) as kc:
            rc, out = capture(dc.check_flux, self._args(kc))
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("no GitRepository is Ready at a revision containing", out)

    def test_the_right_revision_but_not_ready_is_a_finding(self):
        with self._kubectl([gitrepo("flux-system", "False", "main@sha1:deadbeef")]) as kc:
            rc, out = capture(dc.check_flux, self._args(kc))
        self.assertEqual(rc, dc.FAIL, out)

    def test_kubectl_refusing_the_query_is_cannot_measure(self):
        with self._kubectl([], rc=1) as kc:
            rc, out = capture(dc.check_flux, self._args(kc))
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("could not query the cluster", out)


if __name__ == "__main__":
    unittest.main()
