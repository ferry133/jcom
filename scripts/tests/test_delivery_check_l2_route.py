#!/usr/bin/env python3
"""Tests for delivery-check.py's `l2-route` (jgct#240 cell 4, as rewritten with
fleet-ops-65 [69d6d7]).

Run: python3 .github/workflows/run-tests.py

The check answers one question from a real LAN client: is the subnet this
machine sits on one the tenant NADs route back to? Its three outcomes are the
subject, and the third is the one that matters most: a machine ON node_cidr
needs no route, so it can say nothing about the other subnets -- it must read
UNKNOWN, never PASS (fleet-ops-65's point (c)).

`_merged_config` is patched (what cluster.yaml says is a different subject).
`_client_subnet` is tested separately with `run` patched to canned
`route`/`ifconfig` and `ip` output for each platform, because the interface
must come from the route to the node, not from the first card (point (b)).
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import contextlib
import importlib.util
import io
import pathlib
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)

L2_TENANT = {"name": "homekit", "repository": "x/homekit", "kind": "vendor",
             "grants": {"l2": True},
             "l2_network": {"interface": "enp1s0", "start": "10.9.9.19", "stop": "10.9.9.19"}}


def config(**over):
    c = {"node_cidr": "10.9.9.0/24", "lan_routed_cidrs": ["10.9.1.0/24"],
         "app_repos": [L2_TENANT]}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def check(cfg, client="10.9.1.0/24"):
    args = types.SimpleNamespace(node=None, client_cidr=client)
    buf = io.StringIO()
    with mock.patch.object(dc, "_merged_config", return_value=(cfg, None)), \
            contextlib.redirect_stdout(buf):
        rc = dc.check_l2_route(args)
    return rc, buf.getvalue()


class TestOutcomes(unittest.TestCase):
    def test_listed_subnet_passes_and_says_only_it_was_measured(self):
        rc, out = check(config())
        self.assertEqual(rc, dc.PASS)
        self.assertIn("PASS  10.9.1.0/24 is covered", out)
        self.assertIn("Only this subnet was measured", out)

    def test_a_subnet_inside_a_listed_supernet_passes(self):
        rc, _ = check(config(lan_routed_cidrs=["10.9.0.0/22"]), client="10.9.1.0/24")
        # 10.9.0.0/22 is 10.9.0-3.x: clear of node_cidr 10.9.9.0/24.
        self.assertEqual(rc, dc.PASS)

    def test_unlisted_subnet_fails_and_names_it(self):
        rc, out = check(config(), client="10.9.8.0/24")
        self.assertEqual(rc, dc.FAIL)
        self.assertIn('Add "10.9.8.0/24" to lan_routed_cidrs', out)

    def test_empty_list_fails_for_a_routed_client(self):
        # The negative control of the live run: same client, list emptied.
        rc, _ = check(config(lan_routed_cidrs=[]))
        self.assertEqual(rc, dc.FAIL)

    def test_on_node_cidr_is_unknown_never_pass(self):
        rc, out = check(config(), client="10.9.9.0/24")
        self.assertEqual(rc, dc.UNKNOWN)
        self.assertNotIn("PASS", out)
        self.assertIn("says nothing about the LAN's other subnets", out)

    def test_on_node_cidr_is_unknown_even_with_an_empty_list(self):
        rc, _ = check(config(lan_routed_cidrs=[]), client="10.9.9.0/24")
        self.assertEqual(rc, dc.UNKNOWN)

    def test_no_l2_tenant_is_unknown(self):
        rc, out = check(config(app_repos=[{"name": "a", "repository": "x/a",
                                           "kind": "vendor"}]))
        self.assertEqual(rc, dc.UNKNOWN)
        self.assertIn("no app_repos entry holds grants.l2", out)

    def test_l2_without_the_field_fails(self):
        rc, out = check(config(lan_routed_cidrs=None))
        self.assertEqual(rc, dc.FAIL)
        self.assertIn("lan_routed_cidrs is not set", out)

    def test_unreadable_config_is_unknown(self):
        args = types.SimpleNamespace(node=None, client_cidr="10.9.1.0/24")
        with mock.patch.object(dc, "_merged_config", return_value=(None, "nope")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(dc.check_l2_route(args), dc.UNKNOWN)


def proc(stdout, rc=0):
    return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr="")


class TestClientSubnet(unittest.TestCase):
    def fake(self, table):
        def run(cmd, **kw):
            return table[" ".join(cmd)]
        return mock.patch.object(dc, "run", side_effect=run)

    def test_darwin_takes_the_interface_from_the_route(self):
        table = {
            "route -n get 10.9.9.62": proc("   route to: 10.9.9.62\n  gateway: 10.9.1.1\n"
                                           "  interface: en7\n"),
            # en0 would be the first card; the route says en7.
            "ifconfig en7": proc("en7: flags=8863\n\tinet 10.9.1.30 netmask 0xffffff00 "
                                 "broadcast 10.9.1.255\n"),
        }
        with mock.patch.object(dc.sys, "platform", "darwin"), self.fake(table):
            net, err = dc._client_subnet("10.9.9.62")
        self.assertIsNone(err)
        self.assertEqual(str(net), "10.9.1.0/24")

    def test_linux_takes_the_device_from_the_route(self):
        table = {
            "ip -o route get 10.9.9.62": proc("10.9.9.62 via 10.9.8.1 dev wlan0 src 10.9.8.44 "
                                              "uid 1000\n"),
            "ip -o -4 addr show dev wlan0": proc("3: wlan0    inet 10.9.8.44/24 brd 10.9.8.255 "
                                                 "scope global wlan0\n"),
        }
        with mock.patch.object(dc.sys, "platform", "linux"), self.fake(table):
            net, err = dc._client_subnet("10.9.9.62")
        self.assertIsNone(err)
        self.assertEqual(str(net), "10.9.8.0/24")

    def test_no_interface_in_the_route_is_an_error_not_a_subnet(self):
        table = {"route -n get 10.9.9.62": proc("route: writing to routing socket: "
                                                "not in table\n", rc=1)}
        with mock.patch.object(dc.sys, "platform", "darwin"), self.fake(table):
            net, err = dc._client_subnet("10.9.9.62")
        self.assertIsNone(net)
        self.assertIn("named no interface", err)


if __name__ == "__main__":
    unittest.main()
