#!/usr/bin/env python3
"""Tests for delivery-check.py's `dns` subcommand — #104 (4), batch 2b-2.

Run: python3 .github/workflows/run-tests.py

`dns` is the subcommand whose failure modes are all "a well-formed answer that
means something else":

- `/user/tokens/verify` says *valid and active* for a token belonging to an
  entirely different account.
- `GET /zones` returns **HTTP 200 with an empty result** for a token pasted from
  the wrong field — an R2 key, say. Not a 403. Nothing raises.
- An abandoned account can hold a zone with the same name, complete and
  correct-looking, for hostnames that are NXDOMAIN worldwide.
- A dropped cluster's tunnel records answer exactly like a cluster that has not
  booted yet: proxied A records and HTTP 530 either way.

None of those branches had ever been executed by anything but a person, once.

**Nothing here touches the network.** `_doh` and `urllib.request.urlopen` are
both replaced; the token is injected per-test. A test that reached Cloudflare
would be measuring the operator's credentials, not this check — and it would
pass or fail for reasons no reviewer could reproduce.
"""

from __future__ import annotations

# Keeps the SUBJECT's bytecode out of __pycache__ (jgct#96: a stale .pyc feeds a
# negative control the previous mutation's result). This module's own .pyc is
# written before this line runs — only `python3 -B` or the runner covers that.
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

LIVE_NS = ["amber.ns.cloudflare.com", "beth.ns.cloudflare.com"]
OTHER_NS = ["carl.ns.cloudflare.com", "dina.ns.cloudflare.com"]
OUR_TUNNEL = "1f2e3d4c-5b6a-7890-abcd-ef1234567890"
THEIR_TUNNEL = "99887766-5544-3322-1100-ffeeddccbbaa"


class FakeResponse:
    """What `urllib.request.urlopen` returns, as much of it as this code uses."""

    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def read(self, *_a) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def capture(fn, *a) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*a)
    return rc, buf.getvalue()


@contextlib.contextmanager
def cloudflare(*, zones: list[dict] | None = None, records: list[dict] | None = None,
               live_ns: list[str] | None = None, google_ns: list[str] | None = None,
               token: str | None = "a-token", tunnel: str | None = OUR_TUNNEL):
    """Both network boundaries replaced, plus the token and credentials file.

    `zones`/`records` are what the API would return; `live_ns`/`google_ns` are
    what the two DoH resolvers would answer. Each test sets only what it is
    about, so a reader can see which fact the case turns on.
    """
    live = LIVE_NS if live_ns is None else live_ns
    google = live if google_ns is None else google_ns

    def fake_doh(url: str) -> list[str]:
        return sorted(live if "cloudflare-dns.com" in url else google)

    def fake_urlopen(req, timeout=None):  # noqa: ARG001 — shape must match
        url = req.full_url
        if "/zones?name=" in url:
            return FakeResponse({"result": zones if zones is not None else []})
        if "/dns_records" in url:
            return FakeResponse({"result": records if records is not None else []})
        raise AssertionError(f"a test reached an unexpected URL: {url}")

    with tempfile.TemporaryDirectory() as d:
        creds = pathlib.Path(d) / "cloudflare-tunnel.json"
        if tunnel is not None:
            creds.write_text(json.dumps({"TunnelID": tunnel, "AccountTag": "acc"}))
        args = types.SimpleNamespace(domain="example.com", token_env="TEST_CF_TOKEN",
                                     tunnel_credentials=str(creds))
        saved = os.environ.pop("TEST_CF_TOKEN", None)
        if token is not None:
            os.environ["TEST_CF_TOKEN"] = token
        try:
            with mock.patch.object(dc, "_doh", side_effect=fake_doh), \
                 mock.patch.object(dc.urllib.request, "urlopen", side_effect=fake_urlopen):
                yield args
        finally:
            os.environ.pop("TEST_CF_TOKEN", None)
            if saved is not None:
                os.environ["TEST_CF_TOKEN"] = saved


def zone(ns: list[str], status: str = "active", zid: str = "zone-1") -> dict:
    return {"id": zid, "status": status, "name_servers": ns,
            "account": {"id": "acc-1"}}


def record(content: str, name: str = "im.example.com") -> dict:
    return {"name": name, "content": content}


class TestDelegation(unittest.TestCase):
    """The half that runs without a token."""

    def test_a_domain_delegated_nowhere_is_a_finding(self):
        with cloudflare(live_ns=[], google_ns=[], token=None) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("not delegated anywhere", out)

    def test_resolvers_that_disagree_are_cannot_measure(self):
        """Mid-propagation looks exactly like a misconfiguration. Acting on
        either answer would be acting on a coin flip, so it says retry."""
        with cloudflare(live_ns=LIVE_NS, google_ns=OTHER_NS, token=None) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("disagree", out)

    def test_without_a_token_the_delegation_alone_is_not_a_pass(self):
        """The unchecked half is named: this is what catches a same-named zone in
        an abandoned account, and it needs the token."""
        with cloudflare(token=None) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("NOT that your token sees this zone", out)


class TestTokenSeesTheZone(unittest.TestCase):
    def test_an_empty_zone_list_over_http_200_is_a_finding(self):
        """The wrong-field token. No exception, no 403 — a well-formed empty
        answer, and external-dns filters against this list and logs nothing."""
        with cloudflare(zones=[]) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("EMPTY zone list", out)

    def test_a_same_named_zone_in_another_account_is_a_finding(self):
        """The zone the token sees is complete and correct-looking; it is simply
        not the zone this domain resolves to."""
        with cloudflare(zones=[zone(OTHER_NS)]) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("NOT the zone this domain resolves to", out)

    def test_a_matching_but_inactive_zone_is_a_finding(self):
        with cloudflare(zones=[zone(LIVE_NS, status="pending")]) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("not 'active'", out)


class TestZoneHoldsThisClustersRecords(unittest.TestCase):
    """The half added because "im.<domain> resolves" passes just as happily on a
    dropped cluster's leftovers."""

    def test_records_pointing_at_another_tunnel_are_a_finding(self):
        with cloudflare(zones=[zone(LIVE_NS)],
                        records=[record(f"{THEIR_TUNNEL}.cfargotunnel.com")]) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("DIFFERENT tunnel", out)

    def test_records_pointing_at_this_tunnel_pass(self):
        with cloudflare(zones=[zone(LIVE_NS)],
                        records=[record(f"{OUR_TUNNEL}.cfargotunnel.com")]) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.PASS, out)
        self.assertIn("points at this repo's tunnel", out)

    def test_a_zone_with_no_tunnel_records_passes_for_a_stated_reason(self):
        """Nothing to inherit is a pass, and the reason matters: whatever appears
        next will be this cluster's."""
        with cloudflare(zones=[zone(LIVE_NS)],
                        records=[record("203.0.113.7", name="www.example.com")]) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.PASS, out)
        self.assertIn("nothing to inherit", out)

    def test_missing_tunnel_credentials_is_cannot_measure_not_a_pass(self):
        """Without the local TunnelID there is nothing to compare the zone's
        records against — and saying PASS here is what would let a later DNS
        assertion pass on a corpse."""
        with cloudflare(zones=[zone(LIVE_NS)], tunnel=None) as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("stops a later DNS assertion from passing on a corpse", out)

    def test_credentials_without_a_tunnel_id_are_cannot_measure(self):
        with cloudflare(zones=[zone(LIVE_NS)], tunnel="") as args:
            rc, out = capture(dc.check_dns, args)
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("no TunnelID", out)


class TestDohParsing(unittest.TestCase):
    """`_doh` itself — the step every test above replaces wholesale.

    `[c8c318]` named this gap when accepting #122, and it is the right shape of
    gap to name: the eleven cases above patch `_doh` out, so **if `_doh` returned
    CNAMEs as nameservers, not one of them would go red**. `check_dns` compares
    the two resolvers' lists as sets, so garbage on both sides "agrees" and the
    delegation reads as confirmed.

    Only `urlopen` is replaced here, so the JSON → NS-list step is the thing
    under test rather than the thing assumed.
    """

    @contextlib.contextmanager
    def _resolver(self, payload: dict):
        """Answers with `payload`, and records what the request looked like."""
        seen: dict = {}

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["headers"] = {k.lower(): v for k, v in req.header_items()}
            seen["timeout"] = timeout
            return FakeResponse(payload)

        with mock.patch.object(dc.urllib.request, "urlopen", side_effect=fake_urlopen):
            yield seen

    def test_nameservers_are_normalised_deduped_and_sorted(self):
        """Two resolvers are compared as sets, so a trailing dot or a capital
        letter on one side would read as a delegation mismatch — which this check
        reports as "the zone your token sees is NOT the zone this domain resolves
        to", a strong and wrong claim."""
        # Five distinct names, not two, and the count is the point: dropping
        # `sorted()` leaves the set's iteration order, which str hash
        # randomisation re-rolls every run. `[c8c318]` measured the survival rate
        # of that mutant against the number of distinct elements k (60 seeds per
        # cell): k=2 43.3%, k=3 11.7%, k=4 0/60, k=5 0/60 — tracking 1/k!. At the
        # original k=2 this assertion was a coin flip; at k=5 the mutant is caught
        # in every run measured.
        #
        # NOT fixed by pinning PYTHONHASHSEED in the runner: that trades a
        # measurable coin flip for a permanent one, because the seed might be one
        # where the mutant happens to come out ordered — and then the assertion
        # passes forever. Deterministic-but-arbitrary is worse than probabilistic
        # and known.
        payload = {"Answer": [
            {"type": 2, "data": "Beth.NS.Cloudflare.com."},
            {"type": 2, "data": "amber.ns.cloudflare.com."},
            {"type": 2, "data": "AMBER.ns.cloudflare.com"},
            {"type": 2, "data": "carl.ns.cloudflare.com."},
            {"type": 2, "data": "Dina.NS.Cloudflare.com"},
            {"type": 2, "data": "eve.ns.cloudflare.com."},
        ]}
        with self._resolver(payload):
            got = dc._doh("https://cloudflare-dns.com/dns-query?name=x&type=NS")
        self.assertEqual(got, ["amber.ns.cloudflare.com", "beth.ns.cloudflare.com",
                               "carl.ns.cloudflare.com", "dina.ns.cloudflare.com",
                               "eve.ns.cloudflare.com"])
        # The three properties, asserted one by one rather than left to the
        # equality above — `[c8c318]` asked for this when accepting #122: a
        # property that is only incidentally covered is not locked, and the next
        # person to touch this line cannot tell which parts mattered.
        self.assertEqual(len(got), 5, "six answers, five distinct: deduped")
        self.assertEqual(got, sorted(got), "compared as sets upstream, but the "
                                           "order is what a reader diffs by eye")
        self.assertTrue(all(not n.endswith(".") and n == n.lower() for n in got))

    def test_a_cname_only_answer_is_not_a_delegation(self):
        """type 5 is CNAME. The hazard is not that it is wrong, it is that it is
        wrong on BOTH resolvers identically — so the agreement check passes."""
        payload = {"Answer": [{"type": 5, "data": "example.com.cdn.cloudflare.net."}]}
        with self._resolver(payload):
            self.assertEqual(dc._doh("https://dns.google/resolve?name=x&type=NS"), [])

    def test_mixed_answers_keep_only_the_nameservers(self):
        payload = {"Answer": [{"type": 5, "data": "cname.example."},
                              {"type": 2, "data": "amber.ns.cloudflare.com."}]}
        with self._resolver(payload):
            self.assertEqual(dc._doh("https://dns.google/resolve?name=x&type=NS"),
                             ["amber.ns.cloudflare.com"])

    def test_no_answer_section_is_an_empty_list(self):
        """A domain delegated nowhere answers HTTP 200 with no Answer key. That
        empty list is what `check_dns` turns into its "not delegated anywhere"
        finding, so it must come back empty rather than raising."""
        with self._resolver({"Status": 3}):
            self.assertEqual(dc._doh("https://dns.google/resolve?name=x&type=NS"), [])

    def test_it_asks_for_dns_json(self):
        """Without this header the resolver answers in wire format and
        `json.load` raises — which `check_dns` reports as "could not reach a DoH
        resolver". That is the wrong diagnosis for a header this code controls,
        and it would send someone to look at the network."""
        with self._resolver({"Answer": []}) as seen:
            dc._doh("https://cloudflare-dns.com/dns-query?name=x&type=NS")
        self.assertEqual(seen["headers"].get("accept"), "application/dns-json")

    def test_the_request_is_bounded(self):
        """#117's rule, at the one boundary in this file that is not `run()`:
        nothing here may wait forever."""
        with self._resolver({"Answer": []}) as seen:
            dc._doh("https://dns.google/resolve?name=x&type=NS")
        self.assertIsNotNone(seen["timeout"])
        self.assertLessEqual(seen["timeout"], 30)


class TestDohARecords(unittest.TestCase):
    """`_doh_a` — the other DoH helper, named as untested when #123 was accepted.

    Cell 13 leans on it: `backup_r2_endpoint` must resolve **from outside the
    building**, because the local resolver answers for the LAN and
    `http://10.9.1.12:9000` returned 200 from the lab bench. So the value of this
    helper is entirely in *which* resolver answers and *what* it reports back.

    The distinction this locks, and it is the one that would silently hurt: a
    failed query returns `([], error)` while a name with no A records returns
    `([], None)`. **If a network failure came back as the second, cell 13 would
    report "this name does not resolve" for a problem on the operator's own
    laptop** — a finding pointing at the wrong party.
    """

    @contextlib.contextmanager
    def _resolver(self, payload: dict | None = None, boom: Exception | None = None):
        seen: dict = {}

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["headers"] = {k.lower(): v for k, v in req.header_items()}
            seen["timeout"] = timeout
            if boom is not None:
                raise boom
            return FakeResponse(payload or {})

        with mock.patch.object(dc.urllib.request, "urlopen", side_effect=fake_urlopen):
            yield seen

    def test_only_a_records_come_back(self):
        """CNAME-fronted names are the norm for anything behind a CDN, so a
        resolver answering `type 5` alongside `type 1` is the normal case, not an
        edge one."""
        payload = {"Answer": [
            {"type": 5, "data": "endpoint.example.com.cdn.cloudflare.net."},
            {"type": 1, "data": "203.0.113.10"},
        ]}
        with self._resolver(payload):
            addrs, err = dc._doh_a("endpoint.example.com")
        self.assertEqual((addrs, err), (["203.0.113.10"], None))

    def test_addresses_are_deduped_and_sorted(self):
        """Five distinct values on purpose — #124 measured that a `sorted()`
        mutant survives 43.3% of runs at k=2 and 0/60 at k=4+, because str hash
        randomisation drives set order. A k=2 fixture would make this assertion a
        coin flip."""
        payload = {"Answer": [{"type": 1, "data": ip} for ip in
                              ["203.0.113.50", "203.0.113.10", "203.0.113.40",
                               "203.0.113.20", "203.0.113.30", "203.0.113.10"]]}
        with self._resolver(payload):
            addrs, err = dc._doh_a("endpoint.example.com")
        self.assertIsNone(err)
        self.assertEqual(addrs, ["203.0.113.10", "203.0.113.20", "203.0.113.30",
                                 "203.0.113.40", "203.0.113.50"])
        self.assertEqual(len(addrs), 5, "six answers, five distinct: deduped")
        self.assertEqual(addrs, sorted(addrs))

    def test_no_a_records_is_empty_and_NOT_an_error(self):
        with self._resolver({"Status": 0}):
            self.assertEqual(dc._doh_a("nothing.example.com"), ([], None))

    def test_a_failed_query_is_an_error_and_not_merely_empty(self):
        """The half that keeps cell 13 from blaming the customer's DNS for the
        operator's missing network."""
        with self._resolver(boom=OSError("Network is unreachable")):
            addrs, err = dc._doh_a("endpoint.example.com")
        self.assertEqual(addrs, [])
        self.assertIsNotNone(err)
        self.assertIn("DoH query failed", err)

    def test_the_name_is_percent_encoded_into_the_query(self):
        """An unencoded name with a space produces a malformed URL, and the
        `except Exception` above would report it as "DoH query failed" — a
        network-shaped message for a string-handling bug."""
        with self._resolver({"Answer": []}) as seen:
            dc._doh_a("a name.example.com")
        self.assertIn("a%20name.example.com", seen["url"])
        self.assertNotIn("a name", seen["url"])

    def test_it_asks_for_dns_json(self):
        with self._resolver({"Answer": []}) as seen:
            dc._doh_a("endpoint.example.com")
        self.assertEqual(seen["headers"].get("accept"), "application/dns-json")

    def test_the_request_is_bounded(self):
        with self._resolver({"Answer": []}) as seen:
            dc._doh_a("endpoint.example.com")
        self.assertIsNotNone(seen["timeout"])
        self.assertLessEqual(seen["timeout"], 30)


class TestIsPublicV4(unittest.TestCase):
    """`_is_public_v4` — the judgement cell 13 turns a resolved address into.

    A wrong `True` here is the shape cell 13 exists to catch: an endpoint that
    answers 200 on the lab bench because it is a LAN address.
    """

    def test_private_and_special_ranges_are_not_public(self):
        for addr in ["10.0.0.1", "10.255.255.254", "127.0.0.1",
                     "192.168.1.10", "172.16.0.1", "172.31.255.254",
                     "169.254.1.1"]:
            with self.subTest(addr=addr):
                self.assertFalse(dc._is_public_v4(addr))

    def test_the_172_block_boundaries(self):
        """`172.16/12` is the range, so `172.15` and `172.32` are public. This is
        the off-by-one that a hand-written check gets wrong, and getting it wrong
        in the lenient direction means calling a LAN address public."""
        self.assertFalse(dc._is_public_v4("172.16.0.1"))
        self.assertFalse(dc._is_public_v4("172.31.0.1"))
        self.assertTrue(dc._is_public_v4("172.15.0.1"))
        self.assertTrue(dc._is_public_v4("172.32.0.1"))

    def test_public_addresses_are_public(self):
        for addr in ["8.8.8.8", "203.0.113.10", "1.1.1.1", "172.217.14.206"]:
            with self.subTest(addr=addr):
                self.assertTrue(dc._is_public_v4(addr))

    def test_things_that_are_not_dotted_quads_are_not_public(self):
        """Refusing to answer `True` for a non-address is the safe direction: the
        caller treats `True` as "this is reachable from outside"."""
        for addr in ["", "abc", "1.2.3", "1.2.3.4.5", "10.0.0", "::1"]:
            with self.subTest(addr=addr):
                self.assertFalse(dc._is_public_v4(addr))


if __name__ == "__main__":
    unittest.main()
