#!/usr/bin/env python3
"""Tests for the two handover cells that measured the wrong thing — jgct#131.

Run: python3 .github/workflows/run-tests.py

Both defects shipped green, and both produced a *plausible* sentence:

- cells 7/12 asked for Jobs with `-l app=daily-check`. Nothing sets that label
  — jg-base's `cronjob.yaml` has no `labels:` anywhere — so the selector matched
  zero Jobs on every cluster, forever, and the cells reported "no completed
  daily-check Job", which reads as *the schedule has not come round yet*.
- cell 8 handed `echo-ext.<domain>` to the system resolver. On a LAN whose
  router intercepts port 53, the name resolves to the k8s-gateway address, the
  request never leaves the building, and the 200 arrives with no `cf-ray` —
  reported as "answered by something other than Cloudflare", which sends the
  reader to fix a cluster that is fine. Four such things were checked before
  anyone checked where they were standing.

The shape they share is the one this repo keeps paying for: **a check that
cannot discriminate reads exactly like a check that passed.** So every test
below was run against the pre-fix code first and must FAIL there; a test that
passes both ways is measuring nothing and would have caught neither defect.

**Nothing here touches the network or a cluster.** `_kubectl`, `_doh_a` and
`_curl_headers` are all replaced.
"""

from __future__ import annotations

# Keeps the SUBJECT's bytecode out of __pycache__ (jgct#96: a stale .pyc feeds a
# negative control the previous mutation's result).
import sys

sys.dont_write_bytecode = True

import importlib.util
import json
import pathlib
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)

DOMAIN = "example.test"
HOST = f"echo-ext.{DOMAIN}"
CF_ADDR = "203.0.113.10"          # what a public resolver gives for the name
LAN_ADDR = "10.9.1.12"            # what the intercepting router gives for it


def args(**kw):
    return types.SimpleNamespace(domain=DOMAIN, dir=".", **kw)


def job(name, *, succeeded=1, owner="daily-check", completion="2026-09-13T00:05:00Z"):
    """A Job shaped like the ones a real cluster returns.

    The labels are the four the kubelet writes, copied from a live reading on
    jg-janncotcc — note that `app` is not among them. A fixture that invented an
    `app` label would let the old selector pass and prove nothing.
    """
    meta = {
        "name": name,
        "labels": {
            "batch.kubernetes.io/controller-uid": "u-1",
            "batch.kubernetes.io/job-name": name,
            "controller-uid": "u-1",
            "job-name": name,
        },
    }
    if owner:
        meta["ownerReferences"] = [{"kind": "CronJob", "name": owner}]
    return {"metadata": meta,
            "status": {"succeeded": succeeded, "completionTime": completion}}


class JobLookup(unittest.TestCase):
    """cells 7/12: find the Job by what identifies it, not by an absent label."""

    def _run(self, items, *, ok=True, err="", logs="printed output"):
        calls = []

        def fake_kubectl(_args, *argv):
            """Emulates kubectl, INCLUDING server-side `-l` filtering.

            Without that emulation the stub hands every Job back whatever the
            selector says, the pre-fix code finds one, and two of the tests
            below pass against the defect they exist to catch. A fixture that
            cannot reproduce the failure cannot discriminate — the selector is
            applied by the apiserver, so the fake has to apply it too.
            """
            argv = list(argv)
            calls.append(argv)
            if "get" in argv and "jobs" in argv:
                out = items
                if "-l" in argv:
                    key, _, val = argv[argv.index("-l") + 1].partition("=")
                    out = [j for j in items
                           if ((j.get("metadata") or {}).get("labels") or {}).get(key) == val]
                return ok, json.dumps({"items": out}), err
            return True, logs, ""

        with mock.patch.object(dc, "_kubectl", side_effect=fake_kubectl):
            out = dc._newest_completed_job_log(args())
        return out, calls

    def test_query_carries_no_label_selector(self):
        """The selector is the defect, so its absence is the assertion.

        Asserting on the command and not only on the result, because a fixture
        cannot reproduce kubectl's own server-side filtering: the old code got
        zero items *from kubectl*, and a stub that returns items regardless
        would hide that completely.
        """
        _, calls = self._run([job("daily-check-1")])
        flat = " ".join(calls[0])
        self.assertNotIn("app=daily-check", flat)
        self.assertNotIn("-l", calls[0])

    def test_finds_job_by_owner_reference(self):
        (name, logs, why, hint), _ = self._run([job("daily-check-29820960")])
        self.assertEqual(name, "daily-check-29820960")
        self.assertIsNone(why)
        self.assertEqual(logs, "printed output")

    def test_falls_back_to_name_prefix_when_owner_is_gone(self):
        """A hand-made re-run has no ownerReference; it is still the thing."""
        (name, _, why, _), _ = self._run([job("daily-check-manual", owner=None)])
        self.assertEqual(name, "daily-check-manual")
        self.assertIsNone(why)

    def test_ignores_jobs_from_a_different_cronjob(self):
        """Negative control: the finder must be able to exclude something.

        Without this, a finder that returns every Job in the namespace passes
        all the tests above.
        """
        (name, _, why, _), _ = self._run([
            job("other-thing-7", owner="other-thing"),
            job("daily-check-29820960"),
        ])
        self.assertEqual(name, "daily-check-29820960")

        (name2, _, why2, _), _ = self._run([job("other-thing-7", owner="other-thing")])
        self.assertIsNone(name2)
        self.assertIsNotNone(why2)

    def test_no_completed_job_message_carries_both_counts(self):
        """"0 of 0" and "0 of 3" need opposite next actions."""
        (_, _, why, hint), _ = self._run([
            job("daily-check-1", succeeded=0),
            job("daily-check-2", succeeded=0),
            job("other-thing-7", owner="other-thing"),
        ])
        self.assertIsNotNone(why)
        self.assertIn("2", why)          # from this CronJob
        self.assertIn("3", why)          # in the namespace
        self.assertEqual(hint, dc.NEED_TOOL)

    def test_unreachable_cluster_still_reports_a_vantage_problem(self):
        (name, _, why, hint), _ = self._run([], ok=False, err="connection refused")
        self.assertIsNone(name)
        self.assertEqual(hint, dc.NEED_PLACE)


class EchoExtVantage(unittest.TestCase):
    """cell 8: measure the public path, not the LAN the operator is on."""

    def _run(self, *, doh, curl):
        seen = {}

        def fake_curl(url, timeout=15, resolve=None):
            seen["url"], seen["resolve"] = url, resolve
            return curl(resolve)

        with mock.patch.object(dc, "_doh_a", side_effect=doh), \
             mock.patch.object(dc, "_curl_headers", side_effect=fake_curl):
            out = dc.cell_echo_ext(args())
        return out, seen

    @staticmethod
    def _doh_ok(name):
        return ([CF_ADDR], None) if name == HOST else (["104.16.0.1"], None)

    def test_intercepted_lan_still_passes(self):
        """The regression. Pre-fix this is a FAIL on a perfectly good cluster.

        `cf-ray` comes back only when the request is pinned to the address a
        public resolver gave. Unpinned — which is what the old code did — the
        router's answer is used and the header is missing.
        """
        def curl(resolve):
            if resolve == f"{HOST}:443:{CF_ADDR}":
                return 200, {"cf-ray": "8f0c1d2e3f4a5b6c-TPE"}, None
            return 200, {}, None          # the LAN shortcut: 200, no cf-ray

        (status, msg, hint), seen = self._run(doh=self._doh_ok, curl=curl)
        self.assertEqual(status, dc.PASS, msg)
        self.assertEqual(seen["resolve"], f"{HOST}:443:{CF_ADDR}")

    def test_cannot_ask_a_public_resolver_is_unknown_not_fail(self):
        """Three outcomes, not two: "I could not measure" is its own answer."""
        called = []

        def doh(name):
            return ([], "no route to host")

        def curl(resolve):
            called.append(resolve)
            return 200, {"cf-ray": "x"}, None

        (status, msg, hint), _ = self._run(doh=doh, curl=curl)
        self.assertEqual(status, dc.UNKNOWN)
        self.assertEqual(hint, dc.NEED_TOOL)
        self.assertEqual(called, [], "must not curl when the control failed")

    def test_public_name_missing_is_a_real_failure(self):
        def doh(name):
            return ([], None) if name == HOST else (["104.16.0.1"], None)

        (status, msg, _), _ = self._run(doh=doh, curl=lambda r: (200, {}, None))
        self.assertEqual(status, dc.FAIL)
        self.assertIn("does not resolve", msg)

    def test_public_resolver_answering_with_a_private_address_fails(self):
        """Not the LAN's doing: this is the public answer, and it is private."""
        def doh(name):
            return ([LAN_ADDR], None) if name == HOST else (["104.16.0.1"], None)

        called = []

        def curl(resolve):
            called.append(resolve)
            return 200, {"cf-ray": "x"}, None

        (status, msg, _), _ = self._run(doh=doh, curl=curl)
        self.assertEqual(status, dc.FAIL)
        self.assertIn(LAN_ADDR, msg)
        self.assertEqual(called, [], "no point curling a private answer")

    def test_no_cf_ray_on_the_pinned_public_address_is_still_a_failure(self):
        """The cell must keep its teeth: pinning must not turn FAIL into PASS."""
        (status, msg, _), _ = self._run(doh=self._doh_ok,
                                        curl=lambda r: (200, {}, None))
        self.assertEqual(status, dc.FAIL)
        self.assertIn("cf-ray", msg)


if __name__ == "__main__":
    unittest.main()
