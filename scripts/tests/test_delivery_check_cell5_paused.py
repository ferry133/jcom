#!/usr/bin/env python3
"""Cell 5 under a paused ruling — jgct#131 point 3.

Run: python3 .github/workflows/run-tests.py

The private per-user repo direction was paused on 2026-09-10 (fleet-ops#8,
jgct#56 closed as not planned) and every user repo is public. Cell 5 kept
asserting PRIVATE, so it FAILED on every cluster, and its sentence ("is PUBLIC,
not PRIVATE | sync url is https, not ssh:// | no deploy keys") sent the reader
down the paused path. ferry133 ruled 2026-09-13: make it a `?` that cites the
ruling. Not deleted -- a reversed ruling needs the three checks still there.

Every test here was run against the pre-fix code first and is red there (the
ruling constant, the kind and the early return do not exist on it).
**Nothing here touches the network, GitHub or a cluster**: `_run_bounded`,
`shutil.which` and `check_deploy_key` are all replaced.
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import contextlib
import importlib.util
import io
import json
import pathlib
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)


def args(**kw):
    base = dict(domain="example.test", dir=".", repo="ferry133/example", kubeconfig="kubeconfig")
    base.update(kw)
    return types.SimpleNamespace(**base)


class _Proc:
    def __init__(self, stdout, returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, "", returncode


def _public_world(calls):
    """Stubs that describe what every user repo looks like today: PUBLIC,
    syncing over https with no pull secret, no deploy key. Pre-fix, this world
    is a FAIL; that is the thing the ruling turns off."""

    def run_bounded(cmd, timeout, label):
        calls.append(cmd[0])
        if cmd[0] == "gh":
            return _Proc(json.dumps({"visibility": "PUBLIC"})), None
        return _Proc(json.dumps({"spec": {"sync": {"url": "https://github.com/x/y",
                                                   "pullSecret": ""}}})), None

    def deploy_key(a):
        calls.append("deploy-key")
        print("FAIL x has no deploy keys at all")
        return dc.FAIL

    return (mock.patch.object(dc, "_run_bounded", side_effect=run_bounded),
            mock.patch.object(dc.shutil, "which", return_value="/usr/bin/gh"),
            mock.patch.object(dc, "check_deploy_key", side_effect=deploy_key))


class PausedRuling(unittest.TestCase):

    def test_paused_cell_is_unknown_and_cites_the_ruling(self):
        """The regression. Pre-fix: FAIL, with a sentence that says 'make it private'."""
        calls = []
        with contextlib.ExitStack() as st:
            for m in _public_world(calls):
                st.enter_context(m)
            rc, msg, why = dc.cell_private_repo(args())
        self.assertEqual(rc, dc.UNKNOWN, msg)
        self.assertEqual(why, dc.PAUSED)
        for needle in ("2026-09-10", "fleet-ops#8", "jg-cluster-template#56", "not judged"):
            self.assertIn(needle, msg)
        self.assertEqual(calls, [], "a paused cell must not measure anything")

    def test_paused_wins_over_missing_inputs(self):
        """Without --repo/--kubeconfig the old cell said [vantage+tool] -- 'go get
        them'. Under the ruling there is nothing to go get."""
        rc, msg, why = dc.cell_private_repo(args(repo=None, kubeconfig=None))
        self.assertEqual(rc, dc.UNKNOWN)
        self.assertEqual(why, dc.PAUSED)

    def test_lifting_the_ruling_restores_the_three_checks(self):
        """Preservation: the code behind the early return still judges. Lift the
        ruling (constant -> None) and the public world FAILs again, for all three
        reasons, exactly as before."""
        calls = []
        with contextlib.ExitStack() as st:
            st.enter_context(mock.patch.object(dc, "PRIVATE_REPO_PAUSED", None))
            for m in _public_world(calls):
                st.enter_context(m)
            rc, msg, why = dc.cell_private_repo(args())
        self.assertEqual(rc, dc.FAIL, msg)
        self.assertIn("not PRIVATE", msg)
        self.assertIn("not ssh://", msg)
        self.assertIn("deploy-key -> FAIL", msg)
        self.assertEqual(calls, ["gh", "kubectl", "deploy-key"])

    def test_summary_has_a_place_for_the_new_kind(self):
        """A kind the runner's `order` does not know is dropped from every list --
        the cell would print a bare `?` and vanish from the 'next action' summary,
        which is the silent failure this repo keeps paying for."""
        cells = [(5, "private repo", lambda a: (dc.UNKNOWN, "not judged", dc.PAUSED))]
        buf = io.StringIO()
        with mock.patch.object(dc, "HANDOVER_CELLS", cells), contextlib.redirect_stdout(buf):
            rc = dc.check_handover(args())
        out = buf.getvalue()
        self.assertEqual(rc, dc.UNKNOWN)
        self.assertIn("[ruling]", out)
        self.assertIn(dc.WHY_TEXT[dc.PAUSED], out)
        self.assertIn("cells 5", out)


if __name__ == "__main__":
    unittest.main()
