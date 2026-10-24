#!/usr/bin/env python3
"""Tests for delivery-check.py's bounds on external commands — #117.

Run: python3 .github/workflows/run-tests.py

**An unbounded wait and a correct check are identical on the happy path.** That
is why these tests exist rather than a note saying the timeouts were added:
#114 was an `omnictl` call that blocked forever, and what made it expensive was
not the hang itself but that `ci-checks.py --run` stopped there while the
wrapper's exit code still read like a completed run.

Each test that asserts a bound is paired with a positive control. A `run()` that
raised on everything would satisfy "hangs are stopped" perfectly, and a fake tool
that is simply broken would produce the same `?` as a fake tool that hangs.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import pathlib
import subprocess
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)


def fake_tool(d: str, name: str, body: str) -> None:
    p = pathlib.Path(d) / name
    p.write_text(f"#!/bin/sh\n{body}\n")
    p.chmod(0o755)


@contextlib.contextmanager
def tool_on_path(body: str, remote_timeout: int = 1, name: str = "kubectl"):
    """A fake `name` first on PATH, with REMOTE_TIMEOUT shortened for the test."""
    with tempfile.TemporaryDirectory() as d:
        fake_tool(d, name, body)
        kubeconfig = pathlib.Path(d) / "kubeconfig"
        kubeconfig.write_text("not read by the fake tool, but must exist\n")
        old_path, old_timeout = os.environ["PATH"], dc.REMOTE_TIMEOUT
        os.environ["PATH"] = d + os.pathsep + old_path
        dc.REMOTE_TIMEOUT = remote_timeout
        try:
            yield str(kubeconfig)
        finally:
            os.environ["PATH"] = old_path
            dc.REMOTE_TIMEOUT = old_timeout


class TestRunHasADefaultBound(unittest.TestCase):
    """`run()` without an explicit `timeout=` used to wait forever (16 sites)."""

    def test_default_bound_applies_when_the_caller_passes_nothing(self):
        old = dc.RUN_TIMEOUT
        dc.RUN_TIMEOUT = 1
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                dc.run(["sleep", "5"])
        finally:
            dc.RUN_TIMEOUT = old

    def test_positive_control_a_fast_command_still_returns(self):
        """Without this, a run() that raised unconditionally would pass above."""
        r = dc.run(["sh", "-c", "printf hi"])
        self.assertEqual((r.returncode, r.stdout), (0, "hi"))

    def test_an_explicit_timeout_still_wins(self):
        """`--timeout` and `_run_bounded` set their own numbers; the default is
        a backstop, not a policy."""
        with self.assertRaises(subprocess.TimeoutExpired):
            dc.run(["sleep", "5"], timeout=1)


class TestBoundedCallsReportCannotMeasure(unittest.TestCase):
    def test_a_hang_becomes_a_reason_rather_than_an_exception(self):
        r, reason = dc._run_bounded(["sleep", "5"], 1, "the sleeper")
        self.assertIsNone(r)
        self.assertIn("did not answer within 1s", reason)

    def test_positive_control_a_command_that_answers(self):
        r, reason = dc._run_bounded(["sh", "-c", "exit 0"], 5, "a quick one")
        self.assertIsNotNone(r)
        self.assertIsNone(reason)


class TestHangingRemoteToolIsUnknownNotFail(unittest.TestCase):
    """#117's actual subject, on a real check.

    The distinction is not cosmetic. `check_flux`'s FAIL prints "Flux is not
    installed or not reconciling" and tells the reader every later absence is
    meaningless — a strong claim. If a hanging API server produced that line,
    the operator would go and fix a cluster that may be fine, because the run
    could not ask it anything.
    """

    def _args(self, kubeconfig: str):
        return types.SimpleNamespace(kubeconfig=kubeconfig, expect_sha="deadbee")

    def test_a_kubectl_that_never_answers_gives_unknown(self):
        buf = io.StringIO()
        with tool_on_path("sleep 30") as kubeconfig:
            with contextlib.redirect_stdout(buf):
                rc = dc.check_flux(self._args(kubeconfig))
        self.assertEqual(rc, dc.UNKNOWN, buf.getvalue())
        self.assertIn("did not answer within 1s", buf.getvalue())

    def test_positive_control_a_kubectl_that_answers_does_not_give_unknown(self):
        """Proves the UNKNOWN above came from the hang and not from the fake
        tool merely being unlike kubectl: the same harness, answering, reaches
        the check's own verdict instead."""
        buf = io.StringIO()
        with tool_on_path("printf '%s' '{\"items\": []}'") as kubeconfig:
            with contextlib.redirect_stdout(buf):
                rc = dc.check_flux(self._args(kubeconfig))
        self.assertEqual(rc, dc.FAIL, buf.getvalue())
        self.assertIn("no GitRepository objects at all", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
