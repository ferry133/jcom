"""TEMPLATE_ONLY checks run in the template repo and are skipped elsewhere.

jgct#236 review (fleet-ops-65 [69d6d7]): a repo made from this template
inherits `.github/` and runs `ci-checks.py --run` on every push, but it has no
JG_EXTRAS_READ_KEY. With check-reserved-namespaces.py in RUN, the guard exits 2
there and every customer push is red. These cases hold the split: the template
still runs it (so the fix cannot be "never run it"), another repo reports it as
not run with its own name, and the workflow's clone step is gated on the same
repository name ci-checks.py uses.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import pathlib
import re
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "template-checks.yaml"
GUARD = "check-reserved-namespaces.py"


def load():
    spec = importlib.util.spec_from_file_location(
        "ci_checks", ROOT / ".github" / "workflows" / "ci-checks.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_with(mod, repository):
    """Run `run()` with the real lists' template-only part and no RUN scripts.

    subprocess is replaced so nothing executes; what it was asked to run is the
    reading.
    """
    called = []

    def fake_run(cmd, cwd=None):
        called.append(pathlib.Path(cmd[-1]).name)
        return types.SimpleNamespace(returncode=0)

    mod.RUN = []
    mod.subprocess = types.SimpleNamespace(run=fake_run)
    env = {} if repository is None else {"GITHUB_REPOSITORY": repository}
    mod.os = types.SimpleNamespace(environ=env)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = mod.run()
    return rc, called, out.getvalue()


class TestPlan(unittest.TestCase):
    def setUp(self):
        self.m = load()

    def test_guard_is_template_only(self):
        # If it moved back into RUN, every case below would still pass for the
        # template and the customer repo would be red again.
        self.assertIn(GUARD, self.m.TEMPLATE_ONLY)
        self.assertNotIn(GUARD, self.m.RUN)
        self.assertNotIn(GUARD, self.m.SKIP)

    def test_template_repo_runs_it(self):
        run, skip = self.m.plan(self.m.TEMPLATE_REPO)
        self.assertIn(GUARD, run)
        self.assertNotIn(GUARD, skip)

    def test_local_run_runs_it(self):
        run, _ = self.m.plan(None)
        self.assertIn(GUARD, run)

    def test_customer_repo_skips_it_and_says_where(self):
        run, skip = self.m.plan("ferry133/jg-jcc1")
        self.assertNotIn(GUARD, run)
        self.assertIn("ferry133/jg-jcc1", skip[GUARD])
        self.assertIn(self.m.TEMPLATE_REPO, skip[GUARD])

    def test_customer_repo_loses_nothing_else(self):
        # Gating must not take the ordinary checks with it.
        run, skip = self.m.plan("ferry133/jg-jcc1")
        self.assertEqual(run, self.m.RUN)
        for name in self.m.SKIP:
            self.assertEqual(skip[name], self.m.SKIP[name])


class TestRun(unittest.TestCase):
    def test_template_repo_executes_the_guard(self):
        m = load()
        rc, called, _ = run_with(m, m.TEMPLATE_REPO)
        # Every template-only guard, and nothing else (RUN is emptied above).
        # Was `[GUARD]` while it was the only one; jgct#249 added
        # check-netdev-contract.py, which needs the same jg-base clone.
        self.assertIn(GUARD, called)
        self.assertEqual((rc, called), (0, list(m.TEMPLATE_ONLY)))

    def test_customer_repo_does_not_execute_it_and_prints_the_skip(self):
        m = load()
        rc, called, out = run_with(m, "ferry133/jg-jcc3")
        self.assertEqual((rc, called), (0, []))
        self.assertRegex(out, rf"not run  {re.escape(GUARD)} — only runs in "
                              rf"{re.escape(m.TEMPLATE_REPO)}, this is ferry133/jg-jcc3")


class TestWorkflowGate(unittest.TestCase):
    def test_clone_step_is_gated_on_the_same_repository(self):
        text = WORKFLOW.read_text()
        step = re.search(
            r"- name: Clone jg-base and jg-extras for the namespace guard\n"
            r"((?:        .*\n)+)", text)
        self.assertIsNotNone(step, "clone step not found by name in template-checks.yaml")
        gate = re.search(r"^        if: (.+)$", step.group(1), re.M)
        self.assertIsNotNone(gate, "clone step has no if:")
        self.assertEqual(gate.group(1).strip(),
                         f"github.repository == '{load().TEMPLATE_REPO}'")


if __name__ == "__main__":
    unittest.main()
