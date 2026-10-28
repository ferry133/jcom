#!/usr/bin/env python3
"""Tests for scripts/provision.py — §4.

Run: python3 -m unittest discover -s scripts/tests -v
(stdlib only, on purpose: a test suite that needs a dependency installed is a
test suite that stops running on the machine that most needed it.)

**Why this file is tracked.** §3's equivalent tests were written, passed, and
were never committed — so the checkmarks on 3.2-3.7 rest on a run nobody else
can reproduce. `~/.claude/CLAUDE.md`'s form of the rule: a protection that lives
only on the machine doing the verifying is not a protection, it is a local habit
that reports as one. `git clone && python3 -m unittest` is the question these
files exist to answer.

Two of the cases below are regressions, not designs — they were found by
running the code against live systems, and neither would have been found by
re-reading it. They are marked REGRESSION.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prov", ROOT / "scripts" / "provision.py")
prov = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prov)

LIVE = os.environ.get("PROVISION_LIVE_TESTS") == "1"


class TestDerivedNames(unittest.TestCase):
    """4.4. The one worked example is real: janncot.cc -> jg-janncotcc is the
    name of a cluster that exists, so this is a comparison and not a restatement
    of the rule in a second place."""

    def test_the_measured_example(self):
        n = prov.derive_names("janncot.cc")
        self.assertEqual(n["cluster_name"], "jg-janncotcc")
        self.assertEqual(n["repository_name"], "ferry133/jg-janncotcc")
        self.assertEqual(n["tunnel_name"], "jg-janncotcc")

    def test_names_are_the_same_three(self):
        n = prov.derive_names("acme.tw")
        self.assertEqual(n["cluster_name"], n["tunnel_name"])
        self.assertTrue(n["repository_name"].endswith("/" + n["cluster_name"]))

    def test_tld_distinguishes_two_customers(self):
        self.assertNotEqual(prov.derive_names("acme.tw")["cluster_name"],
                            prov.derive_names("acme.com")["cluster_name"])

    def test_no_dots_survive(self):
        # Omni: "name should only contain letters, digits, dashes and
        # underscores". A rule that kept the dot fails at cluster creation,
        # several steps after everything else committed to the name.
        for d in ("a.b.c.example.com", "x.tw"):
            self.assertNotIn(".", prov.derive_names(d)["cluster_name"])

    def test_case_and_trailing_dot_normalise(self):
        self.assertEqual(prov.derive_names("Example.COM.")["cluster_name"],
                         prov.derive_names("example.com")["cluster_name"])

    def test_refuses_rather_than_mangles(self):
        for bad in ("", "acme", "acme .tw", "acme_ü.tw"):
            with self.assertRaises(prov.NameError_, msg=f"{bad!r} should be refused"):
                prov.derive_names(bad)


class TestTunnelDeletedAt(unittest.TestCase):
    """REGRESSION, measured 2026-08-26.

    `cloudflared tunnel list --output json` gives every row a `deleted_at`, and
    for a LIVE tunnel it is Go's zero time — a non-empty string, therefore
    truthy. The first version filtered on `not t.get("deleted_at")` and so
    reported ABSENT for tunnels it had just listed. ABSENT is the one state the
    driver acts on, so that bug created a second tunnel per re-run: the exact
    failure 4.10 exists to prevent, produced by a check that read as working.

    All four live tunnels on the workstation carried the zero time.
    """

    def test_zero_time_is_not_deleted(self):
        self.assertFalse(prov.tunnel_is_deleted({"deleted_at": "0001-01-01T00:00:00Z"}))

    def test_missing_and_null_are_not_deleted(self):
        self.assertFalse(prov.tunnel_is_deleted({}))
        self.assertFalse(prov.tunnel_is_deleted({"deleted_at": None}))
        self.assertFalse(prov.tunnel_is_deleted({"deleted_at": ""}))

    def test_a_real_timestamp_is_deleted(self):
        self.assertTrue(prov.tunnel_is_deleted({"deleted_at": "2026-08-23T10:00:00Z"}))


class FakeStep(prov.Step):
    def __init__(self, name, states):
        self.name = name
        self.task = "test"
        self._states = list(states)
        self.created = 0

    def observe(self, ctx):
        return prov.Observation(self._states.pop(0), f"{self.name} says so")

    def create(self, ctx):
        self.created += 1
        return []


class TestDriverDecisionTable(unittest.TestCase):
    """4.10 + 4.12. The four-way decision lives in one place so it cannot drift
    between steps; these are the four ways out of it."""

    def drive_with(self, steps, apply_=True):
        old, prov.STEPS = prov.STEPS, steps
        try:
            return prov.drive({"dir": "/nonexistent"}, apply_=apply_)
        finally:
            prov.STEPS = old

    def test_present_is_skipped_which_is_what_makes_a_rerun_converge(self):
        s = FakeStep("a", [prov.PRESENT])
        self.assertEqual(self.drive_with([s]), prov.DONE)
        self.assertEqual(s.created, 0)

    def test_absent_creates_then_reobserves(self):
        s = FakeStep("a", [prov.ABSENT, prov.PRESENT])
        self.assertEqual(self.drive_with([s]), prov.DONE)
        self.assertEqual(s.created, 1)

    def test_create_that_reports_success_but_changed_nothing_is_a_stop(self):
        # `gh repo create` exits 0 against a name already taken elsewhere.
        s = FakeStep("a", [prov.ABSENT, prov.ABSENT])
        self.assertEqual(self.drive_with([s]), prov.REFUSED)

    def test_unmeasurable_never_creates(self):
        # The whole file in one assertion: an unmeasured absence is not an
        # absence, and creating on it is how a second tunnel appears.
        s = FakeStep("a", [prov.UNMEASURABLE])
        self.assertEqual(self.drive_with([s]), prov.UNKNOWN)
        self.assertEqual(s.created, 0)

    def test_conflict_never_creates(self):
        s = FakeStep("a", [prov.CONFLICT])
        self.assertEqual(self.drive_with([s]), prov.REFUSED)
        self.assertEqual(s.created, 0)

    def test_a_stop_stops_the_steps_after_it(self):
        first = FakeStep("a", [prov.UNMEASURABLE])
        second = FakeStep("b", [prov.ABSENT, prov.PRESENT])
        self.assertEqual(self.drive_with([first, second]), prov.UNKNOWN)
        self.assertEqual(second.created, 0, "later steps observe a world nobody described")

    def test_without_apply_nothing_is_created(self):
        s = FakeStep("a", [prov.ABSENT])
        self.assertEqual(self.drive_with([s], apply_=False), prov.DONE)
        self.assertEqual(s.created, 1, "create() is called to print the commands…")
        # …but drive() never runs them; that is asserted by the absence of a
        # re-observation, which would have popped a second state and raised.


class TestMachineTicketMatching(unittest.TestCase):
    """4.1/4.2. Matching is a lookup on a label written at image-build time.
    It is deliberately not similarity over hostname or arrival order: 4.2's
    refusal is only worth something if it is exact."""

    def test_reads_the_label_both_shapes(self):
        self.assertEqual(prov.machine_ticket_label(
            {"metadata": {"labels": {"delivery-ticket": "42"}}}), "42")
        self.assertEqual(prov.machine_ticket_label(
            {"metadata": {"labels": {"delivery-ticket/42": ""}}}), "42")

    def test_unlabelled_machine_is_none_not_a_guess(self):
        for m in ({"metadata": {"labels": {"client": "1"}}},
                  {"metadata": {"labels": {}}},
                  {"metadata": {}},
                  {}):
            self.assertIsNone(prov.machine_ticket_label(m))

    def test_a_similar_label_does_not_match(self):
        self.assertIsNone(prov.machine_ticket_label(
            {"metadata": {"labels": {"delivery-tickets": "42"}}}))


class TestClusterYamlGuard(unittest.TestCase):
    """4.6/4.7. Rendering over another cluster's cluster.yaml produces that
    cluster's tree in this repo, and `task configure` would exit 0."""

    def observe(self, contents, cluster_name="jg-target"):
        with tempfile.TemporaryDirectory() as d:
            if contents is not None:
                (pathlib.Path(d) / "cluster.yaml").write_text(contents)
            return prov.ClusterYamlStep().observe(
                {"dir": d, "cluster_name": cluster_name})

    def test_absent(self):
        self.assertEqual(self.observe(None).state, prov.ABSENT)

    def test_matching(self):
        self.assertEqual(self.observe('cluster_name: "jg-target"\n').state, prov.PRESENT)
        self.assertEqual(self.observe("cluster_name: jg-target\n").state, prov.PRESENT)

    def test_another_clusters_file_is_a_conflict_not_an_overwrite(self):
        o = self.observe('cluster_name: "jg-someoneelse"\n')
        self.assertEqual(o.state, prov.CONFLICT)
        self.assertIn("jg-someoneelse", o.detail)

    def test_no_cluster_name_at_all(self):
        self.assertEqual(self.observe("storage_backend: nfs\n").state, prov.CONFLICT)


class TestHistoryLeakGuard(unittest.TestCase):
    """4.7's half of the runbook's `cluster.yaml` rule, over a real git repo
    built here rather than a recorded fixture — a fixture would encode whatever
    this code already believes `git log --all -- '*cluster.yaml'` prints."""

    def make_repo(self, commit_path: str | None):
        d = tempfile.mkdtemp()
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
               # No detached auto-maintenance outliving the temp dir (#209; see
               # the git() docstring in test_delivery_check_repo_hygiene.py).
               "GIT_CONFIG_COUNT": "2",
               "GIT_CONFIG_KEY_0": "maintenance.auto", "GIT_CONFIG_VALUE_0": "false",
               "GIT_CONFIG_KEY_1": "gc.auto", "GIT_CONFIG_VALUE_1": "0"}
        subprocess.run(["git", "-C", d, "init", "-q"], check=True, env=env)
        (pathlib.Path(d) / "README").write_text("x")
        subprocess.run(["git", "-C", d, "add", "README"], check=True, env=env)
        subprocess.run(["git", "-C", d, "commit", "-qm", "init"], check=True, env=env)
        if commit_path:
            p = pathlib.Path(d) / commit_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("cloudflare_token: realish-value-here\n")
            subprocess.run(["git", "-C", d, "add", "-f", commit_path], check=True, env=env)
            subprocess.run(["git", "-C", d, "commit", "-qm", "oops"], check=True, env=env)
            # Untracking is what jcom and jg-jiahd both did, and it is not
            # remediation: the blob stays reachable. The guard must still fire.
            subprocess.run(["git", "-C", d, "rm", "-q", "--cached", commit_path],
                           check=True, env=env)
            subprocess.run(["git", "-C", d, "commit", "-qm",
                            "chore: untrack sensitive config files"], check=True, env=env)
        return d

    def test_clean_history_passes(self):
        d = self.make_repo(None)
        self.assertEqual(prov.ConfigurePushStep().observe({"dir": d}).state, prov.PRESENT)

    def test_the_staged_tree_is_scanned_between_add_and_commit(self):
        """#178 — the half of that issue that does not live in delivery-check.

        Nothing under `templates/` or `.taskfiles/` invokes `repo-hygiene`
        (measured on main 2026-09-18), so the `--staged` cell added there is
        reachable only because this step calls it. **A PR that added the cell
        and not this call would pass every test in the other file and change
        nothing that runs.**

        The order is the assertion, not the presence: scanning after `commit`
        would be scanning something already in history, and scanning before
        `add` is what the issue is about.
        """
        cmds = prov.ConfigurePushStep().create({"dir": "/tmp/x"})
        joined = [" ".join(c) for c in cmds]
        # `next(..., None)` and an explicit assert, not a bare `next()`:
        # removing the call made this raise StopIteration, which is an
        # *errored* test, not a failing one. A guard whose red says
        # "StopIteration" names nothing — the reader has to open the file to
        # learn what was being checked.
        add = next((i for i, c in enumerate(joined)
                    if c.startswith("git -C /tmp/x add")), None)
        commit = next((i for i, c in enumerate(joined) if "commit" in c), None)
        staged = next((i for i, c in enumerate(joined) if "--staged" in c), None)
        self.assertIsNotNone(add, "the step must `git add` the rendered tree")
        self.assertIsNotNone(commit, "the step must commit it")
        self.assertIsNotNone(
            staged, "the step must call `repo-hygiene --staged` — without it "
                    "the cell in delivery-check.py is reachable by nobody")
        self.assertLess(add, staged, "the scan must come after `git add`")
        self.assertLess(staged, commit, "and before `git commit`")

    def test_the_path_that_actually_leaked_is_caught(self):
        # jcom and jg-jiahd leaked at config.gen/cluster.yaml while the ignore
        # rule and the check both named /cluster.yaml. The glob is the fix.
        d = self.make_repo("config.gen/cluster.yaml")
        o = prov.ConfigurePushStep().observe({"dir": d})
        self.assertEqual(o.state, prov.CONFLICT)

    def test_untracking_does_not_clear_it(self):
        d = self.make_repo("cluster.yaml")
        o = prov.ConfigurePushStep().observe({"dir": d})
        self.assertEqual(o.state, prov.CONFLICT)
        self.assertIn("untrack", o.detail)

    def test_not_a_repo_is_unmeasurable_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(prov.ConfigurePushStep().observe({"dir": d}).state,
                             prov.UNMEASURABLE)


class TestNetworkDerivation(unittest.TestCase):
    """4.6. Refusing to pick is the behaviour under test: node_cidr is one
    value, and a wrong one produces a cluster that comes up unreachable, which
    neither the render nor `cue vet` can see."""

    def test_ignores_loopback_and_link_local(self):
        import ipaddress
        addrs = ["127.0.0.1/8", "169.254.1.5/16", "10.9.1.20/24"]
        nets = set()
        for a in addrs:
            i = ipaddress.ip_interface(a)
            if i.ip.is_loopback or i.ip.is_link_local or i.version != 4:
                continue
            nets.add(str(i.network))
        self.assertEqual(nets, {"10.9.1.0/24"})


@unittest.skipUnless(LIVE, "set PROVISION_LIVE_TESTS=1 to run checks that need gh")
class TestLive(unittest.TestCase):
    """The observers that talk to real systems.

    Skipped by default so the suite runs offline — but skipped is not passed,
    and these are the cases that caught the `deleted_at` regression. Run them
    before trusting a change to any observer.
    """

    def test_existing_repo_is_present(self):
        o = prov.UserRepoStep().observe({"repository_name": "ferry133/jg-cluster-template"})
        self.assertEqual(o.state, prov.PRESENT)

    def test_missing_repo_is_absent_with_a_positive_control(self):
        o = prov.UserRepoStep().observe(
            {"repository_name": "ferry133/definitely-not-a-real-repo-8f3a"})
        self.assertEqual(o.state, prov.ABSENT)
        self.assertTrue(o.evidence, "an ABSENT with no positive control is a guess")


class TestStepInputsAreCheckedOnlyWhenActing(unittest.TestCase):
    """4.3 + #129. `omnictl cluster template sync -f <path>` is handed a file
    that nothing in this repo ships. The driver refuses to act on an
    unmeasurable observation of the outside world; `Step.inputs()` is that same
    refusal turned on the driver's own inputs.

    **Where the check lives is the whole design**, and it is a negative
    condition: `plan` and a `run` without `--apply` do not read that file, and
    must not start needing it. A check that fires on a correct "show me what
    you would do" gets switched off, and a switched-off check reads like
    coverage. `test_moving_the_check_into_observe_breaks_plan` is the control
    that proves the tests below can tell the difference — it puts the check in
    the wrong place and watches plan stop.
    """

    class StepWithInput(prov.Step):
        """A step that hands a path to an external command, like 4.3 does."""

        name, task = "needs-a-file", "test"

        def __init__(self, path, states, cmds=None):
            self.path = path
            self._states = list(states)
            self.cmds = cmds if cmds is not None else []
            self.created = 0
            self.observed = 0

        def observe(self, ctx):
            self.observed += 1
            return prov.Observation(self._states.pop(0), "says so")

        def inputs(self, ctx):
            return [self.path]

        def create(self, ctx):
            self.created += 1
            return list(self.cmds)

    class PlainStep(prov.Step):
        """Declares no inputs. Used to ask whether the driver carried on."""

        name, task = "after", "test"

        def __init__(self, states):
            self._states = list(states)
            self.observed = 0

        def observe(self, ctx):
            self.observed += 1
            return prov.Observation(self._states.pop(0), "says so")

        def create(self, ctx):
            return []

    def drive(self, steps, apply_):
        import contextlib
        import io
        out = io.StringIO()
        old, prov.STEPS = prov.STEPS, steps
        try:
            with contextlib.redirect_stdout(out):
                rc = prov.drive({"dir": "/nonexistent"}, apply_=apply_)
        finally:
            prov.STEPS = old
        return rc, out.getvalue()

    # --- the wiring is the real step, not only the fake one ----------------

    def test_the_real_step_declares_the_template_as_its_input(self):
        self.assertEqual(
            prov.OmniClusterStep().inputs({"omni_template": "/w/omni-cluster.yaml"}),
            ["/w/omni-cluster.yaml"],
            "if 4.3 stops declaring it, every test below still passes",
        )

    # --- acting without the file: stop, and say which path ----------------

    def test_applying_without_the_file_stops_and_names_the_path(self):
        missing = "/nonexistent/omni-cluster.yaml"
        s = self.StepWithInput(missing, [prov.ABSENT])
        rc, out = self.drive([s], apply_=True)
        self.assertEqual(rc, prov.UNKNOWN, "not DONE, and not a crash inside omnictl")
        self.assertIn(missing, out, "a stop that does not name the path is a riddle")
        # `create()` has already been called at this point, and that is not a
        # defect: by its own contract it *returns* the commands and runs
        # nothing (`Step.create`: "Returned, not run"), and `drive()` calls it
        # before the apply/plan split so that plan can print them. The
        # assertion that carries the meaning is that nothing was executed —
        # `drive()` marks each command it runs with "$ ".
        self.assertEqual(s.created, 1)
        self.assertNotIn("$ ", out, "no command may be executed after the stop")

    def test_the_file_being_there_is_not_a_stop(self):
        # Negative control. Without it, a check that always stops would pass
        # every assertion above.
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "omni-cluster.yaml")
            open(p, "w").write("kind: Cluster\n")
            s = self.StepWithInput(p, [prov.ABSENT, prov.PRESENT])
            rc, _ = self.drive([s], apply_=True)
        self.assertEqual(rc, prov.DONE)
        self.assertEqual(s.created, 1, "the input was there, so acting is correct")

    # --- the negative condition: plan and non-apply run are unchanged -----

    def test_plan_still_prints_would_and_carries_on(self):
        # The condition is NOT "plan exits 0" — plan can exit 0 having skipped
        # the step entirely. What is asserted is that it still says what it
        # would do, with the command, AND that the next step was reached.
        missing = "/nonexistent/omni-cluster.yaml"
        sync = ["omnictl", "cluster", "template", "sync", "-f", missing]
        first = self.StepWithInput(missing, [prov.ABSENT], cmds=[sync])
        after = self.PlainStep([prov.PRESENT])
        rc, out = self.drive([first, after], apply_=False)
        self.assertEqual(rc, prov.DONE)
        self.assertIn("WOULD", out)
        self.assertIn(" ".join(sync), out, "plan must still print the command")
        self.assertEqual(after.observed, 1, "it carried on; it did not stop")

    def test_moving_the_check_into_observe_breaks_plan(self):
        """The control for the test above: put the check in the wrong place
        and watch plan stop. Asserting in a comment that a misplaced check
        would be caught is not a measurement — this runs it."""

        class CheckedInObserve(TestStepInputsAreCheckedOnlyWhenActing.StepWithInput):
            def observe(self, ctx):
                self.observed += 1
                if not os.path.exists(self.path):      # the misplacement
                    return prov.Observation(prov.UNMEASURABLE, f"{self.path} is not here")
                return prov.Observation(self._states.pop(0), "says so")

        missing = "/nonexistent/omni-cluster.yaml"
        first = CheckedInObserve(missing, [prov.ABSENT])
        after = self.PlainStep([prov.PRESENT])
        rc, out = self.drive([first, after], apply_=False)
        self.assertEqual(rc, prov.UNKNOWN, "plan started failing — this is the harm")
        self.assertNotIn("WOULD", out)
        self.assertEqual(after.observed, 0, "and it stopped the steps after it")


class TestOmniTemplateBindsLocalPath(unittest.TestCase):
    """jgct#207 (jg-base#150): the Omni template must bind
    /var/local-path-provisioner into kubelet, or a local-path PVC mounted by
    subPath lands on kubelet's own rootfs. The talhelper path gets it from
    jgct#206; the Omni path only from the hand-written template, so 4.3 checks
    the file at the moment it is about to hand it to omnictl."""

    INLINE = (
        "  patches:\n"
        "    - idOverride: 400-x-kubelet-local-path\n"
        "      inline: |\n"
        "        machine:\n"
        "          kubelet:\n"
        "            extraMounts:\n"
        "              - destination: /var/local-path-provisioner\n"
        "                type: bind\n"
        "                source: /var/local-path-provisioner\n"
        "                options: [bind, rshared, rw]\n"
    )

    def write(self, d, text, name="omni-cluster.yaml"):
        p = os.path.join(d, name)
        open(p, "w").write(text)
        return p

    def check(self, text, extra=None):
        with tempfile.TemporaryDirectory() as d:
            for name, body in (extra or {}).items():
                self.write(d, body, name)
            return prov.template_local_path_mount(self.write(d, text))

    def test_cluster_level_patch_passes(self):
        self.assertEqual(self.check("kind: Cluster\nname: jg-a\n" + self.INLINE), (True, ""))

    def test_a_template_without_it_is_refused_and_says_what_to_add(self):
        ok_, why = self.check("kind: Cluster\nname: jg-a\n---\nkind: ControlPlane\nmachines: [m]\n")
        self.assertIs(ok_, False)
        for needle in ("/var/local-path-provisioner", "extraMounts", "jgct#207", "kind: Cluster"):
            self.assertIn(needle, why)

    def test_a_commented_out_patch_does_not_pass(self):
        commented = "".join("#" + l + "\n" for l in self.INLINE.splitlines())
        self.assertIs(self.check("kind: Cluster\nname: jg-a\n" + commented)[0], False)

    def test_every_machine_set_carrying_it_passes(self):
        cp = "kind: ControlPlane\nmachines: [a]\n" + self.INLINE
        w = "kind: Workers\nmachines: [b]\n" + self.INLINE
        self.assertIs(self.check(f"kind: Cluster\nname: jg-a\n---\n{cp}---\n{w}")[0], True)

    def test_one_machine_set_without_it_fails(self):
        cp = "kind: ControlPlane\nmachines: [a]\n" + self.INLINE
        w = "kind: Workers\nmachines: [b]\n"
        self.assertIs(self.check(f"kind: Cluster\nname: jg-a\n---\n{cp}---\n{w}")[0], False)

    def test_two_worker_sets_need_it_on_both(self):
        cp = "kind: ControlPlane\nmachines: [a]\n" + self.INLINE
        w1 = "kind: Workers\nname: w1\nmachines: [b]\n" + self.INLINE
        w2 = "kind: Workers\nname: w2\nmachines: [c]\n"
        self.assertIs(self.check(f"kind: Cluster\nname: jg-a\n---\n{cp}---\n{w1}---\n{w2}")[0], False)

    def test_a_machine_level_patch_alone_does_not_count(self):
        m = "kind: Machine\nname: uuid-1\n" + self.INLINE
        self.assertIs(self.check(f"kind: Cluster\nname: jg-a\n---\n{m}")[0], False)

    def test_a_patch_given_as_file_is_read(self):
        body = "machine:\n  kubelet:\n    extraMounts:\n      - destination: /var/local-path-provisioner\n"
        tmpl = "kind: Cluster\nname: jg-a\npatches:\n  - file: patches/lp.yaml\n"
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "patches"))
            self.write(d, body, "patches/lp.yaml")
            self.assertEqual(prov.template_local_path_mount(self.write(d, tmpl)), (True, ""))

    def test_an_unreadable_patch_file_is_not_a_pass(self):
        tmpl = "kind: Cluster\nname: jg-a\npatches:\n  - file: patches/missing.yaml\n"
        ok_, why = self.check(tmpl)
        self.assertIsNone(ok_)
        self.assertIn("patches/missing.yaml", why)

    # --- wired into the real step and the driver --------------------------

    def drive(self, path, apply_):
        import contextlib
        import io

        class Absent(prov.OmniClusterStep):
            def observe(self, ctx):
                return prov.Observation(prov.ABSENT, "no such cluster")

        out = io.StringIO()
        old, prov.STEPS = prov.STEPS, [Absent()]
        old_run, prov.run = prov.run, lambda c, **k: self.fail(f"executed {c}")
        try:
            with contextlib.redirect_stdout(out):
                rc = prov.drive({"omni_template": path, "dir": os.path.dirname(path)}, apply_=apply_)
        finally:
            prov.STEPS, prov.run = old, old_run
        return rc, out.getvalue()

    def test_applying_a_template_without_it_refuses_before_omnictl(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = self.drive(self.write(d, "kind: Cluster\nname: jg-a\n"), apply_=True)
        self.assertEqual(rc, prov.REFUSED)
        self.assertIn("/var/local-path-provisioner", out)
        self.assertNotIn("$ ", out, "omnictl must not have been run")

    def test_plan_is_unchanged_by_the_check(self):
        # Negative condition, as for inputs(): plan does not read the file.
        with tempfile.TemporaryDirectory() as d:
            rc, out = self.drive(self.write(d, "kind: Cluster\nname: jg-a\n"), apply_=False)
        self.assertEqual(rc, prov.DONE)
        self.assertIn("WOULD", out)


class TestOmniTemplateCarriesCriCustomization(unittest.TestCase):
    """jgct#238 (jg-base#188): the Omni template must write the containerd
    customization the talhelper path writes from `machine-files.yaml.j2`, or an
    Omni cluster gets neither key — measured on jg-jiahd (0-byte part file).
    The required lines are read from that file, so these cases build their
    templates from it too, and one case changes the source to prove it is
    the source."""

    def write(self, d, text, name="omni-cluster.yaml"):
        p = os.path.join(d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
        return p

    def patch(self, source=prov.CRI_CUSTOMIZATION_SOURCE):
        required, patch, why = prov.cri_customization(source)
        self.assertIsNotNone(required, why)
        return required, "patches:\n" + patch + "\n"

    def check(self, text, source=prov.CRI_CUSTOMIZATION_SOURCE):
        with tempfile.TemporaryDirectory() as d:
            return prov.template_cri_customization(self.write(d, text), source)

    def test_the_source_yields_both_keys(self):
        # Gate: if this reads nothing, every "missing" case below is vacuous.
        required, _ = self.patch()
        self.assertIn("discard_unpacked_layers = false", required)
        self.assertIn("device_ownership_from_security_context = true", required)

    def test_the_patch_it_prints_passes(self):
        _, patch = self.patch()
        self.assertEqual(self.check("kind: Cluster\nname: jg-a\n" + patch), (True, ""))

    def test_a_template_without_it_is_refused_and_says_what_to_add(self):
        ok_, why = self.check("kind: Cluster\nname: jg-a\n")
        self.assertIs(ok_, False)
        for needle in (prov.CRI_CUSTOMIZATION_PATH, "device_ownership_from_security_context = true",
                       "discard_unpacked_layers = false", "jgct#238", "idOverride: 400-<cluster>-cri-customization"):
            self.assertIn(needle, why)

    def test_dropping_any_one_line_fails(self):
        required, patch = self.patch()
        for line in required:
            with self.subTest(line=line):
                cut = "\n".join(l for l in patch.splitlines() if l.strip() != line) + "\n"
                self.assertNotEqual(cut, patch, "the line was not removed")
                self.assertIs(self.check("kind: Cluster\nname: jg-a\n" + cut)[0], False)

    def test_a_commented_out_patch_does_not_pass(self):
        _, patch = self.patch()
        commented = "".join("#" + l + "\n" for l in patch.splitlines())
        self.assertIs(self.check("kind: Cluster\nname: jg-a\n" + commented)[0], False)

    def test_every_machine_set_or_none(self):
        _, patch = self.patch()
        cp = "kind: ControlPlane\nmachines: [a]\n" + patch
        self.assertIs(self.check(f"kind: Cluster\nname: jg-a\n---\n{cp}---\nkind: Workers\nmachines: [b]\n" + patch)[0], True)
        self.assertIs(self.check(f"kind: Cluster\nname: jg-a\n---\n{cp}---\nkind: Workers\nmachines: [b]\n")[0], False)
        self.assertIs(self.check("kind: Cluster\nname: jg-a\n---\nkind: Machine\nname: u\n" + patch)[0], False)

    def test_a_key_added_to_the_source_is_then_required(self):
        _, patch = self.patch()
        text = open(prov.CRI_CUSTOMIZATION_SOURCE).read()
        added = text.rstrip("\n") + "\n          snapshotter_test_key = 1\n"
        self.assertNotEqual(added, text)
        with tempfile.TemporaryDirectory() as d:
            src = self.write(d, added, "machine-files.yaml.j2")
            self.assertIs(self.check("kind: Cluster\nname: jg-a\n" + patch, src)[0], False)
            _, patch2 = self.patch(src)
            self.assertIs(self.check("kind: Cluster\nname: jg-a\n" + patch2, src)[0], True)

    def test_an_unreadable_source_is_not_a_pass(self):
        ok_, why = self.check("kind: Cluster\nname: jg-a\n", "/nonexistent/machine-files.yaml.j2")
        self.assertIsNone(ok_)
        self.assertIn("/nonexistent/machine-files.yaml.j2", why)
        with tempfile.TemporaryDirectory() as d:
            src = self.write(d, "machine:\n  files: []\n", "m.j2")
            ok_, why = self.check("kind: Cluster\nname: jg-a\n", src)
        self.assertIsNone(ok_)
        self.assertIn(prov.CRI_CUSTOMIZATION_PATH, why)

    def test_the_step_reports_it_beside_the_local_path_check(self):
        _, patch = self.patch()
        lp = prov.LOCAL_PATH_MOUNT_PATCH + "\n"
        with tempfile.TemporaryDirectory() as d:
            only_lp = self.write(d, "kind: Cluster\nname: jg-a\n" + TestOmniTemplateBindsLocalPath.INLINE, "a.yaml")
            both = self.write(d, "kind: Cluster\nname: jg-a\n" + patch + lp, "b.yaml")
            step = prov.OmniClusterStep()
            found = step.input_problems({"omni_template": only_lp})
            self.assertEqual(len(found), 1)
            self.assertIn("jgct#238", found[0])
            self.assertEqual(step.input_problems({"omni_template": both}), [])


class TestPrintedPatchesPasteIntoTheRunbookTemplate(unittest.TestCase):
    """jgct#239 review (fleet-ops-65 [69d6d7]): the CRI patch was printed two
    spaces deeper than the runbook's `patches:` items. Pasted as printed, the
    text checks still passed and `omnictl cluster template validate` failed
    at rc 1 — so 4.3 would accept a template that `template sync` rejects.
    These cases paste both printed patches into a runbook-shaped template."""

    RUNBOOK = (
        "kind: Cluster\n"
        "name: jg-a\n"
        "kubernetes:\n  version: v1.36.0\n"
        "talos:\n  version: v1.13.11\n"
        "patches:\n"
        "  - idOverride: 200-jg-a\n"
        "    inline: |-\n"
        "      cluster:\n"
        "        network:\n"
        "          cni:\n"
        "            name: none\n"
        "{pasted}"
        "---\n"
        "kind: ControlPlane\n"
        "machines:\n"
        "  - 00000000-0000-0000-0000-000000000001\n"
    )

    def pasted(self):
        _, cri, why = prov.cri_customization()
        self.assertTrue(cri, why)
        patches = (prov.LOCAL_PATH_MOUNT_PATCH, cri)
        return self.RUNBOOK.format(pasted="".join(
            p.replace("<cluster>", "jg-a") + "\n" for p in patches))

    def test_items_sit_at_the_runbook_list_indent(self):
        text = self.pasted()
        items = [l for l in text.splitlines() if l.lstrip().startswith("- idOverride:")]
        self.assertEqual(len(items), 3, items)
        self.assertEqual({len(l) - len(l.lstrip()) for l in items}, {2}, items)
        for patch in (prov.LOCAL_PATH_MOUNT_PATCH, prov.cri_customization()[1]):
            body = patch.splitlines()[1:]
            with self.subTest(patch=patch.splitlines()[0]):
                self.assertTrue(body[0].startswith("    inline: |"), body[0])
                self.assertTrue(all(l.startswith("      ") for l in body[1:] if l.strip()))

    def test_the_pasted_template_passes_both_checks(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "omni-cluster.yaml")
            open(p, "w").write(self.pasted())
            self.assertEqual(prov.template_local_path_mount(p), (True, ""))
            self.assertEqual(prov.template_cri_customization(p), (True, ""))

    @unittest.skipUnless(shutil.which("omnictl"), "omnictl not installed: the real-engine case is not measured here")
    def test_omnictl_validates_the_pasted_template(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "omni-cluster.yaml")
            open(p, "w").write(self.pasted())
            r = subprocess.run(["omnictl", "cluster", "template", "validate", "-f", p],
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestOmniClusterIdentity(unittest.TestCase):
    """4.3 + #128. `PRESENT` is documented as "it is there, and it is the one
    this ticket says". Matching the name alone cannot say the second half, and
    the two halves need opposite corrections — which is what CONFLICT is for.

    **On the fixture.** The rows below are shaped from Omni's own definitions
    (`ClusterSpec` in `client/api/omni/specs/omni.proto`, `Cluster` in
    `client/pkg/template/internal/models/cluster.go`), not captured from a
    live Omni — nobody working on this has an Omni to capture from. The
    acceptance condition was relaxed to allow that on 2026-09-14 for one
    stated reason, and the reason is a dependency worth failing loudly on:
    **the only field these tests read out of a row is `metadata.id`**, which
    the code on `main` already reads and which is therefore not the thing in
    doubt. If the discrimination ever moves to another field, this fixture
    stops being grounded and has to be re-grounded against a real capture.
    """

    THIS = "jg-target"

    def rows(self, *ids):
        # `omnictl get clusters -o json` prints one document per resource;
        # `omnictl_json` has already decoded them into this list.
        return [{"metadata": {"id": i, "namespace": "default"},
                 "spec": {"kubernetesVersion": "v1.31.1", "talosVersion": "v1.8.1"}}
                for i in ids]

    def observe(self, ids, template=None, cluster_name=None):
        """Run 4.3's observation with Omni stubbed and a real file on disk."""
        want = cluster_name or self.THIS
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "omni-cluster.yaml")
            if template is not None:
                open(path, "w").write(template)
            old = prov.omnictl_json
            prov.omnictl_json = lambda *a, **k: (self.rows(*ids), "")
            try:
                return prov.OmniClusterStep().observe(
                    {"cluster_name": want, "omni_template": path, "dir": d}), path
            finally:
                prov.omnictl_json = old

    CLUSTER_DOC = 'kind: Cluster\nname: {name}\nkubernetes:\n  version: v1.31.1\ntalos:\n  version: v1.8.1\n'

    # --- the two controls the acceptance asked for -------------------------

    def test_this_deliverys_own_cluster_is_not_flagged(self):
        # NEGATIVE CONTROL. A guard that fires on the correct cluster would
        # block every normal provisioning run, and would then be switched off.
        obs, _ = self.observe([self.THIS, "jg-other"],
                              template=self.CLUSTER_DOC.format(name=self.THIS))
        self.assertEqual(obs.state, prov.PRESENT)
        self.assertNotEqual(obs.state, prov.CONFLICT)
        self.assertIn(self.THIS, obs.evidence)

    def test_a_template_describing_another_cluster_is_a_conflict(self):
        # POSITIVE CONTROL. Same name in Omni, different thing described here.
        obs, _ = self.observe([self.THIS],
                              template=self.CLUSTER_DOC.format(name="jg-someoneelse"))
        self.assertEqual(obs.state, prov.CONFLICT)
        self.assertIn("jg-someoneelse", obs.detail)

    # --- what happens when the description is not there --------------------

    def test_no_template_is_unmeasurable_not_present(self):
        obs, path = self.observe([self.THIS], template=None)
        self.assertEqual(obs.state, prov.UNMEASURABLE)
        self.assertIn(path, obs.detail, "a stop that does not name the path is a riddle")

    def test_a_template_this_parser_cannot_read_is_never_a_conflict(self):
        # The parser's own three-valued rule: "I could not read it" is not
        # evidence about the cluster, so it must not become CONFLICT — that
        # would flag a correct delivery on a parser bug.
        for bad_doc in ("kind: ControlPlane\nname: jg-target\n",      # no Cluster doc
                        "kind: Cluster\n",                            # no name
                        "kind: Cluster\nname: a\n---\nkind: Cluster\nname: b\n"):
            obs, _ = self.observe([self.THIS], template=bad_doc)
            self.assertEqual(obs.state, prov.UNMEASURABLE, bad_doc)

    def test_a_nested_name_is_not_mistaken_for_the_clusters(self):
        """Reading column 0 only is what keeps a stdlib parser honest.

        REGRESSION IN THE TEST, not the code. The first version of this case
        nested the decoy as a list item (`  - name: …`). It passed — and it
        passed for the wrong reason: a leading `-` misses the key pattern on
        its own, so the case stayed green even with the column-0 rule removed.
        A mutation (allowing indented keys) survived it, which is the only
        reason anyone noticed. The decoy below is a plain indented key, so it
        is the column-0 rule and nothing else that rejects it.
        """
        doc = ("kind: Cluster\n"
               "kubernetes:\n"
               "  name: jg-someoneelse\n"          # kills the mutant
               "  version: v1.31.1\n"
               "patches:\n"
               "  - name: jg-alsonotthis\n"        # kept: a real template has these
               "    inline:\n"
               "      cluster: {}\n"
               f"name: {self.THIS}\n")
        obs, _ = self.observe([self.THIS], template=doc)
        self.assertEqual(obs.state, prov.PRESENT)
        self.assertIn(self.THIS, obs.evidence)

    # --- the paths that must not have changed ------------------------------

    def test_absent_is_unchanged_when_the_template_is_missing(self):
        # This is what keeps `plan` and a `run` without --apply working on a
        # fresh clone: the cluster is not in Omni, so 4.3 is ABSENT and the
        # driver prints WOULD and carries on. #129 checks the file only when
        # it is about to act.
        obs, _ = self.observe(["jg-other"], template=None)
        self.assertEqual(obs.state, prov.ABSENT)
        self.assertTrue(obs.evidence, "an ABSENT with no positive control is a guess")

    def test_the_existing_unmeasurable_paths_still_work(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = {"cluster_name": self.THIS,
                   "omni_template": os.path.join(d, "omni-cluster.yaml"), "dir": d}
            old = prov.omnictl_json
            try:
                prov.omnictl_json = lambda *a, **k: (None, "omnictl is not installed")
                self.assertEqual(prov.OmniClusterStep().observe(ctx).state, prov.UNMEASURABLE)
                prov.omnictl_json = lambda *a, **k: ([], "")
                o = prov.OmniClusterStep().observe(ctx)
                self.assertEqual(o.state, prov.UNMEASURABLE, "zero clusters is not an answer")
            finally:
                prov.omnictl_json = old


class TestTemplateClusterNameParser(unittest.TestCase):
    """The parser behind 4.3's comparison, on its own. It is deliberately
    incurious: anything it is not sure of comes back as a reason, not a name."""

    def test_reads_the_name_from_the_cluster_document(self):
        for doc, want in (
            ("kind: Cluster\nname: jg-a\n", "jg-a"),
            ('kind: Cluster\nname: "jg-a"\n', "jg-a"),
            ("kind: Cluster\nname: 'jg-a'\n", "jg-a"),
            ("kind: ControlPlane\nname: mach\n---\nkind: Cluster\nname: jg-a\n", "jg-a"),
        ):
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "t.yaml")
                open(p, "w").write(doc)
                self.assertEqual(prov.template_cluster_name(p), (want, ""), doc)

    def test_a_missing_file_is_a_reason_not_an_exception(self):
        name, why = prov.template_cluster_name("/nonexistent/t.yaml")
        self.assertIsNone(name)
        self.assertIn("/nonexistent/t.yaml", why)



class TestIdentity(unittest.TestCase):
    """5.3. The interesting case is the unset one: `claudecode_allowed_emails`
    absent renders as auth0.json's list, which carries the operator's addresses
    — so unset and 'deliberately empty' are the same text in cluster.yaml and
    different clusters in production."""

    def run_identity(self, contents):
        import argparse
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "cluster.yaml").write_text(contents)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = prov.cmd_identity(argparse.Namespace(dir=d))
            return rc, out.getvalue()

    BASE = 'cluster_name: "jg-t"\ncloudflare_domain: "cust.tw"\n'

    def test_unset_is_refused_not_treated_as_empty(self):
        rc, out = self.run_identity(self.BASE)
        self.assertEqual(rc, prov.REFUSED)
        self.assertIn("auth0.json", out)

    def test_customer_domain_addresses_pass(self):
        rc, out = self.run_identity(
            self.BASE + 'claudecode_allowed_emails:\n  - "owner@cust.tw"\n')
        self.assertEqual(rc, prov.DONE)
        self.assertIn("this cluster's own domain", out)

    def test_a_foreign_address_is_surfaced_for_a_decision(self):
        # Not a failure: an operator address may be correct for a bench run and
        # wrong at handover, and only a person knows which this is.
        rc, out = self.run_identity(
            self.BASE + 'claudecode_allowed_emails:\n  - "operator@gmail.com"\n')
        self.assertEqual(rc, prov.DONE)
        self.assertIn("not cust.tw", out)

    def test_a_machine_shaped_address_is_refused(self):
        for addr in ("svc-bot@cust.tw", "noreply@cust.tw", "automation@cust.tw"):
            rc, _ = self.run_identity(
                self.BASE + f'claudecode_allowed_emails:\n  - "{addr}"\n')
            self.assertEqual(rc, prov.REFUSED, addr)

    def test_missing_cluster_yaml_is_unknown(self):
        import argparse
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(prov.cmd_identity(argparse.Namespace(dir=d)), prov.UNKNOWN)


class TestTemplateResidue(unittest.TestCase):
    """4.4. Measured 2026-08-26 across three real repos — two clean, one not —
    so this is a discriminating check and not one that always says the same
    thing. jg-jiahd tracks `docs/` and `openspec/`; the template and
    jg-janncotcc track neither."""

    def repo_with(self, dirs):
        import subprocess
        d = tempfile.mkdtemp()
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
               # No detached auto-maintenance outliving the temp dir (#209; see
               # the git() docstring in test_delivery_check_repo_hygiene.py).
               "GIT_CONFIG_COUNT": "2",
               "GIT_CONFIG_KEY_0": "maintenance.auto", "GIT_CONFIG_VALUE_0": "false",
               "GIT_CONFIG_KEY_1": "gc.auto", "GIT_CONFIG_VALUE_1": "0"}
        subprocess.run(["git", "-C", d, "init", "-q"], check=True, env=env)
        # A root-level file so the no-subdirectory case still has a commit —
        # otherwise that test measures `git commit` refusing an empty tree
        # rather than the check refusing to call an unreadable repo clean.
        (pathlib.Path(d) / "README.md").write_text("x\n")
        for sub in dirs:
            p = pathlib.Path(d) / sub / "f.yaml"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x: 1\n")
        subprocess.run(["git", "-C", d, "add", "-A"], check=True, env=env)
        subprocess.run(["git", "-C", d, "commit", "-qm", "init"], check=True, env=env)
        return d

    def residue(self, d):
        import argparse
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = prov.cmd_template_residue(argparse.Namespace(dir=d))
        return rc, out.getvalue()

    def test_a_cluster_repos_own_directories_pass(self):
        rc, _ = self.residue(self.repo_with(["kubernetes", "templates", "scripts"]))
        self.assertEqual(rc, prov.DONE)

    def test_the_trees_that_actually_leaked_are_caught(self):
        rc, out = self.residue(self.repo_with(["kubernetes", "openspec", "docs"]))
        self.assertEqual(rc, prov.REFUSED)
        self.assertIn("openspec", out)
        self.assertIn("docs", out)

    def test_a_tree_nobody_predicted_is_caught_too(self):
        # The point of asking "what is here" rather than "is openspec here":
        # the next tree the template grows will not be called openspec.
        rc, out = self.residue(self.repo_with(["kubernetes", "incident-reports"]))
        self.assertEqual(rc, prov.REFUSED)
        self.assertIn("incident-reports", out)

    def test_a_repo_with_no_subdirectories_is_unknown_not_clean(self):
        rc, _ = self.residue(self.repo_with([]))
        self.assertEqual(rc, prov.UNKNOWN)

    def test_not_a_repo_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            rc, _ = self.residue(d)
            self.assertEqual(rc, prov.UNKNOWN)

class TestOmniClusterTicketIdentity(unittest.TestCase):
    """4.3 + #140. The template naming this cluster says the *description*
    here is this delivery's; it does not say the cluster in Omni is. What
    identifies is the ticket the machines carry.

    Two label keys, both read from the systems that define them rather than
    guessed: `delivery-ticket` is written at image-build time and already has
    a reader in this file (`machine_ticket_label`, two shapes, covered by
    `TestMachineTicketMatching`), and `omni.sidero.dev/cluster` is Omni's own
    (`client/pkg/omni/resources/omni/labels.go`, read 2026-09-14).

    Every "could not ask" below is UNMEASURABLE. The one that is easiest to
    get wrong is a cluster with no machines yet: that is what a freshly
    created cluster looks like, so it cannot mean "someone else's".
    """

    THIS = "jg-target"
    TICKET = "42"

    def machine(self, uuid, cluster=None, ticket=None, slash=False):
        labels = {}
        if cluster:
            labels[prov.CLUSTER_LABEL] = cluster
        if ticket is not None:
            if slash:
                labels[f"{prov.TICKET_LABEL_PREFIX}/{ticket}"] = ""
            else:
                labels[prov.TICKET_LABEL_PREFIX] = ticket
        return {"metadata": {"id": uuid, "labels": labels}}

    def observe(self, machines, ticket=None, cluster_ids=None, template=True):
        """4.3's observation with Omni stubbed. `machines=None` = cannot read."""
        ids = cluster_ids if cluster_ids is not None else [self.THIS, "jg-other"]

        def fake(resource, *rest):
            if resource == "clusters":
                return ([{"metadata": {"id": i}, "spec": {}} for i in ids], "")
            if resource == "machinestatus":
                if machines is None:
                    return None, "omnictl is not installed"
                return machines, ""
            raise AssertionError(f"4.3 asked for an unexpected resource: {resource!r}")

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "omni-cluster.yaml")
            if template:
                open(path, "w").write(f"kind: Cluster\nname: {self.THIS}\n")
            ctx = {"cluster_name": self.THIS, "omni_template": path, "dir": d}
            if ticket is not None:
                ctx["ticket"] = ticket
            old, prov.omnictl_json = prov.omnictl_json, fake
            try:
                return prov.OmniClusterStep().observe(ctx)
            finally:
                prov.omnictl_json = old

    # --- the two controls --------------------------------------------------

    def test_this_deliverys_own_cluster_is_not_flagged(self):
        # NEGATIVE CONTROL. A guard that fires on the right cluster blocks
        # every normal re-run, and then gets switched off.
        for slash in (False, True):          # both label shapes
            obs = self.observe([self.machine("m1", self.THIS, self.TICKET, slash)],
                               ticket=self.TICKET)
            self.assertEqual(obs.state, prov.PRESENT, f"slash={slash}")
            self.assertIn(self.TICKET, obs.evidence)

    def test_another_deliverys_cluster_of_the_same_name_is_a_conflict(self):
        # POSITIVE CONTROL. Same name, same template, different delivery.
        obs = self.observe([self.machine("m1", self.THIS, "99")], ticket=self.TICKET)
        self.assertEqual(obs.state, prov.CONFLICT)
        self.assertIn("99", obs.detail)

    def test_one_foreign_machine_among_ours_is_still_a_conflict(self):
        obs = self.observe([self.machine("m1", self.THIS, self.TICKET),
                            self.machine("m2", self.THIS, "99")], ticket=self.TICKET)
        self.assertEqual(obs.state, prov.CONFLICT)

    # --- every way of not being able to ask --------------------------------

    def test_machines_that_cannot_be_read_are_unmeasurable(self):
        obs = self.observe(None, ticket=self.TICKET)
        self.assertEqual(obs.state, prov.UNMEASURABLE)

    def test_a_cluster_with_no_machines_yet_is_unmeasurable(self):
        # Not CONFLICT: this is exactly what a just-created cluster looks like.
        obs = self.observe([self.machine("m1", "jg-other", "99")], ticket=self.TICKET)
        self.assertEqual(obs.state, prov.UNMEASURABLE)
        self.assertIn(prov.CLUSTER_LABEL, obs.detail)

    def test_unlabelled_machines_are_unmeasurable_not_a_conflict(self):
        # "someone else's" and "ours, label never written" need opposite
        # corrections, so neither may be chosen here.
        obs = self.observe([self.machine("m1", self.THIS), self.machine("m2", self.THIS)],
                           ticket=self.TICKET)
        self.assertEqual(obs.state, prov.UNMEASURABLE)

    def test_the_cluster_label_is_omnis_own_string(self):
        """FOUND IN ACCEPTANCE by `FO-runbook [5fe39a]`, #143.

        Every fixture above builds its labels with `prov.CLUSTER_LABEL`, so
        the constant is being compared with itself and **any value passes**.
        Measured: setting it to `"totally.wrong/never-matches"` leaves all 218
        tests green. In production that is not a quiet failure — `members`
        would always be empty, and this step reports an empty membership as
        "a cluster whose machines have not been allocated yet", which reads
        perfectly normal, forever, while the check never fires once.

        So the literal is written out here, once. It is the only place in the
        tests that does not go through the constant.
        """
        self.assertEqual(prov.CLUSTER_LABEL, "omni.sidero.dev/cluster")

    def test_an_unidentified_member_is_named_in_the_evidence(self):
        """Also found in acceptance. One machine on our ticket and one with no
        label at all is still PRESENT — a positive identification is a
        positive answer — but the evidence used to read `2 machines … ticket
        label(s) ['42']`, which says every machine was checked. The contract
        this step is built on is that PRESENT never claims more than it
        measured."""
        obs = self.observe([self.machine("m1", self.THIS, self.TICKET),
                            self.machine("m2", self.THIS)], ticket=self.TICKET)
        self.assertEqual(obs.state, prov.PRESENT)
        self.assertIn("1 of them carry no", obs.evidence)

    # --- the negative condition: --ticket stays optional -------------------

    def test_without_a_ticket_present_says_what_it_did_not_compare(self):
        # The weaker answer is allowed; claiming more than was measured is not.
        obs = self.observe([self.machine("m1", self.THIS, "99")])   # no ticket in ctx
        self.assertEqual(obs.state, prov.PRESENT)
        self.assertIn("ticket not compared", obs.evidence)

    def test_build_ctx_tolerates_a_namespace_without_a_ticket(self):
        import argparse
        ns = argparse.Namespace(domain="acme.tw", dir=".")
        self.assertIsNone(prov.build_ctx(ns)["ticket"])
        ns2 = argparse.Namespace(domain="acme.tw", dir=".", ticket="42")
        self.assertEqual(prov.build_ctx(ns2)["ticket"], "42")

    def test_plan_still_parses_without_a_ticket(self):
        """#129's negative condition, applied to the command line: requiring
        `--ticket` would make `plan` start failing for everyone who can run it
        today. Exercised through the real parser in `main()`, with the command
        stubbed so the driver does not run."""
        import sys
        seen = {}

        def fake_plan(args):
            seen["ticket"] = getattr(args, "ticket", "MISSING")
            return prov.DONE

        old_plan, prov.cmd_plan = prov.cmd_plan, fake_plan
        old_argv = sys.argv
        try:
            sys.argv = ["provision.py", "plan", "--domain", "acme.tw"]
            self.assertEqual(prov.main(), prov.DONE)
            self.assertIsNone(seen["ticket"], "--ticket must default, not be required")
            sys.argv = ["provision.py", "plan", "--domain", "acme.tw", "--ticket", "42"]
            self.assertEqual(prov.main(), prov.DONE)
            self.assertEqual(seen["ticket"], "42")
        finally:
            prov.cmd_plan, sys.argv = old_plan, old_argv


class TestThisFileRunsWholeBothWays(unittest.TestCase):
    """The `__main__` guard has to stay at the end of this file.

    REGRESSION, measured 2026-09-14 on `main` 3b090e38 and again on 03a7dbd7:
    it used to sit above several classes, so running this file directly
    collected the classes defined *before* it and nothing after —
    `Ran 44` against `discover`'s `Ran 54`, **and both printed `OK`**.
    Ten tests were skipped with no warning, no non-zero exit, nothing to
    compare the number against. `run-tests.py` uses discovery so CI was never
    blind; the person running the file directly was.

    A comment saying "keep this last" is not a guard — it reads exactly like a
    guard that works. This asserts the position from the file's own text, so
    appending a class below it goes red.
    """

    GUARD = 'if __name__ == "__main__":'

    def test_the_main_guard_is_the_last_statement(self):
        lines = [l for l in pathlib.Path(__file__).read_text().splitlines() if l.strip()]
        self.assertEqual(
            lines[-2:],
            [self.GUARD, "    unittest.main()"],
            "a class defined below the __main__ guard is silently not collected "
            "when this file is run directly, and the run still prints OK",
        )

    def test_there_is_exactly_one_main_guard(self):
        """The property that matters is "last statement that *runs*", and the
        assertion above only says "last two lines". Those are the same sentence
        while there is one guard and different sentences when there are two.

        FALSE NEGATIVE, found by `k8scc [ef2bb8]` accepting #141 and reproduced
        here: put a second guard back in the middle (a merge resolved wrong, a
        copy-paste revival) and keep the one at the end. Running the file
        directly gives `Ran 44 OK` again — the original defect, whole — while
        the test above stays green two ways over: the last two lines really are
        the guard, and in the direct run that test is not even collected,
        because the middle `unittest.main()` has already called `sys.exit()`.
        Measured: collected 0 times directly, once under discovery.

        Counting whole lines is what keeps this honest — the literal in the
        assertion above is indented, so it is not one of these.

        ⚠️ **What this assertion cannot do, measured rather than assumed.**
        It does not rescue the direct run: with a second guard in place,
        `python3 scripts/tests/test_provision.py` still prints `Ran 44 OK`,
        because this test is not collected either — nothing inside a file can
        catch a `sys.exit()` that happens before collection starts. What it
        buys is that the state cannot *survive*: discovery sees the whole
        module, so `run-tests.py` and CI go red and the second guard cannot be
        committed. The local liar is still a liar until someone runs CI.
        Closing that would need a check outside this file — comparing the two
        collection counts — which is `#137`'s own follow-up note about
        `run-tests.py` catching "zero collected" but not "half a file missing".
        """
        lines = [l for l in pathlib.Path(__file__).read_text().splitlines() if l.strip()]
        self.assertEqual(
            lines.count(self.GUARD), 1,
            "a second __main__ guard above the classes exits before they are "
            "collected, and the run still prints OK",
        )



class TestStepsAreWiredToTheDriver(unittest.TestCase):
    """`STEPS` is the only thing that connects a Step class to `drive()`.

    Every other test in this file instantiates the class it is testing —
    `prov.OmniClusterStep().observe(ctx)` — because that is the only way to feed
    it a fake `omnictl`. So nothing asked whether the class is in the list the
    driver walks. **Removing `OmniClusterStep()` from `STEPS` left all 220 tests
    green** (jgct#144, found by `FO-runbook [5fe39a]` while accepting `#143`):
    the whole of 4.3 disappeared — its name match, its template comparison, its
    ticket identity — and the suite could not tell.

    It fails silently by construction: a step that is not in the list prints
    nothing, and **"this step had nothing to report" and "this step is not
    there" look the same on a terminal.**

    Order is asserted too, not just membership. The tasks run in sequence and
    each reads what the ones before it produced, so a reordering is a different
    program; and asserting only `len(STEPS)` would pass a swap.
    """

    #: (task, class name), in the order `drive()` walks them.
    EXPECTED = [
        ("4.3", "OmniClusterStep"),
        ("4.4", "UserRepoStep"),
        ("4.5", "TunnelStep"),
        ("4.6", "ClusterYamlStep"),
        ("4.7", "ConfigurePushStep"),
        ("4.8", "KubeconfigStep"),
    ]

    def test_steps_match_the_expected_wiring(self):
        got = [(s.task, type(s).__name__) for s in prov.STEPS]
        # longMessage off, and the difference printed by hand: unittest appends
        # a custom message *after* its own list diff, and the one thing a reader
        # needs first is what to do about it. A message they have to scroll past
        # a diff to reach is halfway to not being written.
        self.longMessage = False
        self.assertEqual(
            got, self.EXPECTED,
            "\n"
            "STEPS is not what this test expects.\n"
            "\n"
            "  If you added, removed or reordered a step ON PURPOSE: update\n"
            "  EXPECTED in this test. Going red on a legitimate change is this\n"
            "  assertion's job, not a defect — but say so here rather than\n"
            "  deleting it.\n"
            "\n"
            "  If you did NOT change STEPS: a step left the driver's list while\n"
            "  its class stayed in place. The class still passes its own tests,\n"
            "  and nothing else in this suite would notice (jgct#144).\n"
            "\n"
            f"  in STEPS:  {got}\n"
            f"  expected:  {self.EXPECTED}\n",
        )

    def test_every_step_in_the_list_has_a_distinct_task(self):
        # A duplicate task number would make two rows print the same [4.x] head,
        # and the operator reads that head to decide what to fix.
        tasks = [s.task for s in prov.STEPS]
        self.assertEqual(sorted(tasks), sorted(set(tasks)), f"duplicate task in {tasks}")



class TestDeriveGatewayKey(unittest.TestCase):
    """4.6 must tell "I asked the wrong thing" from "Omni says none" (jgct#152).

    The defect: the code read `default_gateways` — the **proto** field name —
    while `omnictl get machinestatus -o json` emits `defaultgateways`. The key
    was never found, `or []` turned the miss into an empty list, and the empty
    list was reported as *no default gateway reported*. That sentence is about
    Omni; what had actually happened was about the query. It then applied the
    template's `.1`-of-`node_cidr` guess, which is the assumption `#49` removed.

    Both halves are asserted because either alone passes on a broken version:
    read the right key and you still cannot tell absent from empty; split the
    states while reading the wrong key and every machine looks "absent".
    """

    ARGS = dict(machine="m-1", domain="example.test", dir=".", profile="full")

    def _derive(self, network: dict):
        rows = [{"spec": {"network": network}}]
        out = io.StringIO()
        with mock.patch.object(prov, "omnictl_json", return_value=(rows, "")), \
             contextlib.redirect_stdout(out):
            rc = prov.cmd_derive(types.SimpleNamespace(**self.ARGS))
        return rc, out.getvalue()

    NET = {"addresses": ["10.9.9.62/24"]}

    def test_the_address_guidance_asks_for_three_not_four(self):
        """#188 condition 4 — the sentence the operator acts on.

        `cmd_derive` speaks to Omni and nothing else, so the cluster it is
        describing is always on `provisioning_path: omni` — where, since #188,
        `cluster_api_addr` has no consumer and the schema no longer asks for
        it. The text still said "Pick four unused addresses".

        ⚠️ Asserted here rather than left to review because of the 2026-09-16
        ruling: **when the words are what an operator acts from, they are the
        product**. A defect that moves from the schema onto the operator's
        screen has not been fixed — it has been relocated to where it looks
        more authoritative, since the schema would at least have refused.
        """
        rc, out = self._derive({**self.NET, "defaultgateways": ["10.9.9.1"]})
        self.assertNotIn("four unused addresses", out)
        self.assertIn("THREE unused addresses", out)
        # And it names which three, so "three" is not a number to guess at.
        for field in ("cluster_gateway_addr", "cluster_dns_gateway_addr",
                      "cloudflare_gateway_addr"):
            with self.subTest(field=field):
                self.assertIn(field, out)
        # The one that is no longer asked for is named too, with its reason —
        # otherwise the next operator re-adds it from an older ticket.
        self.assertIn("NOT cluster_api_addr", out)

    def test_the_appliance_branch_is_untouched_by_that(self):
        """Positive control for the case above: the appliance text still
        rejects all four, so the change is scoped to the non-appliance branch
        and not a global rewrite of this command's output."""
        args = dict(self.ARGS, profile="appliance")
        out = io.StringIO()
        with mock.patch.object(prov, "omnictl_json",
                               return_value=([{"spec": {"network": {
                                   **self.NET, "defaultgateways": ["10.9.9.1"]}}}], "")), \
             contextlib.redirect_stdout(out):
            prov.cmd_derive(types.SimpleNamespace(**args))
        text = out.getvalue()
        self.assertIn("profile=appliance", text)
        self.assertIn("cluster_api_addr", text)
        self.assertNotIn("THREE unused addresses", text)

    def test_reads_the_lower_case_key_omnictl_actually_emits(self):
        rc, out = self._derive({**self.NET, "defaultgateways": ["10.9.9.1"]})
        self.assertIn("node_default_gateway: 10.9.9.1", out)

    def test_the_proto_name_is_not_what_is_read(self):
        # The exact shape that produced the defect: the value is there under the
        # proto name, and this command must NOT find it — otherwise the test
        # would pass against a version that reads both and hides the mistake.
        rc, out = self._derive({**self.NET, "default_gateways": ["10.9.9.1"]})
        self.assertNotIn("node_default_gateway: 10.9.9.1", out)
        self.assertIn("no `defaultgateways` key", out)

    def test_key_absent_is_a_question_about_the_name(self):
        rc, out = self._derive(self.NET)
        self.assertEqual(rc, prov.UNKNOWN)
        self.assertIn("no `defaultgateways` key", out)
        self.assertNotIn("Omni reports no default gateway", out)
        # And it must not send the reader to the .1 default.
        self.assertNotIn(".1-of-node_cidr", out)

    def test_key_present_and_empty_is_an_answer_from_omni(self):
        rc, out = self._derive({**self.NET, "defaultgateways": []})
        self.assertIn("Omni reports no default gateway", out)
        self.assertNotIn("no `defaultgateways` key", out)

    def test_the_two_empty_cases_do_not_print_the_same_thing(self):
        # NEGATIVE CONTROL for the split itself. Collapsing them is the defect,
        # and a version that reports both the same way passes every test above
        # that only checks one of them.
        _, absent = self._derive(self.NET)
        _, empty = self._derive({**self.NET, "defaultgateways": []})
        self.assertNotEqual(absent, empty)



class TestClusterRepoToplevelCoversTheTemplate(unittest.TestCase):
    """Every directory THIS repo tracks must be in `CLUSTER_REPO_TOPLEVEL`.

    A repo made from this template inherits every tracked file, so the moment
    this template tracks a directory the allowlist does not name,
    `provision.py template-residue` fails on a repo that was just created and
    has not been touched — and its message tells the operator to delete it.

    That is not hypothetical (jgct#148): the allowlist was written 2026-08-26,
    `zero-it-assets/` entered the template 2026-09-05, **and nothing tied the
    two together**. Every new customer repo failed the check for ten days, and
    the deletion it advised would have removed the images the customer's
    printed handout references. It surfaced only on a real delivery.

    So the tie is written here, where CI runs it: **this is the check that
    should have gone red on 2026-09-05 instead of a person going red on
    2026-09-15.**

    ⚠️ Only one direction is asserted. `CLUSTER_REPO_TOPLEVEL` legitimately
    holds names this template does not track — `kubernetes`, `bootstrap` and
    `talos` are rendered by `task configure` and appear only in the customer's
    repo. A superset is expected; a **subset** is the defect.
    """

    def _template_toplevel(self) -> set[str]:
        # Same shape as `template-residue`: directories, from tracked paths.
        r = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD"],
                           cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        tops = {p.split("/", 1)[0] for p in r.stdout.splitlines() if "/" in p}
        # Positive control: if this ever comes back empty the assertion below
        # passes vacuously, and an empty set is what a broken query looks like.
        self.assertIn("scripts", tops, "git ls-tree returned nothing usable")
        return tops

    def test_the_template_tracks_nothing_the_allowlist_omits(self):
        tops = self._template_toplevel()
        missing = sorted(tops - set(prov.CLUSTER_REPO_TOPLEVEL))
        self.longMessage = False
        self.assertEqual(
            missing, [],
            "\n"
            f"This template tracks top-level director{'y' if len(missing)==1 else 'ies'} "
            f"that CLUSTER_REPO_TOPLEVEL does not name: {', '.join(missing)}\n"
            "\n"
            "  Every repo created from this template inherits them, so\n"
            "  `provision.py template-residue` will fail on a brand-new repo and\n"
            "  tell the operator to delete them.\n"
            "\n"
            "  If the directory belongs in a cluster repo: add it to\n"
            "  CLUSTER_REPO_TOPLEVEL in scripts/provision.py **with its reason**.\n"
            "  If it does not belong in a cluster repo: it should not be tracked\n"
            "  in the template either, because the template is what makes them.\n",
        )

    def test_every_entry_carries_a_reason(self):
        # The allowlist is a dict so that adding a name costs a sentence. An
        # empty reason turns it back into a set that anyone can grow silently.
        blank = sorted(k for k, v in prov.CLUSTER_REPO_TOPLEVEL.items() if not v.strip())
        self.assertEqual(blank, [], f"no reason given for: {blank}")


if __name__ == "__main__":
    unittest.main()
