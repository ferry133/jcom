#!/usr/bin/env python3
"""A stale template checkout must not be allowed to say "edited locally" — jgct#195.

Run: python3 .github/workflows/run-tests.py

`stale_or_edited()` answers by looking the cluster's bytes up in the template
checkout's own history. When that checkout is behind, the newer blobs are not
in its object database, the lookup falls through, and a **synced** file is
reported with the strongest phrase the tool can produce:

    DRIFTED  .taskfiles/template/resources/cluster.schema.cue
             (306 changed lines; edited locally: these bytes are no version
              this path ever had)

Measured by `FO-runbook [5fe39a]` on 2026-09-24: that blob was byte-identical
to jgct `origin/main`, and the local checkout was 146 commits behind.

⚠️ The direction of the error is what makes it worse than a normal false
positive. The tool's own help says `stale` needs no judgement and
`edited locally` is "the one that needs a reason". So the reader goes looking
for a reason that does not exist, and the likeliest resolution is to record the
file as a deliberate local exception — **a synced file becomes a permanent
one**.

Both directions are asserted here. Testing only the fresh side would leave
"passes" and "this classification was never wired up" identical.
"""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "drift", ROOT / "scripts" / "check-template-drift.py")
drift = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(drift)

REL = pathlib.Path("shared.txt")
V0 = "version zero\n"
V1 = "version one\n"
V2 = "version two\n"
NEVER = "bytes that were never committed anywhere\n"


def git(d: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(d), "-c", "user.name=t", "-c", "user.email=t@t",
         "-c", "commit.gpgsign=false",
         # No detached auto-maintenance outliving the temp dir (#209; see the
         # git() docstring in test_delivery_check_repo_hygiene.py).
         "-c", "maintenance.auto=false", "-c", "gc.auto=0", *args],
        capture_output=True, text=True, timeout=60)


def build(tmp: pathlib.Path, *, fresh: bool) -> pathlib.Path:
    """A template checkout with an `origin/main` that has V2.

    `fresh=False` leaves the checkout at V1 while origin holds V2 — the
    situation the issue is about: the newer blob exists, just not here.
    """
    upstream = tmp / "upstream"
    upstream.mkdir()
    git(upstream, "init", "-q", "-b", "main")
    (upstream / REL).write_text(V0)
    git(upstream, "add", "-A")
    git(upstream, "commit", "-qm", "v0")
    (upstream / REL).write_text(V1)
    git(upstream, "add", "-A")
    git(upstream, "commit", "-qm", "v1")

    template = tmp / "template"
    subprocess.run(["git", "clone", "-q", str(upstream), str(template)],
                   check=True, capture_output=True)

    (upstream / REL).write_text(V2)
    git(upstream, "add", "-A")
    git(upstream, "commit", "-qm", "v2")

    git(template, "fetch", "-q", "origin")
    if fresh:
        git(template, "merge", "-q", "--ff-only", "origin/main")
    return template


class TestAStaleCheckoutCannotSayEditedLocally(unittest.TestCase):

    def _classify(self, *, fresh: bool, cluster_bytes: str) -> str:
        with tempfile.TemporaryDirectory() as t:
            tmp = pathlib.Path(t)
            template = build(tmp, fresh=fresh)
            cluster = tmp / "cluster"
            cluster.mkdir()
            (cluster / REL).write_text(cluster_bytes)
            undetermined = drift.staleness_undetermined(template)
            return drift.stale_or_edited(template, REL, cluster / REL,
                                         undetermined)

    def test_a_stale_checkout_does_not_claim_the_file_was_edited(self):
        """The finding. The cluster holds V2 — synced with origin — and the
        checkout simply has not fetched it."""
        got = self._classify(fresh=False, cluster_bytes=V2)
        self.assertNotIn("edited locally", got)
        self.assertIn("staleness undetermined", got)
        self.assertIn("behind", got)

    def test_a_fresh_checkout_still_says_edited_locally_when_it_is_true(self):
        """⚠️ The other direction, and the one that makes the first test mean
        something: if this goes quiet too, the fix is "never say it" rather
        than "say it only when you can tell"."""
        got = self._classify(fresh=True, cluster_bytes=NEVER)
        self.assertIn("edited locally", got)

    def test_a_fresh_checkout_still_recognises_an_older_version_as_stale(self):
        """The classification the tool exists for keeps working."""
        got = self._classify(fresh=True, cluster_bytes=V1)
        self.assertIn("stale:", got)
        self.assertNotIn("edited locally", got)

    def test_a_stale_checkout_still_recognises_what_it_can_see(self):
        """Being behind does not erase the history it does have.

        V0 is two versions back and present in the stale checkout, so that
        answer is still available and still given — **the downgrade applies to
        the one claim that needs the data this checkout lacks**, not to every
        claim. A fix that silenced all four classifications would pass the
        first test in this class and be useless.
        """
        got = self._classify(fresh=False, cluster_bytes=V0)
        self.assertIn("stale:", got)
        self.assertNotIn("undetermined", got)

    def test_matching_this_checkouts_newest_is_downgraded_while_stale(self):
        """⚠️ The branch the issue did not list, and it blames the wrong party.

        When the bytes match the newest commit **this checkout** has for the
        path, the tool used to conclude "the difference is uncommitted work in
        the TEMPLATE". On a stale checkout that sentence points at a template
        working tree that is innocent: the newer version exists, just not here.
        """
        got = self._classify(fresh=False, cluster_bytes=V1)
        self.assertIn("IN THIS CHECKOUT", got)
        self.assertIn("staleness undetermined", got)
        self.assertNotIn("uncommitted work in the TEMPLATE", got)


class TestTheFreshnessProbeItself(unittest.TestCase):

    def test_a_checkout_level_with_origin_is_determined(self):
        with tempfile.TemporaryDirectory() as t:
            template = build(pathlib.Path(t), fresh=True)
            self.assertIsNone(drift.staleness_undetermined(template))

    def test_a_checkout_behind_origin_names_the_distance(self):
        with tempfile.TemporaryDirectory() as t:
            template = build(pathlib.Path(t), fresh=False)
            reason = drift.staleness_undetermined(template)
        self.assertIsNotNone(reason)
        self.assertIn("1 commit", reason)

    def test_no_origin_main_is_its_own_reason_not_zero_commits_behind(self):
        """⚠️ "behind 0 commits" and "there is no origin/main to ask" are both
        the absence of a distance, and only one of them means the answer is
        trustworthy. This repo has paid for that shape twice (#171's population
        counted hits, #178's index counted nothing) — so they get different
        sentences, and the test asserts the difference rather than the pair.
        """
        with tempfile.TemporaryDirectory() as t:
            tmp = pathlib.Path(t)
            template = tmp / "solo"
            template.mkdir()
            git(template, "init", "-q", "-b", "main")
            (template / REL).write_text(V1)
            git(template, "add", "-A")
            git(template, "commit", "-qm", "v1")
            reason = drift.staleness_undetermined(template)
        self.assertIsNotNone(reason)
        self.assertIn("no `origin/main`", reason)
        # Not "does not contain the word behind" — the sentence may use it
        # while saying the distance is unavailable. What must not appear is a
        # *distance claim*, which is what a reader would act on.
        self.assertNotIn("behind origin/main", reason)


if __name__ == "__main__":
    unittest.main()
