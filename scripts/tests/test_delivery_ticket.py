#!/usr/bin/env python3
"""Tests for scripts/delivery-ticket.py — §3.

Run: python3 -m unittest discover -s scripts/tests

**These existed and were not committed.** 3.2-3.7 are ticked on the strength of
a run that happened on one workstation, in a session that has ended. That is the
same shape as the `git check-ignore` finding in the provisioning runbook: the
only thing that would test the guard lived in the one place guaranteed to have
it. A clone had no tests, so the checkmarks asserted coverage that a second
person could not reproduce.

Nothing here calls `gh`. The paths that do are still unexercised — that is 3.9,
and it is still open. A green run of this file is not evidence that the ticket
commands work against GitHub, and it must not be read as such.

Committed to `main` on 2026-09-12 by `#104`. Written 2026-08-26 on the branch
`feat/8-provisioning-flow` (tip `df12239`), which has no PR; a `checkout` away
from that branch on 2026-08-27 13:57 emptied `scripts/tests/`, and nothing said
so for two weeks. Everything below this docstring is byte-identical to the copy
on that branch — only this paragraph was added. Its two siblings,
`test_provision.py` and `test_credential_inventory.py`, are still only there:
their subjects (`provision.py`, `credential-inventory.py`) are not on `main`,
and whether that branch merges is ferry133's undecided call.
"""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dt", ROOT / "scripts" / "delivery-ticket.py")
dt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dt)


class TestSecretScanner(unittest.TestCase):
    """3.5. Both directions matter, and the false-positive direction is the one
    that killed the first version: a guard that fires on correct documentation
    gets switched off, and a switched-off guard reads exactly like a passing one.
    """

    def assertFlagged(self, text, why=""):
        found = dt.scan_for_secrets(text)
        self.assertTrue(found, f"should have been flagged{': ' + why if why else ''}\n{text}")

    def assertQuiet(self, text, why=""):
        found = dt.scan_for_secrets(text)
        self.assertFalse(found, f"should be quiet{': ' + why if why else ''} — got {found}\n{text}")

    # ---- material that must be caught
    def test_age_private_key(self):
        self.assertFlagged("key: AGE-SECRET-KEY-1" + "Q" * 58)

    def test_cloudflare_token(self):
        self.assertFlagged("used cfut_" + "a" * 40)

    def test_github_pat_classic(self):
        self.assertFlagged("ghp_" + "b" * 36)

    def test_github_pat_fine_grained(self):
        self.assertFlagged("github_pat_" + "c" * 40)

    def test_pem_header(self):
        self.assertFlagged("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n")

    def test_jwt(self):
        self.assertFlagged("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27u")

    def test_real_looking_config_fields(self):
        for field in dt.SECRET_FIELDS:
            self.assertFlagged(f"{field}: s3cr3t-value-that-is-long\n", field)

    def test_a_plaintext_value_among_encrypted_ones_is_still_caught(self):
        self.assertFlagged(
            "cloudflare_token: ENC[AES256_GCM,data:abc,type:str]\n"
            "ttyd_credential: actually-plaintext-here\n",
            "every field is examined rather than stopping at the first")

    # ---- what a correct document looks like, and must not be flagged
    def test_empty_field(self):
        self.assertQuiet('cloudflare_token: ""\n')

    def test_angle_bracket_placeholder(self):
        self.assertQuiet('cloudflare_token: "<your-token>"\n')

    def test_shell_substitution(self):
        self.assertQuiet('cloudflare_token: "${CF_TOKEN}"\n')
        self.assertQuiet('cloudflare_token: "$(pass cf)"\n')

    def test_change_me(self):
        self.assertQuiet("claudecode_postgres_password: CHANGE-ME\n")

    def test_masked_value(self):
        self.assertQuiet("ttyd_credential: xxxxxxxxxx\n")

    def test_short_value_is_an_identifier_not_a_credential(self):
        self.assertQuiet("cloudflare_token: abc123\n")

    def test_fingerprint_style_reference_is_the_recommended_form(self):
        # What the refusal message tells people to write instead. If this were
        # flagged the guard would forbid its own remedy.
        self.assertQuiet("used the Cloudflare token ending 4f21\n")
        self.assertQuiet("age recipient age1u02z (public half)\n")

    def test_prose_about_credentials_is_not_a_credential(self):
        self.assertQuiet("Rotated the cloudflare_token; the new one is in 1Password.\n")

    def test_commented_out_field(self):
        self.assertQuiet("# cloudflare_token: leftover-example-value\n")

    def test_ordinary_progress_comment(self):
        self.assertQuiet(
            "Advanced to delivery/verifying.\n"
            "GitRepository READY=True at 700bafffe2b7.\n"
            "echo-ext returned 200 with cf-ray.\n")


class TestRealValueHeuristic(unittest.TestCase):
    def test_placeholders(self):
        for v in ('""', '"<token>"', "${X}", "$(x)", "CHANGE-ME", "your-token",
                  "xxxxxxxx", "", "   ", "# comment only"):
            self.assertFalse(dt.looks_like_a_real_value(v), v)

    def test_real_shapes(self):
        for v in ("s3cr3t-value-that-is-long", '"AbCdEf0123456789"'):
            self.assertTrue(dt.looks_like_a_real_value(v), v)


class TestPhaseVocabulary(unittest.TestCase):
    """3.1/3.3. The list's order IS the state machine, so its shape is the
    assertion — not a restatement of it somewhere else."""

    def test_phases_are_ordered_and_unique(self):
        self.assertEqual(len(dt.PHASES), len(set(dt.PHASES)))
        self.assertEqual(dt.PHASES[0], "delivery/intake")
        self.assertEqual(dt.PHASES[-1], "delivery/done")

    def test_verifying_precedes_handover(self):
        # The reason --force exists: this ordering is what stops a delivery
        # reaching handover with verification never having run.
        self.assertLess(dt.PHASES.index("delivery/verifying"),
                        dt.PHASES.index("delivery/handover"))

    def test_blocked_is_not_a_phase(self):
        self.assertNotIn(dt.BLOCKED, dt.PHASES)

    def test_every_label_carries_the_delivery_prefix(self):
        # `delivery/` is what keeps these from colliding with triage labels,
        # which answer a different question about a different kind of object.
        for p in dt.PHASES + [dt.BLOCKED]:
            self.assertTrue(p.startswith("delivery/"), p)


class TestCurrentPhase(unittest.TestCase):
    """3.3. Two phase labels is refused, not repaired: which one is correct is a
    question about the world, and picking writes a guess down as fact."""

    def test_single_phase(self):
        self.assertEqual(dt.current_phase(["delivery/provisioning", "bug"]),
                         "delivery/provisioning")

    def test_no_phase_is_none_not_the_first_phase(self):
        self.assertIsNone(dt.current_phase(["bug", "delivery/blocked"]))

    def test_blocked_coexists_with_a_phase(self):
        self.assertEqual(
            dt.current_phase(["delivery/provisioning", dt.BLOCKED]),
            "delivery/provisioning",
            "a blocked ticket keeps its phase so resume knows where it stopped")

    def test_two_phases_refuses(self):
        with self.assertRaises(SystemExit) as e:
            dt.current_phase(["delivery/provisioning", "delivery/verifying"])
        self.assertEqual(e.exception.code, 1)


class FakeGh:
    """Records calls instead of making them. Nothing here reaches GitHub — see
    this module's docstring: 3.9 is what covers the real calls, and it is open."""

    def __init__(self, labels):
        self.labels = labels
        self.calls = []

    def __call__(self, args, repo):
        self.calls.append(args)
        if args[:2] == ["issue", "view"]:
            import json as _json
            return _json.dumps({"labels": [{"name": n} for n in self.labels]})
        return ""


class TestTransitions(unittest.TestCase):
    """3.3's transition table, exercised through cmd_advance with `gh` faked."""

    def advance(self, labels, to, force=False):
        import argparse
        fake = FakeGh(labels)
        old, dt.gh = dt.gh, fake
        try:
            args = argparse.Namespace(issue="1", to=to, force=force, repo=None)
            dt.cmd_advance(args)
            return fake
        finally:
            dt.gh = old

    def test_forward_one_step_is_allowed(self):
        fake = self.advance(["delivery/intake"], "delivery/awaiting-hardware")
        edits = [c for c in fake.calls if c[:2] == ["issue", "edit"]]
        self.assertEqual(len(edits), 1)
        self.assertIn("--add-label", edits[0])
        self.assertIn("--remove-label", edits[0])

    def test_skipping_a_phase_is_refused(self):
        with self.assertRaises(SystemExit) as e:
            self.advance(["delivery/intake"], "delivery/handover")
        self.assertEqual(e.exception.code, 1)

    def test_skipping_a_phase_is_allowed_with_force(self):
        fake = self.advance(["delivery/intake"], "delivery/handover", force=True)
        self.assertTrue([c for c in fake.calls if c[:2] == ["issue", "edit"]])

    def test_backwards_is_refused_without_force(self):
        with self.assertRaises(SystemExit):
            self.advance(["delivery/verifying"], "delivery/provisioning")

    def test_same_phase_is_a_no_op_not_an_edit(self):
        fake = self.advance(["delivery/verifying"], "delivery/verifying")
        self.assertFalse([c for c in fake.calls if c[:2] == ["issue", "edit"]])

    def test_advancing_clears_blocked(self):
        fake = self.advance(["delivery/intake", dt.BLOCKED], "delivery/awaiting-hardware")
        edit = [c for c in fake.calls if c[:2] == ["issue", "edit"]][0]
        self.assertEqual(edit.count("--remove-label"), 2)
        self.assertIn(dt.BLOCKED, edit)

    def test_blocking_keeps_the_phase(self):
        fake = self.advance(["delivery/provisioning"], dt.BLOCKED)
        edit = [c for c in fake.calls if c[:2] == ["issue", "edit"]][0]
        self.assertIn("--add-label", edit)
        self.assertNotIn("--remove-label", edit)

    def test_unknown_phase_is_refused(self):
        with self.assertRaises(SystemExit):
            self.advance(["delivery/intake"], "delivery/almost-done")


class TestContradiction(unittest.TestCase):
    """3.7. Stopping rather than reconciling: 'advanced but not finished' and
    'finished but not recorded' need opposite corrections and look identical
    from the ticket."""

    def check(self, labels, observed):
        import argparse
        old, dt.gh = dt.gh, FakeGh(labels)
        try:
            dt.cmd_check(argparse.Namespace(issue="1", observed=observed, repo=None))
        finally:
            dt.gh = old

    def test_agreement_passes(self):
        self.check(["delivery/verifying"], "delivery/verifying")

    def test_disagreement_stops(self):
        with self.assertRaises(SystemExit) as e:
            self.check(["delivery/handover"], "delivery/provisioning")
        self.assertEqual(e.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
