#!/usr/bin/env python3
"""`cluster.sample.yaml` must not ship a credential default anyone could use — jgct#173.

Run: python3 .github/workflows/run-tests.py

**Why this file exists, measured rather than imagined.** For roughly two weeks
in April 2026 the ttyd credential actually serving `jg-jiahd` was the default
written in this repo's sample config. Nobody changed it *because it worked* —
and nothing detected it. It surfaced five months later, by accident, while
chasing the leftover hits of jgct#169 (`FO-runbook [5fe39a]` matched it by
sha256 without ever printing the value).

The same shape has now bitten this file twice: `deployment_profile` used to be
prefilled with `"full"`, so whoever forgot to edit it got a full cluster rather
than an error (jgct#158, fixed by making the default a string that fails).

    A default that works will not be edited. That is this file's own failure
    mode, because being copied verbatim is what it is for.

**The judgement is borrowed, never copied.** `_is_real_credential` and
`_scan_blob_for_secrets` in `scripts/delivery-check.py` already know about
`CHANGE-ME`, `<…>`, `${…}`, template syntax and CUE type expressions. A second
list here would diverge, and the one people follow is usually the wrong one.
"""
import sys

# See the note in test_delivery_check_repo_hygiene.py: a stale `.pyc` makes a
# mutation test report the previous run's result.
sys.dont_write_bytecode = True

import importlib.util
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)

SAMPLE = ROOT / "cluster.sample.yaml"

# Looks live, is nobody's. Deliberately NOT placeholder-shaped: the point of
# the positive control is a value that works, which is the value that does not
# get edited.
USABLE = "ops:Zx7qMr2vTn"


def credential_keys_mentioned(text: str) -> list[str]:
    """Which credential fields this file talks about, commented out or not.

    Derived from the file rather than hardcoded: a list written here would go
    stale the moment a field is added, and a positive control that iterates
    over a stale list still passes.
    """
    found = []
    for field in dc.SECRET_FIELDS:
        if re.search(rf"(?im)^[^\S\n]*#?[^\S\n]*{re.escape(field)}[^\S\n]*:", text):
            found.append(field)
    return found


class TestSampleConfigShipsNoUsableCredential(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = SAMPLE.read_text()

    def test_the_sample_file_exists_and_is_not_empty(self):
        """`read_text()` on a missing file raises, but an empty one would let
        every assertion below pass while measuring nothing."""
        self.assertTrue(SAMPLE.is_file(), SAMPLE)
        self.assertGreater(len(self.text), 1000, "sample config is suspiciously small")

    def test_no_field_holds_a_value_anyone_could_use(self):
        """The guard itself.

        Asserted as "no field holds a real credential", NOT as "ttyd_credential
        equals some particular string" — the next usable default will be in a
        field nobody listed here (jgct#173 condition 4, and the same reasoning
        as jgct#166: do not identify the thing by the name you expect).
        """
        found = dc._scan_blob_for_secrets(self.text)
        self.assertEqual(
            [], found,
            f"cluster.sample.yaml ships a usable value for: {', '.join(found)}. "
            "A default that works will not be edited — make it fail instead.")

    def test_the_file_still_mentions_credential_fields(self):
        """Positive control for the positive control below.

        If this file ever stops naming any credential field, the per-field test
        iterates over an empty list and passes without exercising anything —
        which reads exactly like a clean sample config.
        """
        keys = credential_keys_mentioned(self.text)
        self.assertGreater(len(keys), 2, f"only found {keys}")

    def test_a_usable_value_in_any_of_those_fields_is_caught(self):
        """Positive control, built by mutating THIS file rather than a fixture.

        `[bbf3d2]` spent a full round on a hand-written CUE fixture that did not
        match the shape actually present in the repo (`x?: string & !=""` never
        matched, because of the `?`), and found it by reading the real line
        rather than by rereading the test. So the mutation is applied to the
        real text: whatever indentation, quoting and comment style this file
        uses is what the guard is proved against.
        """
        keys = credential_keys_mentioned(self.text)
        for field in keys:
            with self.subTest(field=field):
                mutant, n = re.subn(
                    rf"(?im)^([^\S\n]*)#?[^\S\n]*{re.escape(field)}[^\S\n]*:.*$",
                    rf'\g<1>{field}: "{USABLE}"', self.text, count=1)
                # The mutation must land: a substitution that matched nothing
                # leaves the text clean, and a clean text passes the scan.
                self.assertEqual(1, n, f"mutation for {field} did not apply")
                self.assertIn(USABLE, mutant)
                self.assertIn(
                    field, dc._scan_blob_for_secrets(mutant),
                    f"a usable {field} was not caught")

    def test_the_borrowed_judgement_can_still_say_yes_and_no(self):
        """The guard is exactly as strong as `_is_real_credential`.

        If that function ever stops recognising a workable value, this whole
        file goes quiet while still reporting success — so the two answers it
        must be able to give are asserted here, next to the thing that depends
        on them.
        """
        self.assertTrue(dc._is_real_credential(f'"{USABLE}"'))
        self.assertFalse(dc._is_real_credential('"ops:CHANGE-ME"'))


if __name__ == "__main__":
    unittest.main()
