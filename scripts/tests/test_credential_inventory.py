#!/usr/bin/env python3
"""Tests for scripts/credential-inventory.py — §5.4 / §5.6.

The behaviour under test is not "does it print a table". It is the three
distinctions the table exists to make, each of which collapses into "nothing at
all" if it is not made deliberately:

  set / blank / not declared     three states, not two
  unclassified                   a credential the table does not know is
                                 printed, not skipped
  no cluster.yaml                exit 2, never exit 0 with a caveat
"""

from __future__ import annotations

import importlib.util
import io
import contextlib
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ci", ROOT / "scripts" / "credential-inventory.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


def inventory(contents: str | None):
    """Run main() over a temp cluster dir; return (exit code, stdout)."""
    import sys
    with tempfile.TemporaryDirectory() as d:
        if contents is not None:
            (pathlib.Path(d) / "cluster.yaml").write_text(contents)
        out = io.StringIO()
        argv, sys.argv = sys.argv, ["credential-inventory.py", "--dir", d]
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                rc = ci.main()
        finally:
            sys.argv = argv
        return rc, out.getvalue()


BASE = 'cluster_name: "jg-t"\ncloudflare_domain: "t.tw"\n'


class TestThreeStates(unittest.TestCase):
    def test_a_set_credential_is_in_the_table(self):
        rc, out = inventory(BASE + 'cloudflare_token: "a-real-looking-value"\n')
        self.assertEqual(rc, ci.DONE)
        self.assertIn("| `cloudflare_token` |", out)

    def test_a_blank_credential_is_named_as_blank(self):
        rc, out = inventory(BASE + 'cloudflare_token: ""\n')
        blank = out.split("## Declared and blank")[1].split("## Not declared")[0]
        self.assertIn("cloudflare_token", blank)

    def test_a_placeholder_counts_as_blank_not_as_set(self):
        for v in ('"<your-token>"', '"${CF_TOKEN}"', '"CHANGE-ME"'):
            _, out = inventory(BASE + f"cloudflare_token: {v}\n")
            blank = out.split("## Declared and blank")[1].split("## Not declared")[0]
            self.assertIn("cloudflare_token", blank, v)

    def test_an_undeclared_credential_is_named_too(self):
        # The bug this section was added for: a cluster that does not need a
        # credential and one whose line was deleted both produced nothing.
        _, out = inventory(BASE)
        undeclared = out.split("## Not declared at all")[1]
        self.assertIn("daily_check_healthchecks_ping_url", undeclared)

    def test_the_three_sections_are_disjoint(self):
        _, out = inventory(BASE + 'cloudflare_token: "a-real-looking-value"\n'
                                  'ttyd_credential: ""\n')
        table = out.split("## Declared and blank")[0]
        blank = out.split("## Declared and blank")[1].split("## Not declared")[0]
        undeclared = out.split("## Not declared at all")[1].split("## Deliberately")[0]
        self.assertIn("cloudflare_token", table)
        self.assertNotIn("cloudflare_token", blank)
        self.assertNotIn("cloudflare_token", undeclared)
        self.assertIn("ttyd_credential", blank)
        self.assertNotIn("ttyd_credential", undeclared)


class TestUnclassified(unittest.TestCase):
    """The inventory must not be a list of names someone thought of. A field
    the table does not know is the case that made `config.gen/cluster.yaml`
    invisible to a rule and a check that shared its premise."""

    def test_an_unknown_credential_field_fails_the_run(self):
        rc, out = inventory(BASE + 'some_future_api_key: "a-real-looking-value"\n')
        self.assertEqual(rc, ci.INCOMPLETE)
        self.assertIn("UNCLASSIFIED", out)
        self.assertIn("some_future_api_key", out)

    def test_an_unknown_but_blank_field_does_not_fail(self):
        rc, _ = inventory(BASE + 'some_future_api_key: ""\n')
        self.assertEqual(rc, ci.DONE)

    def test_known_non_credentials_do_not_trip_it(self):
        rc, _ = inventory(BASE + 'github_webhook_token: "abc12345678"\n'
                                 'backup_r2_endpoint: "https://x.example"\n')
        self.assertEqual(rc, ci.DONE)

    def test_the_sweep_covers_the_words_this_fleet_actually_uses(self):
        for name in ("x_token", "x_secret", "x_password", "x_key", "x_credential",
                     "x_api_key", "x_pat", "x_cert"):
            rc, out = inventory(BASE + f'{name}: "a-real-looking-value"\n')
            self.assertEqual(rc, ci.INCOMPLETE, name)


class TestCannotTell(unittest.TestCase):
    def test_no_cluster_yaml_is_exit_2_not_an_empty_inventory(self):
        rc, _ = inventory(None)
        self.assertEqual(rc, ci.UNKNOWN)


class TestExclusionsAreStated(unittest.TestCase):
    """Half the value of the jg-base document is naming what was left out: a
    row considered and dropped looks, from outside, exactly like one nobody
    thought of."""

    def test_the_excluded_list_is_printed_with_reasons(self):
        _, out = inventory(BASE)
        section = out.split("## Deliberately not in this inventory")[1]
        self.assertEqual(len(ci.EXCLUDED), 3)
        for cred, why in ci.EXCLUDED:
            self.assertIn(cred, section)
            self.assertIn(why[:30], section)

    def test_every_known_row_carries_a_rotation_procedure(self):
        # 5.6 lives in the fifth column. An empty one is a credential nobody
        # can rotate, which is discovered at the worst moment.
        for field, row in ci.KNOWN.items():
            self.assertEqual(len(row), 4, field)
            self.assertTrue(row[3].strip(), f"{field} has no rotation procedure")

    def test_age_key_rotation_names_the_in_place_command(self):
        rot = [r for r in ci.OUT_OF_BAND if r[0] == "age.key"][0][4]
        self.assertIn("sops updatekeys", rot)


if __name__ == "__main__":
    unittest.main()
