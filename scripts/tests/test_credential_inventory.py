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


def inventory_err(contents: str):
    """As inventory(), and stderr too: (exit code, stdout, stderr)."""
    import sys
    with tempfile.TemporaryDirectory() as d:
        (pathlib.Path(d) / "cluster.yaml").write_text(contents)
        out, err = io.StringIO(), io.StringIO()
        argv, sys.argv = sys.argv, ["credential-inventory.py", "--dir", d]
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = ci.main()
        finally:
            sys.argv = argv
        # The temp directory's name is random and is printed in the header.
        return rc, out.getvalue().replace(d, "<dir>"), err.getvalue().replace(d, "<dir>")


USER, TOK1, TOK2 = "pull-account-7Qz", "tok-ONE-4f9a1c", "tok-TWO-b82e07"
TWO = (BASE + "registry_pull_secrets:\n"
       "  - name: ghcr-pull\n"
       "    registry: ghcr.io\n"
       f'    username: "{USER}"\n'
       f'    token: "{TOK1}"\n'
       "    namespaces: [freepbx, default]\n"
       "  - name: quay-pull   # a comment\n"
       "    registry: quay.io\n"
       f"    username: {USER}\n"
       f"    token: {TOK2}\n"
       "    namespaces:\n"
       "      - media\n"
       'daily_check_smtp_host: "smtp.example"\n')


def sections(out: str):
    table = out.split("## Declared and blank")[0]
    blank = out.split("## Declared and blank")[1].split("## Not declared")[0]
    return table, blank


class TestRegistryPullSecrets(unittest.TestCase):
    """jgct#274. The one field whose credential sits inside a list entry: the
    top-level sweep sees `registry_pull_secrets:` and nothing under it, and
    that name does not even trip the keyword sweep."""

    def test_each_entry_is_a_row_named_by_name_and_registry(self):
        rc, out, _ = inventory_err(TWO)
        self.assertEqual(rc, ci.DONE)
        table, blank = sections(out)
        rows = [l for l in table.splitlines() if "registry_pull_secrets[" in l]
        self.assertEqual(len(rows), 2, rows)
        self.assertIn("registry_pull_secrets[ghcr-pull].token", rows[0])
        self.assertIn("`ghcr.io`", rows[0])
        self.assertIn("`freepbx`, `default`", rows[0])
        self.assertIn("registry_pull_secrets[quay-pull].token", rows[1])
        self.assertIn("`quay.io`", rows[1])
        self.assertIn("`media`", rows[1])
        self.assertNotIn("registry_pull_secrets", blank)
        for row in rows:   # the five columns, none empty
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            self.assertEqual(len(cells), 5, row)
            self.assertTrue(all(cells), row)

    def test_no_username_and_no_token_reaches_either_stream(self):
        # The second document is unreadable AT the token's own line, so an
        # error message that quotes the line it stopped on would carry it.
        for doc in (TWO, TWO.replace(f"    token: {TOK2}\n", f"    token {TOK2}\n")):
            rc, out, err = inventory_err(doc)
            for secret in (USER, TOK1, TOK2):
                self.assertNotIn(secret, out)
                self.assertNotIn(secret, err)
        self.assertEqual(rc, ci.UNKNOWN)
        self.assertIn("line 12", err)      # it does say where

    def test_the_fixture_values_would_be_found_if_printed(self):
        # The control for the test above: the same search finds a value this
        # script does print, so "not in the output" is a reading and not a
        # search that cannot hit.
        _, out, _ = inventory_err(TWO)
        self.assertIn("quay-pull", out)

    def test_absent_and_empty_list_change_nothing(self):
        _, absent, _ = inventory_err(BASE)
        self.assertNotIn("registry_pull", absent)
        for empty in ("registry_pull_secrets: []\n", "registry_pull_secrets:\n",
                      "registry_pull_secrets: []   # none yet\n"):
            rc, out, _ = inventory_err(BASE + empty)
            self.assertEqual(rc, ci.DONE, empty)
            self.assertEqual(out, absent, empty)

    def test_an_empty_or_placeholder_token_is_blank_not_set(self):
        for v in ('""', "", '"<your-token>"', '"CHANGE-ME"'):
            doc = TWO.replace(f'token: "{TOK1}"', f"token: {v}")
            rc, out, _ = inventory_err(doc)
            table, blank = sections(out)
            self.assertEqual(rc, ci.DONE, v)
            self.assertNotIn("[ghcr-pull]", table, v)
            self.assertIn("registry_pull_secrets[ghcr-pull].token", blank, v)
            self.assertIn("[quay-pull]", table, v)   # the other entry still a row

    def test_an_entry_with_no_token_key_is_blank(self):
        rc, out, _ = inventory_err(TWO.replace(f'    token: "{TOK1}"\n', ""))
        table, blank = sections(out)
        self.assertNotIn("[ghcr-pull]", table)
        self.assertIn("registry_pull_secrets[ghcr-pull].token", blank)

    def test_a_quoted_token_starting_with_a_hash_is_set(self):
        # `split("#")` reads this value as a comment and the token as blank.
        rc, out, _ = inventory_err(TWO.replace(f'"{TOK1}"', '"#starts-with-hash"'))
        table, blank = sections(out)
        self.assertIn("[ghcr-pull]", table)
        self.assertNotIn("[ghcr-pull]", blank)

    def test_the_list_may_sit_at_column_zero(self):
        doc = (BASE + "registry_pull_secrets:\n- name: ghcr-pull\n  registry: ghcr.io\n"
               f"  username: u\n  token: {TOK1}\n  namespaces: [freepbx]\n"
               'cloudflare_token: "a-real-looking-value"\n')
        rc, out, _ = inventory_err(doc)
        self.assertEqual(rc, ci.DONE)
        self.assertIn("registry_pull_secrets[ghcr-pull].token", out)
        self.assertIn("| `cloudflare_token` |", out)   # the field after it is still read

    def test_an_entry_without_a_name_is_still_a_row(self):
        rc, out, _ = inventory_err(TWO.replace("  - name: ghcr-pull\n    registry", "  - registry"))
        self.assertIn("registry_pull_secrets[#1].token", sections(out)[0])

    def test_what_it_cannot_read_is_exit_2_never_skipped(self):
        flow = BASE + "registry_pull_secrets: [{name: a, registry: ghcr.io, token: %s}]\n" % TOK1
        block_scalar = TWO.replace(f'token: "{TOK1}"', "token: |\n      " + TOK1)
        not_kv = TWO.replace("    registry: quay.io\n", "    registry quay.io\n")
        under_empty = BASE + "registry_pull_secrets: []\n  - name: a\n"
        twice = TWO + "registry_pull_secrets: []\n"
        for label, doc in (("flow", flow), ("block scalar", block_scalar),
                           ("not key: value", not_kv),
                           ("entries under []", under_empty), ("twice", twice)):
            rc, out, err = inventory_err(doc)
            self.assertEqual(rc, ci.UNKNOWN, label)
            self.assertEqual(out, "", label)          # no table that looks complete
            self.assertIn("registry_pull_secrets", err, label)
            self.assertNotIn(TOK1, err, label)

    def test_an_unknown_credential_key_in_an_entry_fails_the_run(self):
        doc = TWO.replace("    registry: quay.io\n",
                          '    registry: quay.io\n    password: "a-real-looking-value"\n')
        rc, out, _ = inventory_err(doc)
        self.assertEqual(rc, ci.INCOMPLETE)
        self.assertIn("registry_pull_secrets[quay-pull].password", out.split("UNCLASSIFIED")[1])
        self.assertNotIn("a-real-looking-value", out)

    def test_the_documented_example_is_read(self):
        # The fixture is the block cluster.sample.yaml tells an operator to
        # write, uncommented -- not a shape made up here.
        sample = (ROOT / "cluster.sample.yaml").read_text().splitlines()
        start = sample.index("# registry_pull_secrets:")
        block = []
        for line in sample[start:]:
            if not line.startswith("#"):
                break
            block.append(line[2:] if line.startswith("# ") else line[1:])
        self.assertGreaterEqual(len(block), 6, block)
        doc = BASE + "\n".join(block) + "\n"
        rc, out, _ = inventory_err(doc)
        self.assertEqual(rc, ci.DONE)
        self.assertIn("registry_pull_secrets[ghcr-pull].token (registry ghcr.io)",
                      sections(out)[1])          # the sample's token is ""
        rc, out, _ = inventory_err(doc.replace('token: ""', f'token: "{TOK1}"'))
        self.assertIn("`registry_pull_secrets[ghcr-pull].token` (registry `ghcr.io`)",
                      sections(out)[0])
        self.assertIn("`freepbx`", sections(out)[0])


if __name__ == "__main__":
    unittest.main()
