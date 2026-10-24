#!/usr/bin/env python3
"""Tests for delivery-check.py's `repo-hygiene` subcommand — #104 (4), batch 2a.

Run: python3 .github/workflows/run-tests.py

No fake tools here: this subcommand only ever runs `git -C <dir>`, so every case
builds a real repository in a temp dir and lets the real git answer. A stub would
be testing the stub — and the defects this check exists for are all about what
git actually records versus what the working copy shows.

Three properties are worth more than the happy path, and each has a mutation in
the PR that turns exactly one of these tests red:

1. **A failed positive control must report "cannot measure", not "clean".**
   `git log --all -- '*cluster.yaml'` returning nothing is also what a wrong
   pathspec, an empty repo or a broken invocation returns. The check asserts the
   same query shape finds `*.md`; if that finds nothing either, the clean result
   above it proves nothing.
2. **The history query must match any path**, not the expected one. jg-jiahd's
   eleven credential-bearing blobs were at `config.gen/cluster.yaml`.
3. **The deep scan must NOT fire on SOPS ciphertext.** Every cluster repo is
   *supposed* to commit `cluster-secrets.sops.yaml` with all these field names
   present and encrypted. Measured on jg-janncotcc 2026-08-22: five fields
   matched, all five values began `ENC[`, and the delivery reported a leak. A
   guard that fires on the correct state gets switched off, and a switched-off
   guard reads exactly like a passing one.
"""

from __future__ import annotations

# Loading the subject with `spec_from_file_location` writes
# `scripts/__pycache__/delivery-check.*.pyc` unless this is set first. That
# cached bytecode is not a tidiness question: CPython reuses a `.pyc` when the
# source mtime (to the second) AND size both match, which is exactly what a
# minimal mutation looks like — so a negative control can report the PREVIOUS
# mutation's result (jgct#96, and #102 was bitten by it).
#
# `.github/workflows/run-tests.py` sets this too, so the sanctioned entry point
# is already clean (measured: 0 `.pyc` after a full run). This line covers the
# other way in, `python3 -m unittest scripts/tests/<file>`, which no runner
# guards. **It cannot prevent this test module's OWN `.pyc`** — that is written
# while unittest imports it, before this line executes. Only `python3 -B` or
# `PYTHONDONTWRITEBYTECODE=1` covers that, and every test file in this directory
# shares the gap, so it is written here rather than fixed silently in one of them.
import sys

sys.dont_write_bytecode = True

import contextlib
import importlib.util
import io
import pathlib
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)

# Looks like a live Cloudflare token; belongs to nobody.
FAKE_TOKEN = "0123456789abcdef0123456789abcdef01234567"


def git(d: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    """Real git, with identity forced so the test does not depend on ~/.gitconfig.

    `-c core.excludesFile=/dev/null` is **redundant defence, not what makes
    these tests hermetic** — measured 2026-09-13 after `[c8c318]` asked for the
    control. What makes them immune is that every `add` below passes `-f`:

        hostile global excludesFile listing `.gitignore`:
          plain `git add .gitignore`  -> stages 0 files   (the config does bite)
          `git add -f .gitignore`     -> stages 1 file    (-f overrides it)
          the 18 tests, override present -> 18 pass
          the 18 tests, override removed -> 18 pass       (so it is not load-bearing)

    An earlier version of this docstring claimed the override was the thing
    keeping the operator's global ignore list out. That was reasoning, written in
    the voice of a measurement. The list is still worth neutralising — a future
    case that drops `-f` would depend on it — but the claim had to match what was
    measured.

    `maintenance.auto=false` / `gc.auto=0` (jg-cluster-template#209): since git
    2.47 every `commit` here spawns a DETACHED `git maintenance run --auto`
    (measured with GIT_TRACE2_EVENT on git 2.52: one spawn per commit without
    these, zero with them). That child can still be writing under `.git` when
    `TemporaryDirectory` removes the tree, which is the shape of the one CI
    error on record: `OSError: [Errno 39] Directory not empty: '…/.git'`.
    ⚠️ The mechanism is measured; the CAUSATION is not -- 280 local runs of
    this class did not reproduce the error with or without the fix.
    """
    return subprocess.run(
        ["git", "-C", str(d), "-c", "user.name=t", "-c", "user.email=t@t",
         "-c", "commit.gpgsign=false", "-c", "core.excludesFile=/dev/null",
         "-c", "maintenance.auto=false", "-c", "gc.auto=0", *args],
        capture_output=True, text=True, timeout=60,
    )


@contextlib.contextmanager
def repo(*, ignore: str | None = "cluster.yaml\n", track_ignore: bool = True,
         extra: dict[str, str] | None = None, with_md: bool = True):
    """A committed repository, shaped by what each case needs."""
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d)
        git(p, "init", "-q")
        if with_md:
            (p / "README.md").write_text("# a repo\n")
            git(p, "add", "README.md")
        if ignore is not None:
            (p / ".gitignore").write_text(ignore)
            if track_ignore:
                git(p, "add", "-f", ".gitignore")
        for name, body in (extra or {}).items():
            f = p / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)
            git(p, "add", "-f", name)
        git(p, "commit", "-q", "-m", "initial")
        yield p


def capture(fn, *a) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*a)
    return rc, buf.getvalue()


def args_for(p: pathlib.Path, deep: bool = False, staged: bool = False):
    return types.SimpleNamespace(dir=str(p), deep=deep, staged=staged)


class TestRepoHygiene(unittest.TestCase):
    def test_a_clean_repo_passes(self):
        """The positive control for every refusal below."""
        with repo() as p:
            rc, out = capture(dc.check_repo_hygiene, args_for(p))
        self.assertEqual(rc, dc.PASS, out)
        self.assertIn("no *cluster.yaml at any path", out)

    def test_an_untracked_gitignore_is_a_finding(self):
        """jg-jiahd's shape: the rule exists on this machine only, and
        `git check-ignore` — which reads the working copy — says it is fine."""
        with repo(track_ignore=False) as p:
            rc, out = capture(dc.check_repo_hygiene, args_for(p))
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("NOT tracked", out)

    def test_a_tracked_gitignore_without_the_rule_is_a_finding(self):
        """#167 changed this cell's wording; the assertion used to be
        `assertIn("no cluster.yaml rule")`, which bound the test to one
        sentence rather than to the behaviour. It now asserts the verdict and
        that the finding names the file — a message can be rewritten without
        the guard changing what it decides."""
        with repo(ignore="*.log\n") as p:
            rc, out = capture(dc.check_repo_hygiene, args_for(p))
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("cluster.yaml", out)
        self.assertIn("FAIL", out)

    def test_cluster_yaml_at_an_unexpected_path_is_still_found(self):
        """The eleven blobs were at `config.gen/cluster.yaml`, not at the root.
        A pathspec without the leading `*` would miss exactly that."""
        with repo(extra={"config.gen/cluster.yaml": "cloudflare_token: x\n"}) as p:
            rc, out = capture(dc.check_repo_hygiene, args_for(p))
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("appears in history", out)

    def test_untracking_later_does_not_clear_the_history(self):
        """`git rm` makes the file absent from the working copy and from HEAD,
        which is the state someone reports as fixed."""
        with repo(extra={"cluster.yaml": "cloudflare_token: x\n"}) as p:
            git(p, "rm", "-q", "--cached", "cluster.yaml")
            git(p, "commit", "-q", "-m", "untrack it")
            rc, out = capture(dc.check_repo_hygiene, args_for(p))
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("Rotate the credentials", out)

    def test_a_failed_positive_control_reports_cannot_measure(self):
        """No `*.md` anywhere: the history query cannot be trusted, so the clean
        `*cluster.yaml` result above it means nothing. This must not read as a
        pass — it is the difference between "nothing there" and "not looking"."""
        with repo(with_md=False) as p:
            rc, out = capture(dc.check_repo_hygiene, args_for(p))
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("positive control found no *.md", out)

    def test_a_directory_that_is_not_a_repo_is_cannot_measure(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = capture(dc.check_repo_hygiene, args_for(pathlib.Path(d)))
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("not a git repository", out)


class TestDeepScan(unittest.TestCase):
    def test_deep_finds_a_credential_at_a_name_nobody_predicted(self):
        with repo(extra={"odd/name.yaml": f"stringData:\n  cloudflare_token: {FAKE_TOKEN}\n"}) as p:
            rc, out = capture(dc.check_repo_hygiene, args_for(p, deep=True))
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("credential-shaped content", out)

    def test_deep_does_not_fire_on_sops_ciphertext(self):
        """The correct state of every cluster repo. This is the case that made a
        whole delivery report a leak on jg-janncotcc, and the reason the check
        has the exemption at all."""
        body = ("stringData:\n"
                "  cloudflare_token: ENC[AES256_GCM,data:abcd,iv:ef,tag:gh,type:str]\n"
                "  ttyd_credential: ENC[AES256_GCM,data:ijkl,iv:mn,tag:op,type:str]\n")
        with repo(extra={"kubernetes/cluster-secrets.sops.yaml": body}) as p:
            rc, out = capture(dc.check_repo_hygiene, args_for(p, deep=True))
        self.assertEqual(rc, dc.PASS, out)
        self.assertIn("control sample recognised", out)

    def test_deep_does_not_fire_on_template_placeholders(self):
        """`${VAR}` and `<your-token>` are documentation. A check that flags the
        templates in this very repo would be switched off by its first user."""
        body = ("stringData:\n"
                "  cloudflare_token: \"${CLOUDFLARE_TOKEN}\"\n"
                "  ttyd_credential: <user:password>\n"
                # `changeme-please` lived here until #175; it is now flagged
                # (anchored placeholder matching), so the case uses the shape
                # this repo actually ships instead — which is what it was
                # always meant to stand for.
                "  claudecode_postgres_password: \"#{ claudecode_postgres_password }#\"\n")
        with repo(extra={"templates/secret.yaml": body}) as p:
            rc, out = capture(dc.check_repo_hygiene, args_for(p, deep=True))
        self.assertEqual(rc, dc.PASS, out)


class TestIsRealCredential(unittest.TestCase):
    """The exemptions, as a unit. Each one is a case that would otherwise make
    the scan fire on a correct repository."""

    def test_a_real_looking_value_is_a_credential(self):
        self.assertTrue(dc._is_real_credential(FAKE_TOKEN))

    def test_sops_ciphertext_is_not(self):
        self.assertFalse(dc._is_real_credential("ENC[AES256_GCM,data:abcd,type:str]"))

    def test_a_flux_substitution_is_not(self):
        self.assertFalse(dc._is_real_credential("${CLOUDFLARE_TOKEN}"))

    def test_an_angle_bracket_placeholder_is_not(self):
        self.assertFalse(dc._is_real_credential("<your-token-here>"))

    def test_an_exact_placeholder_word_marks_a_placeholder(self):
        """#175 narrowed this from a substring test to an anchored one.

        This case used to assert `changeme-please` is a placeholder, because
        the rule was `"change" in v.lower()`. Anchoring flags it — and that is
        the point: the same looseness waved through `ops:Exchange2026!` and
        `exchange_rate_api_key_live_abc123`. **The compound case is the
        borderline the issue itself marked "arguable"**, so it is named here
        rather than quietly moved.
        """
        self.assertFalse(dc._is_real_credential("ops:CHANGE-ME"))
        self.assertTrue(dc._is_real_credential("changeme-please"))

    def test_a_short_value_is_not_a_credential(self):
        self.assertFalse(dc._is_real_credential("abc"))

    def test_a_trailing_comment_is_stripped_before_judging(self):
        """`cloudflare_token: ${VAR}  # set in cluster.yaml` is a placeholder;
        reading the comment as part of the value would make it look real."""
        self.assertFalse(dc._is_real_credential("${VAR}  # set in cluster.yaml"))

    def test_the_scanners_own_control_sample_is_recognised(self):
        """If this ever returns empty, every clean deep scan in this repo's
        history stops meaning anything."""
        self.assertTrue(dc._scan_blob_for_secrets(dc._SCAN_CONTROL))


class TestTheDeepScanFindsByContentNotByFilename(unittest.TestCase):
    """#166 — the path axis, which had no coverage at all.

    `_SCAN_CONTROL` above is fed straight to `_scan_blob_for_secrets`, so it
    proves the *matcher* recognises a credential. It never passes through
    `_scan_history_for_secrets`, so it said nothing about whether the scan
    walks to that blob — and for four years of filenames it did not: anything
    that was not `*.yaml`/`*.yml` was skipped while the check reported clean.

    Every case here goes through `_scan_history_for_secrets` against a real
    repository, because that function *is* the thing under test.
    """

    EXTENSIONS = ["yaml", "md", "env", "sh", "json"]

    @staticmethod
    def _history(d: pathlib.Path, *, secret: bool, extensions=None,
                 binary: bool = False) -> None:
        """Commit one file per extension, then delete them all.

        Two traps, both hit before this shape was settled on, both of which
        produce "nothing was scanned" that reads like "nothing was found":

        - **Identical contents collapse into one git object**, so five files
          would leave one blob with one path. Each body is made distinct.
        - The path only appears in `rev-list --objects` for a *reachable*
          object, so the files are committed first and removed second — which
          is also the situation being modelled: a credential committed once
          and deleted afterwards is still in the history.
        """
        for i, ext in enumerate(extensions or TestTheDeepScanFindsByContentNotByFilename.EXTENSIONS):
            body = (f"# distinct-body-{i}\n" + (
                f"stringData:\n  cloudflare_token: {FAKE_TOKEN}{i}\n"
                if secret else f"harmless: value-{i}\n"))
            (d / f"leaked.{ext}").write_text(body)
        if binary:
            # A JPEG's first bytes; `text=True` used to raise UnicodeDecodeError
            # on exactly this, which is a crash and not a finding.
            (d / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" * 8)
        git(d, "add", "-fA")
        git(d, "commit", "-qm", "add")
        for ext in extensions or TestTheDeepScanFindsByContentNotByFilename.EXTENSIONS:
            (d / f"leaked.{ext}").unlink()
        if binary:
            (d / "photo.jpg").unlink()
        git(d, "add", "-fA")
        git(d, "commit", "-qm", "remove")

    def _hits(self, **kw) -> set[str]:
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            git(d, "init", "-q")
            self._history(d, **kw)
            return {path for path, _ in dc._scan_history_for_secrets(str(d))}

    def test_a_credential_in_a_yaml_blob_is_found(self):
        """Positive control. If this goes red the rest of this class proves
        nothing — four Falses and a broken scanner look the same."""
        self.assertIn("leaked.yaml", self._hits(secret=True))

    def test_a_credential_outside_yaml_is_found(self):
        """The defect: `.md`/`.env`/`.sh`/`.json` were invisible.

        Asserted as one set comparison rather than four `assertIn`s so that a
        future narrowing cannot pass by finding some of them.
        """
        self.assertEqual(
            {f"leaked.{e}" for e in self.EXTENSIONS}, self._hits(secret=True))

    def test_a_history_with_no_credentials_is_reported_clean(self):
        """Negative control."""
        self.assertEqual(set(), self._hits(secret=False))

    def test_that_negative_control_can_fail(self):
        """The negative control's own positive control.

        Same builder, same repo shape, one credential added: it must go
        non-empty. Without this, "clean" above is also what a scan that never
        ran returns.
        """
        self.assertNotEqual(set(), self._hits(secret=True))

    def test_a_binary_blob_neither_crashes_nor_hides_the_text_ones(self):
        """Removing the filename filter let binary objects reach the reader.

        Measured on this repo's own history: eight blobs whose bytes are not
        UTF-8, and a `text=True` read raises on the first. A crash mid-scan
        would take the credentials found after it down with it, so the case
        asserts both halves: no exception, and the text hits still arrive.
        """
        self.assertEqual(
            {f"leaked.{e}" for e in self.EXTENSIONS},
            self._hits(secret=True, binary=True))

    def test_a_non_utf8_blob_without_a_nul_is_read_not_raised(self):
        """The NUL guard and `errors="replace"` catch *different* blobs.

        Written after a mutation test found this hole: dropping
        `errors="replace"` broke nothing, because the JPEG in the case above
        contains NUL and is skipped before anything is decoded. A blob can be
        invalid UTF-8 with no NUL in it at all — latin-1 prose, a truncated
        binary — and that one reaches the decoder. Without `errors="replace"`
        it raises, and the credentials found after it are lost with it.
        """
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            git(d, "init", "-q")
            (d / "latin1.txt").write_bytes(b"caf\xe9 " * 8)          # no NUL
            (d / "leaked.md").write_text(
                f"stringData:\n  cloudflare_token: {FAKE_TOKEN}\n")
            git(d, "add", "-fA")
            git(d, "commit", "-qm", "add")
            hits = {path for path, _ in dc._scan_history_for_secrets(str(d))}
        self.assertEqual({"leaked.md"}, hits)

    def test_a_credential_shaped_line_inside_a_binary_blob_is_not_a_leak(self):
        """The one narrowing this keeps, and the only axis it narrows on.

        `#166` is about a narrowing along *filenames*. This one is along
        content: a blob containing NUL is not a YAML document — NUL is not
        legal in one — so a `key: value` match inside it is a byte coincidence
        rather than a pasted credential.

        Measured before keeping it: on this repo's own history the guard
        changes nothing at all (127 hits with it, 127 without, 0.39s vs
        0.44s). It is kept for the class of blob rather than for a number, and
        this case exists so that the claim is falsifiable — remove the guard
        and this goes red. A narrowing nobody can turn red is exactly the
        shape this issue is about.
        """
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            git(d, "init", "-q")
            (d / "blob.bin").write_bytes(
                b"\x00\x01\x02\n"                       # NUL, then a line break
                + f"cloudflare_token: {FAKE_TOKEN}\n".encode()
                + b"\x00\xff")
            (d / "leaked.md").write_text(
                f"stringData:\n  cloudflare_token: {FAKE_TOKEN}\n")
            git(d, "add", "-fA")
            git(d, "commit", "-qm", "add")
            hits = {path for path, _ in dc._scan_history_for_secrets(str(d))}
        # The text one still arrives: this asserts the narrowing, not silence.
        self.assertEqual({"leaked.md"}, hits)

    def test_the_extensionless_case_is_covered_too(self):
        """A filename filter would also miss a file with no extension at all —
        `Dockerfile`, `Makefile`, or a pasted note called `notes`."""
        self.assertEqual({"leaked.notes-no-extension"},
                         self._hits(secret=True, extensions=["notes-no-extension"]))

class TestTheIgnoreRuleIsAskedOfGitNotOfARegex(unittest.TestCase):
    """#167 — the `.gitignore` cell used to ask whether a string appears.

    `re.search(r"cluster\\.yaml", head_ignore)` passes a file that only
    *mentions* the name in a comment, and passes `!cluster.yaml`, which is the
    line that turns the protection off. It also refuses `cluster.*`, which
    protects. Wrong in both directions — and the second direction was not in
    the issue; it came out of writing the table.

    Each case is the `.gitignore` text itself, so a reader can rerun one
    without building a repository.
    """

    def test_the_real_delivery_shape_is_covered(self):
        """Positive control. Red here and the rest of this class says nothing."""
        self.assertIs(True, dc._ignore_text_covers(
            "/cluster.yaml\n/config.gen/cluster.yaml\n", "cluster.yaml"))

    def test_a_mention_inside_a_comment_is_not_a_rule(self):
        self.assertIs(False, dc._ignore_text_covers(
            "# remember to ignore cluster.yaml one day\n", "cluster.yaml"))

    def test_a_negation_is_the_protection_being_turned_off(self):
        """The worst row: the old cell reported "protected" about a file whose
        meaning is the opposite of protection."""
        self.assertIs(False, dc._ignore_text_covers(
            "*.yaml\n!cluster.yaml\n", "cluster.yaml"))

    def test_an_unrelated_ignore_file_is_not_covered(self):
        """Negative control — the helper must be able to say no."""
        self.assertIs(False, dc._ignore_text_covers(
            "*.log\nnode_modules/\n", "cluster.yaml"))

    def test_ignoring_only_the_generated_copy_leaves_the_root_one_exposed(self):
        self.assertIs(False, dc._ignore_text_covers("config.gen/\n", "cluster.yaml"))

    def test_a_wildcard_rule_does_protect(self):
        """The other direction: `cluster.*` is a real rule, and the old cell
        called that repo unprotected."""
        self.assertIs(True, dc._ignore_text_covers("cluster.*\n", "cluster.yaml"))

    def test_an_instrument_that_cannot_say_yes_returns_cannot_measure(self):
        """The helper's own control, exercised.

        If git stops answering, every text comes back "not ignored" — a
        fleet-wide false alarm that reads exactly like a real finding. The
        sentinel rule must come back ignored before any False is believed.
        """
        with mock.patch.object(
                dc, "run",
                side_effect=lambda cmd, **kw: types.SimpleNamespace(
                    returncode=0 if "init" in cmd else 1, stdout="", stderr="")):
            self.assertIsNone(
                dc._ignore_text_covers("/cluster.yaml\n", "cluster.yaml"))

    def test_a_git_error_is_cannot_measure_not_a_finding(self):
        """128 is not "not ignored"."""
        calls = {"n": 0}

        def fake(cmd, **kw):
            if "init" in cmd:
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            calls["n"] += 1
            # sentinel answers "ignored"; the real question then errors out
            return types.SimpleNamespace(
                returncode=0 if calls["n"] == 1 else 128, stdout="", stderr="")

        with mock.patch.object(dc, "run", side_effect=fake):
            self.assertIsNone(
                dc._ignore_text_covers("/cluster.yaml\n", "cluster.yaml"))

    def test_the_cell_reports_unknown_rather_than_pass_or_fail(self):
        """Three outcomes reach the subcommand, not two."""
        with repo(ignore="/cluster.yaml\n") as p:
            with mock.patch.object(dc, "_ignore_text_covers", return_value=None):
                rc, out = capture(dc.check_repo_hygiene, args_for(p))
        self.assertEqual(rc, dc.UNKNOWN, out)


class TestWhatCountsAsARealCredential(unittest.TestCase):
    """#169 — the value side. Written before the fix, so the fixtures are not
    shaped by the implementation that has to satisfy them.

    Two halves, and the second is the one that matters:

    - **must NOT be a credential** — type expressions, template syntax, known
      placeholders. Easy to satisfy, and easy to *over*satisfy.
    - **must STILL be a credential** — values that look placeholder-ish and are
      real. "No longer firing" is trivially achievable by tightening until
      nothing fires, and **a check that was tightened too far reads exactly
      like one that was tightened correctly.**
    """

    NOT_CREDENTIALS = [
        ('string & !=""', "CUE type constraint"),
        ("bool | *false", "CUE default"),
        ('=~"^[a-z]+$"', "CUE regex constraint"),
        ("#{ cluster.ttyd_credential }#", "makejinja variable"),
        ("{{ .Values.credential }}", "Helm template"),
        ('"user:password"', "the sample file's placeholder"),
        ('"TOKEN_PLACEHOLDER"', "the renderer's placeholder"),
        # Added after a mutation test: removing the template-syntax rule broke
        # nothing, because every template case above is already rejected by an
        # older rule (`#{…}#` loses everything to the comment strip, `{{…}}`
        # starts with a brace). A value that is *partly* template is the one
        # only that rule catches — and a guard no case can turn red is the
        # shape this issue is about.
        ("admin{{ suffix }}", "a value that is part literal, part template"),
    ]

    STILL_CREDENTIALS = [
        ("0123456789abcdef0123456789abcdef01234567", "40 hex, the shape of a real token"),
        ("c2VjcmV0LXZhbHVlLWhlcmU=", "base64 ending in one ="),
        ("aGVsbG8td29ybGQtdGhpcy1pcy1yZWFs==", "base64 ending in == — NOT a `!=` type expression"),
        ("p@ssw0rd!=notatype", "a password that happens to contain !="),
        ("example0123456789abcdef0123456789abcdef", "contains the word example, and is 38 chars of hex"),
        ("user:Tr0ub4dor&3xplanation", "contains & and a colon, and is somebody's password"),
    ]

    def test_the_shapes_that_are_not_values(self):
        for value, why in self.NOT_CREDENTIALS:
            with self.subTest(why=why):
                self.assertFalse(dc._is_real_credential(value), why)

    def test_the_values_that_only_look_like_placeholders(self):
        """The negative control's positive control (#169 condition 3)."""
        for value, why in self.STILL_CREDENTIALS:
            with self.subTest(why=why):
                self.assertTrue(dc._is_real_credential(value), why)

    def test_a_key_with_no_inline_value_is_not_read_across_the_newline(self):
        r"""The class nobody had named: `\s` matches newlines.

            TTYD_CREDENTIAL:
              valueFrom:
                secretKeyRef:

        `^\\s*(field)\\s*:\\s*(.+)$` lets the `\\s*` after the colon swallow the
        line break, so the *next* line becomes the value and `valueFrom:` is
        judged a live credential. Three of this repo's seven hit paths were
        this, and it is not a placeholder problem at all — the field has no
        value on that line.
        """
        nested = ("              TTYD_CREDENTIAL:\n"
                  "                valueFrom:\n"
                  "                  secretKeyRef:\n"
                  "                    name: claude-code-secret\n")
        self.assertEqual([], dc._scan_blob_for_secrets(nested))

    def test_a_value_on_the_same_line_is_still_read(self):
        """Positive control for the line-break fix: narrowing the whitespace
        class must not stop the scanner reading ordinary values."""
        self.assertEqual(
            ["cloudflare_token"],
            dc._scan_blob_for_secrets(
                "  cloudflare_token: 0123456789abcdef0123456789abcdef01234567\n"))

    def test_the_scanners_control_sample_still_matches(self):
        """`_SCAN_CONTROL` is the thing every clean deep scan leans on."""
        self.assertTrue(dc._scan_blob_for_secrets(dc._SCAN_CONTROL))


class TestTheScannedPopulationIsPartOfTheAnswer(unittest.TestCase):
    """#171 — `--all` means "every ref this clone happens to have".

    Two clones of the same repository scan different things and both print
    "clean". Measured four ways, all on one repository:

      two machines, same minute          127 hits vs 124
      one machine, two hours apart        79 refs ->  77
      one machine, one minute apart      179 refs -> 115   (a `fetch --prune`)
      one machine's leftovers             92 local branches nobody else has

    Written before the implementation, so that "the hit disappears" is a
    property these cases demand rather than one the code happens to have.
    """

    @staticmethod
    def _repo(d: pathlib.Path) -> None:
        git(d, "init", "-q")
        (d / "README.md").write_text("# nothing\n")
        git(d, "add", "-fA")
        git(d, "commit", "-qm", "root")

    @staticmethod
    def _on_branch(d: pathlib.Path, branch: str, name: str, body: str) -> None:
        """Put a file on its own branch and go back — so the blob is reachable
        only from that branch, which is the situation being modelled."""
        git(d, "checkout", "-q", "-b", branch)
        (d / name).write_text(body)
        git(d, "add", "-fA")
        git(d, "commit", "-qm", f"add {name}")
        git(d, "checkout", "-q", "-")

    def test_a_credential_only_on_a_side_branch_is_found(self):
        """Condition 2. `--all` is what makes this pass today."""
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            self._repo(d)
            self._on_branch(d, "side", "leaked.yaml",
                            f"cloudflare_token: {FAKE_TOKEN}\n")
            hits = {path for path, _ in dc._scan_history_for_secrets(str(d))}
        self.assertEqual({"leaked.yaml"}, hits)

    def test_removing_that_branch_removes_the_finding(self):
        """Condition 3 — the negative control's own positive control.

        Deleting the branch is the only change; the blob is still in the object
        database until gc runs. If the hit *stayed*, this test would be
        measuring something other than the ref set, and the whole issue would
        be misdiagnosed.
        """
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            self._repo(d)
            self._on_branch(d, "side", "leaked.yaml",
                            f"cloudflare_token: {FAKE_TOKEN}\n")
            before = {path for path, _ in dc._scan_history_for_secrets(str(d))}
            git(d, "branch", "-qD", "side")
            after = {path for path, _ in dc._scan_history_for_secrets(str(d))}
        self.assertEqual({"leaked.yaml"}, before, "setup failed, not a finding")
        self.assertEqual(set(), after,
                         "the scan still sees a blob no ref points at — then "
                         "this test is not measuring the ref set")

    def test_the_population_is_reported_and_matches_what_was_scanned(self):
        """Condition 1, plus the thing that makes it trustworthy.

        A population printed by a second code path could drift from the
        population actually walked — the same "two copies diverge" failure this
        repo keeps paying for. Both numbers come from `_history_objects`, and
        this asserts they agree rather than trusting that they do.
        """
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            self._repo(d)
            self._on_branch(d, "side", "extra.yaml", "harmless: yes\n")
            pop = dc._history_population(str(d))
            walked = len(dc._history_objects(str(d)))
        self.assertEqual(walked, pop.objects)
        self.assertGreater(pop.objects, 0)
        self.assertGreaterEqual(pop.refs, 2)          # main + side

    def test_the_population_count_moves_when_the_ref_set_moves(self):
        """The population line's own control: a number that never changes
        cannot tell anyone which clone they are reading about."""
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            self._repo(d)
            self._on_branch(d, "side", "extra.yaml", "harmless: yes\n")
            with_branch = dc._history_population(str(d))
            git(d, "branch", "-qD", "side")
            without = dc._history_population(str(d))
        self.assertGreater(with_branch.refs, without.refs)
        self.assertGreater(with_branch.objects, without.objects)


class TestTheCoverageOfTheScanIsAsked(unittest.TestCase):
    """#171 conditions 4 and 5 — the narrowing is stated, not assumed.

    Three outcomes, because "the server says we are current" and "the server
    could not be asked" are the same silence otherwise, and only one of them
    means the scan below was complete.
    """

    @staticmethod
    def _fake_run(heads_rc=0, heads="", local="", pulls_rc=0, pulls=""):
        def run(cmd, **kw):
            if "ls-remote" in cmd and "--heads" in cmd:
                return types.SimpleNamespace(returncode=heads_rc, stdout=heads, stderr="")
            if "ls-remote" in cmd:
                return types.SimpleNamespace(returncode=pulls_rc, stdout=pulls, stderr="")
            if "for-each-ref" in cmd:
                return types.SimpleNamespace(returncode=0, stdout=local, stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        return run

    def test_a_clone_holding_every_remote_branch_reports_none_missing(self):
        with mock.patch.object(dc, "run", side_effect=self._fake_run(
                heads="aaa\trefs/heads/main\nbbb\trefs/heads/side\n",
                local="refs/heads/main\nrefs/remotes/origin/side\n",
                pulls="ccc\trefs/pull/1/head\n")):
            cov = dc._remote_coverage(".")
        self.assertEqual([], cov.missing_heads)
        self.assertEqual(2, cov.remote_heads)
        self.assertEqual(1, cov.pull_refs)

    def test_a_stale_clone_names_the_branches_it_cannot_see(self):
        """The finding this issue exists for: the scan reports clean about a
        population that is missing a branch."""
        with mock.patch.object(dc, "run", side_effect=self._fake_run(
                heads="aaa\trefs/heads/main\nbbb\trefs/heads/side\n",
                local="refs/heads/main\n")):
            cov = dc._remote_coverage(".")
        self.assertEqual(["side"], cov.missing_heads)

    def test_an_unreachable_server_is_cannot_measure_not_current(self):
        with mock.patch.object(dc, "run", side_effect=self._fake_run(heads_rc=128)):
            self.assertIsNone(dc._remote_coverage("."))

    def test_the_pull_ref_count_is_minus_one_when_that_query_fails(self):
        """A ceiling nobody could measure must not print as zero — `0 refs/pull`
        would read as "nothing is outside the scan", the opposite of the truth."""
        with mock.patch.object(dc, "run", side_effect=self._fake_run(
                heads="aaa\trefs/heads/main\n", local="refs/heads/main\n",
                pulls_rc=128)):
            self.assertEqual(-1, dc._remote_coverage(".").pull_refs)

class TestThePlaceholderExemptionIsAnchored(unittest.TestCase):
    """#175 — `"change" in v.lower()` exempted any value containing those five
    letters, anywhere. Written before the fix.

    The dangerous direction here is the opposite of #169's: that one was about
    noise, this one is about silence. A password an operator really set to
    `Change2026!`, committed into a public repo's history, was reported clean.

    ⚠️ And the *other* dangerous direction is tightening too far: if a real
    placeholder stops being exempt, the sample config starts failing, and **a
    guard that fires on the correct state gets switched off** — which costs
    more than the hole it closed.
    """

    # Provenance is part of each fixture. Two of these were read out of the
    # repository; two are existing behaviour being pinned so a rewrite cannot
    # drop it silently. **An invented fixture's blind spots never show up in
    # any result** — `[bbf3d2]` spent a round on a hand-written CUE case whose
    # shape did not exist here, and this list lost two entries the same way:
    # `changeme-changeme` was mine, and anchoring correctly flags it.
    STILL_EXEMPT = [
        # OBSERVED — cluster.sample.yaml:616, the only non-empty placeholder in
        # the file (the other five credential fields are `""`).
        ("ops:CHANGE-ME", "the placeholder cluster.sample.yaml documents"),
        # MINE, but a one-character variant of the observed one.
        ("ops:change-me", "the same, lower case and unshouted"),
        # EXISTING BEHAVIOUR, not an observed shape: the old rule's other half.
        ("xxxxxxxxxx", "all-x, the second half of the rule being replaced"),
        # EXISTING BEHAVIOUR: the `<` prefix rule, which predates both.
        ("<your-token-here>", "angle brackets — asserted so a rewrite of this "
                              "function cannot drop an older rule"),
    ]

    FLAGGED_NOW = [
        ("ops:Exchange2026!", "the word Exchange contains change"),
        ("exchange_rate_api_key_live_abc123", "so does exchange_rate"),
        ("ops:changeme-but-real-99", "starts like the placeholder and is not one"),
        ("ops:hunter2", "control: was already flagged, must stay flagged"),
        ("admin:120120cla", "control: this one was really live on jg-jiahd"),
    ]

    def test_the_documented_placeholders_are_still_exempt(self):
        """Condition 1. Red here means the sample config is about to start
        failing, which is worse than the hole this issue closes."""
        for value, why in self.STILL_EXEMPT:
            with self.subTest(why=why):
                self.assertFalse(dc._is_real_credential(value), why)

    def test_a_real_value_that_merely_contains_change_is_flagged(self):
        """Conditions 2 — the hole itself."""
        for value, why in self.FLAGGED_NOW:
            with self.subTest(why=why):
                self.assertTrue(dc._is_real_credential(value), why)

    def test_an_exempt_placeholder_turned_into_a_usable_value_is_flagged(self):
        """Condition 3 — the negative control's own positive control.

        Every entry of STILL_EXEMPT, mutated into something workable by
        appending entropy. If the exemption matched loosely again, these would
        stay silent and the list above would still pass.
        """
        for value, why in self.STILL_EXEMPT:
            with self.subTest(why=why):
                # Strip the delimiters that are themselves the exemption:
                # `<…>` is exempt by shape, so appending entropy inside the
                # brackets would test nothing.
                usable = value.strip("<>") + "-7fQ2mK9x"
                self.assertTrue(
                    dc._is_real_credential(usable),
                    f"a usable value built from {value!r} was exempted")

    # 4 usernames x 12 placeholder words. Spelled out, not described: two
    # people counting this space got 38 and 37 because their word lists
    # differed, and a number nobody can rebuild is not a reading.
    COLON_USERS = ["admin", "ttyd", "user", "ops"]
    COLON_WORDS = ["none", "example", "xxx", "todo", "tbd", "placeholder",
                   "changeme", "change-me", "replaceme", "replace-me",
                   "token_placeholder", "?????"]

    def test_the_colon_space_is_exempt_wholesale_and_that_is_the_widening(self):
        """⚠️ This PR tightens overall and **loosens** inside `user:password`.

        `[bbf3d2]` found it: applying the placeholder pattern to the part after
        the colon exempts cells that were flagged before. Enumerated over the
        grid below, **38 of 48 cells loosened and 0 tightened** — the mirror of
        the rule jgct#166 set, since an unrecorded widening inside a PR whose
        purpose is narrowing is the same shape as an unrecorded narrowing.

        ⚠️ **That 38 cannot be recomputed here**, and saying so is the point:
        it came from loading the pre-#175 module side by side with this one,
        and once this lands that version is gone from the tree. What a test can
        hold is the *direction* and the representative cells; the number lives
        in the comment on `_is_placeholder` together with how it was taken.
        **A number a test cannot rebuild is a record, not an assertion, and the
        two should not be dressed the same.**
        """
        for user in self.COLON_USERS:
            for word in self.COLON_WORDS:
                with self.subTest(value=f"{user}:{word}"):
                    self.assertTrue(dc._is_placeholder(f"{user}:{word}"))
        # And the direction: none of this space became stricter. Asserted
        # against the four cells that carry the old rule's own exemption, so
        # "0 tightened" is not a count over an empty set.
        for value in ["ops:changeme", "user:change-me", "xxxxxxxxxx", "admin:xxx"]:
            with self.subTest(value=value):
                self.assertFalse(dc._is_real_credential(value))

    def test_the_tracked_tree_keeps_exactly_the_shapes_it_has_today(self):
        """Condition 5, asserted rather than eyeballed once.

        Measured on `main` before writing the fix: 89 tracked files, 10 values
        reach this function, and **none of them is exempt because of the
        `change` substring** — they are template syntax, CUE types, empty
        strings and `TOKEN_PLACEHOLDER`. So tightening cannot change this
        repo's verdicts, and this case pins that claim rather than leaving it
        in a commit message.
        """
        shapes = [
            '"#{ cloudflare_token }#"', '"#{ ttyd_credential | default(\'\') }#"',
            'string & !=""', 'string', '""', '"TOKEN_PLACEHOLDER"',
        ]
        for value in shapes:
            with self.subTest(value=value):
                self.assertFalse(dc._is_real_credential(value))


class TestTheStagedTreeIsScannedBeforeItIsPushed(unittest.TestCase):
    """#178 — the population is history, and the thing being pushed is not yet in it.

    `provision.py`'s ConfigurePushStep runs five commands in this order:

        task configure --yes          # render
        repo-hygiene --dir … --deep   # scans `--all` history
        git add kubernetes
        git commit
        git push                      # -> a public repo

    Step 2 asks about objects reachable from a ref. What steps 3-5 send is a
    tree that **is not on any ref yet** — it joins the history one command
    later, by which time it is already published. Measured on `main`: 23 files
    under `templates/`, 19 of them not `*.sops.*`, **read 19, skipped 0, hits
    0** — so this is "that cell is unmeasured", not "something leaked".

    Written before the implementation.
    """

    @staticmethod
    def _repo(d: pathlib.Path) -> None:
        git(d, "init", "-q")
        (d / "README.md").write_text("# nothing\n")
        git(d, "add", "-fA")
        git(d, "commit", "-qm", "root")

    def test_a_credential_staged_but_not_committed_is_found(self):
        """Condition 2 — and deliberately NOT in a `*.sops.*` path, which would
        be caught by the encryption step instead and prove nothing here."""
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            self._repo(d)
            (d / "kubernetes").mkdir()
            (d / "kubernetes" / "secret.yaml").write_text(
                f"stringData:\n  cloudflare_token: {FAKE_TOKEN}\n")
            git(d, "add", "-f", "kubernetes")
            found = dc._scan_index_for_secrets(str(d))
        self.assertIsNotNone(found, "should be measurable in a real repo")
        self.assertEqual([("kubernetes/secret.yaml", "cloudflare_token")],
                         [(p, f) for p, f, _ in found.hits])
        # The population, not just the result: one path staged, one blob read.
        self.assertEqual((1, 1), (found.staged_paths, found.scanned))

    def test_a_clean_staged_tree_is_clean_and_that_green_can_be_falsified(self):
        """Condition 3: not "red became green" — the count must differ by one.

        A guard that goes from some failures to none has only shown that
        something changed. Staging the same tree without the one credential and
        asserting the hit count drops by exactly 1 shows that the thing which
        changed is the thing under test.
        """
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            self._repo(d)
            (d / "kubernetes").mkdir()
            (d / "kubernetes" / "a.yaml").write_text("harmless: yes\n")
            (d / "kubernetes" / "b.yaml").write_text(
                f"stringData:\n  cloudflare_token: {FAKE_TOKEN}\n")
            git(d, "add", "-f", "kubernetes")
            with_secret = len(dc._scan_index_for_secrets(str(d)).hits)
            (d / "kubernetes" / "b.yaml").write_text("harmless: also\n")
            git(d, "add", "-f", "kubernetes")
            after = dc._scan_index_for_secrets(str(d))
            without = len(after.hits)
        self.assertEqual(1, with_secret)
        self.assertEqual(0, without)
        self.assertEqual(1, with_secret - without, "the delta is the assertion")
        # And the population is unchanged across the two runs — otherwise the
        # delta could come from having scanned less, not from having found less.
        self.assertEqual(2, after.scanned)

    def test_a_sops_path_is_excluded_by_a_stated_rule(self):
        """Condition 4 — excluded on purpose, not by happening not to match.

        The file here is plaintext despite its name: if the exclusion were
        relying on `ENC[` (which `_is_real_credential` already waives), this
        case would fail. It asserts the *path* rule, which is the one that has
        to hold when encryption has not run yet — which is exactly the window
        this check sits in.
        """
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            self._repo(d)
            (d / "kubernetes").mkdir()
            (d / "kubernetes" / "cluster-secrets.sops.yaml").write_text(
                f"stringData:\n  cloudflare_token: {FAKE_TOKEN}\n")
            git(d, "add", "-f", "kubernetes")
            found = dc._scan_index_for_secrets(str(d))
        self.assertEqual([], found.hits)
        # ⚠️ and the skip is *reported*: a silent zero here would be the exact
        # failure this round of review caught — 0 found and 0 looked at print
        # the same thing otherwise.
        self.assertEqual((1, 0, 1), (found.staged_paths, found.scanned,
                                     found.skipped_sops))

    def test_four_different_reasons_do_not_report_the_same_thing(self):
        """The review finding this round, pinned so it cannot come back.

        The first version printed `len(hits)` under the name `population`, so
        **nothing staged**, **a clean file**, **a binary blob holding a
        credential** (skipped by the NUL rule) and **an all-`*.sops.*` index**
        all printed `staged population: 0` and PASS. Every skip is correct;
        none of them said so. "I read three blobs and they were clean" and "I
        read nothing" were the same sentence.

        Asserted as four distinct tuples: a change that collapses any two of
        them fails here, not just one that breaks a single case.
        """
        def scan(build) -> tuple:
            with tempfile.TemporaryDirectory() as t:
                d = pathlib.Path(t)
                self._repo(d)
                build(d)
                git(d, "add", "-fA")
                r = dc._scan_index_for_secrets(str(d))
            return (r.staged_paths, r.scanned, r.skipped_sops,
                    r.skipped_binary, len(r.hits))

        nothing = scan(lambda d: None)
        clean = scan(lambda d: (d / "k.yaml").write_text("harmless: y\n"))
        binary = scan(lambda d: (d / "b.bin").write_bytes(
            b"\x00\x01\nttyd_credential: ops:hunter2xyz99\n\x00"))
        sops = scan(lambda d: (d / "x.sops.yaml").write_text(
            f"stringData:\n  cloudflare_token: {FAKE_TOKEN}\n"))

        self.assertEqual(4, len({nothing, clean, binary, sops}),
                         f"two are indistinguishable: {nothing=} {clean=} "
                         f"{binary=} {sops=}")
        self.assertEqual((0, 0, 0, 0, 0), nothing)
        self.assertEqual((1, 1, 0, 0, 0), clean)
        self.assertEqual((1, 0, 0, 1, 0), binary)
        self.assertEqual((1, 0, 1, 0, 0), sops)

    def test_nothing_staged_is_cannot_measure_at_the_cell_level(self):
        """Nothing staged is not a clean staging area — it is the absence of
        one, and `provision.py` only reaches this line after `git add`.

        ⚠️ Cost, asserted rather than hidden: a re-run whose render is
        byte-identical stages nothing and now reports UNKNOWN instead of green.
        That is the direction to be wrong in when the next command publishes to
        a public repository.
        """
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            self._repo(d)
            rc, out = capture(dc.check_repo_hygiene, args_for(d, staged=True))
        self.assertEqual(dc.UNKNOWN, rc, out)
        self.assertIn("absence of one", out)

    def test_a_directory_that_is_not_a_repo_is_cannot_measure(self):
        """Condition 5 — `None`, never an empty list.

        "Nothing staged is dirty" and "there is no index to read" produce the
        same empty result otherwise, and only one of them is a pass.
        """
        with tempfile.TemporaryDirectory() as t:
            self.assertIsNone(dc._scan_index_for_secrets(t))

    def test_an_empty_index_is_measurable_and_empty(self):
        """The other side of the three outcomes: a repo with nothing staged is
        a measurement that found nothing, not a failure to measure."""
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            self._repo(d)
            empty = dc._scan_index_for_secrets(str(d))
            self.assertEqual([], empty.hits)
            self.assertEqual(0, empty.staged_paths)


if __name__ == "__main__":
    unittest.main()
