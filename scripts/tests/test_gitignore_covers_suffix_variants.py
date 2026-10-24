#!/usr/bin/env python3
"""`.gitignore`'s secret rules must cover SUFFIX variants, and must not catch tracked files — jgct#184.

Run: python3 .github/workflows/run-tests.py

**The defect, measured.** `*cluster.yaml` covered only prefix variants, so
`cluster.yaml.bak`, `cluster.yaml.orig` and `cluster.yaml.20260919` were all
committable — and a suffix is what a hand-made backup actually looks like: `cp`
to `.bak`, an editor's `.orig`, a date appended. `cluster.yaml` is the one file
holding every plaintext credential a cluster has, and this `.gitignore` is
copied into every customer repo, all of them public.

Asking every rule in the file the same question turned up **fifteen** with that
shape, not three filenames — including `age.key`, whose exposure is worse than
`cluster.yaml`'s: a leaked `cluster.yaml` credential can be rotated, while
`age.key` decrypts every off-site backup already uploaded, and those cannot be.

**This file's own header already said so.** Lines 3-8 of `.gitignore` read
"Rules are shaped by WHAT IS PROTECTED, not by filenames someone thought of …
Prefer a glob over an exact name". Fifteen of its rules did not follow it. The
lesson was written down and applied to three rules (`kubeconfig*`,
`talosconfig*`, `omniconfig*`) and to no others.

**Why a test and not just wider rules.** Widening rules made two of them match
TRACKED template files — `templates/…/controller/cluster.yaml.j2` and
`templates/config/.sops.yaml.j2`. Both were found by asking all tracked files;
a hand-picked list of seven "files that must stay tracked" missed the first and
would have missed the second. And a `.gitignore` rule that matches a tracked
file breaks nothing on the day it lands, because tracking wins — which is
exactly why it would have sat there until someone re-added the file. So the
collision check belongs in CI, not in whoever-remembers.

**The instrument is the repo's own.** `_ignore_text_covers` writes HEAD's
`.gitignore` into a throwaway repo with `core.excludesFile=/dev/null` and asks
git. Bare `git check-ignore` answers about the workstation running it, which is
also the workstation doing the checking — that is jgct#167, and jg-jiahd's
eleven credential-bearing blobs landed behind exactly that confusion.
"""
import sys

# See the note in test_delivery_check_repo_hygiene.py: a stale `.pyc` makes a
# mutation test report the previous run's result.
sys.dont_write_bytecode = True

import importlib.util
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)

GITIGNORE = ROOT / ".gitignore"

# OBSERVED, not invented: `.bak` and `.orig` are what the jgct#184 reporters
# actually found, and the dated form is `cp cluster.yaml cluster.yaml.$(date)`.
SUFFIXES = (".bak", ".orig", ".20260919")

# The secret-bearing rules, written as the base name a suffix would be appended
# to. Derived from the rules in `.gitignore`, so a rule added later without a
# trailing `*` is NOT automatically covered here — `test_every_secret_rule_is_a_glob`
# below is the half that notices that.
SECRET_BASES = (
    "age.key", "x.agekey", "agex.txt",
    "github-deploy.key", "github-deploy.key.pub", "github-push-token.txt",
    "jg-extras.deploy.key", "jg-extras.deploy.key.pub", "x.deploy.key",
    "cloudflare-tunnel.json", "auth0.json",
    "kubeconfigx", "talosconfigx", "omniconfigx", "acme.age.key",
    "talsecretx.yaml", "secrets.yaml", ".sops.yaml",
    "trello-notifier.yaml", "cluster.yaml", "nodes.yaml",
    ".merged-config.yaml",
)


def _text() -> str:
    return GITIGNORE.read_text()


def _covers(path: str) -> bool | None:
    return dc._ignore_text_covers(_text(), path)


class TestSuffixVariantsAreIgnored(unittest.TestCase):
    """The defect itself: every secret rule's suffix variants must be ignored."""

    def test_the_three_shapes_the_issue_found(self):
        """Condition 1 of jgct#184, named one by one rather than in a loop count."""
        for suffix in SUFFIXES:
            with self.subTest(suffix=suffix):
                self.assertIs(_covers("cluster.yaml" + suffix), True)

    def test_every_secret_base_covers_its_suffix_variants(self):
        """The population is the rules, not the three filenames in the report."""
        for base in SECRET_BASES:
            for suffix in SUFFIXES:
                with self.subTest(base=base, suffix=suffix):
                    self.assertIs(_covers(base + suffix), True,
                                  f"{base}{suffix} is committable")

    def test_the_prefix_variants_that_already_worked_still_do(self):
        """Positive control for the widening: it must not have traded one
        direction for the other. `bak-cluster.yaml` and the jgct#166 path case
        were already covered before this change."""
        self.assertIs(_covers("bak-cluster.yaml"), True)
        self.assertIs(_covers("config.gen/cluster.yaml"), True)
        self.assertIs(_covers("cluster.yaml"), True)


class TestTheWideRulesDoNotCatchTrackedFiles(unittest.TestCase):
    """The cost of widening, checked against the OBSERVED population.

    A hand-picked list of "files that must stay tracked" missed both real
    collisions. `git ls-files` cannot.
    """

    def test_no_tracked_file_is_ignored(self):
        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"],
            capture_output=True, text=True, timeout=60,
        )
        if tracked.returncode != 0:
            self.skipTest("not a git checkout — this cell needs the tracked set")
        paths = [p for p in tracked.stdout.split("\n") if p.strip()]
        # Cannot-measure guard: an empty tracked set would make this cell pass
        # while looking at nothing, which is the shape this repo keeps paying for.
        self.assertGreater(len(paths), 50, "tracked set implausibly small")
        caught = [p for p in paths if _covers(p) is True]
        self.assertEqual([], caught, "these tracked files are matched by a secret rule")

    def test_the_tracked_sweep_can_actually_say_yes(self):
        """Positive control for the cell above: the same query shape, asked
        about a path that MUST be ignored, has to come back True. Without this,
        an `_ignore_text_covers` that answered False for everything would make
        the sweep above pass on a broken instrument."""
        self.assertIs(_covers("cluster.yaml"), True)

    def test_an_unrelated_name_is_not_ignored(self):
        """Constructed negative control, not an observed one.

        An observed "not ignored" name (say `README.md`) stops being a control
        the day someone adds a rule for it; a name nothing will ever match does
        not. Both are here — the observed one reads on real content, the
        constructed one does not expire.
        """
        self.assertIs(_covers("README.md"), False)
        self.assertIs(_covers("zzz-nothing-will-ever-match-this-9f2.md"), False)


class TestTheDeliberateExceptionsStillHold(unittest.TestCase):
    """Two negations are load-bearing, and a wide rule could silently eat either."""

    def test_the_encrypted_talos_secret_stays_committable(self):
        self.assertIs(_covers("talsecret.sops.yaml"), False)
        # …while the plaintext one it is an exception to stays ignored.
        self.assertIs(_covers("talsecret.yaml"), True)

    def test_templates_stay_committable(self):
        """`!*.j2` — one principled negation rather than one per collision.

        Enumerating `!*cluster.yaml.j2`, `!*.sops.yaml.j2` … would be this
        issue's own mistake: naming what someone thought of. A `.j2` holds
        `#{ placeholders }#`; the thing that must never be committed is the
        rendered output, which has no `.j2` suffix.
        """
        self.assertIs(_covers("templates/config/talos/patches/controller/cluster.yaml.j2"), False)
        self.assertIs(_covers("templates/config/.sops.yaml.j2"), False)

    def test_what_that_negation_costs(self):
        """Written down rather than discovered later: `!*.j2` also un-ignores a
        `.bak` that happens to end in `.j2`. Asserted so the cost is a reading
        in this file and not a surprise in someone's `git status`."""
        self.assertIs(_covers("cluster.yaml.bak.j2"), False)
        # The suffix variant that matters is still caught.
        self.assertIs(_covers("cluster.yaml.bak"), True)


class TestTenantCredentialsAreIgnored(unittest.TestCase):
    """jgct#214 task 3.5: `/tenants*/` and `*.age.key*`.

    The population is what the provisioning skill could write (design D2/D5),
    including names no extension rule would match, and the tracked side is
    what the templates render: `kubernetes/tenants/` must stay committable or
    Flux never sees the tenant Secrets — the shape root task 1.2 hit when a
    sops file named `secrets.yaml` was ignored and Flux answered `no such file`.
    """

    KEYS = (
        "tenants/acme.age.key",       # the design's own name (D2)
        "tenants/acme.agekey",
        "tenants/acme.key",
        "tenants/acme-deploy",        # `ssh-keygen -f tenants/acme-deploy`
        "tenants/acme-deploy.pub",
        "tenants/im-apps-write",      # the agent's write key, any name
        "tenants/sub/dir/anything",
    )

    def test_every_tenant_credential_name_is_ignored(self):
        for path in self.KEYS:
            for suffix in ("",) + SUFFIXES:
                with self.subTest(path=path + suffix):
                    self.assertIs(_covers(path + suffix), True,
                                  f"{path}{suffix} is committable")

    def test_a_backup_copy_of_the_directory_is_ignored(self):
        self.assertIs(_covers("tenants.bak/acme.age.key"), True)
        self.assertIs(_covers("tenants-20261018/acme-deploy"), True)

    def test_an_age_key_by_that_name_outside_tenants_is_ignored(self):
        """`*.age.key*` is not tied to the directory: the same file copied to
        the repo root is the same credential."""
        self.assertIs(_covers("acme.age.key"), True)
        self.assertIs(_covers("config.gen/acme.age.key.bak"), True)

    def test_the_rendered_tenant_objects_stay_committable(self):
        """The anchor. An unanchored `tenants/` would ignore all of these, and
        a directory rule cannot be negated back."""
        for path in ("kubernetes/tenants/im-apps-write-key.sops.yaml",
                     "kubernetes/tenants/tenant-sops-age.sops.yaml",
                     "kubernetes/tenants/acme/namespace.yaml",
                     "templates/config/kubernetes/tenants/namespace.yaml.j2"):
            with self.subTest(path=path):
                self.assertIs(_covers(path), False, f"{path} would not be committed")


class TestEveryRuleInTheFileIsChecked(unittest.TestCase):
    """The half that notices a rule added later in the OLD shape.

    `SECRET_BASES` above is a list someone wrote. This cell reads the file
    instead, so a new exact-name secret rule fails here rather than being
    quietly outside the population.
    """

    # Rules that are legitimately not globs: directories, negations, and the
    # non-secret build outputs. Everything else must end in `*`.
    # `/tenants*/` is a directory rule whose glob is in the name; see
    # TestTenantCredentialsAreIgnored.
    ALLOWED_NON_GLOB = {"/bootstrap/", "/talos/", ".venv/", ".claude/",
                        "__pycache__/", "dist/", ".merged-config.yaml",
                        "/tenants*/"}

    def test_every_secret_rule_ends_in_a_glob(self):
        rules = [l.strip() for l in _text().splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        self.assertGreater(len(rules), 20, "rule set implausibly small")
        offenders = [r for r in rules
                     if not r.startswith("!")
                     and not r.endswith("*")
                     and r not in self.ALLOWED_NON_GLOB]
        self.assertEqual(
            [], offenders,
            "exact-name secret rules — their suffix variants are committable; "
            "add a trailing `*`, or add the rule to ALLOWED_NON_GLOB with a reason")


if __name__ == "__main__":
    unittest.main()
