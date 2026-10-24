"""check-extras-source.py can tell a correct extras switch from a broken one (jgct#217).

Each case copies the template inputs, applies one mutation (asserted to have
landed — an edit that did not apply returns the same exit 0 as a guard that
cannot see it), and runs the guard with `--tree`. Case 0 is the unmutated copy.
Needs makejinja, cue, age-keygen and yq (mise installs them in CI).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "scripts" / "check-extras-source.py"
KS = Path("templates/config/kubernetes/flux/cluster/ks.yaml.j2")
SECRET = Path("templates/config/kubernetes/components/sops/jg-extras-deploy-key.sops.yaml.j2")
COPY = ["templates", "makejinja.toml", "trello-notifier.sample.yaml",
        ".taskfiles/template/resources"]


class ExtrasSourceGuard(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="extras-guard-test.")
        self.tree = Path(self._tmp.name)
        for rel in COPY:
            src, dst = ROOT / rel, self.tree / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            (shutil.copytree(src, dst, symlinks=True) if src.is_dir() else shutil.copy2(src, dst))

    def tearDown(self):
        self._tmp.cleanup()

    def run_guard(self, *extra):
        p = subprocess.run([sys.executable, str(GUARD), "--tree", str(self.tree), *extra],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def edit(self, rel: Path, old: str, new: str):
        path = self.tree / rel
        text = path.read_text()
        self.assertIn(old, text, f"mutation anchor not found in {rel}")
        path.write_text(text.replace(old, new, 1))
        self.assertNotEqual(path.read_text(), text, "mutation did not change the file")

    def test_0_unmutated_copy_passes(self):
        rc, out = self.run_guard()
        self.assertEqual(rc, 0, out)
        self.assertIn("ok  [appliance-minimal] no extras", out)

    def test_1_a_changed_path_fails(self):
        # The root's own negative control: one `path` moved.
        self.edit(KS, "  path: ./kubernetes/apps/extras/#{extra}#\n",
                  "  path: ./kubernetes/apps/extra/#{extra}#\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("path './kubernetes/apps/extra/default/postgres'", out)

    def test_2_secretref_naming_nothing_fails(self):
        # jgct#56's shape: the reference and the credential disagree.
        self.edit(KS, "  secretRef:\n    name: jg-extras-deploy-key\n",
                  "  secretRef:\n    name: jg-extras-key\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("secretRef 'jg-extras-key' names no Secret", out)

    def test_3_secret_without_extras_fails(self):
        self.edit(SECRET, "#% if extras_from_repo %#\n", "#% if true %#\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("[appliance-minimal] no extras, yet kubernetes/components/sops/jg-extras-deploy-key.sops.yaml is rendered", out)

    def test_4_loop_still_on_jg_base_fails(self):
        self.edit(KS, "    kind: GitRepository\n    name: jg-extras\n    namespace: flux-system\n",
                  "    kind: GitRepository\n    name: jg-base\n    namespace: flux-system\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("sourceRef {'kind': 'GitRepository', 'name': 'jg-base'", out)

    def test_5_gitrepository_without_extras_fails(self):
        self.edit(KS, "#% if extras_from_repo %#\n---\n# ── GitRepository — the optional apps",
                  "#% if true %#\n---\n# ── GitRepository — the optional apps")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("[appliance-minimal] no extras, yet GitRepository jg-extras is rendered", out)

    def test_6_secret_template_gone_fails(self):
        (self.tree / SECRET).unlink()
        self.assertFalse((self.tree / SECRET).exists())
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("names no Secret", out)

    def test_7_against_catches_an_unrelated_change(self):
        # CI mode is blind to this by design; --against is not.
        self.edit(KS, "  name: cluster-apps-base\n  namespace: flux-system\nspec:\n",
                  "  name: cluster-apps-base\n  namespace: flux-system\n  labels: {x: y}\nspec:\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 0, out)
        rc, out = self.run_guard("--against", "HEAD")
        self.assertEqual(rc, 1, out)
        self.assertIn("differs from the reference beyond jg-extras + sourceRef.name", out)


if __name__ == "__main__":
    unittest.main()
