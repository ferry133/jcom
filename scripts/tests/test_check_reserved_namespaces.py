"""check-reserved-namespaces.py against two throwaway repos and a throwaway list.

Each case builds its own jg-base / jg-extras stand-ins (git repos, files
staged so `git ls-files` sees them) and a one-field schema, so nothing here
depends on a sibling checkout being present. Case 0 is the unmutated fixture
and must pass: if the harness itself is broken, every other case goes red and
reads as "every mutation was caught".
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
GUARD = ROOT / "scripts" / "check-reserved-namespaces.py"

NS = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}\n"
RESERVED = ["claudecode", "default", "flux-system", "linebot", "mqtt"]


class ReservedNamespaces(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing tools are a failure, not a skip: CI installs both through
        # mise, and a suite that skips reads as a suite that passed.
        for tool in ("cue", "yq", "git"):
            if not shutil.which(tool):
                raise AssertionError(f"{tool} is not on PATH")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.base = self.repo("jg-base", {
            "kubernetes/apps/base/claudecode/namespace.yaml": NS.format("claudecode"),
            "kubernetes/apps/base/flux-system/ks.yaml":
                "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\n"
                "metadata:\n  name: x\n  namespace: flux-system\n"
                "spec:\n  targetNamespace: default\n",
        })
        self.extras = self.repo("jg-extras", {
            "kubernetes/apps/extras/default/linebot/namespace.yaml": NS.format("linebot"),
            "kubernetes/apps/extras/mqtt/kustomization.yaml":
                "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
                "namespace: mqtt\nresources: []\n",
        })
        self.schema = self.write_schema(RESERVED)

    def repo(self, name, files):
        d = self.tmp / name
        d.mkdir()
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        for rel, text in files.items():
            self.add(d, rel, text)
        return d

    def add(self, repo, rel, text, stage=True):
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        if stage:
            subprocess.run(["git", "-C", str(repo), "add", rel], check=True)

    def write_schema(self, names):
        p = self.tmp / "cluster.schema.cue"
        quoted = ", ".join(f'"{n}"' for n in names)
        p.write_text(f"package config\n\n#ReservedNamespaces: [{quoted}]\n")
        return p

    def run_guard(self, extras=None):
        p = subprocess.run(
            [sys.executable, str(GUARD), "--base", str(self.base),
             "--extras", str(extras or self.extras), "--schema", str(self.schema)],
            capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def test_0_unmutated_fixture_passes(self):
        rc, out = self.run_guard()
        self.assertEqual(rc, 0, out)
        self.assertIn("jg-base @ ?: 2 files, 3 namespaces", out)
        self.assertIn("jg-extras @ ?: 2 files, 2 namespaces", out)

    def test_1_jg_base_side_gap_fails(self):
        self.schema = self.write_schema([n for n in RESERVED if n != "claudecode"])
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL  jg-base: namespace 'claudecode' is not in #ReservedNamespaces", out)

    def test_2_jg_extras_only_gap_fails(self):
        # The gap a jg-base-only reading cannot see (#235).
        self.schema = self.write_schema([n for n in RESERVED if n != "linebot"])
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL  jg-extras: namespace 'linebot' is not in #ReservedNamespaces", out)

    def test_3_missing_repo_cannot_measure(self):
        rc, out = self.run_guard(extras=self.tmp / "absent")
        self.assertEqual(rc, 2, out)
        self.assertIn("cannot tell: jg-extras: no checkout", out)
        self.assertNotIn("ok    every namespace", out)

    def test_4_gap_wins_over_missing_repo(self):
        self.schema = self.write_schema([n for n in RESERVED if n != "claudecode"])
        rc, out = self.run_guard(extras=self.tmp / "absent")
        self.assertEqual(rc, 1, out)

    def test_5_name_far_from_kind_is_found(self):
        # The grep -A3 reading on #235 missed exactly this layout.
        self.add(self.extras, "kubernetes/x.yaml",
                 "apiVersion: v1\nkind: Namespace\nmetadata:\n  labels:\n    a: b\n"
                 "    c: d\n  annotations:\n    e: f\n  name: zz-far\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("namespace 'zz-far'", out)

    def test_6_each_source_field_is_read(self):
        cases = {
            "metadata.namespace": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: zz-meta\n",
            "spec.targetNamespace": "apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata:\n  name: h\n  namespace: default\nspec:\n  targetNamespace: zz-target\n",
            "kustomization namespace": "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: zz-kust\n",
            "second document": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\n" + NS.format("zz-second"),
        }
        for i, (label, text) in enumerate(cases.items()):
            with self.subTest(label):
                self.setUp()
                self.add(self.base, f"kubernetes/case{i}.yaml", text)
                rc, out = self.run_guard()
                self.assertEqual(rc, 1, out)
                self.assertIn(f"({label.replace('second document', 'kind: Namespace')})", out)

    def test_7_unsubstituted_value_is_counted_not_compared(self):
        self.add(self.base, "kubernetes/v.yaml",
                 "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: v\n  namespace: ${NS_VAR}\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 0, out)
        self.assertIn("1 values still holding ${VAR}", out)

    def test_8_untracked_file_is_not_read(self):
        self.add(self.base, "kubernetes/stray.yaml", NS.format("zz-untracked"), stage=False)
        rc, out = self.run_guard()
        self.assertEqual(rc, 0, out)

    def test_9_repo_with_no_namespace_cannot_measure(self):
        empty = self.repo("hollow", {"kubernetes/a.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n"})
        rc, out = self.run_guard(extras=empty)
        self.assertEqual(rc, 2, out)
        self.assertIn("and not one namespace in them", out)

    def test_10_unreadable_list_cannot_measure(self):
        self.schema.write_text("package config\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 2, out)
        self.assertIn("#ReservedNamespaces not readable", out)


if __name__ == "__main__":
    unittest.main()
