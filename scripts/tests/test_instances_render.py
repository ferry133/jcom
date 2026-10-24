"""Every file the rendered `instances/kustomization.yaml` lists must be rendered.

jgct#229: `instances/kustomization.yaml` is static and lists
`./state-archive.yaml`, but that template's whole output sits inside
`#% for instance in claude_instances %#`. With no instances the render was
empty, makejinja does not write empty renders, and every cluster with
`claude_instances: []` (jg-jiahd and jcom among them) failed `task configure`
in validate-manifests: kustomize pointed at a file that did not exist.

Each case renders with the real makejinja, through check-tenant-render.py's
own staging (`stage`/`render`), so the inputs are the ones that guard uses.

- Case 0, `claude_instances: []`: the instances kustomization resolves, and
  `kustomize build` on that directory exits 0.
- Case 1, `claude_instances: ["cc"]` (positive control): the CronJob is
  rendered for `cc`. Without this case an empty file would pass case 0 even if
  the loop had stopped rendering for everybody.
- Case 2, every rendered `kustomization.yaml` in both renders lists only
  files that were rendered. This is the class #229 belongs to, so it is not
  limited to the one directory that broke.

Needs makejinja, age-keygen and kustomize on PATH (CI installs them with
mise). A missing tool fails the case instead of skipping it: a skipped test
reads green.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
INSTANCES = "kubernetes/apps/base/claudecode/claude-code/instances"

_spec = importlib.util.spec_from_file_location("check_tenant_render",
                                               ROOT / "scripts" / "check-tenant-render.py")
ctr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ctr)
FIXTURES = {name: (cfg, nodes) for name, cfg, nodes in ctr.FIXTURES}


def need(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise AssertionError(f"`{tool}` not on PATH (run under `mise exec --`); "
                             "failing rather than skipping")
    return path


def local_resources(body: bytes) -> list[str]:
    """`resources:` entries of a kustomization that name a file, not a dir or URL.

    A line-based read on purpose: the rendered kustomizations are flat lists,
    and this keeps the test free of a yaml dependency. Entries ending in `/`
    or without a YAML/JSON suffix are directories and are checked as such.
    """
    out, inside = [], False
    for line in body.decode().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "-")):
            inside = line.rstrip() == "resources:"
            continue
        item = line.strip()
        if inside and item.startswith("- "):
            ref = item[2:].strip().strip("'\"")
            if "://" not in ref:
                out.append(ref)
    return out


class InstancesRender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need("makejinja")
        cls._tmp = tempfile.TemporaryDirectory(prefix="instances-render-test.")
        key = Path(cls._tmp.name) / "age.key"
        proc = subprocess.run([need("age-keygen"), "-o", str(key)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise AssertionError(f"age-keygen failed: {proc.stderr.strip()}")
        cls.renders = {}
        for label, base, instances in (("none", "appliance-minimal", []),
                                       ("cc", "appliance-instances-auth0", ["cc"])):
            cfg, nodes = FIXTURES[base]
            cfg = dict(cfg, claude_instances=instances)
            cls.renders[label] = ctr.render(ROOT, cfg, nodes, key)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def files_under(self, label: str, prefix: str) -> dict[str, bytes]:
        return {k: v for k, v in self.renders[label].items() if k.startswith(prefix + "/")}

    def test_0_no_instances_kustomization_builds(self):
        files = self.files_under("none", INSTANCES)
        self.assertIn(f"{INSTANCES}/kustomization.yaml", files,
                      "the instances kustomization itself was not rendered")
        listed = local_resources(files[f"{INSTANCES}/kustomization.yaml"])
        self.assertIn("./state-archive.yaml", listed,
                      "kustomization no longer lists state-archive.yaml; "
                      "this test's premise changed, re-read #229")
        missing = [r for r in listed if f"{INSTANCES}/{r.removeprefix('./')}" not in files]
        self.assertEqual(missing, [], f"listed but not rendered with claude_instances: []: {missing}")
        self.assertNotIn(b"kind: CronJob", files[f"{INSTANCES}/state-archive.yaml"],
                         "a CronJob rendered with no instances")
        with tempfile.TemporaryDirectory(prefix="instances-build.") as tmp:
            for rel, body in files.items():
                dst = Path(tmp) / Path(rel).name
                dst.write_bytes(body)
            proc = subprocess.run([need("kustomize"), "build", tmp],
                                  capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"kustomize build failed:\n{proc.stderr.strip()}")

    def test_1_one_instance_renders_its_cronjob(self):
        body = self.files_under("cc", INSTANCES).get(f"{INSTANCES}/state-archive.yaml", b"")
        self.assertIn(b"kind: CronJob", body)
        self.assertIn(b"name: cc-state-backup", body)

    def test_2_every_rendered_kustomization_resolves(self):
        checked = 0
        for label, files in self.renders.items():
            dirs = {str(Path(k).parent) for k in files}
            for rel, body in files.items():
                if Path(rel).name != "kustomization.yaml":
                    continue
                base = Path(rel).parent
                for ref in local_resources(body):
                    target = os.path.normpath(os.path.join(base, ref))
                    checked += 1
                    with self.subTest(render=label, kustomization=rel, resource=ref):
                        self.assertTrue(target in files or target in dirs
                                        or any(d.startswith(target + "/") for d in dirs),
                                        f"{rel} lists {ref}, which the render did not produce")
        self.assertGreater(checked, 0, "no kustomization resources were read; the reader is broken")


if __name__ == "__main__":
    unittest.main()
