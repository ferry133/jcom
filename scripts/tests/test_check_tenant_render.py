"""check-tenant-render.py can tell a tenant-free render from one that is not.

Each case copies the template inputs into a temporary tree, applies one
mutation, and runs the guard on it with `--tree`. The mutation is asserted to
have landed before the guard runs: an edit that did not apply returns the same
exit 0 as a guard that cannot see it.

Case 0 is the unmutated copy and must pass. If the harness itself is broken,
every mutation would go red and read as "every mutation is caught".

Needs makejinja, cue and age-keygen on PATH (CI installs them with mise). A
missing tool makes the guard exit 2, which fails every case here: a skipped
test reads green.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "scripts" / "check-tenant-render.py"
KS = Path("templates/config/kubernetes/flux/cluster/ks.yaml.j2")
SCHEMA = Path(".taskfiles/template/resources/cluster.schema.cue")
PLUGIN = Path("templates/scripts/plugin.py")
COPY = ["templates", "makejinja.toml", "trello-notifier.sample.yaml",
        ".taskfiles/template/resources", "cluster.sample.yaml"]


class TenantRenderGuard(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="tenant-guard-test.")
        self.tree = Path(self._tmp.name)
        for rel in COPY:
            src, dst = ROOT / rel, self.tree / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, symlinks=True)
            else:
                shutil.copy2(src, dst)

    def tearDown(self):
        self._tmp.cleanup()

    def run_guard(self, *extra, env=None):
        proc = subprocess.run([sys.executable, str(GUARD), "--tree", str(self.tree), *extra],
                              capture_output=True, text=True, env=env)
        return proc.returncode, proc.stdout + proc.stderr

    def edit(self, rel: Path, old: str, new: str):
        path = self.tree / rel
        text = path.read_text()
        self.assertIn(old, text, f"mutation anchor not found in {rel}")
        path.write_text(text.replace(old, new, 1))
        self.assertNotEqual(path.read_text(), text, "mutation did not change the file")

    def append(self, rel: Path, tail: str):
        path = self.tree / rel
        before = path.read_text() if path.exists() else None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text((before or "") + tail)
        self.assertNotEqual(path.read_text(), before, "mutation did not change the file")

    # 0 ---------------------------------------------------------------------
    def test_0_unmutated_copy_passes(self):
        rc, out = self.run_guard()
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS", out)

    # 1 ---------------------------------------------------------------------
    def test_1_render_that_reacts_to_empty_app_repos_fails(self):
        # Since task 3.2 plugin.py sets `app_repos` to `[]` when it is absent,
        # so a template alone can no longer tell the two apart and the
        # template half below would be a mutation that cannot fail. The
        # defect it stands for is now "plugin.py stops normalising AND a
        # template reacts to the key", so the case mutates both.
        self.edit(PLUGIN, "        data['app_repos'] = app_repos(data)\n",
                  "        if 'app_repos' in data:\n"
                  "            data['app_repos'] = app_repos(data)\n")
        self.append(KS, "\n#% if app_repos is defined %#\n---\n# reacts to app_repos: []\n#% endif %#\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("absent vs `[]` differ", out)
        self.assertIn("differs: kubernetes/flux/cluster/ks.yaml", out)

    # 2 ---------------------------------------------------------------------
    def test_2_unconditional_tenants_file_fails(self):
        self.append(Path("templates/config/kubernetes/tenants/marker.yaml"),
                    "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: marker\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("kubernetes/tenants/marker.yaml: a tenants/ path", out)

    # 3 ---------------------------------------------------------------------
    def test_3_unconditional_cluster_tenants_kustomization_fails(self):
        self.append(KS, "\n---\napiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\n"
                        "metadata:\n  name: cluster-tenants\n  namespace: flux-system\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("contains `name: cluster-tenants`", out)

    # 4 ---------------------------------------------------------------------
    def test_4_against_catches_a_deleted_line(self):
        # Whole-line deletion, the shape refactors and merge conflicts produce.
        self.edit(KS, "  deletionPolicy: WaitForTermination\n  interval: 1h\n  path: ./kubernetes/apps/extras/",
                  "  interval: 1h\n  path: ./kubernetes/apps/extras/")
        rc, out = self.run_guard("--against", "HEAD")
        self.assertEqual(rc, 1, out)
        self.assertIn("render differs from HEAD", out)
        # Fixtures without extras render no extras block, so only some fixtures differ.
        self.assertIn("ok  [appliance-minimal]", out)

    # 5 ---------------------------------------------------------------------
    def test_5_invalid_fixture_is_reported_as_a_guard_defect(self):
        self.edit(SCHEMA, 'storage_backend: "local-path" | "nfs" | "replicated"',
                  'storage_backend: "replicated"')
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("fixture fails cue vet (guard defect)", out)

    # 6 ---------------------------------------------------------------------
    def test_6_missing_makejinja_is_could_not_measure(self):
        self.assertIsNotNone(shutil.which("makejinja"), "makejinja must be on PATH for this suite")
        # Drop every PATH entry that holds a makejinja -- mise can put more than
        # one on PATH (the python install and the pipx one).
        keep = [p for p in os.environ["PATH"].split(os.pathsep)
                if p and not (Path(p) / "makejinja").exists()]
        env = dict(os.environ, PATH=os.pathsep.join(keep))
        self.assertIsNone(shutil.which("makejinja", path=env["PATH"]),
                          "could not hide makejinja from PATH")
        rc, out = self.run_guard(env=env)
        self.assertEqual(rc, 2, out)
        self.assertIn("COULD NOT MEASURE", out)

    # 7-12: part 3, the shape of a render that HAS tenants (task 3.3). Each
    # mutation is one way the tenant loop could stop isolating the tenant
    # while still rendering something that looks like a tenant.

    # 7 ---------------------------------------------------------------------
    def test_7_tenant_kustomization_with_substitution_fails(self):
        # cluster-secrets is every credential the cluster has.
        self.edit(KS, "  path: ./\n  prune: true\n",
                  "  path: ./\n  prune: true\n  postBuild:\n    substituteFrom:\n"
                  "      - name: cluster-secrets\n        kind: Secret\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("Kustomization/tenant-acme has spec.postBuild", out)

    # 8 ---------------------------------------------------------------------
    def test_8_tenant_kustomization_without_its_service_account_fails(self):
        # Without it, kustomize-controller applies as itself: cluster-admin.
        self.edit(KS, "  serviceAccountName: tenant-#{ repo.name }#\n", "")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("Kustomization/tenant-acme .spec.serviceAccountName = None", out)

    # 9 ---------------------------------------------------------------------
    def test_9_tenant_decrypting_with_the_cluster_key_fails(self):
        self.edit(KS, "    secretRef:\n      name: tenant-#{ repo.name }#-sops-age\n", "")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("Kustomization/tenant-acme .spec.decryption", out)

    # 10 --------------------------------------------------------------------
    def test_10_a_tenant_loop_that_renders_nothing_fails(self):
        # The shape part 3 exists for: parts 1 and 2 pass on it.
        self.edit(KS, "#% for repo in app_repos %#", "#% for repo in [] %#")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("ServiceAccount/tenant-acme: 0 rendered, expected 1", out)
        self.assertIn("ok  [full-omni-extras]", out)

    # 11 --------------------------------------------------------------------
    def test_11_tenants_changing_a_non_tenant_object_fails(self):
        self.edit(KS, "  path: ./kubernetes/apps/base/claudecode/claude-code/instances\n",
                  "  path: ./kubernetes/apps/base/claudecode/claude-code/instances"
                  "#{ '-t' if app_repos else '' }#\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("the non-tenant documents differ from the tenant-free render", out)

    # 12 --------------------------------------------------------------------
    def test_12_cluster_role_binding_for_a_tenant_fails(self):
        self.edit(KS, "    - name: cluster-tenants\n#% endfor %#\n",
                  "    - name: cluster-tenants\n---\napiVersion: rbac.authorization.k8s.io/v1\n"
                  "kind: ClusterRoleBinding\nmetadata:\n  name: tenant-#{ repo.name }#-oops\n"
                  "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n"
                  "  name: view\nsubjects:\n  - kind: ServiceAccount\n"
                  "    name: tenant-#{ repo.name }#\n    namespace: flux-system\n#% endfor %#\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("ClusterRoleBinding/tenant-acme-oops names tenant-acme", out)

    # 12b -------------------------------------------------------------------
    def test_12b_tenant_kustomization_on_another_path_fails(self):
        # fleet-ops-96 [cde990]'s finding on #220: this mutation stayed green.
        self.edit(KS, "  path: ./\n  prune: true\n", "  path: ./kubernetes\n  prune: true\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("Kustomization/tenant-acme .spec.path = './kubernetes'", out)

    # 13-19: task 3.4, the objects cluster-tenants applies.
    T = Path("templates/config/kubernetes/tenants")

    # 13 --------------------------------------------------------------------
    def test_13_binding_to_admin_fails(self):
        # The spec's own negative control: a tenant bound to `admin`.
        self.edit(self.T / "rbac.yaml.j2", "  name: tenant-admin\n", "  name: admin\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("'name': 'admin'", out)

    # 14 --------------------------------------------------------------------
    def test_14_a_declared_psa_level_fails(self):
        self.edit(self.T / "namespaces.yaml.j2",
                  "pod-security.kubernetes.io/enforce: #{ repo.psa_level }#",
                  "pod-security.kubernetes.io/enforce: privileged")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("Namespace/acme labels", out)

    # 15 --------------------------------------------------------------------
    def test_15_quota_without_the_nodeport_cap_fails(self):
        self.edit(self.T / "quota.yaml.j2", '    services.nodeports: "0"\n', "")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("ResourceQuota acme", out)

    # 16 --------------------------------------------------------------------
    def test_16_policy_restricting_egress_fails(self):
        self.edit(self.T / "networkpolicy.yaml.j2", "  endpointSelector: {}\n",
                  "  endpointSelector: {}\n  egress:\n    - toEntities:\n        - cluster\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("restricts egress", out)

    # 17 --------------------------------------------------------------------
    def test_17_im_writing_with_the_read_only_key_fails(self):
        self.edit(self.T / "im-apps-write-key.sops.yaml.j2",
                  "tenant_key(repo.name, 'write')", "tenant_key(repo.name, 'deploy')")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("im-apps-write-key identity is not the agent's write key", out)

    # 18 --------------------------------------------------------------------
    def test_18_an_extra_object_fails(self):
        # How a ClusterRole or a second binding would arrive.
        self.append(self.T / "rbac.yaml.j2",
                    "#% if app_repos %#\n---\napiVersion: rbac.authorization.k8s.io/v1\n"
                    "kind: ClusterRole\nmetadata:\n  name: tenant-extra\nrules: []\n#% endif %#\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("unexpected object ('ClusterRole', '', 'tenant-extra')", out)

    # 19 --------------------------------------------------------------------
    def test_19_unconditional_im_apps_repo_fails(self):
        # Part 1, not part 3: a cluster with no tenants must not gain the key.
        self.append(Path("templates/config/kubernetes/components/sops/cluster-secrets.sops.yaml.j2"),
                    '  IM_APPS_REPO: ""\n')
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("contains `IM_APPS_REPO`", out)

    # 20 --------------------------------------------------------------------
    def test_20_pool_selecting_on_the_label_alone_fails(self):
        # fleet-ops-96 [cde990] on #221: a Service label is tenant-writable.
        path = self.tree / self.T / "lb-pools.yaml.j2"
        text = path.read_text()
        start = text.index("    matchExpressions:\n")
        end = text.index("#% endfor %#\n", start) + len("#% endfor %#\n")
        path.write_text(text[:start] + text[end:])
        self.assertNotIn("io.kubernetes.service.namespace\n", path.read_text())
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("pool tenant-im-apps selector", out)

    # 21-24: root task 3.7 follow-ups.

    # 21 --------------------------------------------------------------------
    def test_21_tenant_known_hosts_drifting_from_bootstrap_fails(self):
        path = self.tree / self.T / "tenant-git-auth.sops.yaml.j2"
        lines = path.read_text().splitlines(keepends=True)
        kept = [l for l in lines if not l.lstrip().startswith("github.com ssh-rsa ")]
        self.assertEqual(len(kept), len(lines) - 1, "mutation did not remove one line")
        path.write_text("".join(kept))
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("known_hosts differs from", out)

    # 22 --------------------------------------------------------------------
    def test_22_agent_objects_on_a_vendor_only_cluster_fail(self):
        self.edit(self.T / "kustomization.yaml.j2",
                  "#% if app_repos | selectattr('kind', 'equalto', 'agent') | list %#\n"
                  "  - im-apps-write-key.sops.yaml\n#% endif %#\n",
                  "  - im-apps-write-key.sops.yaml\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("[vendor-only]", out)
        self.assertIn("resources do not list exactly the rendered files", out)

    # 23 --------------------------------------------------------------------
    def test_23_host_network_without_its_label_fails(self):
        self.edit(self.T / "namespaces.yaml.j2", "    jg.tenant-privileged: granted\n", "")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("Namespace/edge labels", out)

    # 24 --------------------------------------------------------------------
    def test_24_a_sample_example_the_schema_refuses_fails(self):
        self.edit(Path("cluster.sample.yaml"), "#   - name: im-apps\n", "#   - name: shop\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("[sample-example] the example operators copy fails cue vet", out)


    # 25 --------------------------------------------------------------------
    def test_25_public_without_its_label_fails(self):
        self.edit(self.T / "namespaces.yaml.j2", "    jg.tenant-public: granted\n", "")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("Namespace/im-apps-db labels", out)

    # 26 --------------------------------------------------------------------
    def test_26_public_label_without_the_grant_fails(self):
        self.edit(self.T / "namespaces.yaml.j2", "#% if repo.grants.public %#\n", "#% if true %#\n")
        rc, out = self.run_guard()
        self.assertEqual(rc, 1, out)
        self.assertIn("Namespace/acme labels", out)


if __name__ == "__main__":
    unittest.main()
