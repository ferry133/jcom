#!/usr/bin/env python3
"""Handover cell 15, `tenants` — jgct#214 task 3.8.

Run: python3 .github/workflows/run-tests.py

The cell reads three things: which tenants cluster.yaml declares (real yq on a
temp file), what Flux has live (kubectl), and which deploy keys GitHub holds
(gh). The two remote ones are replaced by stand-ins that ANSWER FROM THEIR
ARGUMENTS — a stand-in that ignores what it is asked returns the same thing
for the wrong question, and the cell would pass on a lookup it never made.

Every outcome is asserted, SKIP included, because the shape this file guards
against is a cell that can only ever return one value.
"""
import sys

sys.dont_write_bytecode = True

import contextlib
import importlib.util
import io
import json
import pathlib
import shutil
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)

PUB = {
    ("acme", "deploy"): "ssh-ed25519 AAAAacmeRO",
    ("im-apps", "deploy"): "ssh-ed25519 AAAAimRO",
    ("im-apps", "write"): "ssh-ed25519 AAAAimRW",
}
CLUSTER_YAML = """\
cluster_name: bench
cloudflare_token: "SECRETVALUE-must-not-print"
app_repos:
  - name: acme
    repository: org/acme
    kind: vendor
  - name: im-apps
    repository: org/im-apps
    kind: agent
    namespaces: [im-apps, im-apps-db]
"""


def ks(name, ready=True):
    return {"metadata": {"name": name},
            "status": {"conditions": [{"type": "Ready", "status": "True" if ready else "False"}]}}


@unittest.skipUnless(shutil.which("yq"), "yq is installed by mise in CI")
class TenantsCell(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="dc-tenants.")
        self.dir = pathlib.Path(self._tmp.name)
        (self.dir / "tenants").mkdir()
        for (n, kind), pub in PUB.items():
            (self.dir / "tenants" / f"{n}.{kind}.key.pub").write_text(pub + " comment\n")
        self.live = {"cluster-secrets": ks("cluster-secrets"),
                     "cluster-tenants": ks("cluster-tenants"),
                     "tenant-acme": ks("tenant-acme"),
                     "tenant-im-apps": ks("tenant-im-apps")}
        self.policies = {"acme", "im-apps", "im-apps-db"}
        self.keys = {"org/acme": [{"key": PUB[("acme", "deploy")], "read_only": True}],
                     "org/im-apps": [{"key": PUB[("im-apps", "deploy")], "read_only": True},
                                     {"key": PUB[("im-apps", "write")], "read_only": False}]}
        self.gh_error = None
        self.asked = []

    def tearDown(self):
        self._tmp.cleanup()

    def kubectl(self, args, *rest):
        self.asked.append(rest)
        if rest[:3] == ("-n", "flux-system", "get") and rest[3].startswith("kustomizations."):
            return True, json.dumps({"items": list(self.live.values())}), ""
        if rest[2:4] == ("get", "ciliumnetworkpolicies.cilium.io") and rest[4] == "tenant-ingress":
            ns = rest[1]
            if ns in self.policies:
                return True, f"ciliumnetworkpolicy.cilium.io/tenant-ingress\n", ""
            return False, "", f'ciliumnetworkpolicies "tenant-ingress" not found in {ns}'
        raise AssertionError(f"cell asked kubectl something unexpected: {rest}")

    def run_bounded(self, cmd, timeout, label):
        assert cmd[:2] == ["gh", "api"], cmd
        repo = cmd[2].removeprefix("repos/").removesuffix("/keys")
        if self.gh_error:
            return types.SimpleNamespace(returncode=1, stdout="", stderr=self.gh_error), None
        body = [{"key": k["key"] + " title", "read_only": k["read_only"]}
                for k in self.keys.get(repo, [])]
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(body), stderr=""), None

    def cell(self, cluster_yaml=CLUSTER_YAML):
        if cluster_yaml is not None:
            (self.dir / "cluster.yaml").write_text(cluster_yaml)
        args = types.SimpleNamespace(dir=str(self.dir), kubeconfig="kc")
        with mock.patch.object(dc, "_kubectl", self.kubectl), \
             mock.patch.object(dc, "_run_bounded", self.run_bounded):
            return dc.cell_tenants(args)

    # -- outcomes ------------------------------------------------------------

    def test_all_wired_passes(self):
        rc, note, why = self.cell()
        self.assertEqual((rc, why), (dc.PASS, None), note)
        self.assertIn("2 tenant(s) declared, 2 live", note)
        # It really asked for each declared namespace's policy.
        asked_ns = {r[1] for r in self.asked if "ciliumnetworkpolicies.cilium.io" in r}
        self.assertEqual(asked_ns, {"acme", "im-apps", "im-apps-db"})

    def test_no_tenants_anywhere_is_skip_not_pass(self):
        self.live = {"cluster-secrets": ks("cluster-secrets")}
        rc, note, why = self.cell("cluster_name: bench\n")
        self.assertEqual(rc, dc.SKIP, note)
        self.assertNotEqual(dc.SKIP, dc.PASS)

    def test_no_cluster_yaml_is_a_vantage_problem(self):
        rc, note, why = self.cell(cluster_yaml=None)
        self.assertEqual((rc, why), (dc.UNKNOWN, dc.NEED_PLACE), note)

    def test_a_listing_without_cluster_secrets_cannot_be_read_as_empty(self):
        # Positive control: the wrong cluster also answers "no tenants".
        self.live = {}
        rc, note, why = self.cell("cluster_name: bench\n")
        self.assertEqual((rc, why), (dc.UNKNOWN, dc.NEED_PLACE), note)
        self.assertIn("cluster-secrets", note)

    def test_tenant_not_ready_fails(self):
        self.live["tenant-acme"] = ks("tenant-acme", ready=False)
        rc, note, _ = self.cell()
        self.assertEqual(rc, dc.FAIL, note)
        self.assertIn("tenant-acme: not Ready", note)

    def test_cluster_tenants_missing_fails(self):
        del self.live["cluster-tenants"]
        rc, note, _ = self.cell()
        self.assertEqual(rc, dc.FAIL, note)
        self.assertIn("cluster-tenants does not exist", note)

    def test_undeclared_live_tenant_fails_even_with_none_declared(self):
        self.live = {"cluster-secrets": ks("cluster-secrets"), "tenant-ghost": ks("tenant-ghost")}
        rc, note, _ = self.cell("cluster_name: bench\n")
        self.assertEqual(rc, dc.FAIL, note)
        self.assertIn("tenant-ghost is live but not declared", note)

    def test_flux_key_registered_writable_fails(self):
        self.keys["org/acme"][0]["read_only"] = False
        rc, note, _ = self.cell()
        self.assertEqual(rc, dc.FAIL, note)
        self.assertIn("org/acme: deploy key registered with read_only=False", note)

    def test_agent_write_key_not_registered_fails(self):
        self.keys["org/im-apps"] = self.keys["org/im-apps"][:1]
        rc, note, _ = self.cell()
        self.assertEqual(rc, dc.FAIL, note)
        self.assertIn("org/im-apps: write key not registered", note)

    def test_missing_policy_in_one_namespace_fails(self):
        self.policies.discard("im-apps-db")
        rc, note, _ = self.cell()
        self.assertEqual(rc, dc.FAIL, note)
        self.assertIn("im-apps-db: no CiliumNetworkPolicy tenant-ingress", note)

    def test_github_unreadable_is_unknown_not_missing(self):
        self.gh_error = "HTTP 404"
        rc, note, why = self.cell()
        self.assertEqual((rc, why), (dc.UNKNOWN, dc.NEED_TOOL), note)
        self.assertNotIn("not registered", note)

    def test_cluster_yaml_values_are_never_printed(self):
        self.assertIn("SECRETVALUE", CLUSTER_YAML)   # the fixture has one
        for mutate in (lambda: None, lambda: self.policies.clear()):
            mutate()
            _, note, _ = self.cell()
            self.assertNotIn("SECRETVALUE", note)

    # -- the table ---------------------------------------------------------------

    def test_cell_is_in_the_handover_table(self):
        self.assertIn((15, dc.cell_tenants), [(n, fn) for n, _, fn in dc.HANDOVER_CELLS])

    def test_handover_prints_skip_and_does_not_count_it_as_a_pass(self):
        cells = [(1, "one", lambda a: (dc.PASS, "fine", None)),
                 (15, "tenants", lambda a: (dc.SKIP, "no app_repos declared", None))]
        buf = io.StringIO()
        with mock.patch.object(dc, "HANDOVER_CELLS", cells), contextlib.redirect_stdout(buf):
            rc = dc.check_handover(types.SimpleNamespace())
        out = buf.getvalue()
        self.assertEqual(rc, dc.PASS, out)
        self.assertIn("skip  15. tenants", out)
        self.assertIn("1/1 applicable cells pass.", out)
        self.assertIn("not applicable to this cluster (not a pass): 15", out)


if __name__ == "__main__":
    unittest.main()
