#!/usr/bin/env python3
"""Tests for delivery-check.py's three credential subcommands — #104 (4).

Run: python3 .github/workflows/run-tests.py

`escrow`, `deploy-key` and `tunnel-cert` had no tests at all. What they had was
"someone ran them once on their own machine", and #104 is the issue about that
being indistinguishable from coverage. These three go first because **their
wrong direction is the expensive one**: each has a state where a real credential
problem reads as a pass.

- `escrow`: a *valid* age key that belongs to a different cluster passes both
  "the file is there" and "it parses as a key". Only comparing the derived
  public half rejects it. A wrong key in an escrow slot is worse than an empty
  one, because it will be trusted.
- `deploy-key`: "the list is not empty" accepts a repo carrying somebody else's
  key. The check compares key material; these tests hold it to that.
- `tunnel-cert`: the cert body contains `apiToken`. A check that leaks the
  secret it validates is a worse trade than the check is worth, so the leak is
  asserted against, not left to review.

Every fake tool here is hermetic: no test touches the network, a real cluster,
or the operator's own `~/.cloudflared`. Where a test asserts a refusal, a
positive control asserts the same harness reaching a verdict — otherwise "the
fake tool was simply broken" and "the check caught something" are one result.
"""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dc", ROOT / "scripts" / "delivery-check.py")
dc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dc)

# Not real keys. Shaped to match `age1[a-z0-9]{20,}`, which is what the check
# greps .sops.yaml for.
KEY_OURS = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsuuuuuu"
KEY_THEIRS = "age1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzsvvvvvv"


@contextlib.contextmanager
def fake_bin(**tools: str):
    """A temp dir first on PATH holding `name` -> shell body, and its path.

    Nothing in these tests may fall through to the real `gh`, `age-keygen` or
    `cloudflared`: a test that happens to pass because the operator's own tools
    answered is measuring the operator, not the check.
    """
    with tempfile.TemporaryDirectory() as d:
        for name, body in tools.items():
            p = pathlib.Path(d) / name
            p.write_text(f"#!/bin/sh\n{body}\n")
            p.chmod(0o755)
        old = os.environ["PATH"]
        os.environ["PATH"] = d + os.pathsep + old
        try:
            yield pathlib.Path(d)
        finally:
            os.environ["PATH"] = old


def capture(fn, *a, **kw) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*a, **kw)
    return rc, buf.getvalue()


# ----------------------------------------------------------------- escrow (0)

class TestEscrow(unittest.TestCase):
    def _args(self, d: pathlib.Path, sops_body: str, key_body: str = "not read"):
        (d / "escrow.key").write_text(key_body)
        (d / ".sops.yaml").write_text(sops_body)
        return types.SimpleNamespace(escrowed_key=str(d / "escrow.key"),
                                     sops_yaml=str(d / ".sops.yaml"))

    def test_a_valid_key_from_another_cluster_is_a_finding(self):
        """The case that makes this subcommand worth having.

        The file is present, age-keygen parses it, and it is a perfectly good
        key — for someone else. Everything except the comparison says pass.
        """
        with fake_bin(**{"age-keygen": f"printf '%s' '{KEY_THEIRS}'"}) as d:
            args = self._args(d, f"creation_rules:\n  - age: {KEY_OURS}\n")
            rc, out = capture(dc.check_escrow, args)
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("NOT this cluster's", out)

    def test_positive_control_the_matching_key_passes(self):
        """Same harness, same fake tool: only the key differs.

        Without this, the FAIL above could equally mean "the fake age-keygen
        output is not something this check can ever accept".
        """
        with fake_bin(**{"age-keygen": f"printf '%s' '{KEY_OURS}'"}) as d:
            args = self._args(d, f"creation_rules:\n  - age: {KEY_OURS}\n")
            rc, out = capture(dc.check_escrow, args)
        self.assertEqual(rc, dc.PASS, out)

    def test_a_truncated_copy_is_a_finding_not_an_unknown(self):
        """age-keygen refusing the file is evidence about the file."""
        with fake_bin(**{"age-keygen": "echo 'malformed' >&2; exit 1"}) as d:
            args = self._args(d, f"creation_rules:\n  - age: {KEY_OURS}\n")
            rc, out = capture(dc.check_escrow, args)
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("truncated or partial copy", out)

    def test_no_recipient_in_sops_is_cannot_measure(self):
        """Nothing to compare against is not the same as a mismatch."""
        with fake_bin(**{"age-keygen": f"printf '%s' '{KEY_OURS}'"}) as d:
            args = self._args(d, "creation_rules:\n  - pgp: SOMEFINGERPRINT\n")
            rc, out = capture(dc.check_escrow, args)
        self.assertEqual(rc, dc.UNKNOWN, out)

    def test_a_missing_sops_file_is_cannot_measure(self):
        with fake_bin(**{"age-keygen": f"printf '%s' '{KEY_OURS}'"}) as d:
            args = self._args(d, "unused")
            os.remove(args.sops_yaml)
            rc, out = capture(dc.check_escrow, args)
        self.assertEqual(rc, dc.UNKNOWN, out)


# ------------------------------------------------------------- deploy-key (6)

SSH_TYPE = "ssh-ed25519"
SSH_BODY_OURS = "AAAAC3NzaC1lZDI1NTE5AAAAIOURSOURSOURSOURSOURSOURSOURSOURSOURS"
SSH_BODY_THEIRS = "AAAAC3NzaC1lZDI1NTE5AAAAITHEIRSTHEIRSTHEIRSTHEIRSTHEIRSTHEIR"


class TestDeployKey(unittest.TestCase):
    def _args(self, d: pathlib.Path, comment: str = "operator@workstation"):
        pub = d / "github-deploy.key.pub"
        pub.write_text(f"{SSH_TYPE} {SSH_BODY_OURS} {comment}\n")
        return types.SimpleNamespace(pubkey=str(pub), repo="ferry133/jg-example")

    def test_a_repo_carrying_someone_elses_key_is_a_finding(self):
        """"The list is not empty" would accept this, which is the whole point."""
        with fake_bin(gh=f"printf '%s\\n' '{SSH_TYPE} {SSH_BODY_THEIRS}'") as d:
            rc, out = capture(dc.check_deploy_key, self._args(d))
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("none of them this one", out)

    def test_positive_control_the_matching_key_passes(self):
        with fake_bin(gh=f"printf '%s\\n' '{SSH_TYPE} {SSH_BODY_OURS}'") as d:
            rc, out = capture(dc.check_deploy_key, self._args(d))
        self.assertEqual(rc, dc.PASS, out)

    def test_the_comment_field_does_not_take_part(self):
        """ssh-keygen writes a third field; GitHub does not return it.

        If the comment were compared, every real deployment would be a false
        FAIL — and this is the kind of thing that gets "fixed" by loosening the
        comparison to a substring, which then accepts a prefix of someone
        else's key.
        """
        with fake_bin(gh=f"printf '%s\\n' '{SSH_TYPE} {SSH_BODY_OURS}'") as d:
            args = self._args(d, comment="a-totally-different-comment")
            rc, out = capture(dc.check_deploy_key, args)
        self.assertEqual(rc, dc.PASS, out)

    def test_no_keys_at_all_says_so_specifically(self):
        with fake_bin(gh="exit 0") as d:
            rc, out = capture(dc.check_deploy_key, self._args(d))
        self.assertEqual(rc, dc.FAIL, out)
        self.assertIn("no deploy keys at all", out)

    def test_github_refusing_the_query_is_cannot_measure(self):
        """No answer and an empty answer are different, and only one of them is
        a finding. This is #56's shape: the absence was real, but a check that
        cannot ask must not claim the absence."""
        with fake_bin(gh="echo 'HTTP 403' >&2; exit 1") as d:
            rc, out = capture(dc.check_deploy_key, self._args(d))
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("could not list deploy keys", out)


# ------------------------------------------------------------ tunnel-cert (7)

def cert_text(account: str = "acc-1", zone: str = "zone-1",
              token: str = "SECRET-API-TOKEN-DO-NOT-PRINT") -> str:
    payload = base64.b64encode(
        json.dumps({"accountID": account, "zoneID": zone, "apiToken": token}).encode()
    ).decode()
    return ("-----BEGIN ARGO TUNNEL TOKEN-----\n" + payload +
            "\n-----END ARGO TUNNEL TOKEN-----\n")


class TestCertBinding(unittest.TestCase):
    def test_the_api_token_never_leaves_the_parser(self):
        """The cert's third key is a credential. This asserts the boundary
        rather than trusting a reviewer to notice it moved."""
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "cert.pem"
            p.write_text(cert_text(token="SECRET-API-TOKEN-DO-NOT-PRINT"))
            binding, err = dc._cert_binding(p)
        self.assertIsNone(err)
        self.assertEqual(binding, {"accountID": "acc-1", "zoneID": "zone-1"})
        self.assertNotIn("apiToken", binding)
        self.assertNotIn("SECRET-API-TOKEN-DO-NOT-PRINT", repr(binding))

    def test_a_file_without_the_token_block_is_not_a_cloudflared_cert(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "cert.pem"
            p.write_text("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")
            binding, err = dc._cert_binding(p)
        self.assertEqual(binding, {})
        self.assertIn("is this a cloudflared cert", err)

    def test_a_malformed_block_is_cannot_tell_not_a_finding(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "cert.pem"
            p.write_text("-----BEGIN ARGO TUNNEL TOKEN-----\n!!!!\n"
                         "-----END ARGO TUNNEL TOKEN-----\n")
            binding, err = dc._cert_binding(p)
        self.assertEqual(binding, {})
        self.assertIn("did not decode", err)


class TestTunnelCert(unittest.TestCase):
    """No test here may reach Cloudflare.

    `CLOUDFLARE_TOKEN` is cleared for each case, which is also the state the
    check reports as "could not measure" — so these cover the vantage branch and
    the parse branches, not the comparison. The comparison needs a real zone
    lookup and is still unexercised; that gap is named in the PR rather than
    papered over with a fake that would only test the fake.
    """

    def setUp(self):
        self._saved = os.environ.pop("CLOUDFLARE_TOKEN", None)

    def tearDown(self):
        if self._saved is not None:
            os.environ["CLOUDFLARE_TOKEN"] = self._saved

    def _args(self, cert: pathlib.Path):
        return types.SimpleNamespace(cert=str(cert), token_env=None,
                                     domain="example.com")

    def test_without_a_token_it_reports_cannot_measure_and_prints_no_secret(self):
        secret = "SECRET-API-TOKEN-DO-NOT-PRINT"
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "cert.pem"
            p.write_text(cert_text(token=secret))
            rc, out = capture(dc.check_tunnel_cert, self._args(p))
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertNotIn(secret, out)
        # Positive control for that assertNotIn: the ids ARE printed, so the
        # output is not simply empty.
        self.assertIn("acc-1", out)

    def test_a_missing_cert_is_cannot_measure(self):
        """Absent and wrong are different answers; this is also the state right
        before `cloudflared tunnel login` has ever run."""
        with tempfile.TemporaryDirectory() as d:
            rc, out = capture(dc.check_tunnel_cert,
                              self._args(pathlib.Path(d) / "nope.pem"))
        self.assertEqual(rc, dc.UNKNOWN, out)

    def test_a_cert_missing_the_ids_is_cannot_measure(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "cert.pem"
            payload = base64.b64encode(json.dumps({"apiToken": "x"}).encode()).decode()
            p.write_text("-----BEGIN ARGO TUNNEL TOKEN-----\n" + payload +
                         "\n-----END ARGO TUNNEL TOKEN-----\n")
            rc, out = capture(dc.check_tunnel_cert, self._args(p))
        self.assertEqual(rc, dc.UNKNOWN, out)
        self.assertIn("expected accountID and zoneID", out)


if __name__ == "__main__":
    unittest.main()
