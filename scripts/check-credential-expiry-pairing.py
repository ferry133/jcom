#!/usr/bin/env python3
"""Assert the credential <-> expiry pairing (fleet-ops#11, ferry133/jg-base#99).

Renamed from check-omni-key-expiry-pairing.py when factory's GitHub PAT
joined the two Omni keys: the old name would have been a file that lies
about its own subject, which is the defect class this repo spent 2026-09-12
fixing in three other places.

jg-base's daily-check rows 24 and 25 warn before a credential expires: the two
Omni service-account keys, and factory's fine-grained GitHub PAT.
It cannot read the key -- daily-check reads no Secrets, by design -- so it reads
a date recorded at issuance, carried as an annotation on every workload that
holds the key. That makes the date load-bearing in two directions:

  * a key rendered WITHOUT a date is invisible to row 24 -- it expires
    unwatched, which is the exact failure fleet-ops#11 exists to end;
  * a date rendered WITHOUT a key reports on a key this cluster does not hold.

plugin.py refuses both, because the render is the one place that sees the key
and the date together. This file proves it does, and that the refusal names
fields and never echoes the key (these fields sit next to credentials).

It also asserts the template half, derived rather than listed: every template
that mounts the talos-mcp key must carry the annotation row 24 reads, and
cluster-secrets must emit both dates. The annotation name is jg-base's
contract (`OMNI_ANN` in daily-check's run-check.sh); it is typed here because
this repo cannot read that one -- if either side renames it, both break.

What this does NOT cover: whether makejinja's Jinja render of those lines is
correct -- the template assertions are textual. The date normalisation it
does test is the one measured on 2026-09-12: yaml.safe_load_all (makejinja's
loader) reads an unquoted 2027-07-30 as datetime.date.
"""

from __future__ import annotations

import contextlib
import datetime
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANN = "jg-base.jiahd.cc/omni-sa-key-expires"
SENTINEL = "omni-key-SENTINEL-must-never-be-echoed"

FACTORY = {
    "domain": "factory.example.auth0.com",
    "client_id": "factory-client-id",
    "client_secret": "factory-client-secret-not-real",
    "allowed_emails": "ops-a@factory.example",
}
BASE = dict(
    cluster_name="rendertest",
    node_cidr="10.9.1.0/24",
    cluster_svc_cidr="10.96.0.0/12",
    bootstrap_distro="talos",
    deployment_profile="full",
    claude_instances=[],
)


def load_plugin():
    """Import templates/scripts/plugin.py without a real makejinja or age.key."""
    # No bytecode: this guard is run against a MUTATED plugin.py to show it can
    # still tell right from wrong, and a stale .pyc with the same mtime second
    # and size is served silently (jgct#96).
    sys.dont_write_bytecode = True
    importlib.invalidate_caches()
    mj = types.ModuleType("makejinja")
    pl = types.ModuleType("makejinja.plugin")

    class _Base:
        def __init__(self, *a, **k):
            pass

    pl.Plugin, pl.Data, pl.Filters, pl.Functions = _Base, dict, list, list
    mj.plugin = pl
    sys.modules.setdefault("makejinja", mj)
    sys.modules.setdefault("makejinja.plugin", pl)
    spec = importlib.util.spec_from_file_location(
        "_plugin", ROOT / "templates" / "scripts" / "plugin.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.age_key = lambda *a, **k: "jgct-omni-expiry-check-fixed-key"
    return mod


def resolved(plugin, **cluster):
    data = dict(BASE, **cluster)
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "auth0.json").write_text(json.dumps(FACTORY))
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            with contextlib.redirect_stderr(io.StringIO()), \
                 contextlib.redirect_stdout(io.StringIO()):
                plugin.Plugin(data).data()
        finally:
            os.chdir(cwd)
    return data


def expect_ok(plugin, label, check, **cluster) -> int:
    try:
        d = resolved(plugin, **cluster)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL  {label}\n        render raised {type(e).__name__}: {str(e)[:160]}")
        return 1
    problem = check(d)
    if problem:
        print(f"FAIL  {label}\n        {problem}")
        return 1
    print(f"PASS  {label}")
    return 0


def expect_error(plugin, label, kind, needle, **cluster) -> int:
    try:
        resolved(plugin, **cluster)
    except kind as e:
        msg = str(e)
        if SENTINEL in msg:
            print(f"FAIL  {label}\n        the refusal ECHOES THE KEY -- it must name fields only")
            return 1
        if needle not in msg:
            print(f"FAIL  {label}\n        raised {type(e).__name__} without {needle!r}: {msg[:160]}")
            return 1
        print(f"PASS  {label}")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"FAIL  {label}\n        raised {type(e).__name__}, wanted {kind.__name__}: {str(e)[:160]}")
        return 1
    print(f"FAIL  {label}\n        no error raised -- a key without a date renders, and expires unwatched")
    return 1


def check_templates() -> int:
    failed = 0
    tdir = ROOT / "templates"
    # Consumers derived from what they mount, not from a list of names.
    consumers = []
    for f in sorted(tdir.rglob("*.j2")):
        t = f.read_text()
        if re.search(r"name:\s*talos-mcp-secret\s*\n\s+key:\s*saKey\b", t):
            consumers.append(f)
            want = f'{ANN}: "${{TALOS_MCP_SA_KEY_EXPIRES:-}}"'
            if want not in t:
                print(f"FAIL  {f.relative_to(ROOT)} mounts talos-mcp-secret/saKey but lacks\n        {want}")
                failed += 1
            else:
                print(f"PASS  {f.relative_to(ROOT)} carries the expiry annotation")
    if not consumers:
        print("FAIL  CANNOT MEASURE: no template mounts talos-mcp-secret/saKey -- the "
              "instances template does; the match is broken, not the repo clean")
        failed += 1
    cs = (tdir / "config/kubernetes/components/sops/cluster-secrets.sops.yaml.j2").read_text()
    for var, field in (("TALOS_MCP_SA_KEY_EXPIRES", "talos_mcp_sa_key_expires"),
                       ("FACTORY_OMNI_SA_KEY_EXPIRES", "factory_omni_sa_key_expires"),
                       ("FACTORY_GITHUB_TOKEN_EXPIRES", "factory_github_token_expires")):
        line = f'  {var}: "#{{ {field} | default(\'\') }}#"'
        if line not in cs.splitlines():
            print(f"FAIL  cluster-secrets does not emit {var} from {field}")
            failed += 1
        else:
            print(f"PASS  cluster-secrets emits {var}")
    schema = (ROOT / ".taskfiles/template/resources/cluster.schema.cue").read_text()
    for field in ("talos_mcp_sa_key_expires", "factory_omni_sa_key_expires",
                  "factory_github_token_expires"):
        if not re.search(rf"^\s*{field}\?:\s*=~", schema, re.M):
            print(f"FAIL  cluster.schema.cue does not declare {field} with a format")
            failed += 1
    return failed


def main() -> int:
    plugin = load_plugin()
    failed = 0
    key = {"talos_mcp_sa_key": SENTINEL}
    fkey = {"factory_omni_sa_key": SENTINEL}
    tok = {"factory_github_token": SENTINEL}

    failed += expect_ok(plugin, "neither key nor date -> renders, no date",
                        lambda d: None if not d.get("talos_mcp_sa_key_expires")
                        else f"a date appeared from nowhere: {d.get('talos_mcp_sa_key_expires')!r}")
    failed += expect_ok(plugin, "talos key + quoted date -> renders the date",
                        lambda d: None if d.get("talos_mcp_sa_key_expires") == "2027-07-30"
                        else f"got {d.get('talos_mcp_sa_key_expires')!r}",
                        talos_mcp_sa_key_expires="2027-07-30", **key)
    # The shape makejinja actually hands over for an unquoted date.
    failed += expect_ok(plugin, "talos key + UNQUOTED date (datetime.date) -> normalised string",
                        lambda d: None if d.get("talos_mcp_sa_key_expires") == "2027-07-30"
                        and isinstance(d.get("talos_mcp_sa_key_expires"), str)
                        else f"got {d.get('talos_mcp_sa_key_expires')!r}",
                        talos_mcp_sa_key_expires=datetime.date(2027, 7, 30), **key)
    failed += expect_ok(plugin, "factory key + date -> renders the date",
                        lambda d: None if d.get("factory_omni_sa_key_expires") == "2027-09-11"
                        else f"got {d.get('factory_omni_sa_key_expires')!r}",
                        factory_omni_sa_key_expires="2027-09-11", **fkey)

    failed += expect_error(plugin, "talos key WITHOUT date -> refused",
                           KeyError, "talos_mcp_sa_key is set but talos_mcp_sa_key_expires is not", **key)
    failed += expect_error(plugin, "factory key WITHOUT date -> refused",
                           KeyError, "factory_omni_sa_key is set but factory_omni_sa_key_expires is not", **fkey)
    failed += expect_ok(plugin, "github token + date -> renders the date",
                        lambda d: None if d.get("factory_github_token_expires") == "2027-09-11"
                        else f"got {d.get('factory_github_token_expires')!r}",
                        factory_github_token_expires="2027-09-11", **tok)
    # The PAT is the one credential with no key id to revoke by, so a date
    # rendered without it, or it without a date, is worse here than elsewhere.
    failed += expect_error(plugin, "github token WITHOUT date -> refused",
                           KeyError, "factory_github_token is set but factory_github_token_expires is not", **tok)
    failed += expect_error(plugin, "github date WITHOUT token -> refused",
                           KeyError, "factory_github_token_expires is set but factory_github_token is not",
                           factory_github_token_expires="2027-09-11")
    failed += expect_error(plugin, "date WITHOUT key -> refused",
                           KeyError, "talos_mcp_sa_key_expires is set but talos_mcp_sa_key is not",
                           talos_mcp_sa_key_expires="2027-07-30")
    # GNU date reads `2027-07-3` as July 3rd; daily-check refuses the shape, so
    # the render must too, or the report says "unknown" every day.
    failed += expect_error(plugin, "truncated date 2027-07-3 -> refused",
                           ValueError, "must be YYYY-MM-DD",
                           talos_mcp_sa_key_expires="2027-07-3", **key)

    failed += check_templates()

    if failed:
        print(f"{failed} check(s) failed.")
        return 1
    print("ok — key and date pair both ways, refusals name fields only, templates carry the annotation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
