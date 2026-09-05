#!/usr/bin/env python3
"""`repository_visibility: private` needs both halves, and they live in two repos.

`#56`, measured on jg-janncotcc 2026-08-30: the template rendered a
`github-deploy-key` Secret whenever the repo was private, **and nothing
referenced it**. The FluxInstance kept an anonymous HTTPS URL, so Flux reported

    GitRepository flux-system  READY=False
    failed to checkout and determine revision: unable to list remote

A credential nobody uses is worse than no credential: it makes the option read
as supported. The fix has two halves and only one of them can live here.

  bootstrap   `values.yaml.gotmpl.j2` writes the URL literally, because there is
              no cluster-secrets to substitute from yet. This repo owns it.

  steady      jg-base's `flux-system/flux-instance` HelmRelease declares the
              whole `sync:` block. Helm renders the FluxInstance from it minutes
              after bootstrap, so a `pullSecret` set only at bootstrap is
              dropped. Adding it needs `pullSecret: "${FLUX_SYNC_PULL_SECRET}"`
              there — a jg-base change, and one nobody has yet measured on a
              PUBLIC cluster, where that value is the empty string.

So this refuses to let a private cluster render while the second half is
missing, rather than producing a bootstrap that works and then breaks. It
measures instead of asserting: the sibling jg-base checkout that bootstrap
already relies on is read directly, so this stops failing by itself the day the
other half lands.

Three outcomes. No sibling checkout is "could not tell" — exit 2 — not a pass:
being unable to see the other repo is the same shape as the defect above.

Exit 0 ok, 1 the chain is incomplete, 2 could not measure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELMRELEASE = "kubernetes/apps/base/flux-system/flux-instance/app/helmrelease.yaml"

# An actual key, not the name appearing anywhere in the file.
#
# This check was `"FLUX_SYNC_PULL_SECRET" in text` until 2026-09-03, which the
# opener of ferry133/jg-base#53 caught while accepting the fix, and which the
# jg-base agent reproduced independently: take the pre-fix helmrelease, append
#
#     # TODO: add FLUX_SYNC_PULL_SECRET here one day
#
# and this printed `ok` and exited 0. **A comment naming the variable made the
# guard report that the chain was built.** jg-base's manifests are heavily
# commented by house style and those comments name the fields they discuss, so
# this was not a hypothetical input — it is the most likely wrong input.
#
# `pullSecret[ \t]*:` and not `pullSecret:` — YAML permits a space before the
# colon, and the first version of this fix rejected `pullSecret : "${VAR}"`,
# which is a valid config. Measured against the parallel fix that reached main
# first (jgct#67): six inputs, and each version was wrong on one the other got
# right. **Neither comparison list would have found its own author's gap** —
# that one came from running both against the same six.
#
# Anchored to line start so it cannot match inside a comment, and the quotes are
# optional because both `pullSecret: "${VAR:=}"` and the unquoted spelling
# substitute the same way. `\b` after the name so a longer variable that merely
# starts with it does not count.
PULL_SECRET_KEY = re.compile(
    r'^[ \t]*pullSecret[ \t]*:[ \t]*["\']?\$\{FLUX_SYNC_PULL_SECRET\b',
    re.MULTILINE,
)


def read_cluster_yaml() -> dict[str, str]:
    """Anchored line reads. A commented `# repository_visibility:` is not a setting."""
    config = ROOT / "cluster.yaml"
    if not config.is_file():
        return {}
    out = {}
    for line in config.read_text().splitlines():
        m = re.match(r'^([a-z_][a-z0-9_]*)\s*:\s*"?([^"#]*?)"?\s*(?:#.*)?$', line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def base_repo_dir(cfg: dict[str, str]) -> str:
    url = cfg.get("base_repo_url") or "https://github.com/ferry133/jg-base"
    return url.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]


def main() -> int:
    cfg = read_cluster_yaml()
    if not cfg:
        print("skip  no cluster.yaml here — this is the template repo")
        return 0

    visibility = cfg.get("repository_visibility", "public")
    if visibility != "private":
        print(f"ok    repository_visibility is {visibility!r} — anonymous HTTPS, "
              "no pull secret, nothing to line up")
        return 0

    sibling = ROOT.parent / base_repo_dir(cfg) / HELMRELEASE
    if not sibling.is_file():
        print(f"?     cannot tell: {sibling} is not here")
        print("      The steady-state half of private-repo support lives in that")
        print("      file. Clone jg-base beside this repo — bootstrap already")
        print("      requires it as a sibling — and run this again.")
        print("      Not reporting ok: not being able to see the other repo is")
        print("      the same shape as the defect this check exists for.")
        return 2

    text = sibling.read_text()
    if PULL_SECRET_KEY.search(text):
        print("ok    private, and jg-base's flux-instance carries "
              "a pullSecret: key reading ${FLUX_SYNC_PULL_SECRET}")
        return 0

    if "FLUX_SYNC_PULL_SECRET" in text:
        # The name is in the file but not as a key that Helm will read. Its own
        # outcome, because "someone wrote a TODO about it" and "the chain is
        # built" were the same result until 2026-09-03 — and the TODO reads as
        # the more reassuring of the two.
        print("FAIL  FLUX_SYNC_PULL_SECRET is mentioned in")
        print(f"      {sibling}")
        print("      but not as a `pullSecret:` key, so Helm never reads it and")
        print("      the FluxInstance is still rendered without a credential.")
        print("      A comment naming the variable is not the variable.")
        return 1

    print("FAIL  repository_visibility is 'private' and the chain is half-built")
    print(f"      {sibling}")
    print("      declares the whole sync: block with no pullSecret, so Helm")
    print("      re-renders the FluxInstance without one minutes after bootstrap")
    print("      and Flux loses its credential. Bootstrap alone is not enough.")
    print("")
    print("      Either land the jg-base half (ferry133/jg-base — add")
    print("      pullSecret: \"${FLUX_SYNC_PULL_SECRET}\" to that HelmRelease,")
    print("      after measuring what an EMPTY value does on a public cluster),")
    print("      or set repository_visibility: \"public\" for now.")
    print("")
    print("      This refuses rather than rendering a bootstrap that works and")
    print("      then breaks — which is the defect #56 reports, one step later.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
