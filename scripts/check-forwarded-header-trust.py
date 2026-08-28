#!/usr/bin/env python3
"""Assert claude-code's oauth2-proxy trusts no forwarded headers.

ferry133/jg-cluster-template#9 was closed by turning `--reverse-proxy` off
rather than by naming a trusted proxy, because in v7.15.3 no trusted-proxy list
covers the field the issue was about: the `client` in every request log comes
from `--real-client-ip-header` (X-Real-IP by default) and is read with no trust
check at all for as long as `--reverse-proxy` is on.

That fix is a single word in a file nobody re-reads, and three separate edits
undo it without looking wrong:

  - `--reverse-proxy=true` comes back. It is the flag anyone reaches for when a
    redirect or a logged hostname looks wrong behind a gateway, and it silently
    restores trust in X-Forwarded-* from 0.0.0.0/0.
  - it comes back *with* `--trusted-proxy-ip`, which is the defensible version
    — so this permits it, rather than pretending the flag is forbidden.
  - `--trusted-ip` gets typed where `--trusted-proxy-ip` was meant. One word
    shorter, adjacent in the docs, and it does something entirely different:
    it is the list of addresses that skip authentication outright. In front of
    a cluster-admin root shell that is not a logging defect.

None of the three shows up in the rendered manifest as anything but a plausible
flag, so assert the shape here, before rendering.

Exit 0 if the args are acceptable, 1 otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTANCES = ROOT / ("templates/config/kubernetes/apps/base/claudecode"
                    "/claude-code/instances/helmrelease.yaml.j2")


def oauth2_args(path: Path) -> list[str]:
    """Every uncommented `- --flag…` line in the file.

    Read as text rather than as YAML: the file is a Jinja template, and the
    thing being checked is what a maintainer will type into it.
    """
    args = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = re.match(r"-\s+(--\S+)", stripped)
        if m:
            args.append(m.group(1))
    return args


def problems(args: list[str]) -> tuple[list[str], str]:
    """Returns (problems, one-line description of the accepted posture)."""
    found = []
    posture = "trusts no forwarded headers"

    reverse_proxy = [a for a in args if a.startswith("--reverse-proxy")]
    trusted_proxy = [a for a in args if a.startswith("--trusted-proxy-ip")]
    # Exact prefix match: --trusted-proxy-ip must not be mistaken for this one.
    trusted_ip = [a for a in args
                  if re.match(r"--trusted-ip($|=)", a)]

    if trusted_ip:
        found.append(
            f"{trusted_ip[0]} is the skip-authentication list, not the "
            "trusted-proxy list. Every address in it reaches a cluster-admin "
            "root shell without logging in. If a trusted proxy was meant, the "
            "flag is --trusted-proxy-ip.")

    if not reverse_proxy:
        found.append(
            "--reverse-proxy is not stated at all. Its default is off, which is "
            "the wanted behaviour, but #9 is then a property of a flag nobody "
            "wrote down — state it explicitly with the reasoning.")

    enabled = [a for a in reverse_proxy if a.endswith(("=true", "=1"))]
    if enabled and not trusted_proxy:
        found.append(
            "--reverse-proxy is enabled with no --trusted-proxy-ip: "
            "X-Forwarded-* is then trusted from 0.0.0.0/0 and ::/0 "
            "(oauth2-proxy's own fallback). That is #9.")
    if trusted_proxy and not enabled:
        found.append(
            "--trusted-proxy-ip is set but --reverse-proxy is not enabled. The "
            "flag is inert in that combination — it reads like a control and is "
            "not one.")
    if enabled and trusted_proxy:
        # Permitted, but it does not close what #9 was actually about, so it
        # must not report as the posture the fix established.
        posture = ("trusts X-Forwarded-Proto/-Host/-Uri from "
                   + trusted_proxy[0].partition("=")[2]
                   + ", and the logged client IP from anywhere")
        print("NOTE  --reverse-proxy is enabled with a trusted-proxy list.")
        print("        X-Forwarded-Proto/-Host/-Uri are gated by it; the `client`")
        print("        field in the request log is not, in v7.15.3. Whoever made")
        print("        this change should have decided that on purpose — see #9")
        print("        and the comment in the instances template.")

    return found, posture


def main() -> int:
    if not INSTANCES.is_file():
        print(f"FAIL  {INSTANCES} not found — wrong repo root?")
        return 1

    args = oauth2_args(INSTANCES)
    if not any(a.startswith("--oidc-issuer-url") for a in args):
        print("FAIL  no oauth2-proxy args found in the instances template — "
              "this check was reading the wrong thing, which is worse than not "
              "running it")
        return 1

    found, posture = problems(args)
    for p in found:
        print(f"FAIL  {p}")
    if found:
        print()
        print(f"{len(found)} problem(s) in the oauth2-proxy args.")
        return 1

    print(f"ok — oauth2-proxy {posture} ({len(args)} args checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
