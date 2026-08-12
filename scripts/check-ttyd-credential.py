#!/usr/bin/env python3
"""Check ttyd_credential is strong enough for something publicly reachable.

The credential guards a shell that the Cloudflare tunnel exposes to the
internet the moment it connects — no port forward, no firewall change — and the
hostname enters Certificate Transparency logs as soon as cert-manager issues for
it. There is no obscurity to fall back on.

`replicas: 0` keeps the pod from running, which is a useful posture but not a
control: anything that scales it up removes it.

This lives here rather than in cluster.schema.cue because a CUE constraint
prints the offending value in its error message. A check that leaks the
credential into a terminal and a CI log in order to complain about it is worse
than no check, so nothing below ever prints the value — only what is wrong
with it.

Usage: ./scripts/check-ttyd-credential.py [cluster.yaml]
Exit 0 if acceptable or unset, 1 otherwise.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

MIN_PASSWORD = 20

# Names and passwords that show up when someone is "just testing" and then ships.
WEAK = {
    "admin", "administrator", "test", "tester", "user", "demo", "guest",
    "root", "changeme", "password", "passw0rd", "letmein", "secret",
    "123456", "12345678", "qwerty", "claude", "ttyd",
}


def read_credential(path: Path) -> str | None:
    """Read the value via yq rather than by splitting on the first colon.

    The credential contains a colon by definition, and the line may carry an
    inline comment or quoting. Hand-parsing it produced a value several
    characters longer than the real one, which silently changes what the length
    check decides — a checker that mis-reads the thing it is checking is worse
    than useless here.
    """
    if not path.is_file():
        return None
    result = subprocess.run(
        ["yq", "-r", ".ttyd_credential // \"\"", str(path)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        sys.exit(f"could not read {path}: {result.stderr.strip()}")
    value = result.stdout.strip()
    return value or None


def problems(credential: str) -> list[str]:
    found: list[str] = []
    user, sep, password = credential.partition(":")
    if not sep:
        return ["not in user:password form"]
    if not user:
        found.append("username is empty")
    elif user.lower() in WEAK:
        found.append(f"username {user!r} is a default that gets guessed first")
    if len(password) < MIN_PASSWORD:
        found.append(f"password is {len(password)} characters, needs {MIN_PASSWORD}")
    lowered = password.lower()
    for weak in sorted(WEAK):
        if weak in lowered:
            found.append(f"password contains {weak!r}")
            break
    if password and re.fullmatch(r"(.)\1*", password):
        found.append("password is a single repeated character")
    return found


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "cluster.yaml")
    credential = read_credential(path)
    if credential is None:
        print("ok    ttyd_credential not set")
        return 0

    found = problems(credential)
    if not found:
        print("ok    ttyd_credential")
        return 0

    print("FAIL  ttyd_credential")
    for problem in found:
        print(f"        {problem}")
    print()
    print("      This guards an internet-reachable shell. Generate one with:")
    print("        python3 -c \"import secrets;"
          " print('ops:' + secrets.token_urlsafe(24))\"")
    print("      then update cluster.yaml and re-run `task configure`.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
