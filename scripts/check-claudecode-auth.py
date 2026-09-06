#!/usr/bin/env python3
"""Check the gate in front of claude-code before anything is rendered.

Every cluster runs a claude-code instance: a root shell with cluster-admin
RBAC that the Cloudflare tunnel exposes to the internet the moment it connects
— no port forward, no firewall change — and whose hostname enters Certificate
Transparency logs as soon as cert-manager issues for it. There is no obscurity
to fall back on, and `replicas: 0` is a posture rather than a control: anything
that scales it up removes it.

Two modes, so two checks:

  Auth0 (the default)   TWO tenants since 2026-09-06 (jgct#84). auth0.json —
                        gitignored, factory-supplied — is the FACTORY tenant and
                        gates the base `im`, so it is REQUIRED on every cluster,
                        all four keys including allowed_emails. cluster.yaml's
                        claudecode_auth0_* are the CUSTOMER tenant and are
                        required only when claude_instances names an instance.
                        Absent, the render dies partway through with a
                        traceback; empty, it deploys an oauth2-proxy that
                        cannot start — and OIDC mode gives ttyd no fallback, so
                        that is a terminal nobody reaches.

                        Until `#64` this said "the shared application's", and
                        told operators to copy auth0.json from another cluster.
                        The 2026-08-25 ruling gives every cluster its own
                        tenant; a cluster that deliberately shares one says so
                        with `claudecode_auth0_shared: true`. This check runs
                        SECOND in `:configure:` and the render is tenth, so
                        whatever this file says is what an operator acts on —
                        the message in plugin.py is never reached.

                        An operator-declared cookie secret is checked here too.
                        It is optional and derived correctly when absent, so the
                        only way to get it wrong is to write one — which one
                        cluster did, and paid the full price for (#17).

  claudecode_auth0:     ttyd basic auth is the whole gate, so the credential
  false                 must exist and must not be guessable. Before this
                        check, an unset one rendered an empty --credential and
                        published an unauthenticated shell.

The strength rules live here rather than in cluster.schema.cue because a CUE
constraint prints the offending value in its error message. A check that leaks
the credential into a terminal and a CI log in order to complain about it is
worse than no check, so nothing below ever prints the value — only what is
wrong with it.

Usage: check-claudecode-auth.py [cluster.yaml]
Exit 0 if acceptable, 1 otherwise.
"""

from __future__ import annotations

import base64
import binascii
import json
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

AUTH0_FIELDS = ("domain", "client_id", "client_secret")


def yq(expression: str, path: Path) -> str:
    """Read one value via yq rather than by hand-parsing the line.

    The ttyd credential contains a colon by definition, and any line may carry
    an inline comment or quoting. Splitting on the first colon produced a value
    several characters longer than the real one, which silently changes what the
    length check decides — a checker that mis-reads the thing it is checking is
    worse than useless here.
    """
    result = subprocess.run(
        ["yq", "-r", expression, str(path)], capture_output=True, text=True,
    )
    if result.returncode != 0:
        sys.exit(f"could not read {path}: {result.stderr.strip()}")
    return result.stdout.strip()


def auth0_enabled(path: Path) -> bool:
    """Mirrors the render-time default in templates/scripts/plugin.py.

    Read bare, not as `.claudecode_auth0 // true`: yq's alternative operator
    falls through on `false` as well as on null, so the opt-out read back as
    opted in and this checked the wrong mode.
    """
    return yq('.claudecode_auth0', path) != "false"


def instances(config: Path) -> list[str]:
    """The cluster's OWN extra instances. Empty is the norm since jgct#81."""
    raw = yq('.claude_instances // [] | .[]', config)
    return raw.split()


def check_auth0(config: Path) -> list[str]:
    """Two tenants since 2026-09-06 (jgct#84): factory gates im, customer gates
    the rest.

    auth0.json is the FACTORY tenant's file — required, not opt-in, because
    jg-base ships the factory's support agent (`im`) on every cluster and that
    file is its gate. cluster.yaml's claudecode_auth0_* are the CUSTOMER tenant
    and are required only when the cluster names extra instances.

    Both directions of jgct#64's rule are enforced here, and they are mirror
    images: auth0.json must not silently become a customer's values (the
    original defect), and a customer's values must not silently become the
    factory agent's gate (what #84 adds). Neither is allowed to be inferred.

    allowed_emails is checked as hard as the OIDC triple: it IS the door. An
    empty list renders a gate that admits nobody, and an unreachable rescue
    terminal reads from outside exactly like a broken cluster — measured
    2026-09-06, a 403 that cost an hour before anyone suspected the allowlist.
    """
    found: list[str] = []

    if yq('.claudecode_auth0_shared // ""', config) in ("true", "True"):
        found.append(
            "claudecode_auth0_shared is set, and it is REFUSED since "
            "2026-09-06: it meant 'take my customer Auth0 values out of "
            "auth0.json', and auth0.json is now the factory tenant that gates "
            "the base im — obeying it would put a customer instance behind the "
            "factory gate (jgct#84). Delete the flag.")

    auth0 = config.parent / "auth0.json"
    if not auth0.is_file():
        found.append(
            "auth0.json is not in this cluster's directory. Since 2026-09-06 it "
            "holds the FACTORY Auth0 tenant and gates the base im — the "
            "factory's support agent that jg-base deploys on every cluster — so "
            "it is required whenever claudecode_auth0 is not false. The factory "
            "supplies it at provisioning; it stays gitignored. A cluster that "
            "will not have an Auth0-gated terminal sets claudecode_auth0: false "
            "and supplies ttyd_credential.")
    else:
        try:
            data = json.loads(auth0.read_text())
        except json.JSONDecodeError as e:
            found.append(f"auth0.json is not valid JSON: {e}")
            data = {}
        absent = [f for f in AUTH0_FIELDS if not data.get(f)]
        if not data.get("allowed_emails"):
            absent.append("allowed_emails")
        if absent:
            found.append(
                "auth0.json is missing or empty: " + ", ".join(absent)
                + " — this is the factory tenant that gates the base im, and "
                "allowed_emails is its login allowlist; an empty one locks "
                "everyone out of the cluster's rescue terminal")

    # The customer tenant is only required when there is a customer instance to
    # gate. Demanding it on a cluster with `claude_instances: []` would be
    # asking for a tenant nothing uses — all live clusters are in that state.
    own = instances(config)
    if own:
        from_config = {
            field: yq(f'.claudecode_auth0_{field} // ""', config)
            for field in AUTH0_FIELDS
        }
        emails = yq('.claudecode_allowed_emails // ""', config)
        absent = [f"claudecode_auth0_{f}" for f in AUTH0_FIELDS
                  if not from_config[f]]
        if not emails:
            absent.append("claudecode_allowed_emails")
        if absent:
            found.append(
                f"claude_instances names {', '.join(own)} — those are CUSTOMER "
                "instances behind the customer's own Auth0 tenant, and "
                "cluster.yaml is missing: " + ", ".join(absent)
                + ". They are NOT inherited from auth0.json (that is the "
                "factory tenant, for the base im only). Set them from this "
                "cluster's tenant, or drop the extra instances.")
    return found



def callback_urls(config: Path) -> list[str]:
    """The Auth0 registrations a render cannot perform on the operator's behalf.

    Rendering succeeds without them and the terminal still fails to open, with
    an Auth0 error page rather than anything pointing back here — so print them
    every time instead of waiting for someone to hit it.
    """
    domain = yq('.cloudflare_domain // ""', config)
    instances = yq('.claude_instances // ["im"] | .[]', config).split()
    if not domain:
        return []
    return [f"https://{i}.{domain}/oauth2/callback" for i in instances]


def credential_problems(credential: str) -> list[str]:
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


# oauth2-proxy's cookie secret becomes an AES key, so it must end up 16, 24 or
# 32 bytes. Two things get conflated in its error message and the difference is
# the whole defect: it reports the *length* it ended up with, never the reason
# it ended up with that length.
#
# The rule below is transcribed from two measured cases plus that error text,
# not from reading oauth2-proxy's source:
#
#   jg-jiahd       44 chars, URL-safe alphabet   → decodes to 32B → accepted,
#                                                  4d11h / 0 restarts
#   jg-janncotcc   44 chars, STANDARD alphabet   → does not decode → falls back
#                                                  to the raw 44 → refused, 23×
#                                                  CrashLoopBackOff
#
# Same image, same length, opposite outcomes. So length is not the thing to
# check; "does it decode, and to what" is.
#
# The fallback branch is kept deliberately permissive: a value that is not
# base64 at all but is itself exactly 16/24/32 bytes is what oauth2-proxy's own
# error text implies it would accept, so this does not reject it. Being
# narrower than the thing you are guarding turns a good value into a failed
# render, and that failure looks identical to a real one.
COOKIE_SECRET_BYTES = (16, 24, 32)


def cookie_secret_problems(secret: str) -> list[str]:
    """Never prints the value — only what is wrong with it. See module docstring."""
    padded = secret + "=" * (-len(secret) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        decoded = None
    else:
        # Python's decoder ignores what it cannot use rather than refusing, so a
        # standard-alphabet value can "decode" to the wrong number of bytes
        # instead of raising. Re-encoding is the discriminating test: only a
        # genuinely URL-safe value round-trips.
        if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != padded.rstrip("="):
            decoded = None

    if decoded is not None:
        if len(decoded) in COOKIE_SECRET_BYTES:
            return []
        return [
            f"decodes to {len(decoded)} bytes; oauth2-proxy needs "
            f"{', '.join(map(str, COOKIE_SECRET_BYTES))}",
        ]

    if len(secret.encode("utf-8")) in COOKIE_SECRET_BYTES:
        return []

    problems = [
        f"is {len(secret)} characters and is not URL-safe base64, so "
        f"oauth2-proxy will measure it raw and refuse it",
    ]
    if set("+/") & set(secret):
        problems.append(
            "it contains '+' or '/' — that is STANDARD base64, and oauth2-proxy "
            "only decodes the URL-safe alphabet ('-' and '_')",
        )
    return problems


def check_cookie_secret(config: Path) -> list[str]:
    """Only reachable in Auth0 mode; unset is the good case, not a gap.

    plugin.py derives it from age.key + cluster_name when absent, and that
    derivation has always emitted URL-safe base64. So this checks the one input
    a human can supply, and says nothing when nobody supplied one.
    """
    secret = yq('.claudecode_oauth2_cookie_secret // ""', config)
    if not secret:
        return []
    problems = cookie_secret_problems(secret)
    if not problems:
        return []
    return [f"claudecode_oauth2_cookie_secret {p}" for p in problems] + [
        "remove the line from cluster.yaml to fall back to the derived value — "
        "but note that changes the secret, which signs out every open session",
    ]


def check_basic_auth(config: Path) -> list[str]:
    credential = yq('.ttyd_credential // ""', config)
    if not credential:
        return [
            "claudecode_auth0 is false and ttyd_credential is unset",
            "that renders ttyd with no --credential at all: an unauthenticated "
            "root shell on a public hostname",
        ]
    return credential_problems(credential)


def main() -> int:
    config = Path(sys.argv[1] if len(sys.argv) > 1 else "cluster.yaml")
    if not config.is_file():
        sys.exit(f"not found: {config}")

    auth0 = auth0_enabled(config)
    if auth0:
        label = "claudecode auth (Auth0)"
        # Both, not the first that fails: a cluster with a broken auth0.json and
        # a broken cookie secret should learn about both in one run rather than
        # discover the second only after fixing the first.
        problems = check_auth0(config) + check_cookie_secret(config)
        remedy = []
    else:
        label, problems = "claudecode auth (ttyd basic)", check_basic_auth(config)
        remedy = [
            "Generate one with:",
            "  python3 -c \"import secrets;"
            " print('ops:' + secrets.token_urlsafe(24))\"",
            "then update cluster.yaml and re-run `task configure`.",
        ]

    if problems:
        print(f"FAIL  {label}", file=sys.stderr)
        for problem in problems:
            print(f"        {problem}", file=sys.stderr)
        if remedy:
            print(file=sys.stderr)
            print("      This guards an internet-reachable shell.", file=sys.stderr)
            for line in remedy:
                print(f"      {line}", file=sys.stderr)
        return 1

    print(f"ok    {label}")
    if auth0:
        for url in callback_urls(config):
            print(f"        Auth0 app must allow callback: {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
