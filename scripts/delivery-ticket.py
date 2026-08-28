#!/usr/bin/env python3
"""Delivery ticket state machine — §3 of the factory-agent change.

One GitHub issue tracks one customer delivery. The issue is the durable record:
factory restarts, sessions end, and people hand over mid-delivery, so anything
not written to the ticket did not happen.

Why a script rather than a rule in the runbook
----------------------------------------------
Every guarantee here is one an agent would otherwise have to remember:

  exactly one phase label   an agent that adds `provisioning` without removing
                            `awaiting-hardware` leaves a ticket that reads as
                            being in two phases, and `resume` then picks one
  ordered transitions       skipping a phase is how a delivery reaches handover
                            without anyone noticing verification never ran
  no key material           a progress comment is the natural place to paste
                            "the token I used", and these repos are public
  observed vs recorded      the ticket says provisioned, the cluster disagrees

A rule in prose is followed until the run where it matters. This exits non-zero.

Usage
-----
  delivery-ticket.py phases
  delivery-ticket.py create   --customer NAME --profile P --machines N [--repo R]
  delivery-ticket.py advance  <issue> --to PHASE [--repo R] [--force]
  delivery-ticket.py comment  <issue> --file FILE [--repo R]
  delivery-ticket.py resume   <issue> [--repo R]
  delivery-ticket.py check    <issue> --observed PHASE [--repo R]

Exit 0 on success, 1 on any refusal. Refusals print what was wrong and what to
do, never the offending secret.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

# Ordered. Position in this list IS the state machine — index n may advance to
# n+1, or to `blocked` from anywhere. Nothing else is a legal transition.
PHASES = [
    "delivery/intake",            # ticket opened: customer, profile, machines
    "delivery/awaiting-hardware",  # waiting for the machine to reach Omni
    "delivery/provisioning",      # cluster, repo, DNS, tunnel being built
    "delivery/verifying",         # assertions from the runbook are being run
    "delivery/handover",          # handover package produced and delivered
    "delivery/done",
]

# Not a phase. Reachable from any phase, and the only label that may coexist
# with nothing else — a blocked ticket keeps its phase so resume knows where it
# stopped, which is why this is checked separately from the exactly-one rule.
BLOCKED = "delivery/blocked"

# Deliberately overlapping with the runbook's history scan. A progress comment
# is the most likely place for a credential to be pasted by hand, and these
# repositories are public.
SECRET_PATTERNS = [
    (r"AGE-SECRET-KEY-1[A-Z0-9]{50,}", "an age private key"),
    (r"\bcfut_[A-Za-z0-9_-]{20,}", "a Cloudflare API token"),
    (r"\bghp_[A-Za-z0-9]{30,}", "a GitHub personal access token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{30,}", "a GitHub fine-grained token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "a PEM private key"),
    (r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "a JWT"),
]

# Config-shaped leaks are handled separately, because deciding them with one
# regex was wrong in both directions when tested: it missed a short JWT and it
# flagged `cloudflare_token: ""`, `"<your-token>"` and `"${CF_TOKEN}"`. Those
# three are exactly what a correct runbook example looks like, and a guard that
# fires on the documentation gets switched off. Capture the value, then judge it.
SECRET_FIELDS = (
    "cloudflare_token",
    "claudecode_auth0_client_secret",
    "backup_r2_secret_access_key",
    "backup_r2_access_key_id",
    "ttyd_credential",
    "claudecode_postgres_password",
    "github_push_token",
)

FIELD_RE = re.compile(
    r"(?im)^\s*(" + "|".join(SECRET_FIELDS) + r")\s*:\s*(.*)$"
)

PLACEHOLDER_MARKERS = ("change", "your-", "your_", "example", "redacted", "todo", "fixme")


def looks_like_a_real_value(raw: str) -> bool:
    """True when a captured field value looks like an actual credential.

    Errs toward False only for shapes that cannot be a secret — empty, a
    template substitution, an angle-bracket placeholder. Anything else counts,
    because the cost of a false positive here is one edit and the cost of a
    false negative is a published credential.
    """
    v = raw.split("#", 1)[0].strip().strip("\"'").strip()
    if not v:
        return False
    if v.startswith(("<", "${", "$(")):
        return False
    low = v.lower()
    if any(m in low for m in PLACEHOLDER_MARKERS):
        return False
    if set(low) <= {"x", ".", "*", "-", "_"}:
        return False
    # Short values are identifiers or fingerprints, not usable credentials.
    return len(v) >= 8


def fail(msg: str) -> None:
    print(f"refused: {msg}", file=sys.stderr)
    sys.exit(1)


def gh(args: list[str], repo: str | None) -> str:
    cmd = ["gh"] + args + (["--repo", repo] if repo else [])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        fail(f"gh failed: {' '.join(cmd)}\n{r.stderr.strip()}")
    return r.stdout


def ticket_labels(issue: str, repo: str | None) -> list[str]:
    out = gh(["issue", "view", issue, "--json", "labels"], repo)
    return [l["name"] for l in json.loads(out)["labels"]]


def current_phase(labels: list[str]) -> str | None:
    found = [l for l in labels if l in PHASES]
    if len(found) > 1:
        fail(
            f"ticket carries {len(found)} phase labels at once: {', '.join(found)}.\n"
            "  A ticket in two phases is a ticket whose state nobody can read, and\n"
            "  resume would pick one arbitrarily. Remove all but the correct one by\n"
            "  hand, then re-run — this is not auto-repaired because which one is\n"
            "  correct is a question about the world, not about the labels."
        )
    return found[0] if found else None


def scan_for_secrets(text: str) -> list[str]:
    found = [what for pattern, what in SECRET_PATTERNS if re.search(pattern, text)]
    for field, value in FIELD_RE.findall(text):
        if looks_like_a_real_value(value):
            found.append(f"{field} set to a real-looking value")
    return sorted(set(found))


def cmd_phases(_args: argparse.Namespace) -> None:
    for i, p in enumerate(PHASES):
        print(f"{i}  {p}")
    print(f"-  {BLOCKED}  (from any phase; keeps the phase label)")


def cmd_create(args: argparse.Namespace) -> None:
    body = (
        f"Customer: {args.customer}\n"
        f"Profile: {args.profile}\n"
        f"Expected machines: {args.machines}\n\n"
        "Opened by delivery-ticket.py. Phase transitions and progress belong on\n"
        "this ticket — the factory agent restarts, and anything not written here\n"
        "did not happen.\n"
    )
    leaked = scan_for_secrets(body)
    if leaked:
        fail(f"ticket body looks like it contains {', '.join(leaked)}")
    out = gh(
        ["issue", "create", "--title", f"Delivery: {args.customer}",
         "--body", body, "--label", PHASES[0]],
        args.repo,
    )
    print(out.strip())


def cmd_advance(args: argparse.Namespace) -> None:
    if args.to not in PHASES and args.to != BLOCKED:
        fail(f"unknown phase {args.to!r}. Run `phases` for the vocabulary.")

    labels = ticket_labels(args.issue, args.repo)
    now = current_phase(labels)

    if args.to == BLOCKED:
        if BLOCKED in labels:
            print(f"already blocked (phase {now})")
            return
        gh(["issue", "edit", args.issue, "--add-label", BLOCKED], args.repo)
        print(f"blocked at phase {now}")
        return

    if now is None:
        fail(
            "ticket has no phase label, so there is no transition to check.\n"
            "  Either this is not a delivery ticket, or a label was removed by\n"
            "  hand. Set the correct phase explicitly with --force."
            if not args.force else ""
        )

    if now == args.to:
        print(f"already at {args.to}")
        return

    expected = PHASES[PHASES.index(now) + 1] if PHASES.index(now) + 1 < len(PHASES) else None
    if args.to != expected and not args.force:
        fail(
            f"illegal transition {now} -> {args.to}.\n"
            f"  The only forward move from {now} is {expected}.\n"
            "  Skipping a phase is how a delivery reaches handover without\n"
            "  verification ever having run. If the skip is genuinely correct,\n"
            "  pass --force, and say why in a progress comment — an unexplained\n"
            "  --force is indistinguishable from a mistake when someone resumes."
        )

    args_edit = ["issue", "edit", args.issue, "--add-label", args.to, "--remove-label", now]
    if BLOCKED in labels:
        args_edit += ["--remove-label", BLOCKED]
    gh(args_edit, args.repo)
    print(f"{now} -> {args.to}" + ("  (forced)" if args.to != expected else ""))


def cmd_comment(args: argparse.Namespace) -> None:
    text = open(args.file).read() if args.file != "-" else sys.stdin.read()
    leaked = scan_for_secrets(text)
    if leaked:
        fail(
            f"comment appears to contain {', '.join(leaked)}.\n"
            "  Nothing was posted. These repositories are public and an edit does\n"
            "  not unpublish a comment — the value would need rotating, not\n"
            "  deleting. Record the identifier or a fingerprint instead of the\n"
            "  value: 'token ending 4f21', 'age recipient age1u02z...'."
        )
    if not text.strip():
        fail("empty comment")
    gh(["issue", "comment", args.issue, "--body-file", args.file], args.repo)
    print("commented")


def cmd_resume(args: argparse.Namespace) -> None:
    labels = ticket_labels(args.issue, args.repo)
    now = current_phase(labels)
    if now is None:
        fail("ticket has no phase label; cannot resume")
    idx = PHASES.index(now)
    print(f"phase:     {now}")
    print(f"blocked:   {'yes' if BLOCKED in labels else 'no'}")
    print(f"completed: {', '.join(PHASES[:idx]) or '(none)'}")
    print(f"remaining: {', '.join(PHASES[idx + 1:]) or '(none)'}")
    print()
    print("Phases listed as completed were NOT re-verified — this reads the")
    print("label, which records what was claimed. If resuming after a crash,")
    print("re-run the current phase's assertions before moving on: the phase")
    print("most likely to be half-done is the one that was in progress.")


def cmd_check(args: argparse.Namespace) -> None:
    labels = ticket_labels(args.issue, args.repo)
    now = current_phase(labels)
    if args.observed not in PHASES:
        fail(f"unknown observed phase {args.observed!r}")
    if now == args.observed:
        print(f"consistent: ticket and observation both say {now}")
        return
    fail(
        f"ticket says {now}, observation says {args.observed}.\n"
        "  Stopping rather than reconciling. Either the ticket was advanced for\n"
        "  work that did not complete, or work completed without being recorded,\n"
        "  and those need opposite corrections. Guessing picks one at random and\n"
        "  writes it down as fact.\n"
        "  Escalate with both values and how the observation was made."
    )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", help="owner/repo; defaults to the current directory's")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("phases").set_defaults(func=cmd_phases)

    c = sub.add_parser("create")
    c.add_argument("--customer", required=True)
    c.add_argument("--profile", required=True)
    c.add_argument("--machines", required=True)
    c.set_defaults(func=cmd_create)

    a = sub.add_parser("advance")
    a.add_argument("issue")
    a.add_argument("--to", required=True)
    a.add_argument("--force", action="store_true")
    a.set_defaults(func=cmd_advance)

    m = sub.add_parser("comment")
    m.add_argument("issue")
    m.add_argument("--file", required=True, help="path, or - for stdin")
    m.set_defaults(func=cmd_comment)

    r = sub.add_parser("resume")
    r.add_argument("issue")
    r.set_defaults(func=cmd_resume)

    k = sub.add_parser("check")
    k.add_argument("issue")
    k.add_argument("--observed", required=True)
    k.set_defaults(func=cmd_check)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
