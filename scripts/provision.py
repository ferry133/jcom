#!/usr/bin/env python3
"""Provisioning flow driver — §4 of the factory-agent change.

`fleet-ops docs/operations/provision-customer-cluster.md` is the procedure. A person
ran it end to end (§7.2, 2026-08-22) in the time before this file existed, on
purpose: automating a procedure nobody has run multiplies whatever is wrong with
it and then hides that behind a script. There have been more runs since; what
matters here is the order, not a count that keeps going up. This file automates
the steps that run against Omni, GitHub and Cloudflare, and refuses the ones
that need a human.

The one rule this file is built around
--------------------------------------
**Never create on an observation you could not make.**

Every external resource here — the Omni cluster, the user repo, the tunnel, the
DNS records — is created at most once per delivery (D4). The only way to keep
that true across a restart is to look before creating. But "look" has three
outcomes, not two:

    PRESENT       it is there, and it is the one this ticket means
    ABSENT        it is not there, and the query that would have found it worked
    UNMEASURABLE  the query did not work

An `UNMEASURABLE` treated as `ABSENT` is precisely how a re-run produces a second
tunnel: `cloudflared tunnel list` without a `cert.pem` prints an error and no
tunnels, which is byte-identical to a correct answer of "none". So this driver
**stops** on `UNMEASURABLE` and never falls through to create. That is 4.10 and
4.12 in one decision, and it is why `Observation` is a three-valued type rather
than a bool.

A fourth outcome exists and is not a failure of measurement:

    CONFLICT      something is there, but it is not what this ticket describes

CONFLICT is also a stop. "There is a repo by that name owned by someone else"
and "there is no repo" need opposite corrections, so choosing one is guessing.

What this file will not do
--------------------------
- **It will not create a cluster for a machine that matches no ticket** (4.2).
  That refusal is load-bearing outside §4: `zero-it-onboarding` D13 concluded a
  join token need not expire *because* nothing auto-assigns an unknown machine.
  Weakening 4.2 silently invalidates that, and whoever does it will not know.
- **It will not retry an unrecognised failure** (4.12). It prints what it ran,
  what it expected and what it got, verbatim, and exits.
- **It will not register an account with any consumer service** (5.2). Not
  Google, not Cloudflare, not Auth0, not a domain registrar. There is no code
  path here that creates one, and there should not be — automating consumer
  sign-up means holding the credential that recovers the account, which is the
  one thing `factory-agent` D11 (`ferry133/jg-cluster-template#5`) exists to
  avoid. **Who registers what,
  and when, is that decision's to state, not this file's**: restating a live
  decision here puts a copy of it in every new customer repo, and that is the
  copy nobody comes back to. The change name is load-bearing — three fleet-ops
  changes each have a D11 (`zero-it-onboarding`'s is about positive controls),
  and a bare `D11` reads perfectly in all three. The change itself lives in
  `fleet-ops openspec/changes/factory-agent/` — private, so a customer reading
  this cannot open it; the pointer still has to resolve for whoever can.
- **It mutates nothing without `--apply`.** The default prints the commands.

A missing input, and what now detects it
---------------------------------------
`build_ctx` computes a path to an Omni cluster template at
`<--dir>/omni-cluster.yaml` (4.3), and **nothing this repo ships provides that
file**. Measured 2026-09-12 on `jg-cluster-template` `main`: zero tracked files match
`omni-cluster.ya?ml` (positive control, same query shape:
`cluster.sample.yaml` → 1). That is one repo on one branch on one day; the
customer repos are measured below (**nothing automated puts it there**), and
they do not ship it either.

`--dir` is **the generated customer repo's working directory**. Neither the
default (`.`) nor `build_ctx` can tell you that — `build_ctx` only calls
`abspath` and `join`, and a default of `.` says "stand in the right place", not
which place. The definition is in what the steps *read*: measured 2026-09-13 on
`jg-janncotcc`, 4.6 reads that repo's `cluster.yaml`, 4.7 its git tree, 4.8 its
`kubeconfig-sa`. Point `--dir` at the template repo instead and 4.6 is `ABSENT`
at its first step — but the three do not fail alike, and the difference is this
file's whole subject. `cluster.yaml` and `kubeconfig-sa` are simply not there,
so those steps say so. The template repo *does* have a `.git`, so 4.7 never
reaches `UNMEASURABLE`: it runs its leak query against the wrong repository,
finds nothing (measured 2026-09-14 — `git log --all -- '*cluster.yaml'` → 0,
positive control `'*cluster.sample.yaml'` → 84) and reports `PRESENT`, tree
clean. **A missing input announces itself; a wrong one answers.**

So the paragraph above is a statement about the *template* repo; the file has
to arrive in the customer repo, and **nothing automated puts it there** —
no repo ships it and no step here writes it. Measured 2026-09-14 across the
three customer repos (`jcom`, `jg-jiahd`, `jg-janncotcc`): `omni-cluster.ya?ml`
has **0 commits** in each history and is tracked by none (per-repo positive
control, the `.editorconfig` each one does track: 1, 2, 1 commits — counted
with `git log --all`, which is the point: sticking to `HEAD` gives 1, 1, 1
because `jg-jiahd` has one of them on a branch, and two people comparing these
numbers without the query shape will disagree and both be right).
`jg-janncotcc` has one in its working tree, untracked — caught by the
`*cluster.yaml` rule in its `.gitignore`, which is there for `cluster.yaml` and
swallows this name too. (Named by rule, not by line — for the reason the next
paragraph gives about line numbers; a citation that contradicts its own section
is worse than no citation.) A person put it there, by hand.

Who does that, and how: `fleet-ops
docs/operations/provision-customer-cluster.md`, **Step 3b**, which carries how
the file is produced (export a template from an existing cluster, then four
edits). Cited by section and not by line: that document is edited daily, and a
line number does not go blank when it rots — it starts pointing at an unrelated
sentence, which is worse than pointing at nothing.

**The path is read on both sides of that question now, for different
reasons** — this used to be the paragraph saying an existing cluster meant the
file was never looked at, and `#128` ended that:

- **Omni already holds a cluster of this name.** `OmniClusterStep.observe`
  opens the template and compares the name it describes, in **every** mode
  including `plan`, because a name match is not an identity check. Same name →
  `PRESENT`. Different → `CONFLICT`. **No template, or one this parser cannot
  read → `UNMEASURABLE`**, and the run stops: the question was not asked, and
  `PRESENT` here would mean only "something is called that".
- **No such cluster (`ABSENT`).** Here the two modes still differ, and the
  difference is the whole point:
  - **Without `--apply`** — that is `plan`, and also `run` with no flag: the
    driver branches on the flag, and argparse offers that flag on `run` only,
    so those two spellings are the whole of it. It prints `WOULD` and the
    `omnictl cluster template sync -f <path>` it would run, then **continues to
    the next step**. It does not stop, and on this path it does not open the
    file.
  - **`run --apply`** stops before running that command if the template is not
    there: `drive()` checks `step.inputs(ctx)` at the moment it is about to
    act — after the `plan` branch, so "show me what you would do" still does
    not need the file — and names the missing path (`#129`).

**What is still predicted rather than observed**: what `omnictl cluster
template sync` does once the file *is* there. §4.14 has never run against a
real Omni. The stopping above is measured; the success beyond it is not.

Until 2026-09-14 this section ended by saying that nothing here ever opened or
stated that path, and that `omnictl`'s failure was the first report of the gap.
`#129` and `#128` made both false, and the two bullets above are what replaced
them — **said once, there, and not restated here**: two copies of the same
explanation in one section is how they start to disagree.

**Detecting the gap is not providing the file.** The rest of this section
stands because the input is still missing and **no step here produces it** —
a person does, per Step 3b above.

Both halves are spelled out because each has already misled someone. The
sentence this replaces said `run`/`plan` "stop there", with no mention of
whether the cluster exists — one reader took that to mean `plan` always stops
at 4.3. The first attempt at a fix then said the new-cluster case "stops there",
which is false for `plan` for the same reason. Same sentence, two halves, one
reader each.

It is written here because the alternative is finding out half-way through a
delivery, in front of a customer — and because a script whose missing input is
only known to the person who wrote it is the shape this repo keeps paying for.
What *has* run against a real Omni: the **observe** path 4.3–4.8, measured
2026-09-13 on `ferry133/jg-janncotcc#2` — six steps PASS, writing nothing
(ruling and evidence: `#116` comment 5653393277). ⚠️ **That reading predates
`#128`**, which changed 4.3's observe to open the template and compare the name
it describes; **that comparison has not been run against a real Omni.** The
`create` side (§4.14) has not either — said once, above.

Usage
-----
  provision.py names    --domain DOMAIN
  provision.py detect   [--ticket-repo OWNER/REPO]
  provision.py absent   --ticket N [--ticket-repo OWNER/REPO]
  provision.py derive   --machine UUID [--profile PROFILE]
  provision.py plan     --domain DOMAIN [--dir PATH]
  provision.py run      --domain DOMAIN [--dir PATH] [--apply]
  provision.py complete --domain DOMAIN [--dir PATH] --expect-sha SHA
                        --escrowed-pubkey age1...
  provision.py quic-repair --kubeconfig PATH [--apply]
  provision.py identity    --dir PATH

Exit codes follow `delivery-check.py`: 0 done, 1 refused or failed, 2 could not
tell. Two codes would force "I could not measure this" into one of them, and it
is always the green one.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

DONE, REFUSED, UNKNOWN = 0, 1, 2

# The ticket label that carries the delivery's identifier onto the machine.
# `omnictl media preset create --initial-labels` writes it at image-build time,
# so matching a registered machine to a ticket is a lookup, not a similarity
# judgement (`zero-it-onboarding` D12). The prefix is the whole contract between
# the two systems: change it here and every already-shipped disk stops matching.
TICKET_LABEL_PREFIX = "delivery-ticket"

# How Omni relates a machine to a cluster. Read 2026-09-14 from the Omni
# checkout in ~/coding/omni, `client/pkg/omni/resources/omni/labels.go`:
# `SystemLabelPrefix = "omni.sidero.dev/"` and `LabelSuffixCluster = "cluster"`.
CLUSTER_LABEL = "omni.sidero.dev/cluster"

# Phase vocabulary is owned by delivery-ticket.py. Imported by name rather than
# re-listed: two copies of an ordered list diverge, and the one being followed
# is whichever the reader opened.
PHASE_PROVISIONING = "delivery/provisioning"


# ---------------------------------------------------------------- reporting

def ok(msg: str) -> None:
    print(f"PASS  {msg}")


def bad(msg: str) -> None:
    print(f"FAIL  {msg}")


def huh(msg: str) -> None:
    print(f"?     {msg}")


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def escalate(what: str, cmd: list[str] | None, expected: str, got: str) -> int:
    """4.12 — stop with evidence rather than retrying.

    Prints what was run and what came back verbatim, including output that
    looked like nothing: "no output" is a finding, and summarising it away is
    how the next reader loses the only fact that distinguished the two causes.
    """
    print()
    print("=" * 72)
    print(f"STOPPED: {what}")
    print("=" * 72)
    if cmd is not None:
        print(f"  ran:      {' '.join(cmd)}")
    print(f"  expected: {expected}")
    print(f"  got:      {got if got.strip() else '(no output — this is the finding, not the absence of one)'}")
    print()
    print("  Not retried. A failure this file does not recognise is a failure")
    print("  whose retry has no reason to succeed, and a retry loop turns one")
    print("  diagnosable event into a wall of identical lines.")
    print()
    print("  Record the three lines above on the delivery ticket:")
    print("      scripts/delivery-ticket.py comment <issue> --file -")
    return REFUSED


# ---------------------------------------------------------------- 4.4 naming

class NameError_(ValueError):
    pass


def derive_names(domain: str, owner: str = "ferry133") -> dict[str, str]:
    """4.4 — the cluster, repo and tunnel names, derived from the domain.

    Settled 2026-08-22 during the first real run (§7.2):

        cluster_name    = jg-<domain, dots removed>     janncot.cc -> jg-janncotcc
        repository_name = <owner>/<cluster_name>
        tunnel name     = <cluster_name>

    D4 requires the names be derivable from the ticket so that a re-run
    converges on the same three resources instead of creating a second of each.
    That property is what makes `observe()` below able to ask "is it already
    there" at all — a chosen name has nothing to ask about.

    **The TLD is in the rule on purpose.** A second-level label alone is not
    unique: `acme.tw` and `acme.com` collide the moment both customers exist.

    **Dots are removed because Omni rejects them**, not for looks — measured:
    `name should only contain letters, digits, dashes and underscores`. A rule
    that kept the dot would produce a name that fails at cluster creation,
    several steps after everything else committed to it.

    `jg-jiahd` and `jcom` predate the rule and drop the TLD. They are left
    alone; an exception added so new names match old ones would put the
    collision back.
    """
    d = domain.strip().lower().rstrip(".")
    if not d:
        raise NameError_("empty domain")
    if "." not in d:
        raise NameError_(
            f"{domain!r} has no TLD. The TLD is part of the rule — without it "
            "acme.tw and acme.com derive the same name."
        )
    if not re.fullmatch(r"[a-z0-9.-]+", d):
        raise NameError_(
            f"{domain!r} contains characters that cannot appear in an Omni "
            "cluster name (letters, digits, dashes and underscores only), and "
            "stripping them silently would make the name underivable from the "
            "domain — which is the property D4 asks for."
        )
    cluster_name = "jg-" + d.replace(".", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", cluster_name):
        raise NameError_(f"derived {cluster_name!r}, which Omni will reject")
    return {
        "domain": d,
        "cluster_name": cluster_name,
        "repository_name": f"{owner}/{cluster_name}",
        "tunnel_name": cluster_name,
    }


def cmd_names(args) -> int:
    try:
        names = derive_names(args.domain, args.owner)
    except NameError_ as e:
        bad(str(e))
        return REFUSED
    for k, v in names.items():
        print(f"{k:16} {v}")
    return DONE


# ------------------------------------------------------- observation model

PRESENT, ABSENT, CONFLICT, UNMEASURABLE = "PRESENT", "ABSENT", "CONFLICT", "UNMEASURABLE"


class Observation:
    """What looking for one external resource produced.

    `state` is one of the four above. `detail` is what was seen, in the words
    of the thing that saw it — not a conclusion drawn from it.
    """

    def __init__(self, state: str, detail: str, evidence: str = ""):
        self.state = state
        self.detail = detail
        self.evidence = evidence

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Observation({self.state}, {self.detail!r})"


class Step:
    """One resource this delivery creates at most once.

    Subclasses supply `observe()` and `create()`. The driver, not the step,
    decides what to do with each observation — so the four-way decision exists
    in exactly one place and cannot drift between steps.
    """

    name = "unnamed"
    task = ""

    def observe(self, ctx: dict) -> Observation:  # pragma: no cover - interface
        raise NotImplementedError

    def inputs(self, ctx: dict) -> list[str]:
        """Files `create()` reads. The driver checks these before it acts.

        Empty for most steps. A step that hands a path to an external CLI names
        it here instead of checking it in `observe()`, and the difference is not
        stylistic: `observe()` runs in every mode, and `plan` and a `run`
        without `--apply` do not touch these files and should not have to have
        them. Checking there would make "show me what you would do" fail on a
        machine where nothing is wrong yet — and a check that fires on a
        correct run is a check that gets switched off.
        """
        return []

    def input_problems(self, ctx: dict) -> list[str]:
        """What is wrong INSIDE the files `inputs()` names, checked at the same
        moment and for the same reason: only when about to act. Empty means
        nothing found. A file that is there but would build the wrong thing is
        a refusal, not a warning — after `create()` the mistake is in a running
        cluster (jgct#207).
        """
        return []

    def create(self, ctx: dict) -> list[list[str]]:  # pragma: no cover - interface
        """Commands that would create the resource. Returned, not run."""
        raise NotImplementedError


# ------------------------------------------------------- external observers
#
# Each helper below distinguishes "the answer is no" from "I could not ask".
# That distinction is the whole file, and it is also the one every one of these
# CLIs makes hardest: `gh`, `omnictl` and `cloudflared` all have a failure mode
# that prints an empty, well-formed answer.

def omnictl_available() -> str | None:
    """Return why omnictl cannot be used, or None if it can.

    `omnictl` needs OMNI_ENDPOINT and OMNI_SERVICE_ACCOUNT_KEY, and this
    Omni is not exposed publicly — it is reached through a port-forward into
    jcom. All three can be missing, and the CLI's error for the third
    ('connection refused') is indistinguishable from Omni being down.
    """
    if not shutil.which("omnictl"):
        return "omnictl is not installed"
    if not os.environ.get("OMNI_ENDPOINT"):
        return "OMNI_ENDPOINT is unset (source ~/.config/omni/env)"
    if not os.environ.get("OMNI_SERVICE_ACCOUNT_KEY"):
        return "OMNI_SERVICE_ACCOUNT_KEY is unset (source ~/.config/omni/env)"
    return None


def omnictl_json(resource: str, *rest: str) -> tuple[list[dict] | None, str]:
    """Read a resource from Omni. Returns (rows, error) — exactly one is set.

    `rows == []` means Omni answered and there are none. `rows is None` means
    the question was never asked, and the caller must not read that as none.
    """
    why = omnictl_available()
    if why:
        return None, why
    cmd = ["omnictl", "get", resource, *rest, "-o", "json"]
    r = run(cmd)
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip()
        # Omni says NotFound for a resource that genuinely is not there. That
        # is an answer, not a failure to ask.
        if "NotFound" in err or "not found" in err.lower():
            return [], ""
        return None, f"{' '.join(cmd)} failed: {err}"
    rows: list[dict] = []
    # omnictl prints one JSON document per resource, concatenated.
    dec = json.JSONDecoder()
    text, i = r.stdout, 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        try:
            obj, j = dec.raw_decode(text, i)
        except json.JSONDecodeError as e:
            return None, f"could not parse omnictl output: {e}"
        rows.append(obj)
        i = j
    return rows, ""


def template_cluster_name(path: str) -> tuple[str | None, str]:
    """The cluster name the Omni template at `path` describes.

    Returns (name, why_not) — exactly one is set. **Anything this parser
    cannot read confidently comes back as `None` with a reason, never a
    guess.** The caller turns a name that differs into CONFLICT, so a misparse
    here would flag a correct delivery, and a guard that fires on correct input
    is worse than no guard: it gets switched off.

    Parsed with the standard library on purpose. This file has no YAML
    dependency and is not going to grow one — a script that stops running on
    the machine that most needed it is the failure this repo keeps paying for.
    What is read is narrow enough not to need one: the documents are split on
    `---`, and only *top-level* keys (column 0) are collected, so a `name:`
    nested under `patches:` or inside a machine set cannot be mistaken for the
    cluster's.

    The three keys come from Omni's own template model (`Cluster` in
    `client/pkg/template/internal/models/cluster.go`, read 2026-09-14 from the
    checkout in `~/coding/omni`): `kind`, `name`, and — not read here —
    `kubernetes.version` / `talos.version`.
    """
    try:
        text = open(path).read()
    except OSError as e:
        return None, f"cannot read {path}: {e}"

    top = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):\s*(.*?)\s*$")
    docs: list[list[str]] = [[]]
    for line in text.splitlines():
        if line.strip() == "---":
            docs.append([])
        else:
            docs[-1].append(line)

    named = []
    for doc in docs:
        fields = {}
        for line in doc:
            m = top.match(line)
            if m:
                fields.setdefault(m.group(1), m.group(2))
        if fields.get("kind") == "Cluster":
            named.append(fields.get("name", ""))

    if not named:
        return None, f"{path} has no `kind: Cluster` document"
    if len(named) > 1:
        # Not a parse failure — a real template cannot mean two things, and
        # picking one would be choosing which cluster this delivery is.
        return None, f"{path} has {len(named)} `kind: Cluster` documents"
    name = named[0].strip().strip('"').strip("'")
    if not name:
        return None, f"{path} has a `kind: Cluster` document with no `name`"
    return name, ""


LOCAL_PATH_DIR = "/var/local-path-provisioner"
# Both patches below are list items at the indent of the runbook's
# `patches:` list (a top-level key, items at two spaces): pasted as printed,
# the template must still pass `omnictl cluster template validate` (jgct#239
# review — the first version was indented two more and failed it at rc 1).
LOCAL_PATH_MOUNT_PATCH = f"""  - idOverride: 400-<cluster>-kubelet-local-path
    inline: |
      machine:
        kubelet:
          extraMounts:
            - destination: {LOCAL_PATH_DIR}
              type: bind
              source: {LOCAL_PATH_DIR}
              options: [bind, rshared, rw]"""


def _template_bodies(path: str) -> tuple[dict[str, list[str]] | None, str]:
    """The Omni template at `path`, as each document's text grouped by `kind`.

    Comment lines are dropped, so a commented-out patch is not there. Patches
    given as `file:` are read relative to the template and appended to the
    document that names them. Read as text, with the standard library, for the
    reason `template_cluster_name` gives. Returns (bodies, "") or (None, why
    it could not be read).
    """
    try:
        text = open(path).read()
    except OSError as e:
        return None, f"cannot read {path}: {e}"
    base = os.path.dirname(os.path.abspath(path))
    top = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):\s*(.*?)\s*$")
    filere = re.compile(r"^\s*-?\s*file:\s*['\"]?([^'\"#\s]+)")

    docs: list[list[str]] = [[]]
    for line in text.splitlines():
        if line.strip() == "---":
            docs.append([])
        else:
            docs[-1].append(line)

    by_kind: dict[str, list[str]] = {}
    for doc in docs:
        kind = ""
        body: list[str] = []
        for line in doc:
            if line.lstrip().startswith("#"):
                continue
            m = top.match(line)
            if m and m.group(1) == "kind" and not kind:
                kind = m.group(2).strip().strip('"').strip("'")
            body.append(line)
            f = filere.match(line)
            if f:
                ref = os.path.join(base, f.group(1))
                try:
                    body.extend(l for l in open(ref).read().splitlines()
                                if not l.lstrip().startswith("#"))
                except OSError as e:
                    return None, f"{path}: patch file {f.group(1)} cannot be read: {e}"
        by_kind.setdefault(kind, []).append("\n".join(body))
    return by_kind, ""


def _on_every_machine(by_kind: dict[str, list[str]], has) -> bool:
    """`has` holds for the Cluster document, or for EVERY ControlPlane and
    Workers document. A `Machine`-level patch covers one machine and does not
    count."""
    if any(has(b) for b in by_kind.get("Cluster", [])):
        return True
    cp, workers = by_kind.get("ControlPlane", []), by_kind.get("Workers", [])
    return bool(cp) and all(has(b) for b in cp) and all(has(b) for b in workers)


def template_local_path_mount(path: str) -> tuple[bool | None, str]:
    """Does the Omni template at `path` bind LOCAL_PATH_DIR into kubelet?

    jg-base#150 / jgct#207: kubelet runs in its own container on Talos and
    resolves a volumeMount's `subPath` there. Without this bind, a local-path
    PVC's subPath lands on kubelet's own rootfs and is lost on every kubelet
    restart, silently (measured on jcom; red-then-green on an Omni throwaway,
    fleet-ops `56abf48`). The talhelper path carries the bind in
    `templates/config/talos/patches/global/machine-kubelet.yaml.j2` (jgct#206);
    the Omni path applies none of those patches, and its template is written
    by hand (runbook Step 3b) — so this is the only place the repo can see it.

    Returns (True, "") / (False, why) / (None, why it could not be read).
    Where it must be, and how the file is read: `_on_every_machine`,
    `_template_bodies`.
    """
    by_kind, why = _template_bodies(path)
    if by_kind is None:
        return None, why
    if _on_every_machine(by_kind, lambda b: "extraMounts" in b and LOCAL_PATH_DIR in b):
        return True, ""
    return False, (f"{path} does not bind {LOCAL_PATH_DIR} into kubelet "
                   f"(no `extraMounts` for it on the Cluster, nor on every "
                   f"ControlPlane/Workers set). A local-path PVC mounted by "
                   f"subPath — im's keyrings — would land on kubelet's own "
                   f"rootfs (jg-base#150, jgct#207). Add to the `patches:` list of "
                   f"the `kind: Cluster` document:\n{LOCAL_PATH_MOUNT_PATCH}")


# The talhelper path's containerd customization. It is the single source: the
# Omni check below reads the required lines out of it, so a key added there is
# required here without anyone editing this file.
CRI_CUSTOMIZATION_SOURCE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir,
    "templates", "config", "talos", "patches", "global", "machine-files.yaml.j2")
CRI_CUSTOMIZATION_PATH = "/etc/cri/conf.d/20-customization.part"


def cri_customization(source: str = CRI_CUSTOMIZATION_SOURCE) -> tuple[list[str] | None, str, str]:
    """(required lines, patch to paste, "") read from the talhelper patch, or
    (None, "", why it could not be read).

    The required lines are the `content: |` block of the file entry whose path
    is CRI_CUSTOMIZATION_PATH, stripped: every TOML table header and key the
    talhelper path puts on the node.
    """
    try:
        text = open(source).read()
    except OSError as e:
        return None, "", f"cannot read the CRI customization source {source}: {e}"
    lines = text.splitlines()
    at = next((i for i, l in enumerate(lines)
               if l.strip() == f"path: {CRI_CUSTOMIZATION_PATH}"), None)
    if at is None:
        return None, "", f"{source} has no file entry with path {CRI_CUSTOMIZATION_PATH}"
    content = next((i for i in range(at + 1, len(lines))
                    if lines[i].strip() == "content: |"), None)
    if content is None:
        return None, "", f"{source}: the {CRI_CUSTOMIZATION_PATH} entry has no `content: |` block"
    indent = len(lines[content]) - len(lines[content].lstrip())
    block = []
    for l in lines[content + 1:]:
        if l.strip() and len(l) - len(l.lstrip()) <= indent:
            break
        block.append(l)
    required = [l.strip() for l in block if l.strip()]
    if not required:
        return None, "", f"{source}: the {CRI_CUSTOMIZATION_PATH} content block is empty"
    patch = ("  - idOverride: 400-<cluster>-cri-customization\n"
             "    inline: |\n"
             + "\n".join("      " + l for l in lines if l.strip()))
    return required, patch, ""


def template_cri_customization(path: str, source: str = CRI_CUSTOMIZATION_SOURCE) -> tuple[bool | None, str]:
    """Does the Omni template at `path` carry the talhelper path's containerd
    customization — every line of it?

    jgct#238 (jg-base#188): the talhelper path writes CRI_CUSTOMIZATION_PATH
    from `machine-files.yaml.j2`; the Omni path applies none of those patches,
    so an Omni cluster gets neither key. Measured: jg-jiahd's part file is
    0 bytes and `device_ownership_from_security_context` is absent, so a
    non-root pod cannot open a device the device plugin hands it; an Omni
    throwaway (jg-jcc2) with the same content as a Cluster patch got it on
    `cri.toml:19`, the same line as jcom. The other key,
    `discard_unpacked_layers = false`, is what spegel needs to serve layers.

    Each required line must appear, stripped, as a line of the same document,
    so dropping one key — or its table header — fails. Returns (True, "") /
    (False, why) / (None, why it could not be read).
    """
    required, patch, why = cri_customization(source)
    if required is None:
        return None, why
    by_kind, why = _template_bodies(path)
    if by_kind is None:
        return None, why

    def has(body: str) -> bool:
        have = {l.strip() for l in body.splitlines()}
        return CRI_CUSTOMIZATION_PATH in body and all(r in have for r in required)

    if _on_every_machine(by_kind, has):
        return True, ""
    return False, (f"{path} does not write the containerd customization "
                   f"{CRI_CUSTOMIZATION_PATH} with every line of "
                   f"{os.path.relpath(source)} (on the Cluster, or on every "
                   f"ControlPlane/Workers set). Without "
                   f"`device_ownership_from_security_context` a non-root pod "
                   f"cannot open a device it was granted (jg-base#188); without "
                   f"`discard_unpacked_layers = false` spegel cannot serve "
                   f"layers (jgct#238). Add to the `patches:` list of the `kind: Cluster` "
                   f"document:\n{patch}")


class OmniClusterStep(Step):
    """4.3 — the Omni cluster, with the patch that must exist before first boot.

    The `cniConfig: none` patch is not a preference. Omni installs flannel,
    CoreDNS and kube-proxy unless told not to, and this fleet installs Cilium
    and CoreDNS from `jg-base` instead. Applied after the first boot it is too
    late: the cluster has to be recreated (`docs/deploy/manual.md` Stage B.2).
    So the patch is part of creating the cluster, never a follow-up.
    """

    name = "omni-cluster"
    task = "4.3"

    def observe(self, ctx: dict) -> Observation:
        rows, err = omnictl_json("clusters")
        if rows is None:
            return Observation(UNMEASURABLE, err)
        names = [r.get("metadata", {}).get("id") for r in rows]
        if ctx["cluster_name"] in names:
            return self._is_this_deliverys(ctx, len(names))
        # The positive control: this listing found *other* clusters, so the
        # empty answer for ours is an answer. A listing that found nothing at
        # all is what a wrong endpoint or an expired key also produces.
        if not names:
            return Observation(
                UNMEASURABLE,
                "omnictl listed zero clusters. This Omni is known to hold "
                "several, so an empty list is more likely a wrong endpoint or "
                "an expired service-account key than an empty Omni.",
            )
        return Observation(ABSENT, f"no Omni cluster named {ctx['cluster_name']}",
                           evidence=f"{len(names)} other clusters listed, so the query worked")

    def _is_this_deliverys(self, ctx: dict, listed: int) -> Observation:
        """A cluster of that name exists. Ask whether it is this delivery's.

        A name match is not an identity check. It reads like one because in a
        single Omni the cluster id *is* the name, so `metadata.id` cannot be
        asked twice — comparing it again adds nothing. Every other field the
        listing carries was measured and rejected (2026-09-14, against Omni's
        own `ClusterSpec` in `client/api/omni/specs/omni.proto`):

        - `kubernetesVersion` / `talosVersion` — a cluster legitimately
          upgraded after provisioning differs from its template, so this would
          flag a *correct* cluster, and a guard that fires on correct input
          gets switched off;
        - `features`, `backupConfiguration` — describe settings, not which
          delivery this is;
        - the `cniConfig: none` patch this class exists around — **not in
          `ClusterSpec` at all**. It is a separate `ConfigPatches.omni.sidero.dev`
          resource bound by label, so reading it is a second query whose JSON
          shape nobody here can verify against a live Omni.

        What is left is the template: it is this delivery's only written
        description of the cluster it means. So the comparison is against that
        file, and when the file is not here the honest answer is that the
        question was not asked.

        **What this still does not answer**, written here rather than left for
        a reader to discover: a template that names this cluster does not prove
        the cluster in Omni is the one this delivery created. Someone else's
        cluster of the same name, or one built by hand, passes this. Closing
        that needs the machines' `delivery-ticket` label — which `plan` and
        `run` cannot reach today, because neither takes `--ticket`.
        """
        want = ctx["cluster_name"]
        path = ctx["omni_template"]
        if not os.path.exists(path):
            return Observation(
                UNMEASURABLE,
                f"Omni holds a cluster named {want}, but {path} is not here, so "
                "there is nothing to compare it against. Note what PRESENT "
                f"would mean without that comparison: 'some cluster is called "
                f"{want}' — which is equally true of one built by hand or by an "
                "earlier delivery that is not this one. The runbook's Step 3b "
                "says where this file comes from.",
            )
        described, why = template_cluster_name(path)
        if described is None:
            # The parser could not read it. That is not evidence about the
            # cluster, so it must not become CONFLICT.
            return Observation(UNMEASURABLE, f"Omni holds a cluster named {want}, but {why}")
        if described != want:
            return Observation(
                CONFLICT,
                f"{path} describes cluster {described!r}, this delivery is "
                f"{want!r}. Syncing it from here would create or change that "
                "other cluster, and the two need opposite corrections.",
            )
        return self._members_carry_this_ticket(ctx, listed, path)

    def _members_carry_this_ticket(self, ctx: dict, listed: int, path: str) -> Observation:
        """The last question, and the only one that actually identifies.

        The template naming this cluster says the *description* here is this
        delivery's. It does not say the cluster in Omni is. Someone else's
        cluster of the same name, or one built by hand, passes everything
        above — which is what `#140` was opened for.

        What identifies is the ticket: machines carry a `delivery-ticket`
        label written at image-build time by `omnictl media preset create
        --initial-labels`, and 4.2's refusal is already built on it. Omni
        relates a machine to a cluster with `omni.sidero.dev/cluster` (read
        2026-09-14 from `client/pkg/omni/resources/omni/labels.go`:
        `SystemLabelPrefix` + `LabelSuffixCluster`) — not a string guessed
        here.

        **`--ticket` is optional, deliberately.** Requiring it would make
        `plan` start failing for everyone who can run it today, and a check
        that fires on a correct "show me what you would do" gets switched off
        — that is #129's lesson, and it applies to command-line arguments too.
        Without it this returns the weaker PRESENT, and says in its evidence
        exactly which comparison was made, so PRESENT never claims more than
        it measured.

        Every way of not being able to ask stays UNMEASURABLE. In particular a
        cluster with no machines yet is normal (it was just created), and
        machines with no ticket label have two opposite corrections — "this is
        someone else's" and "it is ours and the label was never written".
        """
        want = ctx["cluster_name"]
        weak = (f"omnictl get clusters -> {listed} clusters; template's "
                f"`kind: Cluster` name == {want}; ticket not compared "
                f"(no --ticket given)")
        ticket = ctx.get("ticket")
        if not ticket:
            return Observation(
                PRESENT,
                f"Omni cluster {want} exists, and {path} describes that same cluster",
                evidence=weak,
            )

        rows, err = omnictl_json("machinestatus")
        if rows is None:
            return Observation(
                UNMEASURABLE,
                f"Omni cluster {want} exists and {path} describes it, but the "
                f"machines could not be read ({err}), so whether this is "
                f"ticket {ticket}'s cluster was not asked.",
            )
        members = [m for m in rows
                   if (m.get("metadata", {}).get("labels", {}) or {}).get(CLUSTER_LABEL) == want]
        if not members:
            return Observation(
                UNMEASURABLE,
                f"Omni cluster {want} exists, but no machine reports "
                f"{CLUSTER_LABEL}={want}. A cluster whose machines have not "
                "been allocated yet looks exactly like this, so it is not an "
                "answer about whose cluster it is.",
            )
        tickets = {machine_ticket_label(m) for m in members}
        if tickets == {None}:
            return Observation(
                UNMEASURABLE,
                f"{len(members)} machines are in {want}, and none carries a "
                f"{TICKET_LABEL_PREFIX} label. 'This is another delivery's "
                "cluster' and 'it is ours and the label was never written' "
                "need opposite corrections, so this is not evidence either way.",
            )
        others = sorted(t for t in tickets if t is not None and t != str(ticket))
        if others:
            return Observation(
                CONFLICT,
                f"the machines in {want} carry ticket(s) {', '.join(others)}, "
                f"this delivery is ticket {ticket}. A cluster of the right "
                "name built for another delivery needs the opposite correction "
                "to a missing one.",
            )
        # Some members may still be unlabelled while others identify the
        # cluster as ours. PRESENT is right — one machine on this ticket is a
        # positive answer — but the evidence has to say what it could not
        # identify, or it reads as though every machine was checked. The
        # ambiguity deliberately kept above (unlabelled: "someone else's" or
        # "ours, never written") does not disappear because a sibling is
        # labelled; it just stops being the whole answer.
        unlabelled = sum(1 for m in members if machine_ticket_label(m) is None)
        caveat = (f"; {unlabelled} of them carry no {TICKET_LABEL_PREFIX} label "
                  "and were not identified either way") if unlabelled else ""
        return Observation(
            PRESENT,
            f"Omni cluster {want} exists, {path} describes it, and its machines "
            f"carry ticket {ticket}",
            evidence=(f"omnictl get clusters -> {listed} clusters; template's "
                      f"`kind: Cluster` name == {want}; {len(members)} machines "
                      f"with {CLUSTER_LABEL}={want}, ticket label(s) "
                      f"{sorted(t for t in tickets if t is not None)}{caveat}"),
        )

    def inputs(self, ctx: dict) -> list[str]:
        # `omnictl cluster template sync -f` is handed this path. Nothing in
        # this repo ships the file (measured 2026-09-12 and re-measured
        # 2026-09-14 on `main`: zero tracked files match `omni-cluster.ya?ml`,
        # positive control `cluster.sample.yaml` -> 1), so on a fresh clone it
        # is always absent and the operator has to produce it first — the
        # runbook's Step 3b says how.
        return [ctx["omni_template"]]

    def input_problems(self, ctx: dict) -> list[str]:
        found = []
        for check in (template_local_path_mount, template_cri_customization):
            ok_, why = check(ctx["omni_template"])
            if not ok_:
                found.append(why)
        return found

    def create(self, ctx: dict) -> list[list[str]]:
        return [["omnictl", "cluster", "template", "sync", "-f", ctx["omni_template"]]]


class UserRepoStep(Step):
    """4.4 — the per-cluster repo, from this template, at the derived name."""

    name = "user-repo"
    task = "4.4"

    def observe(self, ctx: dict) -> Observation:
        if not shutil.which("gh"):
            return Observation(UNMEASURABLE, "gh is not installed")
        repo = ctx["repository_name"]
        r = run(["gh", "repo", "view", repo, "--json", "name,owner,isTemplate,visibility"])
        if r.returncode == 0:
            try:
                got = json.loads(r.stdout)
            except json.JSONDecodeError:
                return Observation(UNMEASURABLE, f"gh returned unparseable JSON for {repo}")
            owner = got.get("owner", {}).get("login", "")
            if f"{owner}/{got.get('name')}" != repo:
                return Observation(
                    CONFLICT,
                    f"asked for {repo}, got {owner}/{got.get('name')} — gh resolved "
                    "a different repository than the one named",
                )
            return Observation(PRESENT, f"{repo} exists ({got.get('visibility')})")
        err = (r.stderr or "").strip()
        if "Could not resolve to a Repository" in err or "not found" in err.lower():
            # Positive control: prove the token can see *something* under this
            # owner. Without it, a revoked token's 404 reads as "no such repo".
            owner = repo.split("/", 1)[0]
            probe = run(["gh", "repo", "list", owner, "--limit", "1", "--json", "name"])
            if probe.returncode != 0 or not json.loads(probe.stdout or "[]"):
                return Observation(
                    UNMEASURABLE,
                    f"{repo} was not found, but listing {owner}'s repositories "
                    "also returned nothing — so this may be an authentication "
                    "answer rather than a repository answer",
                )
            return Observation(ABSENT, f"{repo} does not exist",
                               evidence=f"gh can list {owner}'s repositories, so the 404 is about the repo")
        return Observation(UNMEASURABLE, f"gh repo view failed: {err}")

    def create(self, ctx: dict) -> list[list[str]]:
        return [
            ["gh", "repo", "create", ctx["repository_name"],
             "--template", "ferry133/jg-cluster-template",
             f"--{ctx.get('repo_visibility', 'public')}", "--clone"],
            # GitHub's template copy takes every TRACKED file, so whatever the
            # template tracks, every customer repo gets — and a customer repo
            # is named after a customer and public. This used to mean 53 files
            # of proposals and incident records arriving in each one.
            #
            # **Fixed at the source on 2026-08-23** (`f4db750`): `openspec/` and
            # `docs/` moved to fleet-ops, and `git ls-files openspec docs` is
            # empty in the template and in jg-janncotcc. So the line below is a
            # regression guard, not a cleanup step, and it must not be read as
            # the current hazard.
            #
            # It asks the general question rather than the two names anyone
            # happens to remember, because the next tree the template grows
            # will not be called openspec. Same shape as the ignore rule that
            # named `/cluster.yaml` while the leak sat at `config.gen/`.
            ["scripts/provision.py", "template-residue", "--dir", ctx["dir"]],
        ]


# `cloudflared tunnel list --output json` sets `deleted_at` on every row, and
# for a LIVE tunnel the value is Go's zero time rather than null. Measured
# 2026-08-26 across four real tunnels: all four carried
# `deleted_at: "0001-01-01T00:00:00Z"` while all four were live.
#
# This is written down rather than fixed quietly because the first version of
# `TunnelStep.observe` treated the field as truthy, and so reported ABSENT for
# a tunnel that was sitting in the list it had just read. The consequence is
# not a wrong message: ABSENT is the one observation this driver acts on, so it
# would have created a second tunnel on every re-run — the exact failure 4.10
# exists to prevent, arrived at by a check that reads as working.
ZERO_TIME_PREFIXES = ("0001-01-01", "0000-00-00")


def tunnel_is_deleted(t: dict) -> bool:
    v = t.get("deleted_at")
    if not v:
        return False
    return not str(v).startswith(ZERO_TIME_PREFIXES)


def cmd_template_residue(args) -> int:
    """Does this spawned repo track anything a customer repo should not?

    Asked as "what is here that a cluster repo has no use for", not as "is
    `openspec/` here". A path-shaped check and a path-shaped rule share a
    premise, and `config.gen/cluster.yaml` is what that costs.

    The allowlist is the thing to review when this fires, not the finding.
    """
    d = os.path.abspath(args.dir)
    r = run(["git", "-C", d, "ls-files"])
    if r.returncode != 0:
        huh(f"{d}: git ls-files failed: {(r.stderr or '').strip()}")
        return UNKNOWN
    tops = sorted({p.split("/", 1)[0] for p in r.stdout.splitlines() if "/" in p})
    if not tops:
        huh(f"{d} tracks no files in any subdirectory — nothing to judge")
        return UNKNOWN

    residue = [t for t in tops if t not in CLUSTER_REPO_TOPLEVEL]
    if not residue:
        ok(f"{d}: {len(tops)} tracked top-level directories, all expected")
        print(f"      ({', '.join(tops)})")
        return DONE
    bad(f"{d} tracks {len(residue)} director(ies) a cluster repo has no use for: "
        + ", ".join(residue))
    print("      Remove them before the first push. Each one is a second copy of")
    print("      a tracked record: the duplicate diverges, and the one being")
    print("      followed is usually the wrong one.")
    print("      If one of these belongs here, add it to CLUSTER_REPO_TOPLEVEL")
    print("      in scripts/provision.py with the reason — reviewing the")
    print("      allowlist is the point, not silencing the finding.")
    return REFUSED


#: Top-level directories a cluster repo legitimately holds, with why.
#:
#: Module level, not a local, so a guard can assert against it — see
#: `scripts/tests/test_provision.py::TestClusterRepoToplevelCoversTheTemplate`.
#: Anything not here is residue until someone adds it *with a reason*.
#:
#: ⚠️ **A repo made from this template inherits every tracked file**, so any
#: directory this template tracks must be in here or `template-residue` flags a
#: repo that was just created and has not been touched. That is what happened
#: between 2026-09-05 and 2026-09-15: `zero-it-assets/` entered the template ten
#: days after this list was written, and nothing tied the two together, so every
#: new repo failed the check and the message told the operator to delete the
#: customer's printed handout (jgct#148).
CLUSTER_REPO_TOPLEVEL = {
    ".github": "workflows the customer repo inherits and runs",
    ".taskfiles": "the task definitions `task configure` uses",
    "bootstrap": "rendered by `task configure`; not tracked in the template",
    "flux": "Flux's own bootstrap manifests",
    "kubernetes": "rendered by `task configure`; not tracked in the template",
    "scripts": "provisioning, credential and delivery tooling",
    "talos": "rendered by `task configure`; not tracked in the template",
    "templates": "the Jinja2 sources `task configure` renders from",
    "zero-it-assets": "images the customer's printed handout references; "
                      "`build-zero-it-print.py` aborts if one cannot be resolved, "
                      "so they are load-bearing, not decoration (jgct#148)",
}


def cloudflared_tunnels() -> tuple[list[dict] | None, str]:
    """List tunnels. `None` when the origin certificate is missing.

    `cloudflared tunnel list` without `~/.cloudflared/cert.pem` prints an error
    and no tunnels. Read as "there are none" it creates a second tunnel on
    every run.
    """
    if not shutil.which("cloudflared"):
        return None, "cloudflared is not installed"
    r = run(["cloudflared", "tunnel", "list", "--output", "json"])
    if r.returncode != 0:
        return None, f"cloudflared tunnel list failed: {(r.stderr or r.stdout).strip()}"
    try:
        return json.loads(r.stdout or "[]"), ""
    except json.JSONDecodeError as e:
        return None, f"could not parse cloudflared output: {e}"


def zone_account_id(domain: str, token: str) -> tuple[str | None, str]:
    """The Cloudflare account that owns `domain`'s zone.

    `GET /zones` answers HTTP 200 with `{"success":true,"result":[]}` for a
    token that has no access to the zone — an R2 access key pasted into the DNS
    token field produced exactly that, and external-dns then filtered against an
    empty zone list and logged nothing at info level. So an empty result is
    returned as an error here, never as "no such zone".
    """
    url = f"https://api.cloudflare.com/client/v4/zones?name={domain}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.load(resp)
    except Exception as e:  # noqa: BLE001 - the class of failure is the finding
        return None, f"{url}: {e}"
    results = body.get("result") or []
    if not results:
        return None, (
            f"Cloudflare returned {len(results)} zones for {domain} under HTTP 200. "
            "A well-formed empty answer is what a token for a different account "
            "returns, so this is not read as 'the zone does not exist'."
        )
    account = (results[0].get("account") or {}).get("id", "")
    if not account:
        return None, f"zone {domain} carries no account id in the API response"
    return account, ""


class TunnelStep(Step):
    """4.5 — the Cloudflare tunnel, named deterministically.

    Two things are asserted, and the second is the one nothing else catches:
    the tunnel exists **and it is in the same Cloudflare account as the zone**.
    Measured 2026-08-23 on jg-janncotcc — a tunnel created under the wrong
    account was Healthy in its own account, the pod ran with four edge
    connections, the DNS record existed and external-dns was satisfied, while
    the hostname returned HTTP 530 / error 1033. Every cheaper check passed.
    """

    name = "tunnel"
    task = "4.5"

    def observe(self, ctx: dict) -> Observation:
        tunnels, err = cloudflared_tunnels()
        if tunnels is None:
            return Observation(UNMEASURABLE, err)
        want = ctx["tunnel_name"]
        mine = [t for t in tunnels if t.get("name") == want and not tunnel_is_deleted(t)]
        if not mine:
            if not tunnels:
                return Observation(
                    UNMEASURABLE,
                    "cloudflared listed zero tunnels. Without a positive control "
                    "this is indistinguishable from a cert.pem for an account "
                    "that holds no tunnels — check which account "
                    "~/.cloudflared/cert.pem belongs to before creating one.",
                )
            return Observation(ABSENT, f"no tunnel named {want}",
                               evidence=f"{len(tunnels)} other tunnels listed")
        if len(mine) > 1:
            return Observation(
                CONFLICT,
                f"{len(mine)} live tunnels are named {want}: "
                + ", ".join(t.get("id", "?") for t in mine)
                + ". D4's derived naming exists so this cannot happen; that it "
                "did means a previous run created one without observing first.",
            )
        tunnel_id = mine[0].get("id")
        return self._same_account(ctx, want, tunnel_id)

    def _same_account(self, ctx: dict, want: str, tunnel_id: str) -> Observation:
        """The tunnel exists. Ask the only question that catches a 1033.

        A CNAME to `<uuid>.cfargotunnel.com` routes only when the tunnel and
        the DNS record live in the SAME Cloudflare account. Cross-account,
        every cheaper check passes — measured on jg-janncotcc 2026-08-23: the
        tunnel Healthy in its own account, the pod 1/1 with four edge
        connections, the DNS record present, external-dns satisfied, and the
        hostname returning HTTP 530 / error 1033.

        Note what PRESENT means without this comparison: "a tunnel of that name
        exists in whichever account this workstation's ~/.cloudflared/cert.pem
        belongs to". That is the sentence that was true on jg-janncotcc while it
        was broken, which is why not being able to run this is UNMEASURABLE and
        not a pass.
        """
        creds = os.path.join(ctx["dir"], "cloudflare-tunnel.json")
        token = os.environ.get("CLOUDFLARE_TOKEN") or os.environ.get("CF_TOKEN")
        if not os.path.exists(creds):
            return Observation(
                UNMEASURABLE,
                f"tunnel {want} = {tunnel_id} exists, but {creds} is not here, so "
                "which account it belongs to cannot be compared with the zone's",
            )
        try:
            account_tag = json.load(open(creds)).get("AccountTag", "")
        except (OSError, json.JSONDecodeError) as e:
            return Observation(UNMEASURABLE, f"cannot read {creds}: {e}")
        if not token:
            return Observation(
                UNMEASURABLE,
                f"tunnel {want} = {tunnel_id} is in account {account_tag[:8]}…, but "
                "CLOUDFLARE_TOKEN is unset so the zone's account cannot be read. "
                "This is the one check that catches a 1033; skipping it is not a pass.",
            )
        zone_account, err = zone_account_id(ctx["domain"], token)
        if zone_account is None:
            return Observation(UNMEASURABLE, f"cannot read the zone's account: {err}")
        if zone_account != account_tag:
            return Observation(
                CONFLICT,
                f"tunnel {want} ({tunnel_id}) is in account {account_tag[:8]}… while "
                f"zone {ctx['domain']} is in {zone_account[:8]}…. The tunnel cannot be "
                "moved: delete it, re-run `cloudflared tunnel login` selecting a zone "
                "in the correct account, create it again, re-render and confirm the "
                "CNAME was rewritten before calling this done.",
            )
        return Observation(PRESENT,
                           f"tunnel {want} = {tunnel_id}, same account as zone {ctx['domain']}")

    def create(self, ctx: dict) -> list[list[str]]:
        return [["cloudflared", "tunnel", "create",
                 "--credentials-file", os.path.join(ctx["dir"], "cloudflare-tunnel.json"),
                 ctx["tunnel_name"]]]


class ClusterYamlStep(Step):
    """4.6 — `cluster.yaml`, with network values taken from Omni, not typed.

    The rule is 4.6's, and it is narrower than "fill in the config": the
    **network** values come from what Omni reports the machine's interfaces
    actually are. A typed CIDR that does not match the customer's LAN produces
    a cluster that comes up and is unreachable, and nothing in the render or
    the schema can tell — `cue vet` accepts any well-formed CIDR.
    """

    name = "cluster-yaml"
    task = "4.6"

    def observe(self, ctx: dict) -> Observation:
        path = os.path.join(ctx["dir"], "cluster.yaml")
        if not os.path.exists(path):
            return Observation(ABSENT, f"{path} does not exist",
                               evidence="checked the path directly; no query involved")
        text = open(path).read()
        want = ctx["cluster_name"]
        m = re.search(r"(?m)^\s*cluster_name\s*:\s*[\"']?([A-Za-z0-9_-]+)", text)
        if not m:
            return Observation(CONFLICT, f"{path} exists but sets no cluster_name")
        if m.group(1) != want:
            return Observation(
                CONFLICT,
                f"{path} is for cluster {m.group(1)!r}, this delivery is {want!r}. "
                "Rendering over it would produce another cluster's tree here.",
            )
        return Observation(PRESENT, f"{path} is this cluster's")

    def create(self, ctx: dict) -> list[list[str]]:
        return [["task", "init"],
                ["#", "then fill cluster.yaml — network values from `provision.py derive`"]]


class ConfigurePushStep(Step):
    """4.7 — render, then commit and push the rendered tree.

    Two assertions the runbook adds, both of which read as passing when absent:

    - `cluster.yaml` must still be absent from history, by content and at any
      path. `config.gen/cluster.yaml` leaked in two public repos past a rule
      and a check that both named `/cluster.yaml`.
    - the tree must be clean **after** re-running `task configure`. A dirty
      tree means what is deployed came from a previous render, not from the
      `cluster.yaml` on this machine.
    """

    name = "configure-push"
    task = "4.7"

    def observe(self, ctx: dict) -> Observation:
        d = ctx["dir"]
        if not os.path.isdir(os.path.join(d, ".git")):
            return Observation(UNMEASURABLE, f"{d} is not a git repository")
        leak = run(["git", "-C", d, "log", "--all", "--oneline", "--", "*cluster.yaml"])
        if leak.returncode != 0:
            return Observation(UNMEASURABLE, f"git log failed: {leak.stderr.strip()}")
        if leak.stdout.strip():
            return Observation(
                CONFLICT,
                "cluster.yaml is in this repository's history:\n      "
                + "\n      ".join(leak.stdout.strip().splitlines()[:5])
                + "\n      Stop the delivery. Close the path first (fix the ignore "
                  "rule), then rotate — rotating first commits the new credential "
                  "down the same open path, which is how jg-jiahd accumulated 8 "
                  "distinct Cloudflare tokens across 11 copies.",
            )
        status = run(["git", "-C", d, "status", "--short"])
        if status.returncode != 0:
            return Observation(UNMEASURABLE, f"git status failed: {status.stderr.strip()}")
        if status.stdout.strip():
            return Observation(ABSENT, "rendered tree is not committed",
                               evidence="git status is non-empty")
        head = run(["git", "-C", d, "rev-parse", "HEAD"])
        return Observation(PRESENT, f"tree clean at {head.stdout.strip()[:12]}")

    def create(self, ctx: dict) -> list[list[str]]:
        return [
            ["task", "configure", "--yes"],
            ["scripts/delivery-check.py", "repo-hygiene", "--dir", ctx["dir"], "--deep"],
            ["git", "-C", ctx["dir"], "add", "kubernetes"],
            # jgct#178 — between `add` and `commit`, because this is the only
            # moment the thing about to be published exists as an object git
            # can be asked about while there is still a step left to stop at.
            # The `--deep` call above scans `--all` history, and the tree
            # staged here is not on any ref yet; `commit` puts it there and
            # `push` is the very next command. **So a scan placed after
            # `commit` would not be too late for `push` — it would be too late
            # for the history**: the content is permanent by then, and
            # untracking does not unpublish. That is why this sits here and not
            # one line down.
            ["scripts/delivery-check.py", "repo-hygiene", "--dir", ctx["dir"],
             "--staged"],
            ["git", "-C", ctx["dir"], "commit", "-m", "chore: rendered cluster configuration"],
            ["git", "-C", ctx["dir"], "push"],
        ]


class KubeconfigStep(Step):
    """4.8 — a service-account kubeconfig, kept separate from the OIDC one.

    `kubeconfig-sa` is what automation uses; `kubeconfig` is the browser-login
    version and is the way back in when the SA token expires. Overwriting the
    second with the first throws that away, so this writes only `kubeconfig-sa`.

    ⚠️ Inference, not measurement, and it belongs to whoever runs this
    unattended: `task bootstrap:apps` has no `--kubeconfig` flag and mise
    re-applies `KUBECONFIG = {{config_root}}/kubeconfig` inside every command
    it wraps, so an inline `KUBECONFIG=` assignment does not reach it. On the
    Omni path that file is an exec-based OIDC config needing a browser. The
    §7.2 run proceeded only because a cached oidc-login token happened to
    exist; nobody has yet run this step on a machine without one.
    """

    name = "kubeconfig-sa"
    task = "4.8"

    def observe(self, ctx: dict) -> Observation:
        path = os.path.join(ctx["dir"], "kubeconfig-sa")
        if not os.path.exists(path):
            return Observation(ABSENT, f"{path} does not exist")
        if not shutil.which("kubectl"):
            return Observation(UNMEASURABLE, "kubectl is not installed; cannot tell if it works")
        r = run(["kubectl", "--kubeconfig", path, "get", "nodes", "-o", "name"])
        if r.returncode != 0:
            return Observation(
                CONFLICT,
                f"{path} exists but does not work: {(r.stderr or '').strip()[:200]}. "
                "An expired SA token and a wrong cluster produce the same file.",
            )
        return Observation(PRESENT, f"{path} reaches {len(r.stdout.split())} node(s)")

    def create(self, ctx: dict) -> list[list[str]]:
        return [["omnictl", "kubeconfig", os.path.join(ctx["dir"], "kubeconfig-sa"),
                 "--cluster", ctx["cluster_name"], "--service-account",
                 "--user", "ferry133", "--ttl", "8760h"]]


STEPS: list[Step] = [
    OmniClusterStep(),
    UserRepoStep(),
    TunnelStep(),
    ClusterYamlStep(),
    ConfigurePushStep(),
    KubeconfigStep(),
]


# ------------------------------------------------- 4.1 / 4.2 machine ↔ ticket

def open_delivery_tickets(repo: str | None) -> tuple[list[dict] | None, str]:
    if not shutil.which("gh"):
        return None, "gh is not installed"
    cmd = ["gh", "issue", "list", "--state", "open", "--label", PHASE_PROVISIONING,
           "--json", "number,title,labels", "--limit", "100"]
    if repo:
        cmd += ["--repo", repo]
    r = run(cmd)
    if r.returncode != 0:
        return None, f"gh issue list failed: {(r.stderr or '').strip()}"
    try:
        return json.loads(r.stdout or "[]"), ""
    except json.JSONDecodeError as e:
        return None, f"could not parse gh output: {e}"


def machine_ticket_label(machine: dict) -> str | None:
    """The ticket identifier a machine carries, or None.

    Written onto the machine by `omnictl media preset create --initial-labels`
    at image-build time, so this is a lookup. It is deliberately not a
    similarity judgement over hostname, MAC or arrival time: those match
    approximately, and 4.2's refusal has to be exact to be worth anything.
    """
    labels = machine.get("metadata", {}).get("labels", {}) or {}
    for k, v in labels.items():
        if k == TICKET_LABEL_PREFIX:
            return str(v)
        if k.startswith(TICKET_LABEL_PREFIX + "/"):
            return k.split("/", 1)[1]
    return None


def cmd_detect(args) -> int:
    """4.1 + 4.2 — match registered machines against open tickets.

    Reports four groups, and three of them are findings:

      matched      a machine and exactly one open ticket agree
      unmatched    a machine carrying no ticket label, or one nobody opened.
                   **Never provisioned automatically.** `zero-it-onboarding`
                   D13 leans on this: the join token is allowed not to expire
                   *because* an unknown machine cannot become a cluster. Anyone
                   relaxing this is changing a security premise in another
                   change, and will not know it.
      ambiguous    two machines claiming one ticket, or the reverse
      waiting      an open ticket with no machine — 4.13's case, not an error
    """
    rows, err = omnictl_json("machinestatus")
    if rows is None:
        huh(f"cannot read machines from Omni: {err}")
        print("      Not reported as 'no machines'. An unreachable Omni and an")
        print("      empty Omni produce the same empty list, and only one of")
        print("      them means nothing is waiting to be provisioned.")
        return UNKNOWN

    tickets, terr = open_delivery_tickets(args.ticket_repo)
    if tickets is None:
        huh(f"cannot read tickets: {terr}")
        return UNKNOWN

    by_ticket: dict[str, list[str]] = {}
    unlabelled: list[str] = []
    for m in rows:
        uuid = m.get("metadata", {}).get("id", "?")
        t = machine_ticket_label(m)
        if t is None:
            unlabelled.append(uuid)
        else:
            by_ticket.setdefault(t, []).append(uuid)

    open_ids = {str(t["number"]) for t in tickets}
    print(f"machines in Omni:      {len(rows)}")
    print(f"open provisioning tickets: {len(tickets)}"
          + (f" (in {args.ticket_repo})" if args.ticket_repo else ""))
    print()

    exit_code = DONE
    for tid in sorted(by_ticket):
        uuids = by_ticket[tid]
        if tid not in open_ids:
            bad(f"machine(s) {', '.join(uuids)} carry ticket {tid}, which is not "
                "an open provisioning ticket")
            print("      Reported, not acted on. The label was written when the")
            print("      disk was imaged; a ticket that has since closed, moved")
            print("      phase or never existed are three different situations")
            print("      needing three different corrections.")
            exit_code = REFUSED
        elif len(uuids) > 1:
            bad(f"ticket {tid} is claimed by {len(uuids)} machines: {', '.join(uuids)}")
            print("      One delivery, one ticket, one machine set — deciding which")
            print("      of these the ticket meant is a question about the world.")
            exit_code = REFUSED
        else:
            ok(f"ticket {tid} <- machine {uuids[0]}")

    for uuid in unlabelled:
        bad(f"machine {uuid} carries no {TICKET_LABEL_PREFIX} label")
        print("      Will not be provisioned. A machine with no ticket is either")
        print("      a bench machine, a disk imaged before presets carried labels,")
        print("      or one that should not be talking to this Omni at all.")
        exit_code = REFUSED

    for t in tickets:
        if str(t["number"]) not in by_ticket:
            huh(f"ticket {t['number']} ({t['title']}) has no machine yet")
            print("      Not a failure. Run `provision.py absent --ticket "
                  f"{t['number']}` for what to check and what not to assert.")
    return exit_code


# --------------------------------------------------- 4.6 derive from Omni

def cmd_derive(args) -> int:
    """4.6 — network values read off the machine, never typed.

    The shape of `MachineStatusSpec.network` was originally read from Omni's
    protobuf definitions (`client/api/omni/specs/omni.proto`, §1.1's spike) and
    not from a live machine, with a note here saying the first real run should
    confirm the field names. **That run happened on 2026-09-14 (`jg-jcc1`) and
    the note earned its keep: one of the names was wrong.** `defaultgateways`
    is what the JSON carries; `default_gateways` is the proto name and matches
    nothing in the reply (#152).

    So the names below are now part proto-derived and part observed. The two
    that have been seen on a live machine are `addresses` and `defaultgateways`.
    Every lookup still fails to UNKNOWN rather than to a default, and reading a
    key by a name the reply does not use produces exactly the same silence as a
    machine that has not finished DHCP — which is why the absent key and the
    empty list are now reported separately below.
    """
    rows, err = omnictl_json("machinestatus", args.machine)
    if rows is None:
        huh(f"cannot read machine {args.machine}: {err}")
        return UNKNOWN
    if not rows:
        huh(f"Omni has no machinestatus for {args.machine}")
        return UNKNOWN

    net = (rows[0].get("spec") or {}).get("network") or {}
    addrs = net.get("addresses") or []
    # `defaultgateways`, all lower case. NOT `default_gateways` (the proto field
    # name, `omni.proto:130`) and NOT `defaultGateways` (the `json=` tag in the
    # generated Go). What `omnictl get machinestatus -o json` actually emits is
    # the lower-case form — measured 2026-09-14 against a live Omni on `jg-jcc1`,
    # where the key was there with a value and this code read `None` (#152).
    #
    # Read into a sentinel, not `or []`: **"the key is not there" and "Omni says
    # there are none" need opposite next actions**, and `or []` collapses them.
    # That collapse is what #152 was: the wrong name produced an absent key, the
    # absent key became `[]`, and `[]` was reported as "no default gateway
    # reported" — a statement about Omni that was really a statement about this
    # query. It then fell back to the template's `.1`-of-`node_cidr` guess,
    # which is the assumption `#49` exists to have removed.
    _GW_ABSENT = object()
    gws_raw = net.get("defaultgateways", _GW_ABSENT)
    gws = [] if gws_raw is _GW_ABSENT else (gws_raw or [])
    if not addrs:
        huh(f"machine {args.machine} reports no addresses "
            f"(keys present: {', '.join(sorted(net)) or 'none'})")
        print("      Not defaulted. A machine that has not finished DHCP and a")
        print("      field this code is reading by the wrong name look the same.")
        return UNKNOWN

    nets = set()
    for a in addrs:
        try:
            iface = ipaddress.ip_interface(a)
        except ValueError:
            continue
        if iface.ip.is_loopback or iface.ip.is_link_local or iface.version != 4:
            continue
        nets.add(str(iface.network))
    if len(nets) != 1:
        bad(f"machine reports {len(nets)} candidate IPv4 subnets: "
            f"{', '.join(sorted(nets)) or '(none)'}")
        print("      Refusing to pick. node_cidr is one value and getting it wrong")
        print("      produces a cluster that comes up unreachable, which nothing")
        print("      in the render or the schema can detect.")
        return REFUSED

    node_cidr = nets.pop()
    print(f"node_cidr:            {node_cidr}")
    if len(gws) == 1:
        print(f"node_default_gateway: {gws[0]}")
    elif gws:
        huh(f"{len(gws)} default gateways reported: {', '.join(gws)} — pick by hand")
    elif gws_raw is _GW_ABSENT:
        # Not "Omni says none". This code looked for a key that is not in the
        # reply at all, which is what reading it by the wrong name looks like.
        huh(f"machine {args.machine} has no `defaultgateways` key in its network "
            f"block (keys present: {', '.join(sorted(net)) or 'none'})")
        print("      That is this command asking for something the reply does not")
        print("      have — a question about the name, not an answer about the")
        print("      network. Do not fall back to a default on it: check the key")
        print("      name against `omnictl get machinestatus -o json` first (#152).")
        return UNKNOWN
    else:
        huh("`defaultgateways` is present and empty: Omni reports no default "
            "gateway for this machine")
        print("      This one IS an answer, and it is the case the template's")
        print("      .1-of-node_cidr default was written for — but it is still a")
        print("      guess, which is what #49 removed. Confirm it on the machine.")

    if args.profile == "appliance":
        print()
        print("profile=appliance: no cluster_api_addr / cluster_gateway_addr /")
        print("cluster_dns_gateway_addr / cloudflare_gateway_addr. The appliance")
        print("discovers its single LAN address at runtime, and the schema")
        print("rejects those fields on this profile rather than ignoring them.")
    else:
        print()
        print("Remaining LB/VIP addresses are a choice about the customer's LAN,")
        print("not a fact Omni reports. Pick THREE unused addresses in the CIDR")
        print("above -- cluster_gateway_addr, cluster_dns_gateway_addr and")
        print("cloudflare_gateway_addr -- and record which, on the ticket.")
        print()
        print("NOT cluster_api_addr (jgct#188): this command only speaks to")
        print("Omni, so the cluster it is describing is on provisioning_path")
        print("omni, where the API is reached through the Omni proxy and that")
        print("field has no consumer. The schema stopped requiring it there.")
        print("It is still accepted if your cluster.yaml already has one.")
    return DONE


# -------------------------------------------------- 4.13 machine not appeared

ABSENT_MACHINE_REPORT = """\
The machine has not appeared in Omni.

**This report enumerates causes. It does not name one.** Every item below
produces exactly the same observation from here — an absence — and the whole
point of writing them all down is that the absence does not distinguish them.

Causes, in the order they are cheapest to rule out:

  1. The box has not been unpacked, plugged in or switched on.
  2. The network cable is in a port that is not live, or in the wrong socket.
  3. The customer's DHCP did not hand out a lease.
  4. The customer's network blocks the machine's egress to Omni.
     Shipped disks are imaged with `--use-siderolink-grpc-tunnel`, so
     SideroLink runs over HTTP/2 on 443 rather than UDP (`zero-it-onboarding`
     D12 ruled this on by default precisely because the UDP failure is
     indistinguishable from "not plugged in" from this end). If the disk for
     this delivery predates that ruling, UDP blocking is back on this list.
  5. The join token burned into that disk has been revoked or expired.
  6. The disk does not hold what was shipped — it booted to nothing, or it was
     re-imaged. Step −1's assertion (`installed = True`, `maintenance = True`)
     is what would have caught this before the box left, so check whether that
     assertion was recorded for this machine, not whether it was performed.
  7. Omni itself is not reachable from here, in which case *every* machine is
     absent. Check that other machines are still listed before reading this
     machine's absence as being about this machine.

**Do not tell the customer which one it is.** Ask them for the three things
they can observe without opening anything:

  - Is there a light on the front of the box?
  - Is there a light next to the network cable where it plugs into the box?
  - Is there a light where the other end plugs in?

Those three answers separate causes 1–3 from 4–7. Nothing else on this list can
be told apart from the factory, and guessing on the customer's behalf turns a
five-minute check into a site visit.
"""


def cmd_absent(args) -> int:
    print(ABSENT_MACHINE_REPORT)
    print()
    print("Post this to the ticket verbatim rather than summarising it:")
    print(f"  provision.py absent --ticket {args.ticket} | \\")
    print(f"    scripts/delivery-ticket.py comment {args.ticket} --file -")
    return DONE


# ------------------------------------------------------------ 4.10 the driver

DECISION = {
    # observation   -> (act?, why this is the only safe reading)
    PRESENT: (False, "already exists — this is what makes a re-run converge"),
    ABSENT: (True, "not there, and the query that would have found it worked"),
    CONFLICT: (False, "something else is there; two opposite corrections fit"),
    UNMEASURABLE: (False, "the query did not work, so absence is not an answer"),
}


def drive(ctx: dict, apply_: bool) -> int:
    """Walk the steps in order. Observe, then act only on ABSENT.

    Stops at the first CONFLICT or UNMEASURABLE. Continuing past either means
    the next step's observation is being made in a world nobody has described.
    """
    worst = DONE
    for step in STEPS:
        obs = step.observe(ctx)
        act, why = DECISION[obs.state]
        head = f"[{step.task}] {step.name}"

        if obs.state == PRESENT:
            ok(f"{head}: {obs.detail}")
            continue

        if obs.state == UNMEASURABLE:
            huh(f"{head}: {obs.detail}")
            print(f"      Stopping. {why}.")
            print("      Creating here is how a re-run produces a second one.")
            return UNKNOWN

        if obs.state == CONFLICT:
            bad(f"{head}: {obs.detail}")
            print(f"      Stopping. {why}.")
            return REFUSED

        # ABSENT
        cmds = step.create(ctx)
        if obs.evidence:
            print(f"      (query worked: {obs.evidence})")
        if not apply_:
            print(f"WOULD {head}: {obs.detail}")
            for c in cmds:
                print("        " + (" ".join(c) if c[0] != "#" else " ".join(c)))
            worst = max(worst, DONE)
            continue

        # About to act. Now — and only now — the files this step will hand to
        # an external CLI have to be here. The driver refuses to act on an
        # UNMEASURABLE observation of the outside world; its own inputs are not
        # exempt, and `omnictl cluster template sync -f <missing>` fails inside
        # omnictl, which reports it as an omnictl problem several lines away
        # from the thing that is actually wrong.
        missing = [p for p in step.inputs(ctx) if not os.path.exists(p)]
        if missing:
            huh(f"{head}: needs a file that is not here: " + ", ".join(missing))
            print("      Stopping. This step's own input could not be measured, "
                  "so acting would be acting on a world nobody described.")
            print("      (The runbook's Step 3b says where this file comes from.)")
            return UNKNOWN

        # The file is here; what it says can still be wrong in a way only a
        # running cluster would show (jgct#207). Same moment, same reason.
        problems = step.input_problems(ctx)
        if problems:
            bad(f"{head}: its input would build the wrong thing")
            for p in problems:
                print("      " + p.replace("\n", "\n      "))
            print("      Stopping before acting: after the create, this is in a running cluster.")
            return REFUSED

        print(f"DO    {head}: {obs.detail}")
        for c in cmds:
            if c[0] == "#":
                print("      -- manual step: " + " ".join(c[1:]))
                return escalate(
                    f"{step.name} needs a step no machine can do",
                    None,
                    "a command",
                    " ".join(c[1:]),
                )
            print("      $ " + " ".join(c))
            r = run(c)
            if r.returncode != 0:
                return escalate(f"{step.name} ({step.task})", c,
                                "exit 0", (r.stderr or r.stdout))
        # Re-observe. A create that returned 0 and produced nothing is a real
        # shape here — `gh repo create` succeeds against a name that already
        # existed under a different owner — and it reads as success.
        after = step.observe(ctx)
        if after.state != PRESENT:
            return escalate(
                f"{step.name} ({step.task}) reported success but is still not there",
                None, f"{step.name} PRESENT", f"{after.state}: {after.detail}")
        ok(f"{head}: created, re-observed present")
    return worst


def build_ctx(args) -> dict:
    names = derive_names(args.domain, getattr(args, "owner", "ferry133"))
    d = os.path.abspath(args.dir)
    return {
        **names,
        "dir": d,
        "omni_template": os.path.join(d, "omni-cluster.yaml"),
        "repo_visibility": getattr(args, "visibility", "public"),
        # Optional on purpose: see OmniClusterStep._members_carry_this_ticket.
        "ticket": getattr(args, "ticket", None),
    }


def cmd_plan(args) -> int:
    ctx = build_ctx(args)
    for k in ("cluster_name", "repository_name", "tunnel_name", "dir"):
        print(f"{k:16} {ctx[k]}")
    print()
    return drive(ctx, apply_=False)


def cmd_run(args) -> int:
    ctx = build_ctx(args)
    if not args.apply:
        print("(no --apply: nothing will be created)")
        print()
    return drive(ctx, apply_=args.apply)


# ------------------------------------------------------- 4.11 QUIC repair

QUIC_SIGNATURE = "Failed to dial a quic connection"


def cmd_quic_repair(args) -> int:
    """4.11 — detect UDP 7844 being blocked, switch to http2, verify, record.

    The symptom is a cloudflared CrashLoopBackOff with repeated QUIC handshake
    timeouts while TCP 443 works. It is not a token problem and rotating the
    token does not help — that is worth stating because rotating is the first
    thing anyone tries, and it produces a new credential and the same crash.

    The repair is a value in `cluster.yaml`, not a hand-edited manifest.
    Before `cloudflare_tunnel_transport` existed the documented fix was a
    nested patch pasted into the user repo's `ks.yaml.j2` — which meant the
    repair lived only in whichever repo someone had pasted it into, and a
    re-render by anyone else silently undid it.
    """
    if not shutil.which("kubectl"):
        huh("kubectl is not installed")
        return UNKNOWN
    kc = ["--kubeconfig", args.kubeconfig]

    pods = run(["kubectl", *kc, "-n", "network", "get", "pods",
                "-l", "app.kubernetes.io/name=cloudflare-tunnel",
                "-o", "json"])
    if pods.returncode != 0:
        huh(f"cannot list cloudflared pods: {(pods.stderr or '').strip()}")
        return UNKNOWN
    items = json.loads(pods.stdout or "{}").get("items", [])
    if not items:
        huh("no cloudflared pod found in namespace network")
        print("      Not reported as healthy. A cluster without the tunnel")
        print("      deployed and one whose pod was deleted look the same here.")
        return UNKNOWN

    name = items[0]["metadata"]["name"]
    logs = run(["kubectl", *kc, "-n", "network", "logs", name,
                "--tail", "200", "--all-containers"])
    if logs.returncode != 0:
        # A CrashLoopBackOff pod's current container has no logs; the previous
        # one does, and that is exactly the case being diagnosed.
        logs = run(["kubectl", *kc, "-n", "network", "logs", name,
                    "--previous", "--tail", "200", "--all-containers"])
    if logs.returncode != 0:
        huh(f"could not read logs from {name}: {(logs.stderr or '').strip()}")
        return UNKNOWN

    if QUIC_SIGNATURE not in logs.stdout:
        ok(f"{name}: no QUIC handshake failures in the last 200 lines")
        print("      This says the logs do not show it now. A pod that has just")
        print("      restarted has short logs; check restart count before")
        print("      concluding the transport is fine.")
        return DONE

    n = logs.stdout.count(QUIC_SIGNATURE)
    bad(f"{name}: {n} QUIC handshake failures — the node's egress blocks UDP 7844")
    print("      Not a token problem. Rotating the token produces a new")
    print("      credential and the identical crash.")
    print()

    path = os.path.join(os.path.abspath(args.dir), "cluster.yaml")
    fix = 'cloudflare_tunnel_transport: "http2"'
    if not os.path.exists(path):
        huh(f"{path} not found; cannot apply the repair from here")
        return UNKNOWN
    text = open(path).read()
    if re.search(r"(?m)^\s*cloudflare_tunnel_transport\s*:\s*[\"']?http2", text):
        bad("cluster.yaml already sets http2, and QUIC errors are still being logged")
        print("      So the value did not reach the cluster. Check that the")
        print("      render was committed and that Flux fetched that SHA before")
        print("      concluding anything about the network.")
        return REFUSED

    if not args.apply:
        print(f"WOULD set {fix} in {path}, then:")
        print("        task configure --yes && git commit && git push")
        print("        wait for Flux, then re-run this command to verify recovery")
        return DONE

    if re.search(r"(?m)^\s*#?\s*cloudflare_tunnel_transport\s*:", text):
        text = re.sub(r"(?m)^\s*#?\s*cloudflare_tunnel_transport\s*:.*$", fix, text)
    else:
        text += f"\n# Set by provision.py quic-repair: {n} QUIC handshake timeouts observed.\n{fix}\n"
    open(path, "w").write(text)
    ok(f"set {fix} in cluster.yaml")
    print()
    print("Record on the ticket — the action, not the conclusion:")
    print(f"  observed {n}x '{QUIC_SIGNATURE}' in {name}")
    print(f"  set cloudflare_tunnel_transport: http2 in {path}")
    print("  recovery NOT yet verified: re-run this command after Flux has")
    print("  fetched the new SHA. Until then the repair is applied, not proven.")
    return DONE


# --------------------------------------------------------- 4.9 completion

def cmd_complete(args) -> int:
    """4.9 — the delivery is complete only when three things hold at once.

    Flux has fetched the pushed commit, the resident agent answers from
    outside, and the escrowed key has been compared against this cluster's
    recipient. Any one of them alone is a green light on a delivery that is not
    one; the third is 5.5's gate, kept after escrow itself became a human step.
    """
    ctx = build_ctx(args)
    results = []

    here = os.path.dirname(os.path.abspath(__file__))
    check = os.path.join(here, "delivery-check.py")

    r = run([sys.executable, check, "flux",
             "--kubeconfig", os.path.join(ctx["dir"], "kubeconfig-sa"),
             "--expect-sha", args.expect_sha])
    print(r.stdout.rstrip() or r.stderr.rstrip())
    results.append(("flux at pushed SHA", r.returncode))

    instance = args.instance
    url = f"https://{instance}.{ctx['domain']}/"
    try:
        req = urllib.request.Request(url, method="GET")
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(req, timeout=15) as resp:
            code, loc = resp.status, resp.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        code, loc = e.code, e.headers.get("Location", "")
    except Exception as e:  # noqa: BLE001 - the class of failure is the finding
        huh(f"{url}: {e}")
        print("      Could not tell. Unreachable-from-here and not-deployed are")
        print("      the same observation from this side of the tunnel.")
        results.append(("agent reachable", UNKNOWN))
        code, loc = None, ""
    if code is not None:
        if code in (301, 302, 303, 307, 308) and "/authorize" in loc:
            ok(f"{url} -> {code} to the OIDC /authorize endpoint")
            results.append(("agent reachable", DONE))
        elif code == 503:
            bad(f"{url} -> 503. In OIDC mode oauth2-proxy is the only route in, "
                "so this is 'no way in at all', not 'one sidecar is unhappy'.")
            results.append(("agent reachable", REFUSED))
        else:
            bad(f"{url} -> {code} (Location: {loc or 'none'}); expected a redirect to /authorize")
            results.append(("agent reachable", REFUSED))

    if not args.escrowed_pubkey:
        bad("no --escrowed-pubkey given, so the escrow gate cannot be evaluated")
        print("      Refusing to call the delivery complete. This gate is the")
        print("      surviving half of 5.5: escrow became a human step, and what")
        print("      a machine still checks is that the human's copy derives the")
        print("      same public half as this cluster's .sops.yaml recipient.")
        print("      What it does NOT check: that the escrowed copy can restore")
        print("      anything, or that the public key was derived from the copy")
        print("      rather than pasted from .sops.yaml. Deliberate forgery is a")
        print("      different threat and this gate does not address it.")
        results.append(("escrow compared", REFUSED))
    else:
        sops_path = os.path.join(ctx["dir"], ".sops.yaml")
        try:
            recipients = re.findall(r"age1[a-z0-9]{20,}", open(sops_path).read())
        except FileNotFoundError:
            huh(f"{sops_path} not found; nothing to compare against")
            recipients = None
        if recipients is None:
            results.append(("escrow compared", UNKNOWN))
        elif not recipients:
            huh(f"no age recipient in {sops_path}")
            results.append(("escrow compared", UNKNOWN))
        elif args.escrowed_pubkey in recipients:
            ok(f"escrowed copy's public half {args.escrowed_pubkey[:16]}… is a "
               f"recipient in {sops_path}")
            print("      Record as: compared, public halves match verbatim.")
            results.append(("escrow compared", DONE))
        else:
            bad("the escrowed copy's public half is NOT a recipient of this cluster")
            results.append(("escrow compared", REFUSED))

    print()
    worst = max(c for _, c in results)
    for label, c in results:
        print(f"  {'PASS' if c == DONE else 'FAIL' if c == REFUSED else '?   '}  {label}")
    print()
    if worst == DONE:
        ok("delivery may be marked complete")
        print("      Then: scripts/delivery-ticket.py advance <issue> --to delivery/handover")
    else:
        print("NOT complete. Do not advance the ticket; a phase advanced past")
        print("work that did not finish is how a delivery reaches handover with")
        print("verification never having run.")
    return worst


def cmd_identity(args) -> int:
    """5.3 - who can log in to this cluster's terminal, and who cannot.

    Two assertions, and the first is about a silence:

    **`claudecode_allowed_emails` unset does not mean "nobody".** Read from
    `templates/scripts/plugin.py:315-317`: when `cluster.yaml` does not set it,
    the shared `auth0.json`'s `allowed_emails` is used via `setdefault`. That
    file carries the operator's addresses, so an unset field puts the company on
    a customer's allowlist and renders without saying so. Unset and
    deliberately-empty are the same text in `cluster.yaml` and different
    clusters in production.

    **A service identity must not be a login identity.** The Omni service
    account, the GitHub PAT's account and the backup keys address machines.
    Anything of theirs in a human allowlist means one credential opens two
    doors, and revoking it at handover closes one somebody is still using.
    """
    d = os.path.abspath(args.dir)
    cfg = os.path.join(d, "cluster.yaml")
    if not os.path.exists(cfg):
        huh(f"{cfg} not found")
        return UNKNOWN
    text = open(cfg).read()

    m = re.search(r"(?ms)^claudecode_allowed_emails\s*:\s*(.*?)(?=^\S|\Z)", text)
    raw = m.group(1) if m else ""
    emails = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", raw)

    domain_m = re.search(r"""(?m)^cloudflare_domain\s*:\s*["']?([\w.-]+)""", text)
    domain = domain_m.group(1) if domain_m else None

    rc = DONE
    if not m:
        bad("claudecode_allowed_emails is not set in cluster.yaml")
        print("      This is NOT an empty allowlist. plugin.py falls back to")
        print("      auth0.json's allowed_emails, which carries the operator's")
        print("      addresses - so this cluster renders with the company on the")
        print("      customer's allowlist, and nothing in the diff says so.")
        print("      Set it explicitly, even to the same list.")
        rc = REFUSED
    elif not emails:
        bad("claudecode_allowed_emails is set but contains no address")
        rc = REFUSED
    else:
        ok(f"claudecode_allowed_emails is set explicitly: {len(emails)} address(es)")
        for e in emails:
            host = e.partition("@")[2]
            if domain and host.endswith(domain):
                print(f"      {e}  (this cluster's own domain)")
            else:
                print(f"      {e}  <- not {domain or 'the cluster domain'}: is this "
                      "the customer, or whoever provisioned the cluster?")
        print("      Record the decision on the ticket. Nothing catches an")
        print("      operator address left on a customer's allowlist: login")
        print("      works, the terminal opens, and it opens for the wrong person.")

    machineish = [e for e in emails
                  if re.search(r"(?i)(service|svc|bot|automation|noreply|no-reply)", e)]
    if machineish:
        bad(f"machine-shaped address(es) in the human allowlist: {', '.join(machineish)}")
        print("      A service identity that can also log in means one credential")
        print("      opens two doors, and revoking it at handover closes one")
        print("      somebody is still using.")
        rc = REFUSED
    elif emails:
        ok("no machine-shaped address in the allowlist")
        print("      Name-shaped, so it is weak: it catches the conventions this")
        print("      fleet uses, not an address that simply looks human.")
    return rc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):  # noqa: D102
        return None


# ----------------------------------------------------------------- main

def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("names", help="4.4 derive cluster/repo/tunnel names")
    n.add_argument("--domain", required=True)
    n.add_argument("--owner", default="ferry133")
    n.set_defaults(func=cmd_names)

    d = sub.add_parser("detect", help="4.1/4.2 match machines to open tickets")
    d.add_argument("--ticket-repo")
    d.set_defaults(func=cmd_detect)

    a = sub.add_parser("absent", help="4.13 report a machine that has not appeared")
    a.add_argument("--ticket", required=True)
    a.set_defaults(func=cmd_absent)

    dv = sub.add_parser("derive", help="4.6 network values from Omni's view")
    dv.add_argument("--machine", required=True)
    dv.add_argument("--profile", default="full")
    dv.set_defaults(func=cmd_derive)

    for name, fn, helptext in (("plan", cmd_plan, "4.10 observe every step, create nothing"),
                               ("run", cmd_run, "4.3-4.8 observe then create")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--domain", required=True)
        s.add_argument("--dir", default=".")
        s.add_argument("--ticket", default=None,
                       help="delivery ticket number. Optional: without it 4.3 "
                            "cannot tell this delivery's cluster from another "
                            "one of the same name, and says so.")
        s.add_argument("--owner", default="ferry133")
        s.add_argument("--visibility", default="public", choices=["public", "private"])
        if name == "run":
            s.add_argument("--apply", action="store_true",
                           help="actually create. Without it nothing is mutated.")
        s.set_defaults(func=fn)

    tr = sub.add_parser("template-residue",
                        help="4.4 what a spawned repo tracks that it should not")
    tr.add_argument("--dir", default=".")
    tr.set_defaults(func=cmd_template_residue)

    q = sub.add_parser("quic-repair", help="4.11 detect blocked UDP 7844 and switch to http2")
    q.add_argument("--kubeconfig", required=True)
    q.add_argument("--dir", default=".")
    q.add_argument("--apply", action="store_true")
    q.set_defaults(func=cmd_quic_repair)

    i = sub.add_parser("identity", help="5.3 who can log in, and who must not")
    i.add_argument("--dir", default=".")
    i.set_defaults(func=cmd_identity)

    c = sub.add_parser("complete", help="4.9 the three conditions for 'delivered'")
    c.add_argument("--domain", required=True)
    c.add_argument("--dir", default=".")
    c.add_argument("--owner", default="ferry133")
    c.add_argument("--expect-sha", required=True)
    c.add_argument("--instance", default="im")
    c.add_argument("--escrowed-pubkey", default="")
    c.set_defaults(func=cmd_complete)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
