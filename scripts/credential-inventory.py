#!/usr/bin/env python3
"""Per-cluster credential inventory — §5.4 and §5.6 of factory-agent.

Emits one cluster's credentials in the five-column form already in use at
`jg-base kubernetes/apps/extras/factory/factory/README.md`: credential, what it
is for, scope, blast radius if read, rotation. One shape, not two — two shapes
diverge, and the one being read is usually the older.

Rotation (5.6) is the fifth column rather than a separate document, because a
rotation procedure filed away from the credential it rotates is one nobody finds
at the moment they need it.

**The thing this script must not do is be a list of names someone thought of.**
The `config.gen/cluster.yaml` leak happened because a rule and a check both
named the file someone expected. So the table below is not the answer on its
own: every field actually present in the cluster's `cluster.yaml` is compared
against it, and anything unrecognised is printed as UNCLASSIFIED. An inventory
that silently omits a credential reads exactly like an inventory of a cluster
that does not have one.

The other half of the same rule, taken from the jg-base document: **a row that
was considered and deliberately left out looks identical, from outside, to one
that was forgotten.** So exclusions are printed with their reason, not dropped.

No credential VALUE is ever printed — only whether one is set. This output is
meant to be pasteable into a delivery ticket in a public repository.

Usage
-----
  credential-inventory.py --dir PATH [--format md|text]

Exit 0 when the inventory is complete, 1 when a credential this cluster needs is
missing, 2 when the inventory could not be built (no cluster.yaml, unreadable
schema) — never 0 with a caveat.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

DONE, INCOMPLETE, UNKNOWN = 0, 1, 2

# credential field -> (what for, scope, blast radius if read, rotation)
#
# Scope and blast radius are deliberately different columns. "Which resources
# does it address" and "what does an attacker get" diverge most for exactly the
# credentials that matter: an age key addresses one cluster's files and yields
# every secret in them.
KNOWN: dict[str, tuple[str, str, str, str]] = {
    "cloudflare_token": (
        "external-dns writes DNS records; cert-manager answers DNS-01",
        "Every zone the token was scoped to — check the token, not this row",
        "DNS for those zones: traffic redirection, certificate issuance, tunnel takeover",
        "Roll in the Cloudflare dashboard, put the new value in cluster.yaml, "
        "`task configure --yes`, commit, push. Needs Zone:DNS:Edit AND "
        "Account:Cloudflare Tunnel:**Edit** — `Read` lists tunnels and cannot "
        "create one (measured 2026-08-23, GET passes and POST returns 10000)",
    ),
    "claudecode_auth0_client_secret": (
        "oauth2-proxy's half of the OIDC exchange in front of every terminal",
        "The Auth0 application it belongs to. If this cluster uses the SHARED "
        "application, that is every cluster",
        "Sign-in as the application: an attacker completes the OIDC flow and "
        "reaches a root shell on the cluster, since ttyd binds loopback and "
        "oauth2-proxy is the only route in",
        "Rotate in Auth0. **If the tenant is shared, rotating breaks every other "
        "cluster at the same instant** — that asymmetry is why 2026-08-25 ruled "
        "each cluster gets its own tenant, and why an existing shared cluster "
        "cannot be handed over without moving tenants first",
    ),
    "claudecode_auth0_domain": (
        "The OIDC issuer this cluster trusts",
        "Not a secret. Listed because it must move with the two that are",
        "None on its own",
        "Set all three Auth0 fields or none — `plugin.py` fills a missing field "
        "from the shared `auth0.json`, so a partial answer mixes one tenant's "
        "issuer with another's client and produces a terminal nobody can log in to",
    ),
    "claudecode_auth0_client_id": (
        "Identifies this cluster's application to Auth0",
        "Not a secret",
        "None on its own",
        "See `claudecode_auth0_domain` — all three together",
    ),
    "backup_r2_access_key_id": (
        "The backup job authenticates to the object store",
        "The bucket the key is scoped to",
        "Read of every backup: the backups hold the databases",
        "Reissue at the provider, update cluster.yaml, re-render. Confirm the "
        "next scheduled run succeeded — a wrong key fails as a network-shaped "
        "error that looks like every other transient",
    ),
    "backup_r2_secret_access_key": (
        "As above, the secret half",
        "The bucket the key is scoped to",
        "Read and delete of every backup",
        "Reissue with the id above; they rotate as a pair",
    ),
    "ttyd_credential": (
        "Basic-auth for the terminal when Auth0 is off (`claudecode_auth0: false`)",
        "Every claude-code instance on this cluster",
        "A root shell on the cluster",
        "Change the value and re-render. Present only on a cluster that "
        "deliberately declined the OIDC gate",
    ),
    "claudecode_postgres_password": (
        "The claudecode Postgres extra's superuser",
        "That database",
        "Read/write of whatever the instance stores",
        "Change in cluster.yaml, re-render, then ALTER the role — the manifest "
        "does not reset an existing database's password on its own",
    ),
    "github_push_token": (
        "The resident agent pushes commits back to the cluster repo",
        "Every repo the token's account can reach",
        "A repo write is a deploy on this fleet, with no review gate",
        "Revoke in GitHub, issue a replacement scoped to this repo, re-render",
    ),
    "github_webhook_token": (
        "Shared secret for Flux's GitHub receiver",
        "This cluster's receiver",
        "Ability to trigger reconciliations — noise, not access",
        "`python3 -c \"import secrets; print(secrets.token_hex(32))\"`, update "
        "cluster.yaml and the webhook in GitHub together",
    ),
    "daily_check_smtp_password": (
        "Gmail app password the daily health check sends through",
        "The Google account that issued it, for SMTP",
        "Send mail as that account",
        "Revoke the app password in the Google account, issue another",
    ),
    "daily_check_healthchecks_ping_url": (
        "Dead-man switch: the URL is the credential",
        "One healthchecks.io check",
        "Ability to suppress the alarm by pinging it",
        "Regenerate the check's UUID at healthchecks.io",
    ),
    "anthropic_api_key": (
        "Model access for extras/default/linebot and extras/default/synophoto",
        "The Anthropic account that issued it",
        "Billable model usage on that account",
        "Revoke in the Anthropic console. **Ruling 2026-08-25: this must be the "
        "customer's own account, not the company's.** Nothing validates whose "
        "it is and nothing can — ask, and record the answer on the ticket",
    ),
    "cloudflare_lan_tunnel_token": (
        "A second tunnel for LAN-only names",
        "That tunnel",
        "Whoever holds it can stand up their own connector for the same tunnel "
        "and Cloudflare will balance traffic across both",
        "Delete and recreate the tunnel, or rotate its secret, then re-render",
    ),
    "talos_mcp_sa_key": (
        "The talos-mcp sidecar's read access to Omni",
        "Omni, at whatever role the service account has",
        "Read of the fleet's machine and cluster state",
        "`omnictl serviceaccount` — destroy and recreate, update the value",
    ),
    "talos_operator_config": (
        "The talos-mcp sidecar's os:operator credential (jg-base im-onsite-operator-tools): direct-LAN reads when SideroLink is down, and the gated graceful `reboot_node`",
        "This one cluster's Talos API at role ceiling os:operator — reboot and shutdown; reset, apply-config, upgrade and certificate minting are refused by the nodes themselves",
        "Graceful reboot or shutdown of any node of this cluster from anywhere on its LAN, for a year. No data read beyond what the os:reader credential already gives",
        "⚠️ Omni cannot revoke it: deleting the value, the file or the pod leaves it live. `fleet-ops talos-operator-credential rotate` — `omnictl cluster -n <cluster> secret rotate talos-ca`, prove the old one is rejected, re-mint, `task configure --yes`, commit, push, restart `im`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop. Expiry (one year) is read from the certificate by the sidecar and by `verify`, not recorded here",
    ),
    # ── classified 2026-09-26 (`FO-runbook [5fe39a]`). Consumers were MEASURED by
    # grepping jg-base `origin/main` for each rendered variable — two of them have
    # none, and that is recorded rather than smoothed over. Where a third-party
    # console path is not something this fleet has measured, the row says so
    # instead of inventing a menu path.
    "postgres_password": (
        "The `claudecode/postgres` base app's DB password (the agent's explicit memory)",
        "That one cluster's postgres — base/claudecode/postgres deployment.yaml, migration.yaml, secret.yaml",
        "Read/write the agent's explicit memory (episodes, knowledge, working_memory) and anything later put in that database",
        "⚠️ Not a value swap: the password is applied by initdb on the PVC's FIRST start, so changing it alone does not take. Dump, change, recreate, restore (`fleet-ops docs/operations/backup-restore.md`). Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "claudecode_oauth2_cookie_secret": (
        "oauth2-proxy's cookie signing/encryption key in front of every terminal",
        "Every claude-code instance on the cluster, plus `factory` where selected — base/claudecode/claude-code/app/secret.yaml, extras/factory/factory",
        "Forge a session cookie and reach an authenticated terminal WITHOUT completing the OIDC flow — the Auth0 client secret's blast radius, reached more cheaply",
        "Generate a fresh 32-byte value; every live session is invalidated, which is the point. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "line_channel_access_token": (
        "LINE Messaging API — the bot posts and replies with this",
        "One LINE channel — extras/default/linebot, extras/default/trello-notifier",
        "Send messages as the customer's bot to everyone who added it, and read inbound webhook content",
        "Reissue in the LINE Developers console for that channel. ⚠️ This fleet has NOT measured that console's current menu path — do not follow a remembered one. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "line_channel_secret": (
        "LINE Messaging API — verifies X-Line-Signature on inbound webhooks",
        "The same LINE channel — extras/default/linebot",
        "Forge webhook calls the bot accepts as coming from LINE",
        "Reissue alongside the access token — ⚠️ they are a pair, and rotating one alone leaves inbound verification on the old value. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "trello_api_key": (
        "Trello REST API key for the board-sync and notifier jobs",
        "⚠️ The Trello ACCOUNT the key belongs to, not one board — extras/default/linebot, extras/default/trello-notifier",
        "With the token below: read and write every board that account can see",
        "Regenerate at Trello's developer API-key page. ⚠️ The token below is issued against this key and stops working when it changes — rotate both together. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "trello_api_token": (
        "Trello REST API token authorising the key above against one account",
        "Whatever scope was granted at issue time — read it from Trello, not from this row",
        "Act as that Trello account within the granted scope",
        "Revoke in Trello account settings, issue a new one against the current key, rotate with the key. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "synophoto_flask_secret_key": (
        "Flask session signing key for the synophoto extra",
        "That one app — extras/default/synophoto/app/secret.yaml",
        "Forge a signed session cookie for synophoto",
        "Generate a fresh random value; live sessions are invalidated. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "synophoto_auth0_client_secret": (
        "⚠️ NO CONSUMER FOUND (measured 2026-09-26): this name appears nowhere in jg-base `origin/main` in any case, while the sibling `synophoto_flask_secret_key` IS found by the same query in README.md and the app's secret.yaml (positive control)",
        "Unknown — nothing renders it, so it addresses nothing in this fleet",
        "Whatever the Auth0 application it came from still permits. ⚠️ A credential with no consumer cannot be needed; it can only be leaked",
        "⛔ REMOVAL, not rotation, and in this order: confirm nothing outside jg-base reads it, revoke it at Auth0, THEN delete the line — deleting first leaves a live secret nobody tracks. Fleet side after deleting: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "synophoto_nas_password": (
        "⚠️ NO CONSUMER FOUND — same measurement and same positive control as `synophoto_auth0_client_secret`",
        "Unknown; the name suggests a Synology NAS account, but nothing renders it",
        "If it is a live NAS account: that account's share access. Unverified",
        "⛔ REMOVAL, not rotation: identify the account, change that account's password at the NAS, then delete the line. Fleet side after deleting: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "freepbx_mysql_password": (
        "FreePBX's application DB user password",
        "The freepbx extra's MariaDB on that cluster — extras/freepbx/freepbx/app/secret.yaml",
        "Read/write the PBX's configuration and call records: extensions, trunks, voicemail, CDR",
        "⚠️ Same initdb shape as `postgres_password` — a value change alone does not take. Change it inside MariaDB and in cluster.yaml together. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "freepbx_mysql_root_password": (
        "MariaDB root password for the freepbx extra",
        "⚠️ That MariaDB server entirely, not just the PBX schema",
        "Full control of the database server, every schema in it, and the ability to grant new users",
        "As above, and ⛔ rotate it WITH the application password, never alone — a root rotation that leaves the app password stale takes the PBX down without making anything safer. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "factory_github_token": (
        "The factory app's GitHub PAT — it creates customer repos from the template",
        "⚠️ Every repo the PAT's account can reach, not one customer — extras/factory/factory credentials-secret.yaml, helmrelease.yaml",
        "Create, read and modify repositories as that account — including the TEMPLATE, from which every future customer cluster is built",
        "Revoke and reissue in GitHub developer settings, scoped to what `jg-base .../extras/factory/factory/README.md` states it needs. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "factory_omni_sa_key": (
        "The factory app's Omni service-account key",
        "⚠️ The whole Omni instance — every cluster it manages, not one",
        "Create, modify and DESTROY any Omni-managed cluster in the fleet",
        "Mint a replacement with `omnictl serviceaccount create`, put it in cluster.yaml, THEN `omnictl serviceaccount destroy` the old one — ⛔ a rotation that only adds leaves the old key live. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "factory_fleet_ops_deploy_key": (
        "Deploy key the factory app uses against the fleet-ops repo",
        "`ferry133/fleet-ops` (private), at whatever access the key was added with",
        "Read — and if it was added with write access, modify — the fleet's routing decisions, runbooks and skills",
        "Remove it in that repo's Settings → Deploy keys and add a fresh pair. ⚠️ Set the write checkbox deliberately rather than copying the old key's setting. Fleet side: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
    "omni_gpg_key": (
        "Omni's own GPG key, used by the Omni deployment on the factory cluster",
        "The Omni instance's stored secrets — extras/omni/omni helmrelease.yaml and secret.yaml, extras/factory/factory",
        "Decrypt what Omni encrypted with it: cluster secrets and machine configuration Omni holds",
        "⛔ Not an ordinary rotation. Omni re-encrypts with the new key while the old one is still needed to read existing data, so this is a migration with a restore path, not a swap — do not attempt it from this row alone. Fleet side once the Omni-side procedure exists: put the new value in cluster.yaml, `task configure --yes`, commit, push, `task reconcile`; then `escrow-refresh` — cluster.yaml is git-ignored, so the escrow bundle is the only copy that leaves the laptop",
    ),
}

# Credential-bearing material that is NOT a cluster.yaml field. Listed because
# the ones people forget are the ones that never appear in a config file.
OUT_OF_BAND = [
    ("age.key", "Decrypts every SOPS secret in this repo",
     "This cluster's repository, all of it",
     "Every secret the cluster holds, including ones rotated later — the "
     "ciphertext is public and permanent",
     "`age-keygen` a new key, then `sops updatekeys` every `*.sops.*` file IN "
     "PLACE — never decrypt into the working tree. Add the new recipient to "
     "`.sops.yaml` BEFORE removing the old one: there is one recipient, so a "
     "botched updatekeys is recoverable only from the escrow copy"),
    ("The escrowed copy of age.key", "The only copy that survives this machine",
     "As age.key", "As age.key",
     "Compare with `age-keygen -y` against `.sops.yaml`'s recipient and record "
     "'compared, public halves match verbatim' — not 'escrowed', which is a "
     "conclusion. `provision.py complete --escrowed-pubkey` refuses to mark a "
     "delivery done without it"),
    ("cloudflare-tunnel.json", "TunnelSecret + AccountTag for the main tunnel",
     "That tunnel, in that account",
     "Run a competing connector for the same tunnel",
     "Delete and recreate the tunnel, re-render, confirm the CNAME was "
     "rewritten to the new UUID"),
    ("github-deploy.key", "Flux's read access to the cluster repo",
     "That repo", "Read of the manifests, which are public anyway on this fleet",
     "Generate a new pair, replace the deploy key in GitHub"),
    ("kubeconfig-sa", "Non-interactive cluster access; embeds a bearer token",
     "This cluster's Kubernetes API at the SA's role",
     "Whatever the service account can do — on this fleet, cluster-admin",
     "`omnictl kubeconfig … --service-account`. Never overwrite `kubeconfig` "
     "with it: that file is the way back in when this token expires"),
    ("~/.cloudflared/cert.pem", "Origin certificate that creates tunnels",
     "The Cloudflare account whose BROWSER SESSION signed it — not necessarily "
     "the account the zone is in",
     "Create tunnels in that account",
     "Re-run `cloudflared tunnel login`. This is the credential behind the "
     "cross-account 1033: a tunnel is created wherever the cert belongs, and "
     "every cheaper check passes"),
]

# Absent by decision, not by omission. Printing these is half the point: from
# outside, a row that was considered and dropped looks exactly like one nobody
# thought of.
EXCLUDED = [
    ("Customer consumer-account passwords (Google, Cloudflare, Auth0 sign-in)",
     "5.2 — no automation registers or holds a consumer account. The customer "
     "registers one Google account at contract time and the company signs in "
     "with it; the password is never a value this fleet stores"),
    ("Omni Admin service account",
     "Held by factory, not by any cluster. It is in "
     "`jg-base .../factory/factory/README.md`, and a second copy here would be "
     "the copy that goes stale"),
    ("Talos client certificate / talosconfig at os:admin",
     "Never issued: Omni grants no identity os:admin (insideman, measured). "
     "The two talosconfigs a cluster DOES hold are rows above — "
     "`talos_mcp_sa_key` (the os:reader one carries no key of its own) and "
     "`talos_operator_config` (os:operator, since im-onsite-operator-tools). "
     "Before 2026-10-13 this row read 'not issued per delivery today'; the "
     "node-level handover path (`factory-agent` 6.1d) is still a sentence"),
]

CLASSIFIED_ELSEWHERE = {c[0] for c in EXCLUDED}

# Fields that hold no credential but whose names would trip a keyword sweep.
NOT_CREDENTIALS = {
    "cloudflare_domain", "cloudflare_gateway_addr", "cloudflare_tunnel_transport",
    "github_username", "repository_name", "repository_branch",
    "repository_visibility", "daily_check_notify_email_to",
    "daily_check_smtp_host", "daily_check_smtp_port", "daily_check_smtp_username",
    "daily_check_notify_email_from", "backup_r2_endpoint", "backup_r2_bucket",
    "backup_retain_days", "claudecode_allowed_emails", "claudecode_auth0",
    "claudecode_oauth2_cookie_secret_source",
}

# Name-shaped sweep used ONLY to find fields the table above does not know
# about. It is not the inventory; it is the check that the inventory is not a
# list of names someone thought of.
SUSPICIOUS = re.compile(
    r"(?i)(token|secret|password|passwd|key|credential|cert|api[_-]?key|pat)\b")


def read_fields(path: pathlib.Path) -> dict[str, str]:
    """Top-level `key: value` pairs. Commented-out lines are not settings."""
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^([a-z][a-z0-9_]*)\s*:\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).split("#", 1)[0].strip()
    return out


def is_set(raw: str) -> bool:
    v = raw.strip().strip("\"'").strip()
    if not v or v in ("[]", "{}", "~", "null"):
        return False
    return not (v.startswith(("<", "${", "$(")) or "CHANGE" in v.upper())


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=".")
    ap.add_argument("--format", default="md", choices=["md", "text"])
    args = ap.parse_args()

    d = pathlib.Path(args.dir).resolve()
    cfg = d / "cluster.yaml"
    if not cfg.exists():
        print(f"?     {cfg} not found — cannot build an inventory", file=sys.stderr)
        print("      Reported as could-not-tell, not as 'no credentials'. A "
              "cluster with no cluster.yaml and one whose file is elsewhere "
              "produce the same empty table.", file=sys.stderr)
        return UNKNOWN

    fields = read_fields(cfg)
    name = fields.get("cluster_name", "?").strip("\"'")

    present, blank, undeclared, unclassified = [], [], [], []
    for field, row in KNOWN.items():
        if field not in fields:
            undeclared.append(field)
        elif is_set(fields[field]):
            present.append((field, row))
        else:
            blank.append(field)
    for field in fields:
        if field in KNOWN or field in NOT_CREDENTIALS:
            continue
        if SUSPICIOUS.search(field) and is_set(fields[field]):
            unclassified.append(field)

    print(f"# Credential inventory — {name}")
    print()
    print(f"Generated from `{cfg}` by `scripts/credential-inventory.py`. "
          "**No value is printed**, only whether one is set, so this is safe to "
          "paste onto a delivery ticket in a public repository.")
    print()
    print("| Credential | What it is for | Scope | Blast radius if read | Rotation |")
    print("|---|---|---|---|---|")
    for field, (what, scope, blast, rot) in present:
        print(f"| `{field}` | {what} | {scope} | {blast} | {rot} |")
    for cred, what, scope, blast, rot in OUT_OF_BAND:
        p = "" if _exists(d, cred) else " *(not in this directory)*"
        print(f"| **{cred}**{p} | {what} | {scope} | {blast} | {rot} |")
    print()

    print("## Declared and blank")
    print()
    if blank:
        print("Blank is a real state — the feature is off. The row is here so "
              "that off-by-decision and off-by-accident are not the same "
              "observation.")
        print()
        for f in sorted(blank):
            print(f"- `{f}`")
    else:
        print("None — every credential field this file declares carries a value.")
    print()

    print("## Not declared at all")
    print()
    print("Absent from `cluster.yaml` entirely, so this cluster does not use "
          "the feature behind them. **This section exists because the version "
          "without it had the same defect the whole file is written against:** "
          "a credential the cluster genuinely does not need and one whose line "
          "someone deleted produced identical output — nothing at all. "
          "`daily_check_healthchecks_ping_url` is the worked example: unset, the "
          "daily check runs, mails, and pings nothing, so a FAIL withholds a "
          "ping that was never configured and the only notification path left "
          "is the mail — which fails silently in exactly the cases that matter.")
    print()
    if undeclared:
        for f in sorted(undeclared):
            print(f"- `{f}`")
    else:
        print("None.")
    print()

    print("## Deliberately not in this inventory")
    print()
    print("From outside, a row that was considered and dropped looks exactly "
          "like one nobody thought of. These were considered.")
    print()
    for cred, why in EXCLUDED:
        print(f"- **{cred}** — {why}")
    print()

    rc = DONE
    if unclassified:
        rc = INCOMPLETE
        print("## ⚠️ UNCLASSIFIED — this inventory is incomplete")
        print()
        print("These fields are set in `cluster.yaml`, their names are "
              "credential-shaped, and this script's table does not know them. "
              "**They are printed rather than skipped**: a credential missing "
              "from the inventory reads exactly like a cluster that does not "
              "have one, which is the failure this file exists to avoid.")
        print()
        for f in sorted(unclassified):
            print(f"- `{f}` — add it to `KNOWN` in "
                  "`scripts/credential-inventory.py`, with its rotation procedure, "
                  "or to `NOT_CREDENTIALS` if it holds none")
        print()
        print("Exit 1. Not a warning: an incomplete inventory handed over as "
              "complete is worse than none, because it is trusted.")
    return rc


def _exists(d: pathlib.Path, cred: str) -> bool:
    if cred.startswith("~"):
        return os.path.exists(os.path.expanduser(cred))
    return (d / cred.split()[0]).exists()


if __name__ == "__main__":
    sys.exit(main())
