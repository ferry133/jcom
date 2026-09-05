from pathlib import Path
from typing import Any

import base64
import hashlib
import hmac
import ipaddress
import makejinja
import re
import sys
import json


# Return the filename of a path without the j2 extension
def basename(value: str) -> str:
    return Path(value).stem


# Base64-encode a string
def b64encode(value: str) -> str:
    return base64.b64encode(value.encode('utf-8')).decode('utf-8')


# Return the nth host in a CIDR range
def nthhost(value: str, query: int) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
        if 0 <= query < network.num_addresses:
            return str(network[query])
    except ValueError:
        pass
    return False


# Return the age public or private key from age.key
def age_key(key_type: str, file_path: str = 'age.key') -> str:
    try:
        with open(file_path, 'r') as file:
            file_content = file.read().strip()
        if key_type == 'public':
            key_match = re.search(r"# public key: (age1[\w]+)", file_content)
            if not key_match:
                raise ValueError("Could not find public key in the age key file.")
            return key_match.group(1)
        elif key_type == 'private':
            key_match = re.search(r"(AGE-SECRET-KEY-[\w]+)", file_content)
            if not key_match:
                raise ValueError("Could not find private key in the age key file.")
            return key_match.group(1)
        else:
            raise ValueError("Invalid key type. Use 'public' or 'private'.")
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error while processing {file_path}: {e}")


# Return cloudflare tunnel fields from cloudflare-tunnel.json
def cloudflare_tunnel_id(file_path: str = 'cloudflare-tunnel.json') -> str:
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        tunnel_id = data.get("TunnelID")
        if tunnel_id is None:
            raise KeyError(f"Missing 'TunnelID' key in {file_path}")
        return tunnel_id

    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except json.JSONDecodeError:
        raise ValueError(f"Could not decode JSON file: {file_path}")
    except KeyError as e:
        raise KeyError(f"Error in JSON structure: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error while processing {file_path}: {e}")


# Return cloudflare tunnel fields from cloudflare-tunnel.json in TUNNEL_TOKEN format
def cloudflare_tunnel_secret(file_path: str = 'cloudflare-tunnel.json') -> str:
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        transformed_data = {
            "a": data["AccountTag"],
            "t": data["TunnelID"],
            "s": data["TunnelSecret"]
        }
        json_string = json.dumps(transformed_data, separators=(',', ':'))
        return base64.b64encode(json_string.encode('utf-8')).decode('utf-8')

    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except json.JSONDecodeError:
        raise ValueError(f"Could not decode JSON file: {file_path}")
    except KeyError as e:
        raise KeyError(f"Missing key in JSON file {file_path}: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error while processing {file_path}: {e}")


# Return the GitHub deploy key from github-deploy.key
def github_deploy_key(file_path: str = 'github-deploy.key') -> str:
    try:
        with open(file_path, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error while reading {file_path}: {e}")


# Return the Flux / GitHub push token from github-push-token.txt
def github_push_token(file_path: str = 'github-push-token.txt') -> str:
    try:
        with open(file_path, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error while reading {file_path}: {e}")


# Return a claude-code Auth0 application's fields from auth0.json
#
# ⚠️ This is the SHARED-tenant path and it is now opt-in. Reading it is gated on
# `claudecode_auth0_shared` in cluster.yaml; see the caller.
#
# The paragraph that used to be here said "every cluster fronts claude-code with
# the same Auth0 application". That was true when it was written and was
# overturned on 2026-08-25 — `fleet-ops docs/operations/provision-customer-cluster.md`
# Step 2: *this cluster gets its own Auth0 tenant*. The code kept implementing
# the old design for eight days, and `#64` is what that cost: three clusters
# shared one tenant, the runbook's own assertion passed over it, and it took
# ferry133 asking "are these the customer's values?" to find out.
#
# A local file rather than cluster.yaml fields because this template repo is
# public: a client secret does not belong in a public repo even per-cluster.
# Same idiom as cloudflare-tunnel.json — gitignored, read at render time, never
# committed.
#
# Missing here is a hard stop, not an empty default: OIDC mode gives ttyd no
# fallback (it binds loopback), so a cluster rendered with a blank client
# secret deploys a terminal nobody can reach.
def auth0_config(file_path: str = 'auth0.json') -> dict[str, str]:
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"File not found: {file_path} — `claudecode_auth0_shared: true` is "
            f"set, which is the only thing that makes reading it legitimate, "
            f"and it is not in this directory. Either put this cluster's own "
            f"Auth0 values in cluster.yaml and drop the flag, or supply the "
            f"shared application's auth0.json here.")
    except json.JSONDecodeError:
        raise ValueError(f"Could not decode JSON file: {file_path}")

    missing = [k for k in ('domain', 'client_id', 'client_secret')
               if not data.get(k)]
    if missing:
        raise KeyError(f"Missing or empty in {file_path}: {', '.join(missing)}")
    return data


# Derive oauth2-proxy's cookie secret from the cluster's own age key
#
# Derived rather than generated so it is stable: a fresh random value on every
# render would sign every session out at each `task configure` and rewrite the
# encrypted secret for no reason. Derived rather than shared so a cookie minted
# for one cluster cannot be replayed at another — jg-jiahd and jgtest were
# hand-copied the same value, which is the mistake this closes.
#
# 32 bytes, base64url — the one length oauth2-proxy accepts besides 16 and 24.
def oauth2_cookie_secret(cluster_name: str, file_path: str = 'age.key') -> str:
    key = age_key('private', file_path)
    digest = hmac.new(key.encode('utf-8'),
                      f"claudecode-oauth2-cookie:{cluster_name}".encode('utf-8'),
                      hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8')


# Return a list of files in the talos patches directory
def talos_patches(value: str) -> list[str]:
    path = Path(f'templates/config/talos/patches/{value}')
    if not path.is_dir():
        return []
    return [str(f) for f in sorted(path.glob('*.yaml.j2')) if f.is_file()]



# The one place the default instance list is written. `claude_instances` and
# `claude_code_always_on` both default to it, and the Jinja template no longer
# carries a `default(...)` of its own -- three copies of ['im'] is how they
# drifted apart (jg-cluster-template#57).
DEFAULT_CLAUDE_INSTANCES = ['im']

class Plugin(makejinja.plugin.Plugin):
    def __init__(self, data: dict[str, Any]):
        self._data = data


    def data(self) -> makejinja.plugin.Data:
        data = self._data

        # Set default values for optional fields.
        # These must match the defaults documented in cluster.sample.yaml —
        # a documented default the code does not apply is a defect.
        # `.1` of node_cidr is an ASSUMPTION about someone else's LAN, not a
        # measurement, and `#49` measured every one of the twelve cluster.yaml
        # on the operator's machine relying on it. It is right here because
        # ferry133's LANs are `.1` — which is also why nothing has caught it:
        # the assumed value and the true one are the same string, so every test
        # this lab can run passes either way. A customer on `.254` (common)
        # gets `task configure` success, `cue vet` pass, a cluster that boots,
        # and no route off the LAN.
        #
        # It stays a default rather than becoming required: making it required
        # would stop `task configure` in all twelve repos to catch a value that
        # is, on this fleet, correct — and a guard that fires on correct input
        # gets switched off. What changes is that the assumption stops being
        # silent. `scripts/delivery-check.py gateway` measures the real default
        # route and compares; the notice below marks the render log on the one
        # path where this value reaches a machine.
        assumed_gateway = 'node_default_gateway' not in data
        data.setdefault('node_default_gateway', nthhost(data.get('node_cidr'), 1))
        if assumed_gateway and data.get('provisioning_path') == 'talos':
            # Only this path. On the Omni path `nodes` is empty, so the routes
            # block in talconfig.yaml.j2 never renders, the global Talos
            # patches are not applied, and NODE_DEFAULT_GATEWAY has no reader
            # in jg-base at all (measured 2026-08-30: 0 files, against 17 for
            # NAS_SERVER as a positive control). Announcing there would be a
            # warning about a value nothing consumes.
            print(
                f"NOTE: node_default_gateway is assumed, not measured — "
                f"{data['node_default_gateway']} is .1 of {data.get('node_cidr')}. "
                f"It becomes every node's default route and nameserver. "
                f"Verify with: scripts/delivery-check.py gateway --node <addr>",
                file=sys.stderr,
            )
        # 2026-08-27: the LAN's router, not Cloudflare. Measured on jg-jiahd
        # (Omni path, no Talos patches applied) that the nodes were already on
        # `10.9.9.1` via DHCP while this file rendered `1.1.1.1` -- so the old
        # default was, on half the fleet, a statement about a file nobody
        # applies. On the other half (patches applied, e.g. jcom) it was real,
        # and it is what stopped those nodes from resolving internal names at
        # all: a node on `1.1.1.1` asks Cloudflare, which does not serve the
        # RFC1918 answer (deployment-profiles D29), so `internal.<domain>`
        # is NXDOMAIN from anything running on that node -- including the `im`
        # rescue terminal.
        #
        # Single entry, deliberately. A public fallback was considered and
        # rejected by ferry133 the same day: `all(is_private)` below would then
        # derive `public` and switch check 18 back off, and CoreDNS's forward
        # plugin selects among multiple upstreams at random by default
        # (coredns.io/plugins/forward: "The default is `random`."), so internal
        # names would resolve on roughly half of all queries with the failures
        # cached. Intermittent is worse than absent. The cost of one entry is
        # stated plainly: if the router's resolver dies the nodes lose name
        # resolution -- but so does every other client on that LAN, and the
        # cluster's upstream is gone with it.
        #
        # The address must do BOTH jobs, ordinary recursion and forwarding the
        # cluster domain -- which is why it is the router and not the shared LAN
        # address (`docs/operations/router-dns.md` in fleet-ops). Pointing this
        # at k8s-gateway makes node name resolution depend on the cluster it is
        # meant to bring up.
        data.setdefault('node_dns_servers', [data['node_default_gateway']])
        # Whether the nodes resolve names the way a LAN client does — read
        # AFTER the default above, because the default is what the nodes get.
        #
        # daily-check probes `internal.<domain>` through the node's ordinary
        # resolution path. That probe is only meaningful where that path is the
        # LAN's: nameservers pinned to a public resolver cannot see what a LAN
        # client sees, and Cloudflare will not serve the RFC1918 answer at all
        # (deployment-profiles D29), so the probe would fail every morning on a
        # cluster whose LAN is perfectly healthy. That is the same defect the
        # probe exists to replace, one layer down.
        #
        # Derived, never declared. Asking the operator "how did you wire the
        # router" would store a second copy of a fact that lives in the router,
        # and when the two disagree the check does not go quiet — it makes a
        # confident wrong claim and withholds the dead-man ping.
        #
        # This used to read `node_dns_servers` BEFORE the default and call unset
        # "LAN", on the reasoning that unset means the nodes take DNS from DHCP
        # like every other client on that LAN. That reasoning skipped the very
        # next line: the default is applied unconditionally and
        # talos/patches/global/machine-network.yaml.j2 writes it into every
        # machine config. Measured 2026-08-23 in four rendered repos --
        # jg-jiahd, jcom, jg-janncotcc, jgt-talos-accept -- all four pin
        # `nameservers: [1.1.1.1, 1.0.0.1]`, and not one cluster.yaml in the
        # fleet sets node_dns_servers. So the branch that said "LAN" described
        # no cluster that exists, and the sibling test case immediately below it
        # asserted the opposite answer for the identical machine config.
        #
        # Reading the effective value is also the only spelling that cannot go
        # stale: whatever the default becomes, this says what the nodes got.
        #
        # Consequence, restated 2026-08-27 when the default above changed.
        # It used to read: with the shipping default every cluster derives
        # `public`, so check 18 reports "not measured" rather than probing.
        # That was true and it was the honest answer, but it made "nothing
        # watches the router" the fleet-wide default.
        #
        # With the default now the LAN router, a cluster that declares nothing
        # derives `lan` and check 18 probes. Two things follow, and neither is
        # automatic:
        #
        #   - Re-rendering is what moves a cluster, not this commit. A cluster
        #     that has not run `task configure` since keeps whatever its
        #     `cluster-secrets` already holds.
        #   - On the Omni path no Talos patch is applied, so the nodes take DHCP
        #     DNS regardless of what this file says. There the change corrects
        #     the *declaration* to match what the nodes were already doing; it
        #     does not change resolution. On a patched path (talhelper) it does
        #     change resolution, and the node must be re-applied for it to take
        #     effect.
        #
        # Deriving from the effective value is still the only spelling that
        # cannot go stale, and it is now right for both paths rather than
        # understating one of them.
        data['node_dns_path'] = 'lan' if all(
            ipaddress.ip_address(s).is_private
            for s in data['node_dns_servers']) else 'public'
        # Where the shared base manifests come from. Defaulted HERE and not only
        # in cluster.schema.cue: CUE's `*default` never reaches this file —
        # plugin.py reads cluster.yaml, not CUE's unified value (the same trap
        # the longhorn selector documents in .taskfiles/template/Taskfile.yaml).
        # Without these three lines every existing cluster.yaml, none of which
        # names them, renders a GitRepository with an empty url.
        data.setdefault('base_repo_url', 'https://github.com/ferry133/jg-base')
        data.setdefault('base_repo_ref', 'main')
        data.setdefault('base_repo_ref_kind', 'branch')
        # The same repo as a directory next to this one, for bootstrap's helmfile
        # — it reads HelmRelease values off disk before the cluster can fetch
        # anything. Derived from the URL rather than declared: two fields for one
        # fact diverge, and this one only shows up at a re-bootstrap.
        data.setdefault(
            'base_repo_dir',
            data['base_repo_url'].rstrip('/').rsplit('/', 1)[-1].removesuffix('.git'))
        data.setdefault('node_ntp_servers', ['162.159.200.1', '162.159.200.123'])
        data.setdefault('cluster_pod_cidr', '10.42.0.0/16')
        # cluster_svc_cidr is required (no default) — see cluster.schema.cue.
        # coredns must sit at .10 of whatever service CIDR the cluster actually
        # uses, so derive it rather than hardcoding a value that is only correct
        # for one provisioning path. An explicit coredns_cluster_ip still wins.
        data.setdefault('coredns_cluster_ip', nthhost(data.get('cluster_svc_cidr'), 10))
        # Storage class for PVCs that do not pick one explicitly. Databases are
        # block-backed regardless — this selects what bulk media and file shares
        # get, which is the only thing the backend axis decides.
        _backend = data.get('storage_backend')
        data.setdefault('default_storage_class', {
            'nfs': 'sc-nas',
            'replicated': 'longhorn',
        }.get(_backend, 'local-path'))
        # claude-code's config PVC (~/.claude plus the keyring on a subPath).
        # Defaults to what it renders TODAY, not to db_storage_class.
        #
        # The block tier is the right destination — gnome-keyring's file locking
        # and claude's small frequent writes lose the same argument against NFS
        # that databases do — but `storageClassName` is immutable, so a default
        # that names a different class does not move anything. It renders a PVC
        # the cluster cannot accept, on every cluster, at whatever moment each
        # one next runs `task configure`. Measured: that default would move
        # jg-jiahd sc-nas→longhorn and jcom sc-nas→local-path, and jcom is
        # single-node, which is the case that must NOT move.
        #
        # So the move is per cluster, deliberate, and by the copy procedure in
        # cluster.sample.yaml. Naming the current class here is also how a
        # cluster RECORDS that it has not moved yet — same use as
        # db_storage_class, for the same reason.
        data.setdefault('claudecode_config_storage_class',
                        data['default_storage_class'])
        # Whether the workspace PVC is rendered at all. True, and the sample
        # says in words that false deletes data: on the NFS class the
        # provisioner's archiveOnDelete catches it, on local-path and
        # longhorn-static nothing does.
        data.setdefault('claudecode_workspace', True)
        # The block tier, for anything that needs fsync durability and file
        # locking. Not derived from storage_backend: NFS is never a valid answer
        # here, whatever the cluster uses for bulk data. An existing cluster
        # whose database is already on NFS overrides this until it can be dumped
        # and restored — a PVC's storageClassName is immutable, so the move is
        # not something a re-render can perform.
        data.setdefault('db_storage_class', 'local-path')
        # Whether the database extras render their NAS backup CronJob:
        # 'nfs' or 'none'. Derived, never declared — it is a restatement of
        # "is there a NAS", and a second copy of that fact would eventually
        # disagree with the first.
        #
        # It has to be a value rather than a condition because **Flux cannot
        # branch on "is NAS_SERVER set"**. Flux substitutes with drone/envsubst,
        # where `${VAR:+alt}` is not implemented and behaves exactly like
        # `${VAR:-alt}`; measured with `flux envsubst` (flux 2.7.4, the same
        # code path). So jg-base selects a directory by this word instead:
        # kubernetes/apps/extras/<ns>/postgres/backup/${NAS_BACKUP:=nfs}.
        # (Checking that with a shell gives the POSIX answer, not Flux's. They
        # are opposites. See ferry133/jg-base#17.)
        #
        # 'none' rather than '' or false: the value lands in a stringData field
        # on the way through, and an empty scalar is YAML null while `false` is
        # a YAML boolean — either one gets the whole Secret rejected, which is
        # what ferry133/jg-base#16 cost.
        #
        # jg-base defaults the variable to 'nfs' where it is absent, so a
        # cluster that has not re-rendered keeps its backup rather than losing
        # it silently. That default is why this can ship without touching every
        # per-user repo at once.
        data['nas_backup'] = 'nfs' if data.get('nas_server') else 'none'
        # Which claude-code instances stay up. Empty by default: each is a root
        # shell with cluster-admin that the tunnel makes reachable. Named here
        # rather than scaled by hand, which works until the next reconcile.
        # list() because the constant is module-level and mutable: without the
        # copy every cluster rendered in one process shares one list, and an
        # append anywhere edits the default for all of them. Do not "tidy" it.
        data.setdefault('claude_instances', list(DEFAULT_CLAUDE_INSTANCES))
        # Exactly one instance -> that one. More than one -> do not guess.
        #
        # `[:1]` was the first attempt and it is wrong, with the only two real
        # examples against it: jg-jiahd and jcom both declare ["cc","im"] and
        # both run **im**, the second one -- and the schema says why, four lines
        # above this field: "jcom keeps `im` up for support and leaves `cc` at
        # zero until it is needed." Picking first encodes the opposite rule, and
        # the stray check below cannot catch it because `cc` IS in the list.
        #
        # Refusing to pick is this repo's existing answer to the same shape --
        # provision.py `derive` refuses when more than one subnet is a candidate.
        # It costs a cluster that declares two instances a `[]` default, which
        # Step 5's "the instance actually answers" assertion then catches. That
        # is the loud failure; a silently-wrong root shell is the quiet one.
        if 'claude_code_always_on' not in data:
            _inst = data['claude_instances']
            data['claude_code_always_on'] = list(_inst) if len(_inst) == 1 else []
            # `> 1`, deliberately not `!= 1`. Zero instances is a legal and
            # deliberate configuration -- claude_instances: [] means this cluster
            # does not want a web terminal, the schema puts no non-empty
            # constraint on the field, and the template renders zero
            # HelmReleases for it. Flagging it would fire on every render of a
            # cluster that did nothing wrong, and the advice ("Name one") cannot
            # be followed: there is nothing to name, and naming anything trips
            # the stray-name KeyError below. That is jg-base#18's shape exactly
            # -- a guard that flags correct input got silenced, and a silenced
            # guard reads like coverage. Do not merge these two branches.
            if len(_inst) > 1:
                print(
                    f"NOTE: claude_code_always_on is unset and claude_instances "
                    f"names {len(_inst)} ({', '.join(_inst)}), so nothing is kept "
                    f"running and the cluster ships with no way in. Name one: "
                    f"claude_code_always_on: [\"<instance>\"]",
                    file=sys.stderr,
                )
        # ⚠️ This default moved on 2026-08-31 (#57): it used to be []. An already
        # delivered cluster that re-renders for an unrelated reason therefore
        # gains a standing root shell it never asked for -- the same "a default
        # only moves on re-render" note NAS_BACKUP, LONGHORN_BACKUP and #29's
        # node_dns_servers each carry. Measured 2026-08-31: all five existing
        # clusters already declare claude_code_always_on explicitly, so none of
        # them moves today. That is true until one of them drops the line.
        # An always-on name that is not an instance renders nothing and says
        # nothing -- the same shape as the allowlist override check further down,
        # and the same fix: refuse at data() time, before any file is written.
        stray = [n for n in data['claude_code_always_on']
                 if n not in data['claude_instances']]
        if stray:
            raise KeyError(
                f"claude_code_always_on names {', '.join(sorted(stray))}, which "
                f"is not in claude_instances ({', '.join(data['claude_instances'])}). "
                "That instance would render no replicas and no error, which is "
                "indistinguishable from a cluster that was never given a way in.")
        # Auth0 OIDC in front of every claude-code instance, on by default.
        #
        # The alternative is ttyd basic auth, a single shared password in front
        # of a root shell with cluster-admin that the tunnel publishes to the
        # internet — one credential for every operator, rotated by editing
        # twenty configs, and no record of who opened the terminal. OIDC gives
        # per-person accounts, an email allowlist, and revocation in one place.
        #
        # What it costs: OIDC mode leaves ttyd on loopback with no fallback, so
        # the instance is reachable only while oauth2-proxy can reach Auth0 and
        # the callback URL is registered. claude-code is the rescue path for a
        # cluster whose Omni/SideroLink is down, so that path now depends on a
        # third party being up. A cluster that will not accept the trade turns
        # it off with `claudecode_auth0: false` and supplies ttyd_credential.
        data.setdefault(
            'claudecode_auth0_enabled',
            bool(data['claudecode_auth0']) if 'claudecode_auth0' in data
            else True)
        if data['claudecode_auth0_enabled']:
            # The paragraph that stood here justified reading auth0.json for
            # whatever cluster.yaml left out, on the grounds that requiring the
            # file would break `task configure` for clusters that already spell
            # everything out inline. Those clusters are unaffected — they set
            # all four. What it also protected was the cluster that set none,
            # and breaking THAT one is the point of `#64`. Removed rather than
            # left to contradict the paragraph below it.
            #
            # 2026-08-25 ruling: each cluster gets its OWN Auth0 tenant. Until
            # `#64` this block read auth0.json for whatever cluster.yaml had
            # left out, which made "forgot to set it" and "deliberately shares
            # a tenant" produce identical output — and the identical output was
            # the shared one. Three clusters ended up on one tenant that way,
            # past a runbook assertion whose prose said "registered under the
            # same Google account" while nothing checked it.
            #
            # Sharing is still allowed, because a cluster may genuinely want it
            # — it just has to say so. The flag is the whole difference between
            # a decision and an accident.
            fields = ('domain', 'client_id', 'client_secret')
            shared = bool(data.get('claudecode_auth0_shared'))
            missing = [f for f in fields
                       if not data.get(f'claudecode_auth0_{f}')]
            # The allowlist came from the same file, so dropping the fallback
            # without this would trade a silent shared tenant for a silently
            # empty door — oauth2-proxy admits nobody and the terminal is the
            # cluster's rescue path.
            if not data.get('claudecode_allowed_emails'):
                missing.append('allowed_emails (claudecode_allowed_emails)')
            if missing and not shared:
                raise KeyError(
                    "claude-code Auth0 is enabled and cluster.yaml is missing: "
                    + ", ".join(missing)
                    + ". Since 2026-08-25 each cluster uses its OWN Auth0 "
                    "tenant, so these are not inherited from auth0.json any "
                    "more. Set them in cluster.yaml from this cluster's tenant, "
                    "or — only if this cluster is deliberately sharing another "
                    "cluster's tenant — set `claudecode_auth0_shared: true` and "
                    "put auth0.json in this directory.")
            # `and missing`, not `if shared` alone: the path from a shared
            # tenant back to an own one is fill in the four values, delete
            # auth0.json, drop the flag — and forgetting the last step used to
            # raise FileNotFoundError over a file nothing needed. Found in
            # acceptance review of `#64` (case c09).
            if shared and missing:
                auth0 = auth0_config()
                for field in fields:
                    data.setdefault(f'claudecode_auth0_{field}', auth0[field])
                # cluster.yaml wins where a cluster needs someone auth0.json
                # does not list — the client's own address, say.
                if auth0.get('allowed_emails'):
                    data.setdefault('claudecode_allowed_emails',
                                    auth0['allowed_emails'])
            if not data.get('claudecode_oauth2_cookie_secret'):
                data['claudecode_oauth2_cookie_secret'] = oauth2_cookie_secret(
                    data['cluster_name'])
            # Resolve the allowlist ONCE PER INSTANCE, here, so the template
            # cannot silently fall back.
            #
            # The allowlist is the whole door: every other layer of separation
            # between two instances on one cluster is already real (each has its
            # own claude-config and claude-workspace PVC, so its own ~/.claude,
            # keyring, login and history), and none of it means anything if both
            # doors admit the same people. An address on the support instance
            # that also opens the owner's instance drops the operator into the
            # owner's signed-in session, on the owner's account and billing.
            #
            # An unknown key is a hard error, not a no-op. A misspelt instance
            # name renders, deploys, and admits the global list — indis-
            # tinguishable from working right up until someone tries the wrong
            # door, and by then the wrong person is already inside. Raised from
            # data(), which runs before any file is written, so a bad override
            # costs a message rather than a half-written kubernetes/ tree.
            instances = data['claude_instances']
            by_instance = data.get('claudecode_allowed_emails_by_instance') or {}
            unknown = [k for k in by_instance if k not in instances]
            if unknown:
                raise KeyError(
                    "claudecode_allowed_emails_by_instance names "
                    f"{', '.join(sorted(unknown))}, which is not in "
                    f"claude_instances ({', '.join(instances)}). An override "
                    "for an instance that does not exist would leave that "
                    "instance on the global allowlist and say nothing.")
            data['claudecode_allowed_emails_by_instance'] = {
                name: by_instance.get(name, data.get('claudecode_allowed_emails', ''))
                for name in instances
            }
        # Backups are encrypted to the cluster's own age public key, taken from
        # .sops.yaml rather than added as another field to fill in. The key is
        # already there, it is already the thing that travels with the cluster
        # at handover, and a public key is not a secret. The consequence worth
        # stating: whoever holds age.key can read the backups, and nobody else
        # can — including the operator holding the R2 credentials.
        #
        # Read from age.key first, .sops.yaml only as a fallback. `.sops.yaml`
        # is ITSELF a makejinja output (templates/config/.sops.yaml.j2), so on
        # the first `task configure` of a fresh repo it does not exist yet when
        # data() runs, and this derived ''. Every later run found the file and
        # derived correctly — so the only run that got it wrong was the one
        # whose output the cluster gets bootstrapped from, and `task configure`
        # still exited 0. The backup CronJob then refuses to upload every night
        # for the life of the appliance (jg-base backup/app/configmap.yaml:49).
        #
        # Reproduced on jg-janncotcc 2026-08-22: remove .sops.yaml, run
        # makejinja, and BACKUP_AGE_RECIPIENT renders as "".
        #
        # age.key is an input, never an output, and `age-keygen` writes the
        # public half into it as a comment — so it is readable at the moment
        # data() runs, on the first render as on the hundredth.
        if 'backup_age_recipient' not in data:
            recipient = ''
            for source, pattern in (
                    (Path('age.key'), r'#\s*public key:\s*(age1[a-z0-9]+)'),
                    (Path('.sops.yaml'), r'age:\s*["\']?(age1[a-z0-9]+)')):
                if not source.is_file():
                    continue
                match = re.search(pattern, source.read_text())
                if match:
                    recipient = match.group(1)
                    break
            data['backup_age_recipient'] = recipient
        # The three LAN-facing services listen on non-overlapping ports
        # (80/443, 53, 1883), so one address serves all of them. Collapsing them
        # turns "find several free addresses on a LAN you have never seen" into
        # "find one", which is the difference between a customer-supplied field
        # and a discovered one.
        #
        # Opt-in, because collapsing is a breaking change for anything on the
        # LAN that already talks to the old addresses — a DNS resolver setting,
        # an MQTT broker address, a HomeKit pairing. An appliance has no such
        # history, so it collapses from the start; an existing cluster does it
        # deliberately by setting lan_shared_addr.
        shared = data.get('lan_shared_addr')
        if shared:
            # Unconditional, not "only if already set". An appliance declares
            # none of these — validation forbids them — so a conditional
            # overwrite would leave them empty and the Gateway annotations null,
            # which is the one shape the Gateway CRD rejects. This field is
            # documented as superseding them, so it supersedes an absent one too.
            for field in ('cluster_gateway_addr', 'cluster_dns_gateway_addr',
                          'mqtt_lb_ip'):
                data[field] = shared
        # Empty is not a sharing key that everything shares — Cilium treats it
        # as no key at all, verified on jgt-omni. So the annotations can sit in
        # jg-base unconditionally and stay inert on clusters that do not share.
        # k8s-gateway answers internal names for clients whose resolver points
        # at it. That is the primary path everywhere, including appliance:
        # Cloudflare refuses to publish RFC1918 answers (D29), so there is no
        # public-DNS route to fall back from. The operator points the router's
        # DNS at it once during installation (D32).
        #
        # It costs no extra address — 4.3 shares one with envoy-internal and
        # mqtt — so the only reason to turn it off is a cluster that runs its
        # own resolver.
        data.setdefault(
            'deploy_k8s_gateway',
            bool(data['k8s_gateway']) if 'k8s_gateway' in data else True)
        # A LoadBalancer on every profile, appliance included. The appliance used
        # to make it a ClusterIP on the reasoning that nothing on the LAN
        # connects to it — cloudflared reaches it by in-cluster DNS. That
        # reasoning missed k8s-gateway, which answers a hostname from whatever
        # address its parent Gateway holds: on jgt-appliance every externally
        # routed name resolved to a ClusterIP no LAN client could reach. The
        # probe now finds a second address for it instead.
        data.setdefault('envoy_external_service_type', 'LoadBalancer')
        # An appliance shares whether or not the address is declared yet. It
        # discovers exactly one address, so on the first boot — before anything
        # is pinned — every LAN service has to share that one or all but the
        # first sit <pending> forever. Keying off `shared` alone left them with
        # jg-base's per-service defaults, which differ by service and therefore
        # share nothing: measured on jgt-appliance, k8s-gateway took 10.9.1.254
        # under key "k8s-gateway" and envoy-internal waited under "envoy-internal".
        share_lan = bool(shared) or data.get('deployment_profile') == 'appliance'
        data.setdefault('lan_sharing_key', 'lan' if share_lan else '')
        # An explicit namespace list, never "*": kustomize strips the quotes
        # around a substituted scalar, and a bare `*` is a YAML alias, so the
        # whole manifest fails to parse after substitution. Naming the two
        # namespaces is also the smaller permission.
        data.setdefault('lan_sharing_cross_namespace',
                        'network,mqtt' if share_lan else '')
        # Every address this cluster actually hands to a LoadBalancer, so the
        # pool can stop covering the customer's entire LAN. `cluster_api_addr`
        # is deliberately absent: it is a Talos VIP, not a Service.
        #
        # The wide pool is only disabled once there is something to replace it
        # with. An appliance declares no addresses at all — it discovers its one
        # address at runtime — so it keeps the wide pool until that lands.
        lb_addrs: list[str] = []
        for field in ('cluster_gateway_addr', 'cluster_dns_gateway_addr',
                      'cloudflare_gateway_addr'):
            if data.get(field):
                lb_addrs.append(str(data[field]))
        for extra, field in (('default/mqtt', 'mqtt_lb_ip'),
                             ('ingress-nginx/ingress-nginx', 'ingress_nginx_lb_ip'),
                             ('default/mariadb', 'mariadb_lb_ip'),
                             ('omni/omni', 'omni_udp_lb_ip')):
            if extra in (data.get('extras') or []) and data.get(field):
                lb_addrs.append(str(data[field]))
        seen: set[str] = set()
        addrs = [a for a in lb_addrs if not (a in seen or seen.add(a))]
        # There is exactly one pool per cluster. A second, narrower pool alongside
        # a wide one cannot work — being a subset it overlaps, and Cilium rejects
        # any overlap with PoolConflict whether or not the wide one is disabled.
        # So a cluster with nothing to enumerate writes out the whole node CIDR
        # here, which is what it was getting implicitly anyway.
        #
        # The appliance test comes FIRST, and the order is the whole fix for
        # ferry133/jg-cluster-template#10.
        #
        # It used to sit after `if addrs:` and was therefore unreachable exactly
        # when it mattered. `lan_shared_addr` back-fills cluster_gateway_addr and
        # cluster_dns_gateway_addr about eighty lines above, and those are two of
        # the three fields `addrs` is built from — so declaring the shared address
        # (which fleet-ops docs/operations/router-dns.md tells every appliance operator to
        # do before touching the router) silently populated `addrs` and took the
        # first branch. The result on jgt-appliance: a static `pool` holding
        # 10.9.1.254 overlapping lan-address-probe's `pool-discovered`
        # [10.9.1.254, 10.9.1.253], Cilium disabling the whole discovered pool
        # with PoolConflict=True, and .253 — the only address envoy-external can
        # use — ceasing to exist. Every LAN name in the cluster's domain went
        # NXDOMAIN while the same names answered fine over the public tunnel,
        # because cloudflared's origin is a ClusterIP and never needed the LB.
        #
        # An appliance discovers its addresses at runtime and lan-address-probe
        # owns allocating them, so the static pool must be empty on an appliance
        # unconditionally — whether or not the operator has since declared the
        # address he was told to declare.
        if data.get('deployment_profile') == 'appliance':
            blocks = []
        elif addrs:
            blocks = [{'start': a, 'stop': a} for a in addrs]
        else:
            blocks = [{'cidr': str(data.get('node_cidr'))}]
        data.setdefault('lb_pool_blocks',
                        json.dumps(blocks, separators=(',', ':')))
        # Whether local-path should claim the cluster-default StorageClass.
        # nfs-subdir claims it whenever it is running, and it only runs on an
        # NFS cluster, so the two never collide.
        data.setdefault(
            'local_path_is_default',
            'true' if data.get('storage_backend') != 'nfs' else 'false',
        )
        # Whether Longhorn is installed. `storage_backend: "replicated"` implies
        # it, but a NAS-backed cluster can ask for it too — the NAS is right for
        # bulk and wrong for a database, and Longhorn is the one block class that
        # does not pin the pod to a node. Those clusters cannot say so through
        # storage_backend, which also decides whether nfs-subdir runs.
        #
        # This is not db_storage_class: installing the tier and moving a database
        # onto it are separate, because storageClassName is immutable and moving
        # means dump and restore. Keeping them separate is what lets the install
        # be verified before anything depends on it.
        data.setdefault(
            'deploy_longhorn',
            bool(data['replicated_storage']) if 'replicated_storage' in data
            else data.get('storage_backend') == 'replicated')
        # Single-node clusters must not run components that require peers. The
        # node list is only authoritative on the manual path — the Omni path
        # always renders `nodes: []` — so an Omni cluster that is not an
        # appliance has to say so with `single_node`, or it is assumed to have
        # peers. Assuming wrongly here only costs a component that would have
        # worked; assuming the other way silently disables one that was needed.
        if 'single_node' in data:
            data.setdefault('is_single_node', bool(data['single_node']))
        elif data.get('deployment_profile') == 'appliance':
            data.setdefault('is_single_node', True)
        elif data.get('provisioning_path') == 'talos':
            data.setdefault('is_single_node', len(data.get('nodes') or []) <= 1)
        else:
            data.setdefault('is_single_node', False)
        data.setdefault('repository_branch', 'main')
        data.setdefault('repository_visibility', 'public')

        return data


    def filters(self) -> makejinja.plugin.Filters:
        return [
            basename,
            nthhost,
            b64encode,
        ]


    def functions(self) -> makejinja.plugin.Functions:
        return [
            age_key,
            cloudflare_tunnel_id,
            cloudflare_tunnel_secret,
            github_deploy_key,
            github_push_token,
            talos_patches,
        ]
