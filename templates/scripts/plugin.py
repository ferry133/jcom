from pathlib import Path
from typing import Any

import base64
import ipaddress
import makejinja
import re
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


# Return a list of files in the talos patches directory
def talos_patches(value: str) -> list[str]:
    path = Path(f'templates/config/talos/patches/{value}')
    if not path.is_dir():
        return []
    return [str(f) for f in sorted(path.glob('*.yaml.j2')) if f.is_file()]


class Plugin(makejinja.plugin.Plugin):
    def __init__(self, data: dict[str, Any]):
        self._data = data


    def data(self) -> makejinja.plugin.Data:
        data = self._data

        # Set default values for optional fields.
        # These must match the defaults documented in cluster.sample.yaml —
        # a documented default the code does not apply is a defect.
        data.setdefault('node_default_gateway', nthhost(data.get('node_cidr'), 1))
        # 2026-08-27: the LAN's router, not Cloudflare. A node pinned to a
        # public resolver cannot resolve `internal.<domain>` at all -- that name
        # is deliberately never published publicly -- so everything running on
        # this node got NXDOMAIN for every internal name, including the `im`
        # rescue terminal. Measured here: `dig @10.43.0.10 internal.janncot.com`
        # was NXDOMAIN while `dig @10.9.8.1 internal.janncot.com` returned
        # 10.9.8.4, and `dig @1.1.1.1 github.com` answered (so the node's path
        # was working, it was just pointed at somewhere that has no such record).
        #
        # Single entry, deliberately -- a public fallback would make CoreDNS
        # pick between upstreams at random (its forward plugin's default policy)
        # and internal names would resolve on roughly half of all queries.
        #
        # Mirrors ferry133/jg-cluster-template#29. Applied here as a one-line
        # change rather than by syncing this copy: templates/ in this repo has
        # drifted ~890 lines from upstream, and pulling all of it in would be a
        # template upgrade wearing a DNS fix's clothes. The drift is real and
        # tracked separately; it is not this change's to resolve.
        data.setdefault('node_dns_servers', [data['node_default_gateway']])
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
        # The block tier, for anything that needs fsync durability and file
        # locking. Not derived from storage_backend: NFS is never a valid answer
        # here, whatever the cluster uses for bulk data. An existing cluster
        # whose database is already on NFS overrides this until it can be dumped
        # and restored — a PVC's storageClassName is immutable, so the move is
        # not something a re-render can perform.
        data.setdefault('db_storage_class', 'local-path')
        # Which claude-code instances stay up. Empty by default: each is a root
        # shell with cluster-admin that the tunnel makes reachable. Named here
        # rather than scaled by hand, which works until the next reconcile.
        data.setdefault('claude_code_always_on', [])
        # Backups are encrypted to the cluster's own age public key, taken from
        # .sops.yaml rather than added as another field to fill in. The key is
        # already there, it is already the thing that travels with the cluster
        # at handover, and a public key is not a secret. The consequence worth
        # stating: whoever holds age.key can read the backups, and nobody else
        # can — including the operator holding the R2 credentials.
        if 'backup_age_recipient' not in data:
            sops_config = Path('.sops.yaml')
            recipient = ''
            if sops_config.is_file():
                match = re.search(r'age:\s*["\']?(age1[a-z0-9]+)',
                                  sops_config.read_text())
                if match:
                    recipient = match.group(1)
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
            for field in ('cluster_gateway_addr', 'cluster_dns_gateway_addr',
                          'mqtt_lb_ip'):
                if data.get(field):
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
        # Nothing on the LAN connects to the external gateway — cloudflared
        # reaches it by in-cluster DNS name — so on an appliance it takes no LAN
        # address at all. Elsewhere it stays a LoadBalancer, because operators do
        # reach it directly today and changing that is not this change's business.
        data.setdefault(
            'envoy_external_service_type',
            'ClusterIP' if data.get('deployment_profile') == 'appliance'
            else 'LoadBalancer')
        data.setdefault('lan_sharing_key', 'lan' if shared else '')
        # An explicit namespace list, never "*": kustomize strips the quotes
        # around a substituted scalar, and a bare `*` is a YAML alias, so the
        # whole manifest fails to parse after substitution. Naming the two
        # namespaces is also the smaller permission.
        data.setdefault('lan_sharing_cross_namespace',
                        'network,mqtt' if shared else '')
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
        # There is exactly one pool. A second, narrower pool alongside the wide
        # one cannot work — being a subset it overlaps, and Cilium rejects any
        # overlap with PoolConflict=cidr_overlap whether or not the wide one is
        # disabled. So a cluster with nothing to enumerate writes out the whole
        # node CIDR here, which is what it was getting implicitly anyway.
        if addrs:
            blocks = [{'start': a, 'stop': a} for a in addrs]
        elif data.get('deployment_profile') == 'appliance':
            # An appliance declares no addresses; lan-address-probe discovers one
            # and publishes it as a second pool. This one stays empty so the two
            # cannot overlap — Cilium rejects overlapping pools outright.
            blocks = []
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
