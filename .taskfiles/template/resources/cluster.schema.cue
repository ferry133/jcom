package config

import (
	"net"
	"list"
)

#Config: {
	// Who this cluster is for. No default: an unmigrated config must fail here
	// rather than be rendered under an assumed profile.
	//   appliance  zero customer-supplied fields; single node; operator-managed
	//   prosumer   customer has a NAS and some infrastructure of their own
	//   full       expert operates it directly; today's behaviour
	deployment_profile: "appliance" | "prosumer" | "full"

	// Where stateful data lives. Databases always want block storage regardless
	// of this — it selects what bulk media and file shares use.
	//
	//   local-path   node-local disk; correct on one node, pins on several
	//   nfs          NAS-backed
	//   replicated   Longhorn. Requires Talos system extensions on every node,
	//                which no manifest can install — see
	//                docs/operations/replicated-storage.md
	storage_backend: "local-path" | "nfs" | "replicated"

	// An appliance has no NAS to configure and nobody to configure it. It is
	// also a single node, where replication has nothing to replicate onto.
	if deployment_profile == "appliance" {
		storage_backend: "local-path"
	}
	// Replication across one node is a copy of a copy on the same disk: the
	// cost of Longhorn with none of the protection.
	if single_node == true {
		storage_backend: "local-path" | "nfs"
	}

	// Whether this cluster has exactly one node. Derived where it can be —
	// appliance is single by definition, and the manual path has an authoritative
	// node list — but an Omni-provisioned cluster renders `nodes: []`, so it must
	// declare this or be treated as having peers. Components that need peers
	// (a peer-to-peer image mirror, for one) are suspended when this is true.
	single_node?: bool

	// local-path volumes live in a directory on one node and the PV carries node
	// affinity to it. On a single node that is simply correct. On more than one
	// node it silently pins every stateful workload to whichever node first
	// scheduled it: the pod cannot be rescheduled elsewhere, and losing that node
	// loses both the data and the ability to restart. The cluster looks
	// replicated and is not.
	//
	// Set this only when that is understood and accepted. The real answer for a
	// multi-node cluster with no NAS is replicated block storage, which this
	// stack does not yet provide.
	accept_node_pinning?: bool

	if deployment_profile == "appliance" {
		single_node: true
	}

	// Extras that put a database on the node-local block tier rather than on
	// bulk storage. NFS does not honour the fsync and lock semantics a database
	// needs, so these land on `local-path` even when the cluster has a NAS —
	// which is the same node-pinning exposure as choosing `local-path` for
	// everything, arriving by a different route.
	#BlockTierExtras: [
		"claudecode/postgres",
		"default/mariadb",
		"default/postgres",
		"freepbx/freepbx",
	]

	// Which class the block tier uses. Node-local by default, but `longhorn`
	// once the cluster has replicated storage — that is the whole point of
	// running it, and leaving the database on local-path would keep it pinned.
	//
	// A cluster whose database is still on NFS names that class here until it
	// can be dumped and restored — a PVC's storageClassName is immutable, so
	// the move is not something a re-render can perform.
	// Deliberately one default, not one per backend. Deploying Longhorn does
	// not move the database onto it — that is an explicit `db_storage_class:
	// "longhorn"`. Forgetting is not silent: the database is still on a
	// node-local class, so the pinning acknowledgement below fires and asks
	// about exactly the thing that was forgotten.
	db_storage_class: *"local-path" | string & !=""

	// Whether anything in this cluster lands on a node-local class. This, and
	// not `storage_backend`, is what the acknowledgement below has to be keyed
	// on: a NAS-backed cluster running a database is pinned just as hard, and
	// asking about the default class would wave it through. Equally, a cluster
	// that has deliberately parked its database on NFS is pinning nothing, and
	// should not be asked to acknowledge what is not happening.
	// `longhorn` is block-backed AND replicated, so it is the one block class
	// that does not pin. Deploying replicated storage is therefore what lifts
	// the acknowledgement, which is the correct incentive.
	_uses_node_local: (storage_backend == "local-path") ||
		(db_storage_class == "local-path" &&
			len([for e in extras if list.Contains(#BlockTierExtras, e) {e}]) > 0)

	if _uses_node_local {
		single_node: bool
		if single_node == false {
			// `bool` and not `true`: an unresolved type is what makes an absent
			// field fail validation. Asserting the value here instead would let
			// CUE satisfy the requirement on the reader's behalf, and the check
			// would pass without anyone having read it.
			accept_node_pinning: bool
			if accept_node_pinning == false {
				accept_node_pinning: _|_
			}
		}
	}

	// How this cluster's machines are provisioned. Declared rather than inferred:
	// nodes.yaml is materialised automatically for every repo (makejinja aborts on
	// a missing data file), so its presence proves nothing about the path.
	provisioning_path: "omni" | "talos"

	// The manual path needs per-node IP, NIC and disk selectors that a zero-IT
	// customer cannot supply, so reject the combination at validation time
	// instead of failing later during bootstrap.
	if deployment_profile == "appliance" {
		provisioning_path: "omni"
	}

	// Omni supplies the machine config, so a node list there is meaningless and
	// would silently render an unused talconfig. The manual path needs at least one.
	if provisioning_path == "omni" {
		nodes: []
	}
	if provisioning_path == "talos" {
		nodes: list.MinItems(1)
	}

	node_cidr: net.IPCIDR & !=cluster_pod_cidr & !=cluster_svc_cidr
	node_dns_servers?: [...net.IPv4]
	node_ntp_servers?: [...net.IPv4]
	node_default_gateway?: net.IPv4 & !=""
	node_vlan_tag?: string & !=""
	cluster_pod_cidr: *"10.42.0.0/16" | net.IPCIDR & !=node_cidr & !=cluster_svc_cidr
	// No default: the correct value differs per provisioning path (manual Talos
	// clusters use 10.43.0.0/16, Omni-provisioned clusters 10.96.0.0/12), and
	// coredns_cluster_ip is derived from it. Guessing wrong yields a coredns
	// clusterIP outside the service CIDR, which fails only after the cluster is
	// up — so require it and fail in `cue vet` instead.
	cluster_svc_cidr: net.IPCIDR & !=node_cidr & !=cluster_pod_cidr
	cluster_api_tls_sans?: [...net.FQDN]

	// LoadBalancer / VIP addresses.
	//
	// Under `appliance` these are not declared at all: the single LAN-facing
	// address is discovered at runtime (see the lan-address-allocation spec),
	// envoy-external needs no LoadBalancer because cloudflared reaches it by
	// in-cluster DNS name, and the API is reached through the Omni proxy.
	// Declaring them there would be a value nothing reads.
	cluster_api_addr?:         net.IPv4
	cluster_gateway_addr?:     net.IPv4
	cluster_dns_gateway_addr?: net.IPv4
	cloudflare_gateway_addr?:  net.IPv4

	if deployment_profile != "appliance" {
		cluster_api_addr:         net.IPv4
		cluster_gateway_addr:     net.IPv4 & !=cluster_api_addr & !=cluster_dns_gateway_addr & !=cloudflare_gateway_addr
		cluster_dns_gateway_addr: net.IPv4 & !=cluster_api_addr & !=cluster_gateway_addr & !=cloudflare_gateway_addr
		cloudflare_gateway_addr:  net.IPv4 & !=cluster_api_addr & !=cluster_gateway_addr & !=cluster_dns_gateway_addr
	}

	// Setting one of these on an appliance is a mistake worth catching: it looks
	// like it configures something but nothing reads it.
	if deployment_profile == "appliance" {
		cluster_api_addr?:         _|_
		cluster_gateway_addr?:     _|_
		cluster_dns_gateway_addr?: _|_
		cloudflare_gateway_addr?:  _|_
		mqtt_lb_ip?:               _|_
	}
	repository_name: string & !="" & !="ferry133/xxxxxx" & !="ferry133/jg-base"
	repository_branch?: string & !=""
	repository_visibility?: *"public" | "private"
	cloudflare_domain: net.FQDN
	cloudflare_token: string
	github_webhook_token?: string & !=""
	// Cilium native routing instead of the default vxlan tunnel.
	//
	// A cluster that hosts Omni needs this: SideroLink carries WireGuard over
	// the pod network, and vxlan's 1370-byte pod MTU is too small for it — the
	// tunnel fails with `sendmmsg: message too long`. Removing the encapsulation
	// allows MTU 1500 and makes DSR load balancing usable, which vxlan does not
	// support.
	//
	// Requires every node on one L2 segment: native routing installs direct
	// routes to each node's pod CIDR rather than encapsulating between them.
	// Can be removed when the cluster no longer hosts Omni, or when SideroLink
	// stops needing more than 1370 bytes.
	cilium_native_routing?: bool

	cilium_bgp_router_addr?: net.IPv4 & !=""
	cilium_bgp_router_asn?: string & !=""
	cilium_bgp_node_asn?: string & !=""
	cilium_loadbalancer_mode?: *"dsr" | "snat"
	// NAS — only meaningful when bulk storage is NFS-backed. nas_coding_path
	// stays optional even then: without it the claude-code workspace falls back
	// to the profile's default storage class.
	nas_server?: net.IPv4 & !=""
	nas_path?: string & !=""
	nas_coding_path?: string & !=""

	if storage_backend == "nfs" {
		nas_server: net.IPv4 & !=""
		nas_path: string & !=""
	}
	cluster_name: string & !=""
	coredns_cluster_ip?: net.IPv4


	// Off-site backup. A single-node appliance on local disk has no redundancy,
	// so losing the disk loses the database and the agent's accumulated context.
	// Required there rather than opt-in: rendering a cluster whose data is
	// unprotected should not be possible.
	backup_r2_bucket?: string & !=""
	backup_r2_endpoint?: string & !=""
	backup_r2_access_key_id?: string & !=""
	backup_r2_secret_access_key?: string & !=""

	// Whether age.key has been escrowed somewhere outside this cluster.
	//
	// Backups are encrypted to the cluster's own public key, so age.key is the
	// only thing that can read them. On a single-node appliance it lives on the
	// one disk whose failure the backups exist to survive — an unescrowed key
	// means the backups are ciphertext nobody can open, which is worse than no
	// backups because it looks like protection.
	//
	// Declared rather than defaulted, for the same reason as
	// accept_node_pinning: a default would answer on the operator's behalf.
	age_key_escrowed?: bool

	if deployment_profile == "appliance" {
		// `bool` and not `true`: an absent field must fail validation.
		age_key_escrowed: bool
		if age_key_escrowed == false {
			age_key_escrowed: _|_
		}
		backup_r2_bucket: string & !=""
		backup_r2_endpoint: string & !=""
		backup_r2_access_key_id: string & !=""
		backup_r2_secret_access_key: string & !=""
	}
	// Defaulted rather than optional so the block-tier test above can read it
	// unconditionally.
	extras: *[] | [...string]
	freepbx_mysql_root_password?: string & !=""
	freepbx_mysql_password?: string & !=""
	claudecode_postgres_password?: string & !=""
	claude_code_database_url?: string
	// claudecode/claude-code (base app on every cluster). claude_instances
	// defaults to ["im"] at render time; ttyd_credential is only unused when
	// claudecode_auth0_* switches the instances to OIDC login.
	claude_instances?: [...string]
	// Which claude-code instances stay running. Empty by default — each is a
	// root shell with cluster-admin RBAC that the tunnel exposes — so a cluster
	// that wants one standing names it here. Scaling by hand instead works
	// until the next reconcile and then disappears without an apparent cause.
	//
	// A list rather than a flag because clusters do mix: jcom keeps `im` up for
	// support and leaves `cc` at zero until it is needed.
	claude_code_always_on?: [...string]
	// Strength is checked by scripts/check-ttyd-credential.py, not here: a CUE
	// constraint prints the offending value in its error, and a check that leaks
	// the credential into a terminal and CI log to complain about it is worse
	// than no check.
	ttyd_credential?: string & !=""
	claudecode_auth0_domain?: string & !=""
	claudecode_auth0_client_id?: string & !=""
	claudecode_auth0_client_secret?: string & !=""
	claudecode_oauth2_cookie_secret?: string & !=""
	claudecode_allowed_emails?: string & !=""
	talos_mcp_config?: string & !=""
	talos_mcp_sa_key?: string & !=""
	talos_mcp_omni_endpoint?: string & !=""
	postgres_password?: string & !=""
	trello_api_key?: string
	trello_api_token?: string
	trello_board_id?: string
	line_channel_access_token?: string
	line_channel_secret?: string
	line_notify_group_id?: string
	anthropic_api_key?: string
	database_url?: string
	synophoto_auth0_domain?: string
	synophoto_auth0_client_id?: string
	synophoto_auth0_client_secret?: string
	synophoto_allowed_emails?: string
	synophoto_flask_secret_key?: string
	synophoto_nas_username?: string
	synophoto_nas_password?: string
	omni_gpg_key?: string
	mqtt_lb_ip?: net.IPv4 & !=""
	ingress_nginx_lb_ip?: net.IPv4 & !=""
	// LoadBalancer addresses for extras that used to hardcode one in jg-base.
	// Declared here so the narrowed pool knows about them — an address the pool
	// does not contain is an address the Service cannot get.
	mariadb_lb_ip?: net.IPv4 & !=""
	omni_udp_lb_ip?: net.IPv4 & !=""

	// Collapse every LAN-facing service onto one address. Their ports do not
	// overlap (80/443, 53, 1883), so one address serves all three, and finding
	// one free address on an unknown LAN is a far smaller problem than finding
	// three. When set it supersedes cluster_gateway_addr,
	// cluster_dns_gateway_addr and mqtt_lb_ip — those stay declared because the
	// cluster still has to state which addresses it claims, but all three
	// render to this one.
	//
	// Opt-in: collapsing moves services off addresses that LAN clients may
	// already be configured with.
	lan_shared_addr?: net.IPv4 & !=""

	// Deploy k8s-gateway, the in-cluster resolver for internal names. On by
	// default everywhere, because it is the only thing that answers them:
	// Cloudflare refuses to publish RFC1918 addresses, so there is no
	// public-DNS route. The operator points the router's DNS at it once during
	// installation. It shares its address with envoy-internal and mqtt, so it
	// costs nothing extra. Turn it off only where something else resolves those
	// names.
	k8s_gateway?: bool
	cloudflare_lan_tunnel_token?: string & !=""
	// monitoring/daily-check (base app on every cluster). Fields stay optional:
	// an unconfigured cluster's CronJob exits 0 with a "not configured" log
	// line instead of failing daily, so nothing breaks until these are set.
	daily_check_smtp_host?:             string
	daily_check_smtp_port?:             string
	daily_check_smtp_username?:         string
	daily_check_smtp_password?:         string
	daily_check_smtp_from?:             string
	daily_check_notify_email_to?:       string
	daily_check_healthchecks_ping_url?: string
	daily_check_endpoints?:             string
}

#Config
