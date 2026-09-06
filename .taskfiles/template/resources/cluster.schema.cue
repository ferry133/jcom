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
	//                fleet-ops docs/operations/replicated-storage.md
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

	// Whether Longhorn is installed, independent of which tier bulk data uses.
	// `storage_backend: "replicated"` means "Longhorn, and it is also the bulk
	// tier"; this means "Longhorn is available" and leaves bulk where it is.
	//
	// A NAS-backed cluster with several nodes needs exactly that combination: the
	// NAS is right for bulk and wrong for a database, and the only class that is
	// block-backed without pinning the pod to one node is Longhorn. Expressing it
	// through storage_backend alone is not possible — that field also decides
	// whether nfs-subdir runs, so asking for Longhorn there takes the NAS away
	// from everything already on it.
	//
	// Installing it does not move any database onto it; that is db_storage_class
	// below, and it is a separate step because storageClassName is immutable and
	// moving means dump and restore.
	//
	// Defaults to whether storage_backend is "replicated" — declared here without
	// a value so the derivation lives in exactly one place (see plugin.py).
	replicated_storage?: bool

	// Same reasoning as storage_backend above: two replicas on one machine are
	// two copies of one disk.
	if single_node == true {
		replicated_storage?: false
	}

	// Where Longhorn writes its backups. Optional, and absent means no Longhorn
	// backups at all — which is what every cluster did before this existed.
	//
	// Longhorn's replica count survives a node dying. It does not survive
	// `kubectl delete pvc` or a corrupt table: both are replicated faithfully to
	// every replica. This is the only thing in the stack that does.
	//
	// A URL, not a bool, because the destination is per-cluster and unguessable
	// — it is a LAN NAS export that most clusters cannot reach, which is exactly
	// why it cannot be hardcoded in jg-base. Longhorn accepts nfs://, cifs://,
	// s3://, azblob:// and gcs://; only NFS is exercised here.
	//
	// jg-base derives the on/off selector from whether this is set, so there is
	// no second field to keep in agreement with it (see plugin.py).
	// Defaulted rather than optional, so the guard below can actually read it.
	// `longhorn_backup_target?: string` with `if longhorn_backup_target != _|_`
	// looks like the same thing and is not: that comparison never fires, and a
	// guard that never fires reads exactly like one that passes. Caught by
	// running the negative control instead of only the positive one.
	longhorn_backup_target: *"" | string

	// Backing up a Longhorn volume requires Longhorn.
	//
	// ⚠️ This catches HALF the problem and it is worth knowing which half.
	// It fires on the outright contradiction — a target together with an
	// explicit `replicated_storage: false` — measured: "conflicting values
	// true and false". It does NOT fire when `replicated_storage` is simply
	// absent, because defining an optional field is not a conflict, and
	// plugin.py derives `deploy_longhorn` from cluster.yaml rather than from
	// CUE's unified value, so this line changes nothing about the render.
	//
	// The absent case is the one that happens, and it is covered by
	// scripts/check-longhorn-backup.py against the rendered artifacts. Do not
	// read this block as the guard; it is the cheap half of one.
	if longhorn_backup_target != "" {
		replicated_storage: true
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
	// claude-code's config PVC — ~/.claude and the keyring it holds, one volume
	// because a token and the keyring holding it have no reason to be apart.
	//
	// Defaults to default_storage_class (today's value), NOT to db_storage_class.
	// `storageClassName` is immutable, so pointing a default somewhere else does
	// not migrate a cluster, it renders a PVC the cluster cannot accept. Naming
	// a class here is how a cluster records where it is — including recording
	// that it has not moved yet.
	claudecode_config_storage_class?: string & !=""
	// Whether the workspace PVC is rendered at all. Default true.
	//
	// ⚠️ false REMOVES the PVC from the release. On the NFS class the
	// provisioner archives rather than deletes; on local-path and
	// longhorn-static the reclaim policy is Delete and nothing catches it.
	claudecode_workspace?: bool

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
	// Where this cluster's shared base manifests come from. Defaulted, not
	// optional: every cluster has an answer, and the default is the fleet's.
	//
	// A cluster whose owner takes over maintenance points these at their own
	// fork; a cluster that wants to stop tracking `main` pins a tag or a commit.
	// Nothing else about the rendered Flux tree may change with them — see
	// ks.yaml.j2 for why renaming the GitRepository tears the cluster down.
	base_repo_url: *"https://github.com/ferry133/jg-base" | string & !=""
	base_repo_ref: *"main" | string & !=""
	// Which Flux ref field `base_repo_ref` lands in. Declared rather than
	// inferred: a tag and a branch are both just strings, and guessing wrong
	// produces a GitRepository that reconciles something other than what the
	// operator named — which reads exactly like it worked.
	base_repo_ref_kind: *"branch" | "tag" | "semver" | "commit"
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

	// NAS — only meaningful when bulk storage is NFS-backed. nas_coding_path
	// stays optional even then: without it the claude-code workspace falls back
	// to the profile's default storage class.
	nas_server?: net.IPv4 & !=""
	nas_path?: string & !=""
	// ⚠️ UNCONSUMED since the claude-code `coding` mount was removed. Kept
	// because three cluster.yaml files declare it and deleting the field would
	// fail their next `cue vet` over a value that harms nothing. NAS_CODING_PATH
	// is still rendered into cluster-secrets and still read by nobody.
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
	// claudecode/claude-code EXTRA instances. The default `im` is a static
	// base app in jg-base since 2026-09-06 — it deploys on every re-rendered
	// cluster with no field set here, and "im" in this list is a render error
	// (it would fight the base HelmRelease over the same object name; rename
	// the instance instead).
	claude_instances?: [...string]
	// Which EXTRA claude-code instances stay running (the base im always
	// does). Unset means: the one instance if claude_instances names exactly
	// one, and NOTHING if it names more than one — the render refuses to pick
	// and says so on stderr (#57). Each is a root shell with cluster-admin
	// RBAC that the tunnel exposes, so a cluster that wants a specific one
	// standing names it here. Scaling by hand instead works until the next
	// reconcile and then disappears without an apparent cause.
	//
	// The value lives in templates/scripts/plugin.py (DEFAULT_CLAUDE_INSTANCES
	// and the rule beside it). Deliberately not restated here: this comment read
	// "Empty by default" and stayed readable for a day after that stopped being
	// true — the same defect #57 is about, one layer up.
	claude_code_always_on?: [...string]
	// Auth0 OIDC login in front of every claude-code instance. Defaults to true
	// at render time. When on, this cluster's own claudecode_auth0_* values and
	// claudecode_allowed_emails are REQUIRED — they are not inherited from
	// auth0.json unless claudecode_auth0_shared says so (jgct#64).
	//
	// Setting it false does two things: swaps jg-base's claude-code-im to its
	// empty disabled path (the base im hardwires the Auth0 sidecar, so a
	// basic-auth base im cannot exist — Flux prunes it, the retain:true PVCs
	// survive), and falls back to ttyd basic auth for the cluster's own
	// claude_instances, which then needs ttyd_credential — checked by
	// scripts/check-claudecode-auth.py.
	claudecode_auth0?: bool
	// Only used when claudecode_auth0 is false. Strength is checked by
	// scripts/check-claudecode-auth.py, not here: a CUE constraint prints the
	// offending value in its error, and a check that leaks the credential into
	// a terminal and CI log to complain about it is worse than no check.
	ttyd_credential?: string & !=""
	// This cluster's OWN Auth0 tenant (2026-08-25 ruling). Required in practice
	// whenever claudecode_auth0 is not false — enforced in plugin.py rather than
	// here, because a CUE condition on an optional bool is not concrete and
	// `cue vet` reports it against an unrelated field (measured on node_cidr,
	// jgct#51).
	//
	// They are no longer inherited from auth0.json: that fallback made
	// "forgot to set it" and "deliberately shares a tenant" identical, and the
	// identical answer was the shared one (jgct#64). Sharing now needs
	// claudecode_auth0_shared below.
	claudecode_auth0_domain?: string & !=""
	claudecode_auth0_client_id?: string & !=""
	claudecode_auth0_client_secret?: string & !=""
	// Opt in to reading the three values above (and allowed_emails) from a
	// gitignored auth0.json in this cluster's directory — i.e. this cluster
	// deliberately shares another cluster's tenant. Absent, a missing field is
	// an error rather than an inheritance.
	claudecode_auth0_shared?: bool
	// Derived from age.key + cluster_name at render time when absent, so it is
	// stable across renders and distinct per cluster. Leaving it unset is the
	// good case — the derivation has always emitted the shape oauth2-proxy
	// wants, and every value it has ever refused was one a human wrote.
	//
	// The format rule is in scripts/check-claudecode-auth.py, not here, for the
	// same reason as ttyd_credential above: `cue vet` prints the offending
	// value in its error (measured — a mismatching secret came back verbatim in
	// the message), so a CUE constraint would put this secret in a terminal and
	// a CI log in order to complain about it.
	claudecode_oauth2_cookie_secret?: string & !=""
	claudecode_allowed_emails?: string & !=""
	// Per-instance override of the line above, keyed by instance name. Absent
	// keys inherit the global list, so a cluster that sets only the global
	// field renders exactly what it rendered before.
	//
	// Exists because the allowlist is the one layer of separation between two
	// instances on a cluster that was NOT per-instance: each already has its
	// own config and workspace PVC, hence its own ~/.claude, keyring, login and
	// history. One shared door undoes all of that.
	//
	// A key that is not in claude_instances fails the render — see plugin.py.
	// CUE cannot express that cross-check against a field it may only see
	// defaulted, and an override that silently does nothing is exactly the
	// failure this field exists to prevent.
	claudecode_allowed_emails_by_instance?: [string]: string & !=""
	talos_mcp_config?: string & !=""
	talos_mcp_sa_key?: string & !=""
	talos_mcp_omni_endpoint?: string & !=""
	// factory provisioning credentials (extras/factory/factory in jg-base).
	// Only the cluster that hosts factory sets these -- jcom today. Every one is
	// optional and renders empty elsewhere, which is what the consuming Secret
	// expects: empty means "not issued yet", and each consumer fails loudly on
	// it (omnictl refuses to authenticate, gh reports no token, a zero-byte
	// deploy key fails at key load).
	//
	// Declared here 2026-08-27. Before that the consuming half existed in
	// jg-base while nothing could declare the values, so factory's pod ran
	// 2/2 Ready holding three empty credentials -- measured on jcom that day:
	// OMNI_SERVICE_ACCOUNT_KEY, GITHUB_TOKEN and CLOUDFLARE_API_TOKEN were all
	// len=0 while the pod, the Secret and the env names all read as present.
	//
	// Four, not five. `factory_cloudflare_token` was declared here on
	// 2026-08-27 and removed on 2026-08-29: ferry133/jg-base#44 established
	// that its premise was gone. That row assumed "the operator's Cloudflare
	// account holds every customer zone", and D11 (2026-08-25) puts each
	// customer's Cloudflare account under the customer's own identity —
	// measured, janncot.cc and jiahd.cc answer from different NS pairs, which
	// Cloudflare assigns per account. jg-base removed the consuming key in
	// #46, so a value set here would render into a Secret key that no longer
	// exists. Do not re-add it without reading that README section: the
	// deciding argument is that the credential cannot be singular while this
	// field is a scalar.
	factory_omni_sa_key?:            string & !=""
	factory_omni_endpoint?:          string & !=""
	factory_github_token?:           string & !=""
	factory_fleet_ops_deploy_key?:   string & !=""
	postgres_password?: string & !=""
	trello_api_key?: string
	trello_api_token?: string
	trello_board_id?: string
	line_channel_access_token?: string
	line_channel_secret?: string
	line_notify_group_id?: string
	// Optional in general, REQUIRED when an extra that reads it is selected.
	// Conditional and not unconditional: a cluster that runs neither must not be
	// made to supply a key it does not use.
	//
	// Without this, selecting either extra rendered cleanly with an empty key
	// and the failure arrived later, from the workload, as an auth error a long
	// way from the field that caused it.
	//
	// ⚠️ What this does NOT check is provenance. Presence is all a schema can
	// see; whether the key belongs to the cluster's owner rather than to the
	// operator is a delivery-time question with a recorded answer, and a set,
	// valid, working key that bills the wrong party passes every check here.
	// Same shape as a notification address that delivers mail to the wrong
	// people.
	//
	// Also worth knowing: the two extras share this ONE variable rather than
	// holding a key each. Fine while one party owns both; a cluster that ever
	// runs them for different parties would be using one credential for both.
	anthropic_api_key?: string
	#AnthropicExtras: [
		"default/linebot",
		"default/synophoto",
	]
	if len([for e in extras if list.Contains(#AnthropicExtras, e) {e}]) > 0 {
		anthropic_api_key: string & !=""
	}
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
