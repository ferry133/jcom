package config

import (
	"net"
)

#Config: {
	node_cidr: net.IPCIDR & !=cluster_pod_cidr & !=cluster_svc_cidr
	node_dns_servers?: [...net.IPv4]
	node_ntp_servers?: [...net.IPv4]
	node_default_gateway?: net.IPv4 & !=""
	node_vlan_tag?: string & !=""
	cluster_pod_cidr: *"10.42.0.0/16" | net.IPCIDR & !=node_cidr & !=cluster_svc_cidr
	cluster_svc_cidr: *"10.43.0.0/16" | net.IPCIDR & !=node_cidr & !=cluster_pod_cidr
	cluster_api_addr: net.IPv4
	cluster_api_tls_sans?: [...net.FQDN]
	cluster_gateway_addr: net.IPv4 & !=cluster_api_addr & !=cluster_dns_gateway_addr & !=cloudflare_gateway_addr
	cluster_dns_gateway_addr: net.IPv4 & !=cluster_api_addr & !=cluster_gateway_addr & !=cloudflare_gateway_addr
	repository_name: string & !="" & !="ferry133/xxxxxx" & !="ferry133/jg-base"
	repository_branch?: string & !=""
	repository_visibility?: *"public" | "private"
	cloudflare_domain: net.FQDN
	cloudflare_token: string
	cloudflare_gateway_addr: net.IPv4 & !=cluster_api_addr & !=cluster_gateway_addr & !=cluster_dns_gateway_addr
	github_webhook_token?: string & !=""
	cilium_bgp_router_addr?: net.IPv4 & !=""
	cilium_bgp_router_asn?: string & !=""
	cilium_bgp_node_asn?: string & !=""
	cilium_loadbalancer_mode?: *"dsr" | "snat"
	nas_server?: net.IPv4 & !=""
	nas_path?: string & !=""
	nas_coding_path?: string & !=""
	cluster_name: string & !=""
	coredns_cluster_ip?: net.IPv4
	extras?: [...string]
	freepbx_mysql_root_password?: string & !=""
	freepbx_mysql_password?: string & !=""
	claudecode_postgres_password?: string & !=""
	claude_code_database_url?: string
	claude_instances?: [...string]
	ttyd_credential?: string & !=""
	postgres_password?: string & !=""
	trello_api_key?: string
	trello_api_token?: string
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
}

#Config
