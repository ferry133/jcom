#!/usr/bin/env bash
set -Eeuo pipefail

source "$(dirname "${0}")/lib/common.sh"

export LOG_LEVEL="debug"
export ROOT_DIR="$(git rev-parse --show-toplevel)"

# Talos requires the nodes to be 'Ready=False' before applying resources
function wait_for_nodes() {
    log debug "Waiting for nodes to be available"

    # Skip waiting if all nodes are 'Ready=True'
    if kubectl wait nodes --for=condition=Ready=True --all --timeout=10s &>/dev/null; then
        log info "Nodes are available and ready, skipping wait for nodes"
        return
    fi

    # Wait for all nodes to be 'Ready=False'
    until kubectl wait nodes --for=condition=Ready=False --all --timeout=10s &>/dev/null; do
        log info "Nodes are not available, waiting for nodes to be available. Retrying in 10 seconds..."
        sleep 10
    done
}

# Namespaces to be applied before the SOPS secrets are installed
function apply_namespaces() {
    log debug "Applying namespaces"

    # Base namespaces from jg-base/kubernetes/apps/base/ — not present in per-user repo.
    # Extras namespaces (e.g. claude-code) are created by Flux on first reconcile.
    local -ra namespaces=(cert-manager default flux-system kube-system network storage)

    for namespace in "${namespaces[@]}"; do
        # Check if the namespace resources are up-to-date
        if kubectl get namespace "${namespace}" &>/dev/null; then
            log info "Namespace resource is up-to-date" "resource=${namespace}"
            continue
        fi

        # Apply the namespace resources
        if kubectl create namespace "${namespace}" --dry-run=client --output=yaml \
            | kubectl apply --server-side --filename - &>/dev/null;
        then
            log info "Namespace resource applied" "resource=${namespace}"
        else
            log error "Failed to apply namespace resource" "resource=${namespace}"
        fi
    done
}

# SOPS secrets to be applied before the helmfile charts are installed
function apply_sops_secrets() {
    log debug "Applying secrets"

    # Ensure flux-system namespace exists (jg-base manages it via Flux,
    # so it's not under kubernetes/apps/ for apply_namespaces to create)
    kubectl create namespace flux-system --dry-run=client --output=yaml \
        | kubectl apply --server-side --filename - &>/dev/null \
        || log error "Failed to ensure flux-system namespace"

    local -r secrets=(
        "${ROOT_DIR}/bootstrap/github-deploy-key.sops.yaml"
        "${ROOT_DIR}/bootstrap/sops-age.sops.yaml"
        "${ROOT_DIR}/kubernetes/components/sops/cluster-secrets.sops.yaml"
    )

    for secret in "${secrets[@]}"; do
        if [ ! -f "${secret}" ]; then
            log warn "File does not exist" "file=${secret}"
            continue
        fi

        # Check if the secret resources are up-to-date
        if sops exec-file "${secret}" "kubectl --namespace flux-system diff --filename {}" &>/dev/null; then
            log info "Secret resource is up-to-date" "resource=$(basename "${secret}" ".sops.yaml")"
            continue
        fi

        # Apply secret resources
        if sops exec-file "${secret}" "kubectl --namespace flux-system apply --server-side --filename {}" &>/dev/null; then
            log info "Secret resource applied successfully" "resource=$(basename "${secret}" ".sops.yaml")"
        else
            log error "Failed to apply secret resource" "resource=$(basename "${secret}" ".sops.yaml")"
        fi
    done
}

# CRDs to be applied before the helmfile charts are installed
function apply_crds() {
    log debug "Applying CRDs"

    local -r helmfile_file="${ROOT_DIR}/bootstrap/helmfile.d/00-crds.yaml"

    if [[ ! -f "${helmfile_file}" ]]; then
        log fatal "File does not exist" "file" "${helmfile_file}"
    fi

    if ! crds=$(helmfile --file "${helmfile_file}" template --quiet | yq eval-all --exit-status 'select(.kind == "CustomResourceDefinition")') || [[ -z "${crds}" ]]; then
        log fatal "Failed to render CRDs from Helmfile" "file" "${helmfile_file}"
    fi

    if echo "${crds}" | kubectl diff --filename - &>/dev/null; then
        log info "CRDs are up-to-date"
        return
    fi

    if ! echo "${crds}" | kubectl apply --server-side --filename - &>/dev/null; then
        log fatal "Failed to apply crds from Helmfile" "file" "${helmfile_file}"
    fi

    log info "CRDs applied successfully"
}

# Sync Helm releases
function sync_helm_releases() {
    log debug "Syncing Helm releases"

    # If Flux helm-controller is already running, it owns these releases.
    # Re-running helmfile would conflict with helm-controller's server-side apply.
    if kubectl --namespace flux-system get deployment helm-controller &>/dev/null; then
        log info "Flux helm-controller detected, skipping bootstrap helmfile sync (cluster already bootstrapped)"
        return 0
    fi

    local -r helmfile_file="${ROOT_DIR}/bootstrap/helmfile.d/01-apps.yaml"

    if [[ ! -f "${helmfile_file}" ]]; then
        log error "File does not exist" "file=${helmfile_file}"
    fi

    if ! helmfile --file "${helmfile_file}" sync --hide-notes; then
        log error "Failed to sync Helm releases"
    fi

    log info "Helm releases synced successfully"
}

function main() {
    check_env KUBECONFIG
    check_cli helmfile kubectl kustomize sops yq

    # Prerequisites that belong to one provisioning path must not gate the other.
    # The path is read from cluster.yaml rather than inferred from which files
    # happen to exist: nodes.yaml is materialised for every repo, so its presence
    # proves nothing, and a leftover talos/ directory would mislead too.
    local provisioning_path
    provisioning_path="$(yq --exit-status '.provisioning_path' "${ROOT_DIR}/cluster.yaml" 2>/dev/null || true)"
    case "${provisioning_path}" in
        omni)
            log debug "Omni provisioning path, skipping talhelper prerequisites"
            ;;
        talos)
            # The manual path is driven by talhelper against a generated talosconfig.
            check_env TALOSCONFIG
            check_cli talhelper
            ;;
        *)
            log error "cluster.yaml must declare provisioning_path" \
                "value=${provisioning_path:-<unset>}" "expected=omni|talos"
            ;;
    esac

    # Apply resources and Helm releases
    wait_for_nodes
    apply_namespaces
    apply_sops_secrets
    apply_crds
    sync_helm_releases

    log info "Congrats! The cluster is bootstrapped and Flux is syncing the Git repository"
}

main "$@"
