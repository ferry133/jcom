# Runbook — Spegel disabled on jcom (single-node) & dead-mirror recovery

**Date:** 2026-06-27
**Cluster:** jcom (single control-plane node `jcom-0-0`, `10.9.8.10`)
**Commit:** `fd36278` — `fix(spegel): disable on jcom (single-node) — dead mirror broke image pulls`

## TL;DR

Spegel was wrongly deployed on this **single-node** cluster, failed to install, and
left behind a containerd registry-mirror config pointing every registry at a now-dead
endpoint (`10.9.8.10:29999` / `:30021`). Result: **every un-cached image pull failed
cluster-wide** with `ErrImagePull … connection refused`, while already-cached images
kept running (so it went unnoticed for ~43 days until a pod was recreated).

Fix = **disable Spegel on jcom** (it is useless on 1 node) + clean up its leftovers +
remove the stale node mirror config. Verified: un-cached image pulls direct from
docker.io again.

## Symptoms

- A recreated pod stuck in `ImagePullBackOff`:
  ```
  failed to resolve reference "docker.io/<img>": failed to do request:
  Head "http://10.9.8.10:29999/v2/.../manifests/latest": dial tcp 10.9.8.10:29999: connect: connection refused
  ```
- Cached images keep running fine; only **new / un-cached** image pulls fail.
- `kubectl -n kube-system get hr spegel` → `Stalled / UpgradeFailed`, DaemonSet never Ready.

## Root cause (full chain)

1. **Design intent: Spegel off for single-node.** The cluster-template
   (`templates/scripts/plugin.py`) sets `spegel_enabled = len(nodes) > 1`. Spegel is a
   peer-to-peer image cache — pointless with one node. jcom is single-node → it should be OFF.
2. **But jg-base deploys it unconditionally** (`kubernetes/apps/base/kube-system/kustomization.yaml`
   → `spegel/ks.yaml`). Template intent and the shared GitOps base disagree.
3. **Spegel never became Ready** → Helm timed out → Flux `HelmRelease/spegel` went
   `Stalled (MissingRollbackTarget)` and gave up; the DaemonSet was removed.
4. **It had already poisoned containerd.** Talos sets `config_path = /etc/cri/conf.d/hosts`
   (template, harmless on its own). Spegel wrote `/etc/cri/conf.d/hosts/_default/hosts.toml`:
   ```toml
   [host.'http://10.9.8.10:29999']   # Spegel hostPort   — dead
   [host.'http://10.9.8.10:30021']   # Spegel NodePort   — dead
   ```
   `_default` applies to **all** registries with **no upstream fallback**.
5. Spegel dead + stale `hosts.toml` → all un-cached pulls hit the dead mirror → fail.

## The fix

### 1. GitOps — stop Flux from recreating Spegel (prevents recurrence)

Added a jcom-only patch to the `cluster-apps-base` Kustomization that suspends the
`spegel` child Kustomization. Edited **both** the rendered file and its template
(mirrors the existing Cilium-override convention):

- `kubernetes/flux/cluster/ks.yaml`
- `templates/config/kubernetes/flux/cluster/ks.yaml.j2`

```yaml
    # ── jcom-only: disable Spegel (single-node cluster) ──────────────────────────
    - patch: |-
        apiVersion: kustomize.toolkit.fluxcd.io/v1
        kind: Kustomization
        metadata:
          name: spegel
          namespace: flux-system
        spec:
          suspend: true
      target:
        group: kustomize.toolkit.fluxcd.io
        kind: Kustomization
        name: spegel
```

> Scalar-only strategic merge (sets `spec.suspend` only) — it does **not** touch
> `spec.patches`, so the generic HR-strategy patch above it is preserved.

Apply:
```sh
git add kubernetes/flux/cluster/ks.yaml templates/config/kubernetes/flux/cluster/ks.yaml.j2
git commit && git push
flux -n flux-system reconcile source git flux-system
flux -n flux-system reconcile kustomization cluster-apps-base
kubectl -n flux-system get kustomization spegel -o jsonpath='{.spec.suspend}'   # → true
```

### 2. Remove the failed Spegel release + orphan resources (one-time)

Deleting the HelmRelease did **not** auto-uninstall (the release was failed/stalled),
so the resources were removed manually by label:

```sh
kubectl -n kube-system delete helmrelease spegel
kubectl -n kube-system delete svc,sa,servicemonitor -l app.kubernetes.io/instance=spegel
kubectl -n kube-system delete secret sh.helm.release.v1.spegel.v1 sh.helm.release.v1.spegel.v2
# verify nothing remains:
kubectl get all,sa,servicemonitor,secret,clusterrole,clusterrolebinding -A | grep -i spegel
```

### 3. Remove the stale node mirror config (one-time)

`kubectl debug node`'s `/host` mount is **read-only** on Talos, so `rm` there fails.
Mount the specific path **read-write** via a hostPath pod (the way Spegel itself did):

```sh
kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata: { name: spegel-hosts-cleanup, namespace: kube-system }
spec:
  restartPolicy: Never
  nodeName: jcom-0-0
  hostNetwork: true
  tolerations: [{ operator: Exists }]
  containers:
    - name: cleanup
      image: docker.io/library/busybox:1.36   # already node-cached
      imagePullPolicy: IfNotPresent
      securityContext: { privileged: true }
      command: ["sh","-c","rm -fv /hosts/_default/hosts.toml"]
      volumeMounts: [{ name: hosts, mountPath: /hosts }]
  volumes:
    - name: hosts
      hostPath: { path: /etc/cri/conf.d/hosts, type: Directory }
YAML
kubectl -n kube-system wait --for=jsonpath='{.status.phase}'=Succeeded pod/spegel-hosts-cleanup --timeout=60s
kubectl -n kube-system delete pod spegel-hosts-cleanup
```

containerd reads `hosts.toml` dynamically per pull — **no containerd/node restart needed.**

## Verification

```sh
kubectl run pull-test -n kube-system --image=docker.io/library/hello-world:latest \
  --image-pull-policy=Always --restart=Never \
  --overrides='{"spec":{"nodeName":"jcom-0-0","tolerations":[{"operator":"Exists"}]}}'
# → Successfully pulled "docker.io/library/hello-world:latest" … (direct from docker.io)
kubectl -n kube-system delete pod pull-test
```

## Talos gotchas (learned here)

- A **failed/stalled** Flux HelmRelease does **not** helm-uninstall on CR deletion —
  clean orphan resources manually (by `app.kubernetes.io/instance=<release>` label).
- `kubectl debug node/<n>`'s `/host` is **read-only** — to edit node files, mount the
  exact path read-write via a `hostPath` volume in a privileged pod.

## Recurrence / applies-to

- If un-cached image pulls fail again: check `kubectl -n flux-system get kustomization
  spegel -o jsonpath='{.spec.suspend}'` is still `true`, and that
  `/etc/cri/conf.d/hosts/_default/hosts.toml` has not reappeared.
- The same disable-Spegel fix applies to **any other single-node cluster variant**
  (genie*, jgt*, etc.) built from this template, since jg-base deploys Spegel
  unconditionally regardless of node count.

> Side note: the `freepbx` Deployment was pinned to `imagePullPolicy: IfNotPresent`
> while the mirror was broken (commit `c47e52e` in jg-base). That workaround is now
> redundant but harmless. (FreePBX's own Asterisk/SIP install is a separate issue.)
