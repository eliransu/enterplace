# Kubernetes

Two ways in: the Helm chart in `deploy/helm/gantry`, or the plain manifests in `deploy/kubernetes/gantry.yaml` (the chart's defaults with metrics on, written out). Both run the container image from `scripts/release.sh image`.

## One replica, one audit chain

Gantry runs as a single node today. The audit log is one hash chain in one file, and budgets, rate limits and the cache are counted in the memory of one process. Two replicas would each write a chain of their own and each count a budget from zero, so a team could spend twice its budget. The chart therefore:

- refuses `replicaCount` other than 1 (`helm template` fails with the reason),
- uses the `Recreate` strategy, so the old pod lets go of the volume before the new one starts (a few seconds with no gateway on every upgrade),
- keeps the audit log and the keys file on one `ReadWriteOnce` volume, with `helm.sh/resource-policy: keep` so `helm uninstall` does not delete the record.

High availability (several replicas behind one Service) waits for audit and budgets shared across nodes, which are not built.

## Install with Helm

```bash
kubectl create secret generic gantry-provider-keys --from-literal=OPENAI_PROVIDER_KEY=sk-...
helm install gantry deploy/helm/gantry --set image.repository=<your registry>/gantry --set image.tag=0.0.1
kubectl exec deploy/gantry -- /gantry key new admin --team platform --admin --keys /var/lib/gantry/gantry.keys.yaml
```

The image has no shell; `kubectl exec` runs the `gantry` binary directly. The new key works within 2 seconds.

| Value | Default | Meaning |
|---|---|---|
| `policy` | one OpenAI provider, one rule | The policy file, as text. Its `audit: { path: ... }` must be under `/var/lib/gantry/` |
| `providerSecrets` | `[gantry-provider-keys]` | Secrets loaded as environment variables, one per provider `key_env`. Gantry does not start while one is unset or empty |
| `persistence.size` | `10Gi` | The volume for the audit log and keys file. A million forwarded requests make about 1.35 GB of audit log |
| `persistence.existingClaim` | empty | Use a claim you made instead |
| `tls.secretName` | empty | A `kubernetes.io/tls` Secret: Gantry serves HTTPS itself with `--tls-cert` and `--tls-key`, and the probes use HTTPS |
| `metrics.enabled` | `false` | Serves `/metrics` on port 9464, in the Service but never in the Ingress |
| `metrics.serviceMonitor.enabled` | `false` | A Prometheus Operator `ServiceMonitor` for that port |
| `ingress.enabled` | `false` | An Ingress for the gateway port, with ingress-nginx annotations that turn off buffering and allow 32 MiB bodies |
| `keysInit.image` | `busybox:1.36.1` | Used once per start to write an empty keys file on a new volume |
| `resources` | 100m CPU and 64Mi requested, 384Mi limit | The limit leaves room for the 256 MiB body budget ([Operations](operations.html#memory-budget)) |

## What the pod looks like

- Runs as user and group 65532, never root, with a read-only root filesystem, no privilege escalation, every Linux capability dropped, the runtime's default seccomp profile, and no service account token.
- The policy is a ConfigMap mounted as a folder at `/etc/gantry/policy`. A `helm upgrade` that changes the policy does not restart the pod: the kubelet updates the file (within about a minute) and Gantry checks and uses it within 2 seconds, or keeps the old one and records `config_rejected`.
- `/var/lib/gantry` is the volume: `gantry-audit.jsonl` and `gantry.keys.yaml`. The keys file is writable because the console and the admin API issue and revoke keys there. An init container writes `keys: []` to it on a new volume, because `serve --keys` will not start on a keys file that does not exist; it never touches an existing file.
- Readiness and liveness probes call `/healthz`, which turns 503 when the audit log cannot be written. Gantry then refuses every request until a restart, which the liveness probe does after a minute.
- `SIGTERM` gives requests in flight 30 seconds; the pod gets 40 before it is killed, so the last audit sync happens.

## Checking the files

```bash
python3 scripts/check_deploy.py target/debug/gantry
```

It parses every YAML file, checks the security settings above and the single replica, runs `gantry check` on the policy, and compares the chart's policy with the plain manifest's. With `helm` installed it also runs `helm lint` and `helm template`. It never contacts a cluster.

**Tested in this release:** the container image ran with the pod's settings (`docker run --read-only --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges`, the policy folder read-only, a writable `/var/lib/gantry` holding the init container's `keys: []`): `/healthz` and `/metrics` answered, `gantry key new` through `docker exec` added the first key, a request was refused and recorded, and `gantry audit verify` passed. **Not tested:** a real cluster, and `helm lint` and `helm template`, because helm was not installed on the build machine; the templates were only checked for balanced blocks.
