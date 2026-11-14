# Gantry Enterprise Helm chart

Runs the `gantry` image (`serve`) as a StatefulSet. The full install guide comes later; this is the short
version.

The chart ships inside the image, at `/deploy/helm/gantry`, so it matches the image version. Docker and the registry
token are all a customer needs:

```bash
docker login ghcr.io -u <user>
docker create --name gantry-files ghcr.io/ggantry/gantry:<version>
docker cp gantry-files:/deploy ./gantry-deploy && docker rm gantry-files
kubectl create secret docker-registry ghcr --docker-server=ghcr.io --docker-username=<user> --docker-password=<token>
kubectl create secret generic gantry-secrets \
  --from-literal=OPENAI_PROVIDER_KEY=sk-... --from-literal=GANTRY_LICENSE=...
helm install gantry ./gantry-deploy/helm/gantry \
  --set 'imagePullSecrets[0].name=ghcr' --set image.tag=<version>
```

The first pod prints a one-time link to make the first admin (`kubectl logs gantry-0 -c gantry`). Admin commands run in
the pod with the image's own binary, which takes every `gantry` command:

```bash
kubectl exec gantry-0 -c gantry -- /gantry key new maya.cohen --team payments --keys /var/lib/gantry/gantry.keys.yaml --policy /etc/gantry/gantry.policy.yaml
kubectl exec gantry-0 -c gantry -- /gantry audit verify /var/lib/gantry/gantry-audit.jsonl
```

## Why a StatefulSet

Each replica writes its own hash-chained audit log, so each needs a volume of its own. `volumeClaimTemplates` give
every pod its claim (`data-<release>-0`, `data-<release>-1`, ...) and keep it across restarts, upgrades, scale down and
`helm uninstall`. A Deployment would make every replica share one claim.

## Replicas and the store

Without the policy's `store:` section, keys, budgets and kill switches live in one process: the chart refuses
`replicaCount` above 1. With `store: { postgres_url_env: DATABASE_URL }` and DATABASE_URL in a Secret, replicas share
keys, budgets and kill switches. Rate limits and the response cache stay per replica.

`postgres.enabled` starts a one-pod Postgres in the chart for trials. It is not for production: no backups, no high
availability, no TLS: Gantry connects to it with `sslmode=disable` and says at start that the connection is not encrypted.

## Master key and export key

Both are optional, 64 hex characters (`openssl rand -hex 32`), the same on every replica, and read only from Secrets
you make; neither is ever a value in `values.yaml`.

```bash
kubectl create secret generic gantry-master-key --from-literal=master-key=$(openssl rand -hex 32)
kubectl create secret generic gantry-export-key --from-literal=export-key=$(openssl rand -hex 32)
helm upgrade --install gantry ./gantry-deploy/helm/gantry --reuse-values \
  --set masterKey.existingSecret=gantry-master-key --set exportKey.existingSecret=gantry-export-key
```

- `masterKey` seals provider credentials kept in the store. It is mounted as a file at `/etc/gantry-master` and named
  by `GANTRY_MASTER_KEY_FILE`. Keep a copy in your secret manager: a lost master key cannot be recovered. Without it,
  provider credentials are off and providers use `key_env`. Do not also set `GANTRY_MASTER_KEY` through
  `envFromSecrets`: Gantry refuses both.
- `exportKey` becomes `GANTRY_EXPORT_KEY`, which encrypts SIEM export destinations' secrets (license feature `siem`).
  Without it, only destinations that sign in with the pod's cloud identity can be saved.

## Values

| Value | Default | Description |
|---|---|---|
| `replicaCount` | `1` | Above 1 only with `store:` in the policy |
| `image.repository`, `image.tag`, `image.pullPolicy` | `ghcr.io/ggantry/gantry`, appVersion, `IfNotPresent` | |
| `imagePullSecrets` | empty | The registry is private |
| `policy` | One OpenAI provider, one rule | The policy file, mounted at `/etc/gantry/gantry.policy.yaml`; reloads without a restart |
| `existingPolicyConfigMap` | empty | Your own ConfigMap with key `gantry.policy.yaml` instead |
| `envFromSecrets` | `[gantry-secrets]` | Secrets loaded as environment variables: provider keys, DATABASE_URL, GANTRY_LICENSE |
| `masterKey.existingSecret`, `masterKey.key` | empty, `master-key` | Optional. A Secret with the master key for provider credentials, mounted as `GANTRY_MASTER_KEY_FILE` |
| `exportKey.existingSecret`, `exportKey.key` | empty, `export-key` | Optional. A Secret with `GANTRY_EXPORT_KEY`, for SIEM destination secrets |
| `keys.existingSecret` | empty | A Secret with `gantry.keys.yaml`, copied to a new volume once |
| `keys.initImage` | `busybox:1.36.1` | Writes the keys file on a new volume (the Gantry image has no shell) |
| `persistence.size`, `persistence.storageClassName` | `10Gi`, cluster default | One claim per replica |
| `service.type`, `service.port` | `ClusterIP`, `8080` | |
| `metrics.enabled`, `metrics.port` | `false`, `9464` | `/metrics` on its own port, never on the Ingress |
| `metrics.serviceMonitor.enabled` | `false` | Needs the Prometheus Operator CRD |
| `ingress.*` | off | Host, class, annotations for streaming, `tlsSecretName` for TLS at the Ingress |
| `networkPolicy.*` | off | Gateway port from `from`, metrics from the namespace and `metricsFrom`, egress to DNS, the trial Postgres and `egress` (default any host on 443) |
| `otel` | empty | `OTEL_*` environment variables |
| `proxy.https`, `proxy.noProxy` | empty | `HTTPS_PROXY`, `NO_PROXY`. `serve` does not route provider calls through it today |
| `resources` | 100m CPU and 64Mi requested, 384Mi limit | |
| `postgres.*` | off | The trial Postgres |

Pods run as user 65532 with a read-only root filesystem, no privilege escalation, every capability dropped, the
default seccomp profile and no service account token. Readiness calls `/readyz` (every 5 seconds, out after 2 failures) and liveness `/healthz` (every 10 seconds, restarted after 6); the pod gets 45 seconds to drain after SIGTERM.

## Tests

`.github/workflows/helm.yml` lints and renders the chart with each file in `ci/`, then installs it on a kind cluster
with the image built in CI and a mock provider, and makes a governed call through the Service.
