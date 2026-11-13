# Gantry Enterprise Helm chart

Runs the `gantry-enterprise` image (`serve`) as a StatefulSet. The full install guide comes later; this is the short
version.

```bash
kubectl create secret docker-registry ghcr --docker-server=ghcr.io --docker-username=<user> --docker-password=<token>
kubectl create secret generic gantry-secrets \
  --from-literal=OPENAI_PROVIDER_KEY=sk-... --from-literal=GANTRY_LICENSE=...
gantry key new admin --team platform --admin --keys gantry.keys.yaml   # the open source CLI
kubectl create secret generic gantry-keys --from-file=gantry.keys.yaml
helm install gantry deploy/helm/gantry \
  --set 'imagePullSecrets[0].name=ghcr' --set keys.existingSecret=gantry-keys
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

## Values

| Value | Default | Description |
|---|---|---|
| `replicaCount` | `1` | Above 1 only with `store:` in the policy |
| `image.repository`, `image.tag`, `image.pullPolicy` | `ghcr.io/ggantry/gantry-enterprise`, appVersion, `IfNotPresent` | |
| `imagePullSecrets` | empty | The registry is private |
| `policy` | One OpenAI provider, one rule | The policy file, mounted at `/etc/gantry/gantry.policy.yaml`; reloads without a restart |
| `existingPolicyConfigMap` | empty | Your own ConfigMap with key `gantry.policy.yaml` instead |
| `envFromSecrets` | `[gantry-secrets]` | Secrets loaded as environment variables: provider keys, DATABASE_URL, GANTRY_LICENSE |
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
default seccomp profile and no service account token. Probes call `/healthz`.

## Tests

`.github/workflows/helm.yml` lints and renders the chart with each file in `ci/`, then installs it on a kind cluster
with the image built in CI and a mock provider, and makes a governed call through the Service.
