# gantry-node-kubernetes

Runs Gantry hybrid nodes on Kubernetes: a Deployment of the `gantry-enterprise` image in node mode and a Service in
front of it. Each pod pulls the policy and keys from the Gantry control plane and ships audit metadata back. Prompts,
answers and provider keys stay in your cluster.

The module references Secrets you already have and never creates them, so the node token and provider keys never
enter Terraform state.

## Use

1. Register a node in the Gantry app (Gateways) and put its token in a Secret:
   `kubectl -n ai create secret generic gantry-node --from-literal=token=gnode_...`
2. Put the provider keys the policy names in a Secret:
   `kubectl -n ai create secret generic llm-keys --from-literal=openai=sk-...`
3. Add the module:

```hcl
module "gantry" {
  source = "./deploy/terraform/gantry-node-kubernetes"

  namespace         = "ai"
  image             = "registry.example.com/gantry-enterprise:0.0.1"
  control_plane_url = "https://gantry-control.eliran.me"
  node_token_secret = { name = "gantry-node", key = "token" }
  provider_key_secrets = {
    OPENAI_PROVIDER_KEY = { name = "llm-keys", key = "openai" }
  }
  replicas = 2
}

output "gantry_url" {
  value = module.gantry.base_url # http://gantry.ai.svc.cluster.local:80
}
```

Callers use `OPENAI_BASE_URL=<base_url>/v1`. A pod with workload identity needs no stored Gantry key: it posts its
projected service account token to `https://gantry-control.eliran.me/token/<org>` and gets a short-lived key. Add a
trust policy for the cluster's issuer with subject `system:serviceaccount:<namespace>:<service account>`.

## Inputs

| Name | Default | What it is |
|---|---|---|
| `image` | required | The gantry-enterprise image |
| `node_token_secret` | required | `{ name, key }` of the Secret with the node token |
| `provider_key_secrets` | `{}` | Env name the policy uses => `{ name, key }` of a Secret |
| `namespace` | `default` | Where it runs |
| `control_plane_url` | `https://gantry-control.eliran.me` | The control plane |
| `replicas` | `2` | Gateway pods |
| `service_type`, `service_port` | `ClusterIP`, `80` | How the Service is exposed |
| `cpu`, `memory` | `250m`, `256Mi` | Pod size |

Outputs: `deployment_name`, `service_name`, `base_url`.

## The image

There is no public registry yet. Build the image from the folder that holds both repositories and push it to your own registry:

```bash
docker buildx build --platform linux/amd64 -f gantry-enterprise/Dockerfile -t <your-registry>/gantry-enterprise:0.0.1 --push .
```

## Limits to know

- Run one replica per gateway. Budgets, rate limits and the cache are counted per process, so two replicas allow twice the budget.
- On SIGTERM the node ships its last audit records and stops the gateway; give it the default 30 second grace period.
- `extra_args` passes node flags: `--max-offline <seconds>` fails closed after a control plane outage that long, `--pass-env` lets the gateway read named variables (Bedrock's AWS credentials), and `--secrets` reads provider keys from Vault or AWS Secrets Manager and rotates them without a restart.
- The node reaches the control plane through `HTTPS_PROXY` when it is set.
