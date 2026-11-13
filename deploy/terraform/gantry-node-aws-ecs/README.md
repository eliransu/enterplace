# gantry-node-aws-ecs

Runs Gantry hybrid nodes on AWS Fargate. Each task runs the `gantry-enterprise` image in node mode: it pulls the
policy and keys from the Gantry control plane, serves the gateway on port 8080, and ships audit metadata back.
Prompts, answers and provider keys stay in your account.

The node token and the provider keys are read from Secrets Manager by the task execution role, so they never appear in
the task definition or in Terraform state.

## Use

1. Register a node in the Gantry app (Gateways) and store its token in Secrets Manager.
2. Store each provider key the policy names (for example `OPENAI_PROVIDER_KEY`) in Secrets Manager.
3. Add the module:

```hcl
module "gantry" {
  source = "./deploy/terraform/gantry-node-aws-ecs"

  image                 = "123456789012.dkr.ecr.eu-west-1.amazonaws.com/gantry-enterprise:0.0.1"
  control_plane_url     = "https://gantry-control.eliran.me"
  node_token_secret_arn = aws_secretsmanager_secret.gantry_node_token.arn
  provider_key_secret_arns = {
    OPENAI_PROVIDER_KEY    = aws_secretsmanager_secret.openai.arn
    ANTHROPIC_PROVIDER_KEY = aws_secretsmanager_secret.anthropic.arn
  }

  subnets          = module.vpc.private_subnets
  security_groups  = [aws_security_group.gantry.id]
  desired_count    = 2
  target_group_arn = aws_lb_target_group.gantry.arn # optional
}

output "gantry_service" {
  value = module.gantry.service_name
}
```

Point callers at the load balancer (`OPENAI_BASE_URL=http://<lb>/v1`). With workload identity, callers get their
Gantry key from `POST https://gantry-control.eliran.me/token/<org>` with their OIDC token instead of a stored key.

## Inputs

| Name | Default | What it is |
|---|---|---|
| `image` | required | The gantry-enterprise image |
| `node_token_secret_arn` | required | Secrets Manager ARN of the node token |
| `subnets`, `security_groups` | required | Where the tasks run; they need outbound HTTPS |
| `provider_key_secret_arns` | `{}` | Env name the policy uses => Secrets Manager ARN |
| `control_plane_url` | `https://gantry-control.eliran.me` | The control plane |
| `desired_count` | `2` | Gateway tasks |
| `cluster_arn` | `null` | Existing cluster; null creates one |
| `target_group_arn` | `null` | Load balancer target group (ip, port 8080, health check `/healthz`) |
| `cpu`, `memory`, `cpu_architecture` | `512`, `1024`, `X86_64` | Task size |

Outputs: `service_name`, `cluster_arn`.

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
