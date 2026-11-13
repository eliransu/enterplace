# aws-ecs

Gantry on AWS: ECS Fargate gateways behind an HTTPS Application Load Balancer, RDS Postgres 16 for keys, kill
switches and budgets, and EFS for each gateway's audit log.

## What it creates

| Resource | Why |
|---|---|
| ALB, HTTPS listener (your ACM certificate), HTTP listener that redirects | TLS ends at the load balancer; health check `GET /healthz`; cookie stickiness so a console sign-in stays on one gateway |
| ECS cluster, one service per replica (one task each) | Each gateway writes its own audit hash chain, so each needs its own volume, which ECS gives per task definition |
| EFS file system, one access point per replica (`/gantry-<n>`, owned by 65532) | `/var/lib/gantry`, the audit log. Encrypted, backed up by AWS Backup |
| RDS Postgres 16 (Multi-AZ, encrypted, 7-day backups) and an RDS Proxy | The store. Skipped when `database_url_secret_arn` names an existing database |
| Secrets Manager secret `DATABASE_URL` | Gantry reads the whole connection string from one variable |
| SSM parameter with the policy, a busybox init container per task | ECS cannot mount a parameter as a file and the image has no shell, so the init container writes `/etc/gantry/gantry.policy.yaml` |
| Security groups | Only the ALB reaches the tasks (8080); only the tasks reach the proxy and EFS; only the proxy reaches RDS |
| CloudWatch log group, execution role | Logs; the role reads the secrets and the policy at start. The tasks have no AWS permissions |

Why RDS Proxy: Gantry checks the database's TLS certificate against the Mozilla roots built into it. RDS instances
present certificates from the RDS certificate authorities, which are not among them, so a direct connection is
refused. RDS Proxy presents an ACM certificate that chains to Amazon's public roots.

## Use

Put the provider keys and the license in Secrets Manager first (the module only references them, so their values
never enter Terraform state), then:

```hcl
module "gantry" {
  # Copied out of the image: docker create --name gantry-files ghcr.io/ggantry/gantry-enterprise:<version>
  #   && docker cp gantry-files:/deploy ./gantry-deploy && docker rm gantry-files
  source = "./gantry-deploy/terraform/aws-ecs"

  image              = "ghcr.io/ggantry/gantry-enterprise:0.1.0"
  policy             = file("gantry.policy.yaml")
  vpc_id             = "vpc-..."
  private_subnet_ids = ["subnet-...", "subnet-..."]
  public_subnet_ids  = ["subnet-...", "subnet-..."]
  allowed_cidrs      = ["0.0.0.0/0"]
  certificate_arn    = "arn:aws:acm:..."
  domain_name        = "gantry.example.com"

  image_pull_secret_arn    = "arn:aws:secretsmanager:...:secret:ghcr-pull"
  license_secret_arn       = "arn:aws:secretsmanager:...:secret:gantry-license"
  provider_key_secret_arns = { OPENAI_PROVIDER_KEY = "arn:aws:secretsmanager:...:secret:openai" }
}
```

The policy must have `audit: { path: /var/lib/gantry/gantry-audit.jsonl }` and
`store: { postgres_url_env: DATABASE_URL }`. `gantry.policy.yaml` beside the modules (`/deploy/terraform` in the image) is a starting point. Then point
`domain_name` at the output `alb_dns_name`, issue a key and call `gateway_url`.

`examples/basic` is the configuration CI plans, with no AWS account.

## Notes

- A deploy (new image or policy) stops each gateway before starting its replacement, because two tasks must never
  write one chain. Every service deploys at once, so expect a short gap; with `replicas = 1` always.
- The database password is in Terraform state (it builds `DATABASE_URL`). Keep the state encrypted.
- The policy parameter holds up to 8 KB.
- `deletion_protection` is on for the database and the load balancer. Turn it off before `terraform destroy`.
