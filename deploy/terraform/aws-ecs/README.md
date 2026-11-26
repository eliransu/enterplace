# aws-ecs

Enterplace on AWS: ECS Fargate gateways behind an HTTPS Application Load Balancer, RDS Postgres 16 for keys, kill
switches and budgets, and EFS for each gateway's audit log.

## What it creates

| Resource | Why |
|---|---|
| ALB, HTTPS listener (your ACM certificate), HTTP listener that redirects | TLS ends at the load balancer; health check `GET /healthz`; cookie stickiness so a console sign-in stays on one gateway |
| ECS cluster, one service per replica (one task each) | Each gateway writes its own audit hash chain, so each needs its own volume, which ECS gives per task definition |
| EFS file system, one access point per replica (`/enterplace-<n>`, owned by 65532) | `/var/lib/enterplace`, the audit log. Encrypted, backed up by AWS Backup |
| RDS Postgres 16 (Multi-AZ, encrypted, 7-day backups) and an RDS Proxy | The store. Skipped when `database_url_secret_arn` names an existing database |
| Secrets Manager secret `DATABASE_URL` | Enterplace reads the whole connection string from one variable |
| SSM parameter with the policy, a busybox init container per task | ECS cannot mount a parameter as a file and the image has no shell, so the init container writes `/etc/enterplace/enterplace.policy.yaml` |
| Security groups | Only the ALB reaches the tasks (8080); only the tasks reach the proxy and EFS; only the proxy reaches RDS |
| Secrets Manager secrets `<name>/master-key` and `<name>/export-key`, random 64 hex characters each | `ENTERPLACE_MASTER_KEY` (seals provider credentials in the store) and `ENTERPLACE_EXPORT_KEY` (encrypts SIEM destination secrets). Made once and kept across applies; skipped for a key you pass as `master_key_secret_arn` or `export_key_secret_arn` |
| CloudWatch log group, execution role | Logs; the role reads the secrets and the policy at start |
| Task role allowed `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` on `bedrock_resource_arns` | Bedrock providers sign with it through the AWS default credential chain, so no AWS keys are stored. Not made when `bedrock_resource_arns` is empty: the tasks then have no AWS permissions |

Why RDS Proxy: Enterplace checks the database's TLS certificate against the Mozilla roots built into it. RDS instances
present certificates from the RDS certificate authorities, which are not among them, so a direct connection is
refused. RDS Proxy presents an ACM certificate that chains to Amazon's public roots.

## Use

Put the provider keys and the license in Secrets Manager first (the module only references them, so their values
never enter Terraform state), then:

```hcl
module "enterplace" {
  # Copied out of the image: docker create --name enterplace-files ghcr.io/eliransu/enterplace:<version>
  #   && docker cp enterplace-files:/deploy ./enterplace-deploy && docker rm enterplace-files
  source = "./enterplace-deploy/terraform/aws-ecs"

  image              = "ghcr.io/eliransu/enterplace:0.3.0"
  policy             = file("enterplace.policy.yaml")
  vpc_id             = "vpc-..."
  private_subnet_ids = ["subnet-...", "subnet-..."]
  public_subnet_ids  = ["subnet-...", "subnet-..."]
  allowed_cidrs      = ["0.0.0.0/0"]
  certificate_arn    = "arn:aws:acm:..."
  domain_name        = "enterplace.example.com"

  image_pull_secret_arn    = "arn:aws:secretsmanager:...:secret:ghcr-pull"
  license_secret_arn       = "arn:aws:secretsmanager:...:secret:enterplace-license"
  provider_key_secret_arns = { OPENAI_PROVIDER_KEY = "arn:aws:secretsmanager:...:secret:openai" }

  # For Bedrock providers: the models and inference profiles the task role may invoke. No AWS keys.
  bedrock_resource_arns = ["arn:aws:bedrock:us-east-1::foundation-model/anthropic.*"]
}
```

The policy must have `audit: { path: /var/lib/enterplace/enterplace-audit.jsonl }` and
`store: { postgres_url_env: DATABASE_URL }`. `enterplace.policy.yaml` beside the modules (`/deploy/terraform` in the image) is a starting point. Then point
`domain_name` at the output `alb_dns_name`, issue a key and call `gateway_url`.

`examples/basic` is the configuration CI plans, with no AWS account.

## Notes

- A deploy (new image or policy) stops each gateway before starting its replacement, because two tasks must never
  write one chain. Every service deploys at once, so expect a short gap; with `replicas = 1` always.
- The database password is in Terraform state (it builds `DATABASE_URL`), and so are the master and export keys the
  module makes. Keep the state encrypted, and a copy of the master key outside AWS: a lost one cannot be recovered.
- A Bedrock provider in the policy takes no `key_env`: it signs as the task role. For Bedrock in another account, set
  the provider's `role_arn` and let that role trust the output `bedrock_role_arn`.
- The policy parameter holds up to 8 KB.
- `deletion_protection` is on for the database and the load balancer. Turn it off before `terraform destroy`.
