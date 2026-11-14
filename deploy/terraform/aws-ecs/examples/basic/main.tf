# The example CI plans. The provider settings below let `terraform plan` run with no AWS account: fake keys, and
# every call that would check them skipped. For a real deploy, drop them and use your own credentials.

provider "aws" {
  region                      = "eu-west-1"
  access_key                  = "plan-only"
  secret_key                  = "plan-only"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

module "gantry" {
  source = "../.."

  image  = "ghcr.io/ggantry/gantry:0.1.0"
  policy = file("${path.module}/../../../gantry.policy.yaml")

  vpc_id             = "vpc-0123456789abcdef0"
  private_subnet_ids = ["subnet-0aaaaaaaaaaaaaaa1", "subnet-0bbbbbbbbbbbbbbb2"]
  public_subnet_ids  = ["subnet-0ccccccccccccccc3", "subnet-0ddddddddddddddd4"]
  allowed_cidrs      = ["0.0.0.0/0"]
  certificate_arn    = "arn:aws:acm:eu-west-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
  domain_name        = "gantry.example.com"

  image_pull_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:ghcr-pull-AbCdEf"
  license_secret_arn    = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:gantry-license-AbCdEf"
  bedrock_resource_arns = [
    "arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
    "arn:aws:bedrock:eu-west-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
  ]
  provider_key_secret_arns = {
    OPENAI_PROVIDER_KEY = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:openai-AbCdEf"
  }
}

output "gateway_url" {
  value = module.gantry.gateway_url
}
