# The example CI plans. The provider settings below let `terraform plan` run with no Google account: a fake access
# token, and no project or credentials lookups at plan time. For a real deploy, drop access_token and sign in with
# Application Default Credentials.

provider "google" {
  project      = "enterplace-example"
  region       = "europe-west1"
  access_token = "plan-only"
}

module "enterplace" {
  source = "../.."

  project = "enterplace-example"
  region  = "europe-west1"
  zone    = "europe-west1-b"
  image   = "europe-docker.pkg.dev/enterplace-example/enterplace/enterplace:0.3.0"
  policy  = file("${path.module}/../../../enterplace.policy.yaml")

  license_secret       = "enterplace-license"
  provider_key_secrets = { OPENAI_PROVIDER_KEY = "openai-key" }
}

output "gateway_url" {
  value = module.enterplace.gateway_url
}
