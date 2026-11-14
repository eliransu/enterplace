# The example CI plans. The provider settings below let `terraform plan` run with no Google account: a fake access
# token, and no project or credentials lookups at plan time. For a real deploy, drop access_token and sign in with
# Application Default Credentials.

provider "google" {
  project      = "gantry-example"
  region       = "europe-west1"
  access_token = "plan-only"
}

module "gantry" {
  source = "../.."

  project = "gantry-example"
  region  = "europe-west1"
  zone    = "europe-west1-b"
  image   = "europe-docker.pkg.dev/gantry-example/gantry/gantry:0.1.0"
  policy  = file("${path.module}/../../../gantry.policy.yaml")

  license_secret       = "gantry-license"
  provider_key_secrets = { OPENAI_PROVIDER_KEY = "openai-key" }
}

output "gateway_url" {
  value = module.gantry.gateway_url
}
