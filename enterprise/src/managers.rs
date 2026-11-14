//! Secret managers for `gantry serve` (licensed feature `secrets`): a `*_env` variable whose value is
//! `vault://`, `aws-sm://`, `gcp-sm://` or `azure-kv://` is read from that manager at start and on each refresh
//! (`gantry_core::secrets`). Each manager is signed in to with its platform's own chain, so a workload with an
//! identity needs no static credential:
//!
//! - HashiCorp Vault (<https://developer.hashicorp.com/vault/api-docs>): `VAULT_ADDR`; a token from `VAULT_TOKEN`,
//!   else `~/.vault-token`, else the Kubernetes auth method with `VAULT_K8S_ROLE` and the pod's service account
//!   token; `VAULT_NAMESPACE` when set. `vault://<path>#<field>` reads `GET /v1/<path>`, KV v2 or v1.
//! - AWS Secrets Manager (`GetSecretValue`): the AWS SDKs' default chain as `gantry_server::cloud` reads it (access
//!   keys, IRSA, ECS and Pod Identity, IMDSv2), never the aws command. `aws-sm://<name or ARN>[#field]`.
//! - Google Secret Manager (`versions.access`): Application Default Credentials as `gantry_server::cloud` reads
//!   them. `gcp-sm://projects/<p>/secrets/<s>[/versions/<v>][#field]`, latest unless a version is named.
//! - Azure Key Vault (Get Secret, api-version 7.4): a client secret (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
//!   `AZURE_CLIENT_SECRET`), workload identity (`AZURE_FEDERATED_TOKEN_FILE`), the App Service and Container Apps
//!   identity endpoint (`IDENTITY_ENDPOINT`, `IDENTITY_HEADER`), else the VM's managed identity (IMDS), as the
//!   Azure SDKs' DefaultAzureCredential tries them. `azure-kv://<vault>/<secret>[/<version>][#field]`.
//!
//! Errors name the reference and the fix, never a secret.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use gantry_server::cloud;
use serde_json::Value;

use crate::secrets::{aws_get, aws_value, http_error};

pub type Env = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The secret managers, signed in to once and kept signed in.
pub struct Managers {
    env: Env,
    agent: ureq::Agent,
    aws: Mutex<HashMap<String, cloud::Live<gantry_core::sigv4::Credentials>>>,
    google: Mutex<Option<cloud::Live<axum::http::HeaderValue>>>,
    /// Azure and Vault tokens, until they expire.
    azure: Mutex<Option<(String, Instant)>>,
    vault: Mutex<Option<(String, Instant)>>,
}

const VAULT_SCOPE: &str = "https://vault.azure.net";

impl Managers {
    pub fn new(env: Env) -> Self {
        Managers {
            env,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build(),
            aws: Mutex::default(),
            google: Mutex::default(),
            azure: Mutex::default(),
            vault: Mutex::default(),
        }
    }

    fn var(&self, name: &str) -> Option<String> {
        (self.env)(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    }

    fn vault(&self, rest: &str) -> Result<String, String> {
        let (path, field) = split_field(rest);
        let addr = self.var("VAULT_ADDR").ok_or(
            "VAULT_ADDR is not set. Set it to the Vault address, for example https://vault.example.com:8200",
        )?;
        let addr = addr.trim_end_matches('/');
        safe_url(addr, "VAULT_ADDR")?;
        let token = self.vault_token(addr)?;
        let mut request = self
            .agent
            .get(&format!("{addr}/v1/{}", path.trim_start_matches('/')))
            .set("x-vault-token", &token);
        if let Some(ns) = self.var("VAULT_NAMESPACE") {
            request = request.set("x-vault-namespace", &ns);
        }
        let body: Value = request
            .call()
            .map_err(|err| http_error("Vault", err))?
            .into_json()
            .map_err(|err| format!("Vault sent a response that is not JSON: {err}"))?;
        // KV v2 keeps the fields under data.data, KV v1 under data.
        let data = body
            .pointer("/data/data")
            .filter(|d| d.is_object())
            .or_else(|| body.get("data"))
            .ok_or("the Vault answer has no data. Check the path: a KV v2 secret is read at <mount>/data/<name>")?;
        pick(data, field, "Vault secret")
    }

    fn vault_token(&self, addr: &str) -> Result<String, String> {
        if let Some(token) = self.var("VAULT_TOKEN") {
            return Ok(token);
        }
        if let Some(home) = self.var("HOME")
            && let Ok(token) = std::fs::read_to_string(format!("{home}/.vault-token"))
            && !token.trim().is_empty()
        {
            return Ok(token.trim().to_owned());
        }
        if let Some((token, until)) = self
            .vault
            .lock()
            .map_err(|_| "the Vault token lock was poisoned")?
            .clone()
            && until > Instant::now()
        {
            return Ok(token);
        }
        let Some(role) = self.var("VAULT_K8S_ROLE") else {
            return Err("no Vault token: set VAULT_TOKEN, or VAULT_K8S_ROLE to sign in with the pod's Kubernetes service account".into());
        };
        let jwt_path = self
            .var("VAULT_K8S_TOKEN_PATH")
            .unwrap_or_else(|| "/var/run/secrets/kubernetes.io/serviceaccount/token".into());
        let jwt = std::fs::read_to_string(&jwt_path).map_err(|err| {
            format!("the service account token at {jwt_path} cannot be read ({err})")
        })?;
        let mount = self
            .var("VAULT_K8S_MOUNT")
            .unwrap_or_else(|| "kubernetes".into());
        let body: Value = self
            .agent
            .post(&format!("{addr}/v1/auth/{mount}/login"))
            .send_json(serde_json::json!({ "role": role, "jwt": jwt.trim() }))
            .map_err(|err| http_error("Vault's Kubernetes sign-in", err))?
            .into_json()
            .map_err(|err| format!("Vault sent a sign-in answer that is not JSON: {err}"))?;
        let token = body
            .pointer("/auth/client_token")
            .and_then(Value::as_str)
            .ok_or("Vault's Kubernetes sign-in gave no client_token")?
            .to_owned();
        let lease = body
            .pointer("/auth/lease_duration")
            .and_then(Value::as_u64)
            .unwrap_or(300);
        if let Ok(mut slot) = self.vault.lock() {
            *slot = Some((token.clone(), expiry(lease)));
        }
        Ok(token)
    }

    fn aws(&self, rest: &str) -> Result<String, String> {
        let (id, field) = split_field(rest);
        let region = id
            .strip_prefix("arn:aws:secretsmanager:")
            .and_then(|r| r.split(':').next())
            .filter(|r| !r.is_empty())
            .map(str::to_owned)
            .or_else(|| self.var("AWS_REGION"))
            .or_else(|| self.var("AWS_DEFAULT_REGION"))
            .ok_or("no AWS region: use the secret's ARN, or set AWS_REGION")?;
        let live = {
            let mut cache = self.aws.lock().map_err(|_| "the AWS lock was poisoned")?;
            match cache.get(&region) {
                Some(live) => live.clone(),
                None => {
                    let env = self.env.clone();
                    let live =
                        cloud::aws("secrets", &region, None, &move |n| env(n)).map_err(|err| {
                            err.replace("provider \"secrets\" is on Amazon Bedrock, and ", "")
                        })?;
                    cache.insert(region.clone(), live.clone());
                    live
                }
            }
        };
        let base = self.var("AWS_ENDPOINT_URL_SECRETS_MANAGER");
        let body = aws_get(&self.agent, &live.get(), &region, id, base.as_deref())?;
        aws_value(&body, field)
    }

    fn gcp(&self, rest: &str) -> Result<String, String> {
        let (name, field) = split_field(rest);
        if !name.starts_with("projects/") || !name.contains("/secrets/") {
            return Err("a Google secret is gcp-sm://projects/<project>/secrets/<name>, with /versions/<n> to pin a version".into());
        }
        let name = if name.contains("/versions/") {
            name.to_owned()
        } else {
            format!("{name}/versions/latest")
        };
        let live = {
            let mut slot = self
                .google
                .lock()
                .map_err(|_| "the Google lock was poisoned")?;
            match slot.as_ref() {
                Some(live) => live.clone(),
                None => {
                    let env = self.env.clone();
                    let live = cloud::google("secrets", &move |n| env(n)).map_err(|err| {
                        err.replace("provider \"secrets\" is on Vertex AI, and ", "")
                    })?;
                    *slot = Some(live.clone());
                    live
                }
            }
        };
        let base = self
            .var("CLOUDSDK_API_ENDPOINT_OVERRIDES_SECRETMANAGER")
            .unwrap_or_else(|| "https://secretmanager.googleapis.com/".into());
        safe_url(&base, "CLOUDSDK_API_ENDPOINT_OVERRIDES_SECRETMANAGER")?;
        let bearer = live.get();
        let body: Value = self
            .agent
            .get(&format!("{}/v1/{name}:access", base.trim_end_matches('/')))
            .set("authorization", bearer.to_str().unwrap_or_default())
            .call()
            .map_err(|err| http_error("Google Secret Manager", err))?
            .into_json()
            .map_err(|err| format!("Google sent a response that is not JSON: {err}"))?;
        let data = body
            .pointer("/payload/data")
            .and_then(Value::as_str)
            .and_then(gantry_core::x509::base64_decode)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or("the Google secret has no text payload. Store the key as text")?;
        text_or_field(&data, field, "Google secret")
    }

    fn azure(&self, rest: &str) -> Result<String, String> {
        let (path, field) = split_field(rest);
        let mut parts = path.splitn(3, '/');
        let (Some(vault), Some(secret)) = (parts.next(), parts.next()) else {
            return Err("an Azure secret is azure-kv://<vault name>/<secret name>, with /<version> to pin a version".into());
        };
        let version = parts.next().unwrap_or("");
        // A vault name is the vault's own host; a host with a port or a dot is taken as written (a private
        // endpoint, or a test on this machine).
        let base = if vault.contains([':', '.']) {
            let local = vault.starts_with("127.0.0.1") || vault.starts_with("localhost");
            format!("{}://{vault}", if local { "http" } else { "https" })
        } else {
            format!("https://{vault}.vault.azure.net")
        };
        let token = self.azure_token()?;
        let body: Value = self
            .agent
            .get(&if version.is_empty() {
                format!("{base}/secrets/{secret}?api-version=7.4")
            } else {
                format!("{base}/secrets/{secret}/{version}?api-version=7.4")
            })
            .set("authorization", &format!("Bearer {token}"))
            .call()
            .map_err(|err| http_error("Azure Key Vault", err))?
            .into_json()
            .map_err(|err| format!("Azure sent a response that is not JSON: {err}"))?;
        let value = body
            .get("value")
            .and_then(Value::as_str)
            .ok_or("the Azure secret has no value")?;
        text_or_field(value, field, "Azure secret")
    }

    fn azure_token(&self) -> Result<String, String> {
        if let Some((token, until)) = self
            .azure
            .lock()
            .map_err(|_| "the Azure lock was poisoned")?
            .clone()
            && until > Instant::now()
        {
            return Ok(token);
        }
        let authority = self
            .var("AZURE_AUTHORITY_HOST")
            .unwrap_or_else(|| "https://login.microsoftonline.com".into());
        let authority = authority.trim_end_matches('/');
        let scope = format!("{VAULT_SCOPE}/.default");
        let mut tried = Vec::new();
        let answer: Result<Value, String> = match (
            self.var("AZURE_TENANT_ID"),
            self.var("AZURE_CLIENT_ID"),
            self.var("AZURE_CLIENT_SECRET"),
            self.var("AZURE_FEDERATED_TOKEN_FILE"),
        ) {
            (Some(tenant), Some(client), Some(secret), _) => self
                .agent
                .post(&format!("{authority}/{tenant}/oauth2/v2.0/token"))
                .send_form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", &client),
                    ("client_secret", &secret),
                    ("scope", &scope),
                ])
                .map_err(|err| http_error("Microsoft Entra ID (client secret)", err))
                .and_then(|r| r.into_json().map_err(|e| e.to_string())),
            (Some(tenant), Some(client), None, Some(file)) => {
                let assertion = std::fs::read_to_string(&file).map_err(|err| {
                    format!("AZURE_FEDERATED_TOKEN_FILE {file} cannot be read ({err})")
                })?;
                self.agent
                    .post(&format!("{authority}/{tenant}/oauth2/v2.0/token"))
                    .send_form(&[
                        ("grant_type", "client_credentials"),
                        ("client_id", &client),
                        (
                            "client_assertion_type",
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        ),
                        ("client_assertion", assertion.trim()),
                        ("scope", &scope),
                    ])
                    .map_err(|err| http_error("Microsoft Entra ID (workload identity)", err))
                    .and_then(|r| r.into_json().map_err(|e| e.to_string()))
            }
            _ => match (self.var("IDENTITY_ENDPOINT"), self.var("IDENTITY_HEADER")) {
                (Some(endpoint), Some(header)) => {
                    let mut request = self
                        .agent
                        .get(&endpoint)
                        .query("resource", VAULT_SCOPE)
                        .query("api-version", "2019-08-01")
                        .set("x-identity-header", &header);
                    if let Some(client) = self.var("AZURE_CLIENT_ID") {
                        request = request.query("client_id", &client);
                    }
                    request
                        .call()
                        .map_err(|err| http_error("the managed identity endpoint", err))
                        .and_then(|r| r.into_json().map_err(|e| e.to_string()))
                }
                _ => {
                    tried.push("AZURE_TENANT_ID with AZURE_CLIENT_SECRET or AZURE_FEDERATED_TOKEN_FILE, and IDENTITY_ENDPOINT, are not set");
                    let mut request = self
                        .agent
                        .get("http://169.254.169.254/metadata/identity/oauth2/token")
                        .timeout(Duration::from_secs(2))
                        .query("api-version", "2018-02-01")
                        .query("resource", VAULT_SCOPE)
                        .set("metadata", "true");
                    if let Some(client) = self.var("AZURE_CLIENT_ID") {
                        request = request.query("client_id", &client);
                    }
                    request
                        .call()
                        .map_err(|err| http_error("the VM's managed identity (IMDS)", err))
                        .and_then(|r| r.into_json().map_err(|e| e.to_string()))
                }
            },
        };
        let answer = answer.map_err(|err| {
            format!(
                "Gantry could not sign in to Azure: {err}{}. Run Gantry with a managed identity or workload identity that may read the vault's secrets, or set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET",
                tried.first().map(|t| format!(" ({t})")).unwrap_or_default()
            )
        })?;
        let token = answer
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or("the Azure token answer has no access_token")?
            .to_owned();
        let lasts = answer
            .get("expires_in")
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .unwrap_or(3600);
        if let Ok(mut slot) = self.azure.lock() {
            *slot = Some((token.clone(), expiry(lasts)));
        }
        Ok(token)
    }
}

impl gantry_core::secrets::Source for Managers {
    fn fetch(&self, reference: &str) -> Result<String, String> {
        let value = if let Some(rest) = reference.strip_prefix("vault://") {
            self.vault(rest)
        } else if let Some(rest) = reference.strip_prefix("aws-sm://") {
            self.aws(rest)
        } else if let Some(rest) = reference.strip_prefix("gcp-sm://") {
            self.gcp(rest)
        } else if let Some(rest) = reference.strip_prefix("azure-kv://") {
            self.azure(rest)
        } else {
            Err(format!(
                "the reference is not one of {}",
                gantry_core::secrets::SCHEMES.join(", ")
            ))
        }?;
        let value = value.trim();
        if value.is_empty() {
            return Err("the secret is empty. Store the key in it".into());
        }
        Ok(value.to_owned())
    }
}

/// A token is used until a minute before it expires.
fn expiry(seconds: u64) -> Instant {
    Instant::now() + Duration::from_secs(seconds.saturating_sub(60).max(1))
}

fn split_field(rest: &str) -> (&str, Option<&str>) {
    match rest.rsplit_once('#') {
        Some((path, field)) if !field.is_empty() => (path, Some(field)),
        _ => (rest.trim_end_matches('#'), None),
    }
}

/// A token goes to the address only over https, or plain http to this machine.
fn safe_url(url: &str, name: &str) -> Result<(), String> {
    if gantry_core::config::secure_url(url) {
        Ok(())
    } else {
        Err(format!(
            "{name} is {url}, which is not https. Gantry sends a token there: use https, or http only to this machine"
        ))
    }
}

/// One field of a secret's JSON object, or its only field when none is named.
fn pick(data: &Value, field: Option<&str>, what: &str) -> Result<String, String> {
    let fields = data
        .as_object()
        .ok_or(format!("the {what} is not an object"))?;
    let value = match field {
        Some(field) => fields.get(field),
        None if fields.len() == 1 => fields.values().next(),
        None => {
            return Err(format!(
                "the {what} has {} fields: name the one that holds the key with #field, for example #{}",
                fields.len(),
                fields.keys().next().map_or("api_key", String::as_str)
            ));
        }
    };
    value
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "the {what} has no text field `{}`. Check the #field in the reference",
                field.unwrap_or_default()
            )
        })
}

/// A secret's text, or one field of it when it holds a JSON object and a field is named.
fn text_or_field(text: &str, field: Option<&str>, what: &str) -> Result<String, String> {
    match field {
        None => Ok(text.to_owned()),
        Some(_) => {
            let data: Value = serde_json::from_str(text)
                .map_err(|_| format!("the {what} is not a JSON object, so it has no #field"))?;
            pick(&data, field, what)
        }
    }
}

#[cfg(test)]
mod tests;
