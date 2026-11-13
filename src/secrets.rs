//! Provider keys from secret managers, rotated without restarting the gateway.
//!
//! Each `--secrets NAME=<source>` maps a `key_env` name in the policy to a source the node polls. The node writes
//! the value to `secrets/NAME` in its folder and points the provider at it with `key_file`, which the gateway reads
//! again within 2 seconds of a change. A request already sent keeps the key it was sent with.

use gantry_core::sigv4;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub enum Source {
    File(PathBuf),
    Env(String),
    /// A HashiCorp Vault KV v2 read URL and the field of the secret that holds the key.
    Vault {
        url: String,
        field: String,
    },
    /// An AWS Secrets Manager secret ARN, and the JSON field to take when the secret holds a JSON object.
    AwsSm {
        arn: String,
        field: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Secret {
    pub name: String,
    pub source: Source,
}

/// Parses `NAME=file:/path`, `NAME=env:OTHER`, `NAME=vault:<url>#field` or `NAME=aws-sm:<arn>[#field]`.
pub fn parse(spec: &str) -> Result<Secret, String> {
    let fail = |why: &str| {
        Err(format!(
            "--secrets {spec}: {why}. Write NAME=file:/path, NAME=env:OTHER, NAME=vault:https://vault.example/v1/secret/data/gantry#field or NAME=aws-sm:arn:aws:secretsmanager:region:account:secret:name."
        ))
    };
    let Some((name, source)) = spec.split_once('=') else {
        return fail("there is no `=`");
    };
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return fail("NAME is the key_env name in the policy, letters, digits and _ only");
    }
    let Some((kind, rest)) = source.split_once(':') else {
        return fail("the source has no kind");
    };
    if rest.is_empty() {
        return fail("the source is empty");
    }
    let source = match kind {
        "file" => Source::File(PathBuf::from(rest)),
        "env" => Source::Env(rest.to_owned()),
        "vault" => match rest.rsplit_once('#') {
            Some((url, field))
                // The Vault token travels with the request: plain http only to Vault on this machine.
                if (url.starts_with("https://")
                    || url.starts_with("http://127.0.0.1")
                    || url.starts_with("http://localhost"))
                    && !field.is_empty() =>
            {
                Source::Vault {
                    url: url.to_owned(),
                    field: field.to_owned(),
                }
            }
            _ => return fail("a vault source is an https URL (or http://localhost) and #field"),
        },
        "aws-sm" => {
            let (arn, field) = match rest.split_once('#') {
                Some((arn, field)) => (arn, Some(field.to_owned())),
                None => (rest, None),
            };
            if !arn.starts_with("arn:aws:secretsmanager:") || region(arn).is_none() {
                return fail("an aws-sm source is a Secrets Manager secret ARN");
            }
            Source::AwsSm {
                arn: arn.to_owned(),
                field,
            }
        }
        _ => return fail("the kind is not file, env, vault or aws-sm"),
    };
    Ok(Secret {
        name: name.to_owned(),
        source,
    })
}

fn region(arn: &str) -> Option<&str> {
    arn.split(':').nth(3).filter(|r| !r.is_empty())
}

/// The key in a Vault KV v2 read response: `data.data.<field>`.
pub fn vault_value(body: &Value, field: &str) -> Result<String, String> {
    body.pointer("/data/data")
        .and_then(|data| data.get(field))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("the Vault secret has no string field `{field}` under data.data. Check the #field in --secrets."))
}

/// The key in a GetSecretValue response: `SecretString`, or one field of it when it is a JSON object.
pub fn aws_value(body: &Value, field: Option<&str>) -> Result<String, String> {
    let text = body
        .get("SecretString")
        .and_then(Value::as_str)
        .ok_or("the AWS secret has no SecretString. Store the key as a text secret.")?;
    let Some(field) = field else {
        return Ok(text.to_owned());
    };
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v.get(field).and_then(Value::as_str).map(str::to_owned))
        .ok_or_else(|| format!("the AWS secret is not a JSON object with a string field `{field}`. Check the #field in --secrets."))
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{name} is not set. Set it in the node's environment."))
}

fn http_error(what: &str, err: ureq::Error) -> String {
    match err {
        ureq::Error::Status(code, _) => {
            format!(
                "{what} answered {code}. Check the address and that the credentials may read the secret."
            )
        }
        err => format!("{what} could not be reached: {err}"),
    }
}

impl Secret {
    /// Reads the current value. Never puts the value in an error.
    pub fn fetch(&self, agent: &ureq::Agent) -> Result<String, String> {
        let value = match &self.source {
            Source::File(path) => std::fs::read_to_string(path)
                .map_err(|err| format!("{} cannot be read: {err}", path.display()))?,
            Source::Env(name) => env(name)?,
            Source::Vault { url, field } => {
                let body: Value = agent
                    .get(url)
                    .set("x-vault-token", &env("VAULT_TOKEN")?)
                    .call()
                    .map_err(|err| http_error("Vault", err))?
                    .into_json()
                    .map_err(|err| format!("Vault sent a response that is not JSON: {err}"))?;
                vault_value(&body, field)?
            }
            Source::AwsSm { arn, field } => {
                let region = region(arn).unwrap_or_default();
                let credentials = sigv4::Credentials {
                    access_key_id: env("AWS_ACCESS_KEY_ID")?,
                    secret_access_key: env("AWS_SECRET_ACCESS_KEY")?,
                    session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
                };
                // The variable the AWS SDKs read to reach Secrets Manager at another address, such as a VPC endpoint.
                let base = std::env::var("AWS_ENDPOINT_URL_SECRETS_MANAGER")
                    .unwrap_or_else(|_| format!("https://secretsmanager.{region}.amazonaws.com"));
                let host = base
                    .split_once("://")
                    .map_or(base.as_str(), |(_, h)| h)
                    .trim_end_matches('/');
                let payload = serde_json::json!({ "SecretId": arn }).to_string();
                let headers = [
                    ("content-type", "application/x-amz-json-1.1"),
                    ("host", host),
                    ("x-amz-target", "secretsmanager.GetSecretValue"),
                ];
                let request = sigv4::Request {
                    method: "POST",
                    path: "/",
                    query: "",
                    headers: &headers,
                    payload: payload.as_bytes(),
                };
                let signed = sigv4::sign(
                    &credentials,
                    region,
                    "secretsmanager",
                    &request,
                    &sigv4::amz_date_now(),
                );
                let mut req = agent.post(&format!("{}/", base.trim_end_matches('/')));
                for (name, value) in headers.iter().filter(|(n, _)| *n != "host") {
                    req = req.set(name, value);
                }
                for (name, value) in &signed {
                    req = req.set(name, value);
                }
                let body: Value = req
                    .send_string(&payload)
                    .map_err(|err| http_error("AWS Secrets Manager", err))?
                    .into_json()
                    .map_err(|err| format!("AWS sent a response that is not JSON: {err}"))?;
                aws_value(&body, field.as_deref())?
            }
        };
        let value = value.trim();
        if value.is_empty() {
            return Err("the secret is empty".into());
        }
        Ok(value.to_owned())
    }
}

/// Where the node keeps a managed key.
pub fn key_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("secrets").join(name)
}

/// Points each provider whose `key_env` is a managed name at the file the node keeps its key in.
// ponytail: line-based, so a provider written in YAML flow style (`{ key_env: X }`) keeps reading the environment.
pub fn rewrite_policy(policy: &str, secrets: &[Secret]) -> String {
    let mut out: String = policy
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let managed = trimmed
                .strip_prefix("key_env:")
                .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\''))
                .and_then(|v| secrets.iter().find(|s| s.name == v));
            match managed {
                Some(secret) => {
                    let indent = &line[..line.len() - trimmed.len()];
                    // Relative to the node's folder, where the gateway runs.
                    format!("{indent}key_file: secrets/{}\n", secret.name)
                }
                None => format!("{line}\n"),
            }
        })
        .collect();
    if !policy.ends_with('\n') {
        out.pop();
    }
    out
}

/// Fetches every secret once and writes it, so the gateway can start. Fails on the first that cannot be read.
pub fn load(dir: &Path, secrets: &[Secret], agent: &ureq::Agent) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(dir.join("secrets"))
        .map_err(|err| format!("could not create {}: {err}", dir.join("secrets").display()))?;
    secrets
        .iter()
        .map(|secret| {
            let value = secret
                .fetch(agent)
                .map_err(|err| format!("provider key {}: {err}", secret.name))?;
            crate::node::write_private(&key_path(dir, &secret.name), &value)?;
            Ok(value)
        })
        .collect()
}

/// Polls every secret each `interval` and writes a changed one. A source that fails keeps the key last written.
pub fn watch(
    dir: PathBuf,
    secrets: Vec<Secret>,
    mut values: Vec<String>,
    interval: Duration,
    agent: ureq::Agent,
) {
    loop {
        std::thread::sleep(interval);
        for (secret, last) in secrets.iter().zip(values.iter_mut()) {
            match secret.fetch(&agent) {
                Ok(value) if value != *last => {
                    match crate::node::write_private(&key_path(&dir, &secret.name), &value) {
                        Ok(()) => {
                            eprintln!("gantry node: provider key {} rotated", secret.name);
                            *last = value;
                        }
                        Err(err) => eprintln!("gantry node: provider key {}: {err}", secret.name),
                    }
                }
                Ok(_) => {}
                Err(err) => eprintln!(
                    "gantry node: provider key {}: {err}. Keeping the key it has.",
                    secret.name
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn specs_parse_and_bad_ones_say_how_to_write_them() -> TestResult {
        assert_eq!(
            parse("OPENAI_KEY=file:/run/k")?,
            Secret {
                name: "OPENAI_KEY".into(),
                source: Source::File("/run/k".into())
            }
        );
        assert_eq!(parse("A=env:B")?.source, Source::Env("B".into()));
        assert_eq!(
            parse("A=vault:https://vault.example/v1/secret/data/gantry#openai")?.source,
            Source::Vault {
                url: "https://vault.example/v1/secret/data/gantry".into(),
                field: "openai".into()
            }
        );
        let arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:gantry-AbCd";
        assert_eq!(
            parse(&format!("A=aws-sm:{arn}"))?.source,
            Source::AwsSm {
                arn: arn.into(),
                field: None
            }
        );
        assert_eq!(
            parse(&format!("A=aws-sm:{arn}#openai"))?.source,
            Source::AwsSm {
                arn: arn.into(),
                field: Some("openai".into())
            }
        );
        for bad in [
            "nothing",
            "BAD-NAME=env:B",
            "A=env:",
            "A=s3:bucket",
            "A=vault:https://vault.example/v1/secret/data/gantry",
            "A=vault:ftp://x#f",
            "A=aws-sm:arn:aws:s3:::bucket",
        ] {
            let err = parse(bad).err().ok_or(bad)?;
            assert!(err.contains("NAME=file:/path"), "{err}");
        }
        Ok(())
    }

    #[test]
    fn vault_and_aws_responses_give_the_key() -> TestResult {
        let vault: Value = serde_json::from_str(
            r#"{"data":{"data":{"openai":"sk-1","other":2},"metadata":{"version":3}}}"#,
        )?;
        assert_eq!(vault_value(&vault, "openai")?, "sk-1");
        assert!(vault_value(&vault, "other").is_err());
        let err = vault_value(&vault, "missing").err().ok_or("missing")?;
        assert!(err.contains("`missing`") && !err.contains("sk-1"), "{err}");

        let aws: Value = serde_json::from_str(
            r#"{"ARN":"arn:aws:secretsmanager:eu-west-1:1:secret:x","Name":"x","SecretString":"sk-2","VersionId":"v"}"#,
        )?;
        assert_eq!(aws_value(&aws, None)?, "sk-2");
        let json: Value = serde_json::from_str(r#"{"SecretString":"{\"openai\":\"sk-3\"}"}"#)?;
        assert_eq!(aws_value(&json, Some("openai"))?, "sk-3");
        assert!(aws_value(&json, Some("nope")).is_err());
        let binary: Value = serde_json::from_str(r#"{"SecretBinary":"AAAA"}"#)?;
        assert!(aws_value(&binary, None).is_err());
        Ok(())
    }

    #[test]
    fn only_managed_key_env_lines_become_key_files() -> TestResult {
        let policy = "providers:\n  - name: a\n    key_env: OPENAI_KEY\n  - name: b\n    key_env: \"OTHER\"\nrules: []";
        let secrets = vec![parse("OPENAI_KEY=env:X")?];
        let out = rewrite_policy(policy, &secrets);
        assert_eq!(
            out,
            "providers:\n  - name: a\n    key_file: secrets/OPENAI_KEY\n  - name: b\n    key_env: \"OTHER\"\nrules: []"
        );
        Ok(())
    }
}
