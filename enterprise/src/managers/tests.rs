//! Each secret manager against a mock of its API on 127.0.0.1, signed in to as its platform's chain does.

use std::collections::HashMap;

use axum::{
    Router,
    extract::Path,
    http::{HeaderMap, StatusCode, Uri},
    routing::{get, post},
};
use gantry_core::secrets::Source;
use serde_json::{Value, json};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn bearer(headers: &HeaderMap, want: &str) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(want)
}

async fn mock() -> Result<String, Box<dyn std::error::Error>> {
    let app = Router::new()
        .route(
            "/v1/secret/data/gantry",
            get(|headers: HeaderMap| async move {
                if headers.get("x-vault-token").and_then(|v| v.to_str().ok()) != Some("vault-token") {
                    return (StatusCode::FORBIDDEN, json!({"errors": ["permission denied"]}).to_string());
                }
                (StatusCode::OK, json!({"data": {"data": {"openai": "sk-vault", "other": "x"}, "metadata": {"version": 2}}}).to_string())
            }),
        )
        .route(
            "/v1/kv/gantry",
            get(|| async { json!({"data": {"openai": "sk-vault-v1"}}).to_string() }),
        )
        .route(
            "/v1/auth/kubernetes/login",
            post(|body: String| async move {
                let body: Value = serde_json::from_str(&body).unwrap_or_default();
                if body["role"] == "gantry" && body["jwt"] == "pod-jwt" {
                    (StatusCode::OK, json!({"auth": {"client_token": "vault-token", "lease_duration": 3600}}).to_string())
                } else {
                    (StatusCode::BAD_REQUEST, json!({"errors": ["invalid role"]}).to_string())
                }
            }),
        )
        .route(
            "/",
            post(|headers: HeaderMap, body: String| async move {
                let signed = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256 Credential=AKIATEST/"));
                let target = headers.get("x-amz-target").and_then(|v| v.to_str().ok());
                if !signed || target != Some("secretsmanager.GetSecretValue") {
                    return (StatusCode::FORBIDDEN, json!({"message": "bad signature"}).to_string());
                }
                let id: Value = serde_json::from_str(&body).unwrap_or_default();
                let string = if id["SecretId"] == "prod/json" {
                    r#"{"openai":"sk-aws-json"}"#
                } else {
                    "sk-aws"
                };
                (StatusCode::OK, json!({"SecretString": string}).to_string())
            }),
        )
        .route(
            "/token",
            post(|| async { json!({"access_token": "google-token", "expires_in": 3600}).to_string() }),
        )
        .route(
            "/v1/{*name}",
            get(|Path(name): Path<String>, headers: HeaderMap| async move {
                if !bearer(&headers, "Bearer google-token") || name != "projects/p/secrets/openai/versions/latest:access" {
                    return (StatusCode::FORBIDDEN, json!({"error": name}).to_string());
                }
                (StatusCode::OK, json!({"payload": {"data": gantry_core::x509::base64_encode(b"sk-gcp")}}).to_string())
            }),
        )
        .route(
            "/tenant-1/oauth2/v2.0/token",
            post(|body: String| async move {
                if body.contains("client_secret=azure-secret") && body.contains("scope=https%3A%2F%2Fvault.azure.net%2F.default") {
                    (StatusCode::OK, json!({"access_token": "azure-token", "expires_in": 3600}).to_string())
                } else {
                    (StatusCode::UNAUTHORIZED, json!({"error": "invalid_client"}).to_string())
                }
            }),
        )
        .route(
            "/secrets/{name}",
            get(|Path(name): Path<String>, uri: Uri, headers: HeaderMap| async move {
                if !bearer(&headers, "Bearer azure-token") || uri.query() != Some("api-version=7.4") {
                    return (StatusCode::UNAUTHORIZED, json!({}).to_string());
                }
                (StatusCode::OK, json!({"value": format!("sk-azure-{name}")}).to_string())
            }),
        );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = format!("127.0.0.1:{}", listener.local_addr()?.port());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

fn managers(vars: &[(&str, String)]) -> Managers {
    let map: HashMap<String, String> = vars
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    Managers::new(Arc::new(move |name: &str| map.get(name).cloned()))
}

async fn fetch(m: Arc<Managers>, reference: &str) -> Result<String, String> {
    let reference = reference.to_owned();
    tokio::task::spawn_blocking(move || m.fetch(&reference))
        .await
        .map_err(|e| e.to_string())?
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_is_read_with_a_token_or_the_pods_kubernetes_identity() -> TestResult {
    let addr = mock().await?;
    let m = Arc::new(managers(&[
        ("VAULT_ADDR", format!("http://{addr}")),
        ("VAULT_TOKEN", "vault-token".into()),
    ]));
    assert_eq!(
        fetch(m.clone(), "vault://secret/data/gantry#openai").await?,
        "sk-vault"
    );
    assert_eq!(fetch(m.clone(), "vault://kv/gantry").await?, "sk-vault-v1");
    let err = fetch(m.clone(), "vault://secret/data/gantry")
        .await
        .err()
        .ok_or("no field")?;
    assert!(err.contains("#field"), "{err}");
    let err = fetch(m, "vault://secret/data/gantry#missing")
        .await
        .err()
        .ok_or("missing")?;
    assert!(
        err.contains("`missing`") && !err.contains("sk-vault"),
        "{err}"
    );

    let dir = std::env::temp_dir().join(format!("gantry-managers-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("token"), "pod-jwt\n")?;
    let k8s = Arc::new(managers(&[
        ("VAULT_ADDR", format!("http://{addr}")),
        ("VAULT_K8S_ROLE", "gantry".into()),
        (
            "VAULT_K8S_TOKEN_PATH",
            dir.join("token").display().to_string(),
        ),
    ]));
    assert_eq!(
        fetch(k8s, "vault://secret/data/gantry#openai").await?,
        "sk-vault"
    );

    let wrong = Arc::new(managers(&[
        ("VAULT_ADDR", format!("http://{addr}")),
        ("VAULT_TOKEN", "nope".into()),
    ]));
    let err = fetch(wrong, "vault://secret/data/gantry#openai")
        .await
        .err()
        .ok_or("403")?;
    assert!(err.contains("403"), "{err}");
    let none = Arc::new(managers(&[]));
    let err = fetch(none, "vault://secret/data/gantry#openai")
        .await
        .err()
        .ok_or("addr")?;
    assert!(err.contains("VAULT_ADDR"), "{err}");
    let plain = Arc::new(managers(&[
        ("VAULT_ADDR", "http://vault.example.com".into()),
        ("VAULT_TOKEN", "t".into()),
    ]));
    let err = fetch(plain, "vault://secret/data/gantry#openai")
        .await
        .err()
        .ok_or("http")?;
    assert!(err.contains("not https"), "{err}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn aws_secrets_manager_is_read_signed_with_the_default_chain() -> TestResult {
    let addr = mock().await?;
    let m = Arc::new(managers(&[
        ("AWS_ACCESS_KEY_ID", "AKIATEST".into()),
        ("AWS_SECRET_ACCESS_KEY", "secret".into()),
        ("AWS_REGION", "eu-west-1".into()),
        ("AWS_EC2_METADATA_DISABLED", "true".into()),
        ("AWS_ENDPOINT_URL_SECRETS_MANAGER", format!("http://{addr}")),
    ]));
    assert_eq!(fetch(m.clone(), "aws-sm://prod/openai").await?, "sk-aws");
    assert_eq!(
        fetch(m.clone(), "aws-sm://prod/json#openai").await?,
        "sk-aws-json"
    );
    assert_eq!(
        fetch(
            m,
            "aws-sm://arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/openai"
        )
        .await?,
        "sk-aws"
    );
    let no_region = Arc::new(managers(&[("AWS_ACCESS_KEY_ID", "AKIATEST".into())]));
    let err = fetch(no_region, "aws-sm://prod/openai")
        .await
        .err()
        .ok_or("region")?;
    assert!(err.contains("AWS_REGION"), "{err}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn google_secret_manager_is_read_with_application_default_credentials() -> TestResult {
    let addr = mock().await?;
    let dir = std::env::temp_dir().join(format!("gantry-managers-g-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let file = dir.join("adc.json");
    std::fs::write(
        &file,
        json!({"type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r", "token_uri": format!("http://{addr}/token")}).to_string(),
    )?;
    let m = Arc::new(managers(&[
        ("GOOGLE_APPLICATION_CREDENTIALS", file.display().to_string()),
        ("HOME", dir.display().to_string()),
        ("GCE_METADATA_HOST", "127.0.0.1:9".into()),
        (
            "CLOUDSDK_API_ENDPOINT_OVERRIDES_SECRETMANAGER",
            format!("http://{addr}/"),
        ),
    ]));
    assert_eq!(
        fetch(m.clone(), "gcp-sm://projects/p/secrets/openai").await?,
        "sk-gcp"
    );
    let err = fetch(m, "gcp-sm://openai").await.err().ok_or("shape")?;
    assert!(err.contains("projects/<project>/secrets/<name>"), "{err}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn azure_key_vault_is_read_with_an_entra_token() -> TestResult {
    let addr = mock().await?;
    let m = Arc::new(managers(&[
        ("AZURE_TENANT_ID", "tenant-1".into()),
        ("AZURE_CLIENT_ID", "client".into()),
        ("AZURE_CLIENT_SECRET", "azure-secret".into()),
        ("AZURE_AUTHORITY_HOST", format!("http://{addr}")),
    ]));
    assert_eq!(
        fetch(m.clone(), &format!("azure-kv://{addr}/openai")).await?,
        "sk-azure-openai"
    );
    // The token is kept: a second read signs in no more.
    assert_eq!(
        fetch(m, &format!("azure-kv://{addr}/anthropic")).await?,
        "sk-azure-anthropic"
    );
    let wrong = Arc::new(managers(&[
        ("AZURE_TENANT_ID", "tenant-1".into()),
        ("AZURE_CLIENT_ID", "client".into()),
        ("AZURE_CLIENT_SECRET", "wrong".into()),
        ("AZURE_AUTHORITY_HOST", format!("http://{addr}")),
    ]));
    let err = fetch(wrong, &format!("azure-kv://{addr}/openai"))
        .await
        .err()
        .ok_or("401")?;
    assert!(
        err.contains("could not sign in to Azure") && err.contains("401"),
        "{err}"
    );
    Ok(())
}
