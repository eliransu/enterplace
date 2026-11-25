//! Mutual TLS. Toward callers: `tls: { client_ca_file, require }` makes Enterplace ask for a client certificate and
//! check it, a key with `cert:` works only on a connection that presented that certificate, and the certificate's
//! name is recorded. Toward a provider: `client_cert_file`, `client_key_file` and `ca_file` present Enterplace's own
//! certificate to a private endpoint. The certificates in tests/tls are throwaway ones made with openssl.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{Router, body::Body, http::Request};
use enterplace_core::id::sha256_hex;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    },
};
use tower::ServiceExt;

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

const BOUND: &str = "enterplace_bound_key_for_the_billing_service_0123456789";
const FREE: &str = "enterplace_free_key_for_anyone_at_all_0123456789abcdef";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/tls")
        .join(name)
}

/// A TLS client that trusts the test CA and presents `cert` (a fixture's name without `.pem`), if any.
fn client(cert: Option<&str>) -> Result<TlsConnector, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(fixture("ca.pem"))?)?;
    let builder = rustls::ClientConfig::builder_with_provider(enterplace_server::tls::provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
    let config = match cert {
        None => builder.with_no_client_auth(),
        Some(name) => builder.with_client_auth_cert(
            CertificateDer::pem_file_iter(fixture(&format!("{name}.pem")))?
                .collect::<Result<Vec<_>, _>>()?,
            PrivateKeyDer::from_pem_file(fixture(&format!("{name}-key.pem")))?,
        )?,
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

/// One request over TLS: the status line's code and the body, or `None` when the server gave no answer (it closed
/// the connection in or after the handshake).
async fn get(
    addr: SocketAddr,
    cert: Option<&str>,
    path: &str,
    key: Option<&str>,
) -> Result<Option<(u16, String)>, Error> {
    let socket = TcpStream::connect(addr).await?;
    let Ok(mut tls) = client(cert)?
        .connect(ServerName::try_from("127.0.0.1")?, socket)
        .await
    else {
        return Ok(None);
    };
    let auth = key.map_or(String::new(), |k| format!("Authorization: Bearer {k}\r\n"));
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: enterplace\r\n{auth}Connection: close\r\n\r\n");
    if tls.write_all(request.as_bytes()).await.is_err() {
        return Ok(None);
    }
    let mut answer = Vec::new();
    // A client the server turned away learns of it here, as an error or an empty answer.
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut answer)).await;
    let answer = String::from_utf8_lossy(&answer).into_owned();
    let Some(code) = answer
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
    else {
        return Ok(None);
    };
    let body = answer.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    Ok(Some((code, body.to_string())))
}

async fn serve(app: Router, client_ca: Option<bool>) -> Result<SocketAddr, Error> {
    let ca = fixture("client-ca.pem");
    let acceptor = enterplace_server::tls_acceptor_with(
        &fixture("cert.pem"),
        &fixture("key.pem"),
        client_ca.map(|require| (ca.as_path(), require)),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(enterplace_server::serve_on_tls(
        listener,
        app,
        enterplace_server::Config::default().timeouts,
        std::future::pending(),
        acceptor,
    ));
    Ok(addr)
}

fn workdir(name: &str) -> Result<PathBuf, Error> {
    let dir = std::env::temp_dir().join(format!("enterplace-mtls-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// A gateway on files: one provider (as `provider` writes it), a key bound to the billing certificate, a free one.
fn gateway(name: &str, provider: &str) -> Result<(enterplace_server::Governed, PathBuf), Error> {
    let dir = workdir(name)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1\naudit: {{ path: {} }}\nproviders:\n  - name: mock\n    kind: openai\n{provider}    allow_private: true\n    key_env: K\n    models: [model-a]\nrules:\n  - name: ops\n    principals: {{ team: ops }}\n    models: [model-a]\n",
            dir.join("audit.jsonl").display()
        ),
    )?;
    std::fs::write(
        dir.join("enterplace.keys.yaml"),
        format!(
            "keys:\n  - name: billing\n    team: ops\n    admin: true\n    sha256: {}\n    cert: billing.internal\n  - name: maya\n    team: ops\n    sha256: {}\n",
            sha256_hex(BOUND.as_bytes()),
            sha256_hex(FREE.as_bytes())
        ),
    )?;
    let gw = enterplace_server::governed(&policy, None, &|_| Some("provider-key".into()))?;
    Ok((gw, dir))
}

#[tokio::test]
async fn a_required_client_certificate_is_checked_before_any_request_is_read() -> TestResult {
    let app = enterplace_server::app(enterplace_server::Config::default())?;
    let addr = serve(app, Some(true)).await?;
    assert_eq!(
        get(addr, Some("client"), "/healthz", None)
            .await?
            .map(|a| a.0),
        Some(200),
        "a certificate of the CA is let in"
    );
    assert_eq!(
        get(addr, None, "/healthz", None).await?,
        None,
        "no certificate, no request"
    );
    assert_eq!(
        get(addr, Some("stranger"), "/healthz", None).await?,
        None,
        "a certificate of the same name from another CA is turned away"
    );
    Ok(())
}

#[tokio::test]
async fn a_key_bound_to_a_certificate_works_only_with_it_and_the_certificate_is_recorded()
-> TestResult {
    let (gw, dir) = gateway("bound", "    url: http://127.0.0.1:9\n")?;
    // `require: false`: a certificate is verified when presented, and a caller without one is still served.
    let addr = serve(gw.router.clone(), Some(false)).await?;
    let models = |cert, key| get(addr, cert, "/v1/models", Some(key));

    let (status, body) = models(None, BOUND).await?.ok_or("no answer")?;
    assert_eq!(status, 403, "{body}");
    let refused: Value = serde_json::from_str(&body)?;
    assert_eq!(refused["error"]["code"], "cert_required", "{body}");
    assert!(body.contains("billing.internal"), "{body}");

    let (status, body) = models(Some("client"), BOUND).await?.ok_or("no answer")?;
    assert_eq!(status, 200, "{body}");
    // A key with no cert: works with or without one.
    assert_eq!(models(None, FREE).await?.map(|a| a.0), Some(200));
    assert_eq!(models(Some("client"), FREE).await?.map(|a| a.0), Some(200));
    // The same certificate name from a CA the policy does not trust never gets as far as the key.
    assert_eq!(models(Some("stranger"), BOUND).await?, None);

    // The admin API holds the binding too: the bound admin key alone is of no use there.
    let (status, body) = get(addr, None, "/admin/keys", Some(BOUND))
        .await?
        .ok_or("no answer")?;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("cert_required"), "{body}");
    let (status, body) = get(addr, Some("client"), "/admin/keys", Some(BOUND))
        .await?
        .ok_or("no answer")?;
    assert_eq!(status, 200, "{body}");

    gw.log.flush();
    let log = std::fs::read_to_string(dir.join("audit.jsonl"))?;
    let records: Vec<Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let of = |code: Value| {
        records
            .iter()
            .filter(|r| r["path"] == "/v1/models" && r["code"] == code)
            .collect::<Vec<_>>()
    };
    let refused = of(json!("cert_required"));
    assert_eq!(refused.len(), 1, "{log}");
    assert_eq!(refused[0]["person"], "billing");
    assert!(refused[0].get("client_cert").is_none(), "{log}");
    assert!(
        records
            .iter()
            .any(|r| r["person"] == "billing" && r["client_cert"] == "billing-svc"),
        "the certificate's subject is on the record beside the key: {log}"
    );
    Ok(())
}

#[tokio::test]
async fn a_provider_that_asks_for_a_client_certificate_gets_the_one_the_policy_names() -> TestResult
{
    // The provider: TLS with the test CA's certificate, and no request without a client certificate of client-ca.
    let provider = Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(|cert: Option<axum::Extension<enterplace_server::ClientCert>>| async move {
            (
                [("content-type", "application/json")],
                json!({
                    "id": "c1", "object": "chat.completion", "model": "model-a",
                    "choices": [{"index": 0, "finish_reason": "stop",
                        "message": {"role": "assistant", "content": cert.map_or_else(String::new, |c| c.0.0.join(","))}}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                })
                .to_string(),
            )
        }),
    );
    let at = serve(provider, Some(true)).await?;
    let chat = async |gw: &enterplace_server::Governed| -> Result<(u16, Value), Error> {
        let request = Request::post("/v1/chat/completions")
            .header("authorization", format!("Bearer {FREE}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"model": "model-a", "messages": [{"role": "user", "content": "hi"}]})
                    .to_string(),
            ))?;
        let response = gw.router.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let body = response.into_body().collect().await?.to_bytes();
        Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
    };

    let with = format!(
        "    url: https://127.0.0.1:{}\n    ca_file: {}\n    client_cert_file: {}\n    client_key_file: {}\n",
        at.port(),
        fixture("ca.pem").display(),
        fixture("client.pem").display(),
        fixture("client-key.pem").display()
    );
    let (gw, _dir) = gateway("provider-with", &with)?;
    let (status, body) = chat(&gw).await?;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["choices"][0]["message"]["content"]
            .as_str()
            .is_some_and(|names| names.contains("billing.internal")),
        "the provider saw Enterplace's certificate: {body}"
    );

    // Without the certificate the provider turns Enterplace away, and the caller is told the provider failed.
    let without = format!(
        "    url: https://127.0.0.1:{}\n    ca_file: {}\n",
        at.port(),
        fixture("ca.pem").display()
    );
    let (gw, _dir) = gateway("provider-without", &without)?;
    let (status, body) = chat(&gw).await?;
    assert_eq!(status, 502, "{body}");

    // A certificate file that is not there stops the start, naming the file and the provider.
    let missing = "    url: https://127.0.0.1:9\n    client_cert_file: /nonexistent/c.pem\n    client_key_file: /nonexistent/k.pem\n";
    let err = gateway("provider-missing", missing)
        .err()
        .ok_or("a missing client certificate was accepted")?
        .to_string();
    assert!(
        err.contains("/nonexistent/c.pem") && err.contains("mock"),
        "{err}"
    );
    Ok(())
}

#[test]
fn the_policy_refuses_half_a_certificate_pair_and_a_requirement_with_no_ca() -> TestResult {
    let dir = workdir("check")?;
    let policy = dir.join("enterplace.policy.yaml");
    let base = "version: 1\nproviders:\n  - name: mock\n    kind: openai\n    url: https://api.example.com\n    key_env: K\n    models: [model-a]\nPROVIDER\nrules:\n  - name: ops\n    principals: { team: ops }\n    models: [model-a]\nTOP\n";
    let problems = |provider: &str, top: &str| -> Result<String, Error> {
        std::fs::write(
            &policy,
            base.replace("PROVIDER", provider).replace("TOP", top),
        )?;
        Ok(enterplace_core::config::load(&policy, None)
            .err()
            .unwrap_or_default()
            .join("\n"))
    };
    assert_eq!(
        problems(
            "",
            "tls: { client_ca_file: /etc/enterplace/ca.pem, require: false }"
        )?,
        ""
    );
    assert_eq!(
        problems(
            "    client_cert_file: c.pem\n    client_key_file: k.pem",
            ""
        )?,
        ""
    );
    let half = problems("    client_cert_file: c.pem", "")?;
    assert!(
        half.contains("client_cert_file and client_key_file go together"),
        "{half}"
    );
    let no_ca = problems("", "tls: { require: true }")?;
    assert!(no_ca.contains("client_ca_file"), "{no_ca}");
    let one = problems("", "tls: { cert_file: c.pem }")?;
    assert!(one.contains("cert_file and key_file go together"), "{one}");
    Ok(())
}
