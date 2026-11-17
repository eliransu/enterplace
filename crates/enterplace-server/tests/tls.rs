//! `enterplace serve --tls-cert --tls-key`: Enterplace terminates TLS itself, so keys never cross the network in plain text.
//! The certificates in tests/tls are a throwaway test CA and a leaf for 127.0.0.1, made with openssl (see docs/operations.md).

use std::{path::Path, sync::Arc, time::Duration};

use enterplace_server::Config;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, pki_types::ServerName, pki_types::pem::PemObject},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/tls")
        .join(name)
}

async fn tls_gateway() -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    let acceptor = enterplace_server::tls_acceptor(&fixture("cert.pem"), &fixture("key.pem"))?;
    let config = Config::default();
    let timeouts = config.timeouts.clone();
    let app = enterplace_server::app(config)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(enterplace_server::serve_on_tls(
        listener,
        app,
        timeouts,
        std::future::pending(),
        acceptor,
    ));
    Ok(addr)
}

fn client() -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from_pem_file(fixture(
        "ca.pem",
    ))?)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

#[tokio::test]
async fn healthz_answers_over_tls_with_a_certificate_the_client_trusts() -> TestResult {
    let addr = tls_gateway().await?;
    let socket = TcpStream::connect(addr).await?;
    let mut tls = client()?
        .connect(ServerName::try_from("127.0.0.1")?, socket)
        .await?;
    tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: enterplace\r\nConnection: close\r\n\r\n")
        .await?;
    let mut answer = String::new();
    tokio::time::timeout(Duration::from_secs(5), tls.read_to_string(&mut answer)).await??;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    Ok(())
}

#[tokio::test]
async fn plain_http_to_the_tls_port_gets_no_answer() -> TestResult {
    let addr = tls_gateway().await?;
    let mut socket = TcpStream::connect(addr).await?;
    socket
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: enterplace\r\nConnection: close\r\n\r\n")
        .await?;
    let mut answer = Vec::new();
    // The handshake fails and the connection closes; an error or nothing at all is fine, a 200 is not.
    let _ = tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut answer)).await;
    assert!(!String::from_utf8_lossy(&answer).contains("200 OK"));
    Ok(())
}

#[tokio::test]
async fn a_missing_or_wrong_file_names_the_file_and_the_fix() -> TestResult {
    let missing =
        enterplace_server::tls_acceptor(Path::new("/nonexistent/cert.pem"), &fixture("key.pem"))
            .err()
            .ok_or("a missing certificate file was accepted")?;
    assert!(missing.contains("/nonexistent/cert.pem"), "{missing}");
    // A certificate where the key should be: no private key in it.
    let swapped = enterplace_server::tls_acceptor(&fixture("cert.pem"), &fixture("cert.pem"))
        .err()
        .ok_or("a certificate was accepted as a private key")?;
    assert!(swapped.contains("--tls-key"), "{swapped}");
    // A key that does not belong to the certificate.
    let ca_cert_with_leaf_key =
        enterplace_server::tls_acceptor(&fixture("ca.pem"), &fixture("key.pem"))
            .err()
            .ok_or("a key that does not match the certificate was accepted")?;
    assert!(
        ca_cert_with_leaf_key.contains("match"),
        "{ca_cert_with_leaf_key}"
    );
    Ok(())
}

#[tokio::test]
async fn a_request_over_tls_is_marked_so_the_console_sets_secure_cookies() -> TestResult {
    // QA14-6: an origin-form request has no scheme, so the console reads the mark the TLS listener sets.
    let app = axum::Router::new().route(
        "/mark",
        axum::routing::get(
            |mark: Option<axum::Extension<axum::http::uri::Scheme>>| async move {
                if mark.is_some_and(|m| m.0 == axum::http::uri::Scheme::HTTPS) {
                    "tls"
                } else {
                    "plain"
                }
            },
        ),
    );
    let get = b"GET /mark HTTP/1.1\r\nHost: enterplace\r\nConnection: close\r\n\r\n";
    let acceptor = enterplace_server::tls_acceptor(&fixture("cert.pem"), &fixture("key.pem"))?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let timeouts = Config::default().timeouts;
    tokio::spawn(enterplace_server::serve_on_tls(
        listener,
        app.clone(),
        timeouts.clone(),
        std::future::pending(),
        acceptor,
    ));
    let mut tls = client()?
        .connect(
            ServerName::try_from("127.0.0.1")?,
            TcpStream::connect(addr).await?,
        )
        .await?;
    tls.write_all(get).await?;
    let mut answer = String::new();
    tokio::time::timeout(Duration::from_secs(5), tls.read_to_string(&mut answer)).await??;
    assert!(answer.ends_with("tls"), "{answer}");
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(enterplace_server::serve_on(
        listener,
        app,
        timeouts,
        std::future::pending(),
    ));
    let mut plain = TcpStream::connect(addr).await?;
    plain.write_all(get).await?;
    let mut answer = String::new();
    tokio::time::timeout(Duration::from_secs(5), plain.read_to_string(&mut answer)).await??;
    assert!(answer.ends_with("plain"), "{answer}");
    Ok(())
}
