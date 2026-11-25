//! The one place Enterplace's TLS configurations are made, so every connection it opens or accepts uses the same
//! cryptography: `ring` in the default build, and the AWS-LC FIPS module in a build with the `fips` feature.

use std::{path::Path, sync::Arc};

pub use tokio_rustls::rustls;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// The cryptography every TLS connection of this build uses.
pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The Mozilla roots compiled in, so a container needs no system certificates.
pub fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// A client configuration that trusts the Mozilla roots and presents no certificate.
pub fn client_config() -> Result<rustls::ClientConfig, String> {
    client_config_for(None, None, "")
}

/// A client configuration for one server: it trusts the Mozilla roots and the CAs of the PEM file `ca` (a private
/// endpoint's own CA), and presents the PEM certificate chain and key of `cert` (mutual TLS). `what` says whose
/// the files are, for the message.
pub fn client_config_for(
    ca: Option<&Path>,
    cert: Option<(&Path, &Path)>,
    what: &str,
) -> Result<rustls::ClientConfig, String> {
    let mut roots = roots();
    if let Some(path) = ca {
        for ca in certificates(path, what)? {
            roots.add(ca).map_err(|err| {
                format!("a certificate in {} ({what}) cannot be used as a CA: {err}. Give the PEM certificate of the CA that signed the server's certificate.", path.display())
            })?;
        }
    }
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("TLS could not be set up: {err}. Report this as a bug."))?
        .with_root_certificates(roots);
    match cert {
        None => Ok(builder.with_no_client_auth()),
        Some((cert, key_path)) => {
            let (certs, key) = identity(cert, key_path, what)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|err| format!("the key in {} does not match the certificate in {} ({what}), or is not usable: {err}. Give the key the certificate was issued for.", key_path.display(), cert.display()))
        }
    }
}

/// A PEM certificate chain and its private key, read. `what` says whose they are, for the message.
pub fn identity(
    cert: &Path,
    key: &Path,
    what: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let certs = certificates(cert, what)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|err| format!("could not read a private key from {} ({what}): {err}. Give the PEM private key of the certificate (PKCS#8, PKCS#1 or SEC1), unencrypted.", key.display()))?;
    Ok((certs, key))
}

/// The certificates of a PEM file, which must hold at least one.
pub fn certificates(path: &Path, what: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|err| format!("could not read a certificate from {} ({what}): {err}. Give a PEM file that starts with -----BEGIN CERTIFICATE-----.", path.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "{} ({what}) holds no certificate. Give a PEM file that starts with -----BEGIN CERTIFICATE-----.",
            path.display()
        ));
    }
    Ok(certs)
}

/// The HTTPS connector every outgoing HTTP client is built on: this build's cryptography and the Mozilla roots.
pub fn https() -> hyper_rustls::HttpsConnectorBuilder<hyper_rustls::builderstates::WantsSchemes> {
    https_with(client_config().ok())
}

/// [`https`] with a configuration of the caller's (a client certificate), or the default one for `None`.
pub fn https_with(
    config: Option<rustls::ClientConfig>,
) -> hyper_rustls::HttpsConnectorBuilder<hyper_rustls::builderstates::WantsSchemes> {
    let builder = hyper_rustls::HttpsConnectorBuilder::new();
    match config {
        Some(config) => builder.with_tls_config(config),
        // Not reached: a provider always has a protocol version of its own. hyper-rustls then builds the same.
        None => builder.with_webpki_roots(),
    }
}
