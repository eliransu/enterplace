//! OCI request signing: Oracle Cloud's HTTP signature (version 1, rsa-sha256) with an API signing key, for OCI
//! Generative AI without an API key.
//!
//! As documented on 2026-11-14 (<https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm>): the
//! signing string is one `name: value` line per signed header, lowercase names, joined by newlines, with
//! `(request-target)` as the lowercase method, a space, and the path and query as sent. A request without a body
//! signs `date (request-target) host`; one with a body adds `content-length content-type x-content-sha256`, the last
//! being the base64 SHA-256 of the body. The signature is base64 RSA-SHA256 (PKCS #1 v1.5) of the signing string, sent
//! as `Authorization: Signature version="1",keyId="<tenancy>/<user>/<fingerprint>",algorithm="rsa-sha256",
//! headers="...",signature="..."`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Uri, header};
use enterplace_core::eventstream::{base64_decode, base64_encode};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

/// An API signing key, ready to sign. It cannot be printed.
pub struct Signer {
    key_id: String,
    pair: RsaKeyPair,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[OCI signing key {}]", self.key_id)
    }
}

impl Signer {
    /// The key from its PEM text: PKCS #8 (`BEGIN PRIVATE KEY`, as the OCI console makes it) or PKCS #1
    /// (`BEGIN RSA PRIVATE KEY`). A key with a passphrase is refused with the fix.
    pub fn from_pem(key_id: &str, pem: &str) -> Result<Self, String> {
        if pem.contains("ENCRYPTED") {
            return Err("the OCI API signing key has a passphrase, which Enterplace does not take. Write it out without one (`openssl rsa -in key.pem -out key-plain.pem`) and point oci_signing at that.".into());
        }
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .map(str::trim)
            .collect();
        let der = base64_decode(&body)
            .filter(|der| !der.is_empty())
            .ok_or("the OCI API signing key is not a PEM block. Use the private key file the OCI console gave you when the API key was added.")?;
        let pair = RsaKeyPair::from_pkcs8(&der)
            .or_else(|_| RsaKeyPair::from_der(&der))
            .map_err(|_| "the OCI API signing key is not an RSA private key of 2048 bits or more. Add a new API key in the OCI console and use its private key.".to_string())?;
        Ok(Self {
            key_id: key_id.to_string(),
            pair,
        })
    }

    /// Sets the headers the signature covers, and the Authorization header that carries it.
    pub(crate) fn sign(
        &self,
        method: &Method,
        uri: &Uri,
        body: &[u8],
        headers: &mut HeaderMap,
    ) -> Result<(), String> {
        let host = uri
            .authority()
            .ok_or("the provider URL has no host to sign")?
            .as_str()
            .to_string();
        let date = http_date(SystemTime::now());
        let target = format!(
            "{} {}",
            method.as_str().to_ascii_lowercase(),
            uri.path_and_query().map_or("/", |pq| pq.as_str())
        );
        let mut signed = vec![
            ("date", date.clone()),
            ("(request-target)", target),
            ("host", host.clone()),
        ];
        let with_body = matches!(*method, Method::POST | Method::PUT | Method::PATCH);
        if with_body {
            let content_type = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            signed.push(("content-length", body.len().to_string()));
            signed.push(("content-type", content_type));
            signed.push(("x-content-sha256", content_sha256(body)));
        }
        let mut signature = vec![0; self.pair.public().modulus_len()];
        self.pair
            .sign(
                &RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                signing_string(&signed).as_bytes(),
                &mut signature,
            )
            .map_err(|_| "the OCI API signing key could not sign the request")?;
        let names: Vec<&str> = signed.iter().map(|(name, _)| *name).collect();
        let authorization = format!(
            "Signature version=\"1\",keyId=\"{}\",algorithm=\"rsa-sha256\",headers=\"{}\",signature=\"{}\"",
            self.key_id,
            names.join(" "),
            base64_encode(&signature)
        );
        let unsendable = |_| "a signed header holds a character that cannot be sent".to_string();
        for (name, value) in signed
            .iter()
            .filter(|(name, _)| *name != "(request-target)")
        {
            headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_str(value).map_err(unsendable)?,
            );
        }
        let mut value = HeaderValue::from_str(&authorization).map_err(unsendable)?;
        value.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, value);
        Ok(())
    }
}

/// The lines OCI signs, in the order of the `headers` list.
fn signing_string(signed: &[(&str, String)]) -> String {
    signed
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn content_sha256(body: &[u8]) -> String {
    base64_encode(ring::digest::digest(&ring::digest::SHA256, body).as_ref())
}

/// An HTTP date (RFC 7231), as OCI's `date` header takes it: `Thu, 05 Jan 2014 21:31:40 GMT`.
fn http_date(at: SystemTime) -> String {
    let secs = at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil-from-days, for the proleptic Gregorian calendar.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[usize::try_from(month - 1).unwrap_or(0)],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn dates_and_body_hashes_are_written_as_oci_reads_them() {
        // The documentation's example date.
        assert_eq!(
            http_date(UNIX_EPOCH + std::time::Duration::from_secs(1_388_957_500)),
            "Sun, 05 Jan 2014 21:31:40 GMT"
        );
        assert_eq!(
            http_date(UNIX_EPOCH + std::time::Duration::from_secs(1_794_700_800)),
            "Sun, 15 Nov 2026 00:00:00 GMT"
        );
        // OCI asks for the hash of an empty body too.
        assert_eq!(
            content_sha256(b""),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
        let lines = signing_string(&[
            ("date", "Thu, 05 Jan 2014 21:31:40 GMT".into()),
            (
                "(request-target)",
                "post /20160918/volumeAttachments".into(),
            ),
            ("host", "iaas.us-phoenix-1.oraclecloud.com".into()),
        ]);
        assert_eq!(
            lines,
            "date: Thu, 05 Jan 2014 21:31:40 GMT\n(request-target): post /20160918/volumeAttachments\nhost: iaas.us-phoenix-1.oraclecloud.com"
        );
    }

    #[test]
    fn both_key_forms_sign_and_a_passphrase_is_refused() -> TestResult {
        for pem in [
            include_str!("../tests/cloud/oci-test-key.pem"),
            include_str!("../tests/cloud/oci-test-key-pkcs1.pem"),
        ] {
            let signer = Signer::from_pem("t/u/f", pem)?;
            let mut headers = HeaderMap::new();
            let uri: Uri =
                "https://inference.example.com/20231130/actions/v1/chat/completions?x=1".parse()?;
            signer.sign(&Method::POST, &uri, b"{}", &mut headers)?;
            let auth = headers[header::AUTHORIZATION].to_str()?;
            assert!(auth.starts_with("Signature version=\"1\",keyId=\"t/u/f\",algorithm=\"rsa-sha256\",headers=\"date (request-target) host content-length content-type x-content-sha256\",signature=\""), "{auth}");
            assert_eq!(headers["content-length"], "2");
            assert_eq!(headers["host"], "inference.example.com");
        }
        assert!(
            Signer::from_pem(
                "k",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"
            )
            .is_err_and(|e| e.contains("passphrase"))
        );
        Ok(())
    }
}
