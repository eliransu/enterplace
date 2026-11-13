//! AWS Signature Version 4, to sign requests to Amazon Bedrock with the access key in Gantry's environment.
//!
//! As documented on 2026-11-13 at <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>,
//! and checked against the published test suite (aws-c-auth `tests/aws-signing-test-suite/v4`).

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::id::{hex, sha256_hex};

/// An AWS access key. It cannot be printed.
#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Set for temporary credentials, such as those of an assumed role.
    pub session_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[aws credentials]")
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC takes a key of any length, so this cannot fail.
    match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Err(_) => Vec::new(),
    }
}

/// Percent-encodes every byte but the unreserved ones, as SigV4's UriEncode does. `/` is kept when `slash` is set.
pub fn uri_encode(text: &str, slash: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) || (slash && byte == b'/') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// One request to sign. `path` is the path as sent on the wire, already percent-encoded once.
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// The canonical query string: names and values encoded, sorted by name. Empty when there is none.
    pub query: &'a str,
    /// Every header to sign except `x-amz-date` and `x-amz-security-token`, which are added here. Must hold `host`.
    pub headers: &'a [(&'a str, &'a str)],
    pub payload: &'a [u8],
}

/// The headers that carry the signature: `authorization`, `x-amz-date` and, with temporary credentials,
/// `x-amz-security-token`. `amz_date` is the time as `20150830T123600Z`.
pub fn sign(
    credentials: &Credentials,
    region: &str,
    service: &str,
    request: &Request<'_>,
    amz_date: &str,
) -> Vec<(&'static str, String)> {
    let mut headers: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|(name, value)| {
            // Values are trimmed and inner runs of spaces folded to one.
            let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
            (name.to_ascii_lowercase(), value)
        })
        .collect();
    headers.push(("x-amz-date".into(), amz_date.into()));
    if let Some(token) = &credentials.session_token {
        headers.push(("x-amz-security-token".into(), token.clone()));
    }
    headers.sort();
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let signed: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
    let signed = signed.join(";");
    // Every service but S3 signs the path encoded a second time.
    let path = if request.path.is_empty() {
        "/".to_string()
    } else {
        uri_encode(request.path, true)
    };
    let canonical = format!(
        "{}\n{path}\n{}\n{canonical_headers}\n{signed}\n{}",
        request.method,
        request.query,
        sha256_hex(request.payload)
    );
    let date = amz_date.get(..8).unwrap_or_default();
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let mut key = hmac(
        format!("AWS4{}", credentials.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    for part in [region, service, "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    let signature = hex(&hmac(&key, to_sign.as_bytes()));
    let mut out = vec![
        (
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
                credentials.access_key_id
            ),
        ),
        ("x-amz-date", amz_date.to_string()),
    ];
    if let Some(token) = &credentials.session_token {
        out.push(("x-amz-security-token", token.clone()));
    }
    out
}

/// The time now as SigV4 writes it: `20261113T101500Z`.
pub fn amz_date_now() -> String {
    // The audit log's clock gives `2026-11-13T10:15:00.123Z`.
    let stamp = crate::audit::timestamp();
    let digits: String = stamp
        .get(..19)
        .unwrap_or_default()
        .chars()
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    format!("{digits}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATE: &str = "20150830T123600Z";

    fn example(token: Option<&str>) -> Credentials {
        Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: token.map(String::from),
        }
    }

    fn signature<'a>(headers: &'a [(&'static str, String)]) -> &'a str {
        headers
            .iter()
            .find(|(name, _)| *name == "authorization")
            .and_then(|(_, value)| value.split("Signature=").nth(1))
            .unwrap_or_default()
    }

    // Published suite, get-vanilla.
    #[test]
    fn get_vanilla() {
        let out = sign(
            &example(None),
            "us-east-1",
            "service",
            &Request {
                method: "GET",
                path: "/",
                query: "",
                headers: &[("Host", "example.amazonaws.com")],
                payload: b"",
            },
            DATE,
        );
        assert_eq!(
            signature(&out),
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert_eq!(
            out[0].1,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    // Published suite, post-x-www-form-urlencoded: a body, and headers beyond host signed.
    #[test]
    fn post_with_a_body() {
        let body = b"Param1=value1";
        let hash = sha256_hex(body);
        let out = sign(
            &example(None),
            "us-east-1",
            "service",
            &Request {
                method: "POST",
                path: "/",
                query: "",
                headers: &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Host", "example.amazonaws.com"),
                    ("Content-Length", "13"),
                    ("x-amz-content-sha256", &hash),
                ],
                payload: body,
            },
            DATE,
        );
        assert_eq!(
            signature(&out),
            "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b"
        );
    }

    // Published suite, post-sts-header-before: temporary credentials sign their token.
    #[test]
    fn a_session_token_is_signed_and_sent() {
        let token = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";
        let out = sign(
            &example(Some(token)),
            "us-east-1",
            "service",
            &Request {
                method: "POST",
                path: "/",
                query: "",
                headers: &[("Host", "example.amazonaws.com")],
                payload: b"",
            },
            DATE,
        );
        assert_eq!(
            signature(&out),
            "85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead"
        );
        assert!(out.contains(&("x-amz-security-token", token.to_string())));
    }

    #[test]
    fn a_path_is_encoded_a_second_time_for_the_signature() {
        assert_eq!(
            uri_encode("/model/a%3A0/invoke", true),
            "/model/a%253A0/invoke"
        );
        assert_eq!(uri_encode("a:b/c d", false), "a%3Ab%2Fc%20d");
    }

    /// QA10-5 B1: `sign` itself must sign the path encoded twice, as every Bedrock model ID with a colon needs.
    #[test]
    fn sign_puts_the_twice_encoded_path_in_the_canonical_request() {
        let path = "/model/anthropic.claude-x-v1%3A0/invoke";
        let headers = [("Host", "bedrock-runtime.us-east-1.amazonaws.com")];
        let out = sign(
            &example(None),
            "us-east-1",
            "bedrock",
            &Request {
                method: "POST",
                path,
                query: "",
                headers: &headers,
                payload: b"{}",
            },
            DATE,
        );
        // The canonical request written out by hand, path as AWS signs it outside S3.
        let canonical = format!(
            "POST\n/model/anthropic.claude-x-v1%253A0/invoke\n\nhost:bedrock-runtime.us-east-1.amazonaws.com\nx-amz-date:{DATE}\n\nhost;x-amz-date\n{}",
            sha256_hex(b"{}")
        );
        let scope = "20150830/us-east-1/bedrock/aws4_request";
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{DATE}\n{scope}\n{}",
            sha256_hex(canonical.as_bytes())
        );
        let mut key = hmac(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20150830");
        for part in ["us-east-1", "bedrock", "aws4_request"] {
            key = hmac(&key, part.as_bytes());
        }
        assert_eq!(signature(&out), hex(&hmac(&key, to_sign.as_bytes())));
    }

    #[test]
    fn the_date_has_the_sigv4_shape() {
        let date = amz_date_now();
        assert_eq!(date.len(), 16, "{date}");
        assert_eq!(&date[8..9], "T");
        assert!(date.ends_with('Z'));
    }
}
