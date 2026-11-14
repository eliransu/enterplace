//! The public key of an X.509 certificate, as a SAML identity provider hands it over, and the base64 it travels in.
//!
//! Only the path to `subjectPublicKeyInfo` is read (RFC 5280 section 4.1). The certificate's own signature, issuer
//! and dates are not checked: SAML trusts the certificate the admin pasted, not a chain, as the SAML metadata
//! specification has it (an identity provider's certificate is often self-signed and long expired).

/// A key that verifies signatures, in the form `ring` takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// The DER `RSAPublicKey` (PKCS #1).
    Rsa(Vec<u8>),
    /// The uncompressed P-256 point.
    EcP256(Vec<u8>),
}

const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// One DER element: its tag, its contents, and what follows it.
fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

fn inside(der: &[u8], tag: u8) -> Option<&[u8]> {
    element(der)
        .filter(|(t, _, _)| *t == tag)
        .map(|(_, c, _)| c)
}

/// The public key of a DER certificate.
pub fn public_key(der: &[u8]) -> Result<PublicKey, String> {
    spki(der).ok_or_else(|| {
        "the certificate is not a DER X.509 certificate with an RSA or P-256 public key".to_string()
    })
}

fn spki(der: &[u8]) -> Option<PublicKey> {
    let cert = inside(der, 0x30)?;
    let mut tbs = inside(cert, 0x30)?;
    // version [0] is optional; then serial, signature algorithm, issuer, validity, subject.
    if tbs.first() == Some(&0xa0) {
        tbs = element(tbs)?.2;
    }
    for _ in 0..5 {
        tbs = element(tbs)?.2;
    }
    let info = inside(tbs, 0x30)?;
    let (tag, algorithm, rest) = element(info)?;
    if tag != 0x30 {
        return None;
    }
    let (oid_tag, oid, params) = element(algorithm)?;
    let key = inside(rest, 0x03)?;
    // A BIT STRING whose first byte counts unused bits, which a key never has.
    let (&0, key) = key.split_first()? else {
        return None;
    };
    match (oid_tag, oid) {
        (0x06, RSA) => Some(PublicKey::Rsa(key.to_vec())),
        (0x06, EC) if inside(params, 0x06) == Some(P256) && key.len() == 65 && key[0] == 4 => {
            Some(PublicKey::EcP256(key.to_vec()))
        }
        _ => None,
    }
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648 section 4), padding optional, whitespace skipped as PEM and XML wrap it.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    let mut padded = false;
    for byte in text.bytes().filter(|b| !b.is_ascii_whitespace()) {
        if byte == b'=' {
            padded = true;
            continue;
        }
        if padded {
            return None;
        }
        let value = STANDARD.iter().position(|c| *c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Standard base64 with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(STANDARD[(n >> (18 - 6 * i) & 63) as usize]));
        }
        out.push_str(&"=="[..3 - chunk.len()]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_skips_wrapping() {
        for len in 0..10u8 {
            let bytes: Vec<u8> = (0..len).map(|i| i.wrapping_mul(97)).collect();
            assert_eq!(base64_decode(&base64_encode(&bytes)), Some(bytes));
        }
        assert_eq!(base64_decode("Zm9v\n YmE="), Some(b"fooba".to_vec()));
        assert_eq!(base64_decode("Zm=9v"), None);
        assert_eq!(base64_decode("Zm9v*"), None);
    }

    #[test]
    fn a_certificate_gives_its_key_and_anything_else_is_refused() {
        // A minimal certificate shape: version, serial, algorithm, issuer, validity, subject, then the key.
        let tlv = |tag: u8, body: &[u8]| {
            let mut out = vec![tag, body.len() as u8];
            out.extend_from_slice(body);
            out
        };
        let rsa_key = tlv(0x30, &[tlv(0x02, &[1, 0, 1]), tlv(0x02, &[3])].concat());
        let algorithm = tlv(0x30, &[tlv(0x06, RSA), vec![0x05, 0]].concat());
        let info = tlv(
            0x30,
            &[algorithm, tlv(0x03, &[&[0u8][..], &rsa_key].concat())].concat(),
        );
        let tbs = tlv(
            0x30,
            &[
                tlv(0xa0, &tlv(0x02, &[2])),
                tlv(0x02, &[7]),
                tlv(0x30, &[]),
                tlv(0x30, &[]),
                tlv(0x30, &[]),
                tlv(0x30, &[]),
                info,
            ]
            .concat(),
        );
        let cert = tlv(0x30, &[tbs, tlv(0x30, &[]), tlv(0x03, &[0])].concat());
        assert_eq!(public_key(&cert), Ok(PublicKey::Rsa(rsa_key)));
        assert!(public_key(&cert[..cert.len() - 3]).is_err());
        assert!(public_key(b"not a certificate").is_err());
    }
}
