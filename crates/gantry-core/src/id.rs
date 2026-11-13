//! Decision IDs, Gantry keys and the hashes that stand in for them.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

/// What every Gantry key starts with, so a leaked one can be recognized by a secret scanner.
pub const KEY_PREFIX: &str = "gantry_";

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A new decision ID: 26 characters, sortable by time (the ULID layout: 48 bits of milliseconds, 80 random bits).
pub fn decision_id() -> String {
    static FALLBACK: AtomicU64 = AtomicU64::new(0);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let mut random = [0u8; 16];
    if getrandom::fill(&mut random[6..]).is_err() {
        // An ID must still be unique when the system has no randomness to give. It names a record, it guards nothing.
        let n = FALLBACK.fetch_add(1, Ordering::Relaxed);
        random[8..].copy_from_slice(&n.to_be_bytes());
    }
    let value = ((millis & ((1 << 48) - 1)) << 80) | u128::from_be_bytes(random);
    (0..26)
        .map(|i| CROCKFORD[((value >> (125 - 5 * i)) & 31) as usize] as char)
        .collect()
}

/// A new Gantry key with 256 random bits. Fails if the system cannot supply randomness: a guessable key is worse than none.
pub fn new_key() -> Result<String, String> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)
        .map_err(|err| format!("the system gave no randomness to make a key from: {err}"))?;
    Ok(format!("{KEY_PREFIX}{}", hex(&random)))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decision_id_is_26_crockford_characters_and_sorts_by_time() {
        let first = decision_id();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = decision_id();
        for id in [&first, &second] {
            assert_eq!(id.len(), 26);
            assert!(id.bytes().all(|b| CROCKFORD.contains(&b)), "{id}");
        }
        assert!(first < second, "{first} then {second}");
        assert_ne!(decision_id(), decision_id());
    }

    #[test]
    fn a_key_has_the_prefix_and_256_bits() -> Result<(), String> {
        let key = new_key()?;
        let random = key.strip_prefix(KEY_PREFIX).ok_or("no prefix")?;
        assert_eq!(random.len(), 64);
        assert!(random.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(key, new_key()?);
        Ok(())
    }

    #[test]
    fn sha256_matches_the_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
