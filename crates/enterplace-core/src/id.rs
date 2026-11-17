//! Decision IDs, Enterplace keys and the hashes that stand in for them.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

/// What every Enterplace key starts with, so a leaked one can be recognized by a secret scanner.
pub const KEY_PREFIX: &str = "enterplace_";

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

/// A new Enterplace key with 256 random bits. Fails if the system cannot supply randomness: a guessable key is worse than none.
pub fn new_key() -> Result<String, String> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)
        .map_err(|err| format!("the system gave no randomness to make a key from: {err}"))?;
    Ok(format!("{KEY_PREFIX}{}", hex(&random)))
}

/// What a Enterplace person token starts with. It names a person for subscription passthrough (`x-enterplace-user`) and
/// grants no provider access on its own: a request that sends it as its only credential is refused.
pub const PERSON_PREFIX: &str = "enterplace_u_";

/// A new person token, as random as a key.
pub fn new_person_token() -> Result<String, String> {
    new_key().map(|key| format!("{PERSON_PREFIX}{}", &key[KEY_PREFIX.len()..]))
}

/// `n` random bytes as hex, for trace and span IDs. Without system randomness it falls back to a hash of a fresh
/// decision ID: unique, not secret, which is all a trace ID needs.
/// `n` random bytes as hex, for a secret: an error, never a weaker value, when the system gives no randomness.
pub fn secret_hex(n: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes)
        .map_err(|e| format!("the system gave no randomness ({e}). Try again."))?;
    Ok(hex(&bytes))
}

pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    if getrandom::fill(&mut bytes).is_err() {
        let seed = sha256(decision_id().as_bytes());
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed[i % seed.len()];
        }
    }
    hex(&bytes)
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
