//! The enterprise license: a signed token that says which enterprise features this install may use.
//! It is checked offline against the public key built into the binary: nothing here calls the network, so an
//! air-gapped install works the same as any other.
//!
//! A license never stops model traffic. The gateway is open source and keeps serving whatever the license says;
//! only the enterprise features look at it.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

/// Enterplace's license signing key, public half (Ed25519, base64url). The private half stays with Enterplace staff.
const PUBLIC_KEY: &str = "_S1S_JtovtLjEsm4Je9fzJtAWmmXRn8tjQPDFQkSp1Y";

/// Days an expired license keeps its features, so a renewal that lands late does not switch anything off.
pub const GRACE_DAYS: u64 = 30;

/// The refusal code a feature returns when the license does not unlock it.
pub const LICENSE_REQUIRED: &str = "license_required";

/// What a license says. Serialized as JSON, base64url, then signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct License {
    pub customer: String,
    pub id: String,
    /// Feature names, or `all`.
    pub features: Vec<String>,
    /// Governed people: distinct key holders.
    pub seats: u32,
    /// UTC dates, `2026-11-13`. A license works up to the day before `expires`.
    pub issued: String,
    pub expires: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Missing,
    Valid,
    /// Expired less than `GRACE_DAYS` ago: features stay on, with a warning.
    Grace,
    /// Expired longer ago: enterprise features are off, model traffic is still served.
    Lapsed,
}

#[derive(Debug)]
pub struct Status {
    pub license: Option<License>,
    pub state: State,
}

/// A feature refused for want of a license, for the caller to answer with.
#[derive(Debug)]
pub struct Refused {
    pub code: &'static str,
    pub message: String,
}

static CURRENT: OnceLock<Status> = OnceLock::new();
static MISSING: Status = Status {
    license: None,
    state: State::Missing,
};

/// The license loaded at start, or none if `start` has not run.
pub fn current() -> &'static Status {
    CURRENT.get().unwrap_or(&MISSING)
}

/// Whether the license loaded at start unlocks `feature`.
// S.4 features call this; nothing gated exists yet.
#[allow(dead_code)]
pub fn unlocked(feature: &str) -> bool {
    current().unlocked(feature)
}

/// Loads the license from the environment, says once what it unlocks, and keeps it for `current`.
/// A token that is set and fails its check stops the start: running without the features the customer paid for,
/// and without saying why, is worse than a clear refusal.
pub fn start() -> Result<&'static Status, String> {
    let status = from_env()?;
    let line = status.describe();
    // `enterplace start` prints the dashboard link first; the open source edition needs no word on a first run.
    let first_run = std::env::var_os(enterplace_server::START_ENV).is_some();
    if line.starts_with("warning:") {
        eprintln!("{line}");
    } else if !(first_run && line.starts_with("No license")) {
        println!("{line}");
    }
    Ok(CURRENT.get_or_init(|| status))
}

/// The license in ENTERPLACE_LICENSE or ENTERPLACE_LICENSE_FILE, checked with Enterplace's public key.
pub fn from_env() -> Result<Status, String> {
    let key = B64
        .decode(PUBLIC_KEY)
        .map_err(|e| format!("the built-in license key is broken ({e}). This build is faulty: use an official release."))?;
    load(|name| std::env::var(name).ok(), &key, SystemTime::now())
}

fn load(
    var: impl Fn(&str) -> Option<String>,
    public_key: &[u8],
    now: SystemTime,
) -> Result<Status, String> {
    let set = |name| var(name).filter(|v: &String| !v.trim().is_empty());
    let (token, source) = match (set("ENTERPLACE_LICENSE"), set("ENTERPLACE_LICENSE_FILE")) {
        (Some(_), Some(_)) => {
            return Err("both ENTERPLACE_LICENSE and ENTERPLACE_LICENSE_FILE are set. Keep one: unset ENTERPLACE_LICENSE or ENTERPLACE_LICENSE_FILE.".into());
        }
        (Some(token), None) => (token, "ENTERPLACE_LICENSE".to_owned()),
        (None, Some(path)) => {
            let token = std::fs::read_to_string(&path).map_err(|e| {
                format!("ENTERPLACE_LICENSE_FILE is {path}, which cannot be read: {e}. Fix the path or its permissions, or unset ENTERPLACE_LICENSE_FILE to run the open source features only.")
            })?;
            (
                token,
                format!("the file ENTERPLACE_LICENSE_FILE names ({path})"),
            )
        }
        (None, None) => {
            return Ok(Status {
                license: None,
                state: State::Missing,
            });
        }
    };
    let license = verify(token.trim(), public_key, &source)?;
    let state = state_at(&license, now);
    Ok(Status {
        license: Some(license),
        state,
    })
}

fn verify(token: &str, public_key: &[u8], source: &str) -> Result<License, String> {
    let malformed = |why: &str| {
        format!(
            "{source} is not a Enterplace license: {why}. Paste the whole token from your license, on one line, or unset ENTERPLACE_LICENSE and ENTERPLACE_LICENSE_FILE to run the open source features only."
        )
    };
    let (payload, signature) = token
        .split_once('.')
        .filter(|(_, s)| !s.contains('.'))
        .ok_or_else(|| malformed("a license is two parts joined by one dot"))?;
    let payload = B64
        .decode(payload)
        .map_err(|_| malformed("its first part is not base64url"))?;
    let signature = B64
        .decode(signature)
        .map_err(|_| malformed("its second part is not base64url"))?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&payload, &signature)
        .map_err(|_| {
            format!("{source} is not signed by Enterplace: it was changed after it was issued, or cut short. Paste the token exactly as you received it, or ask Enterplace support for a new one; unset ENTERPLACE_LICENSE and ENTERPLACE_LICENSE_FILE to run the open source features only.")
        })?;
    let license: License = serde_json::from_slice(&payload)
        .map_err(|e| malformed(&format!("its contents do not read ({e})")))?;
    if !dates_ok(&license) {
        return Err(malformed("its dates are not YYYY-MM-DD"));
    }
    Ok(license)
}

fn dates_ok(license: &License) -> bool {
    let shape = |d: &str| d.len() == 10 && enterplace_core::config::valid_expiry(d);
    shape(&license.issued) && shape(&license.expires)
}

/// UTC date of `t`, as licenses write it. Dates in this shape compare as text, so no date arithmetic is needed.
fn date(t: SystemTime) -> String {
    enterplace_core::audit::rfc3339(t)
        .chars()
        .take(10)
        .collect()
}

fn state_at(license: &License, now: SystemTime) -> State {
    let grace_start = now
        .checked_sub(Duration::from_secs(GRACE_DAYS * 86_400))
        .unwrap_or(UNIX_EPOCH);
    if date(now) < license.expires {
        State::Valid
    } else if date(grace_start) < license.expires {
        State::Grace
    } else {
        State::Lapsed
    }
}

/// Distinct people (key names) in a keys file: what a seat counts.
pub fn seats_used(keys_text: &str) -> Result<usize, String> {
    let entries = enterplace_core::config::key_entries(std::path::Path::new("keys"), keys_text)
        .map_err(|errors| errors.join("; "))?;
    let people: std::collections::BTreeSet<_> = entries.into_iter().map(|k| k.name).collect();
    Ok(people.len())
}

impl Status {
    pub fn unlocked(&self, feature: &str) -> bool {
        matches!(self.state, State::Valid | State::Grace)
            && self
                .license
                .as_ref()
                .is_some_and(|l| l.features.iter().any(|f| f == "all" || f == feature))
    }

    /// `Ok` when `feature` is unlocked, else the refusal to answer with.
    pub fn require(&self, feature: &str) -> Result<(), Refused> {
        if self.unlocked(feature) {
            return Ok(());
        }
        let message = match (&self.license, self.state) {
            (None, _) => format!(
                "{feature} is an enterprise feature and this install has no license. Set ENTERPLACE_LICENSE (or ENTERPLACE_LICENSE_FILE) to your license and restart."
            ),
            (Some(l), State::Lapsed) => format!(
                "{feature} is off: license {} for {} expired on {} and its {GRACE_DAYS}-day grace period is over. Set the renewed license in ENTERPLACE_LICENSE and restart.",
                l.id, l.customer, l.expires
            ),
            (Some(l), _) => format!(
                "license {} for {} does not include {feature}. Ask Enterplace to add it, then set the new license in ENTERPLACE_LICENSE and restart.",
                l.id, l.customer
            ),
        };
        Err(Refused {
            code: LICENSE_REQUIRED,
            message,
        })
    }

    /// The line said once at start. Warnings start with `warning:`.
    pub fn describe(&self) -> String {
        let Some(l) = &self.license else {
            return "No license: running the open source features only. Set ENTERPLACE_LICENSE to unlock the enterprise features.".into();
        };
        let features = l.features.join(", ");
        match self.state {
            State::Valid | State::Missing => format!(
                "License {} for {}: {features}, {} seats, until {}.",
                l.id, l.customer, l.seats, l.expires
            ),
            State::Grace => format!(
                "warning: license {} for {} expired on {}. Enterprise features ({features}) stay on for {GRACE_DAYS} days after that, then turn off. Set the renewed license in ENTERPLACE_LICENSE and restart.",
                l.id, l.customer, l.expires
            ),
            State::Lapsed => format!(
                "warning: license {} for {} expired on {} and its {GRACE_DAYS}-day grace period is over: enterprise features are off, model traffic is still served. Set the renewed license in ENTERPLACE_LICENSE and restart.",
                l.id, l.customer, l.expires
            ),
        }
    }

    /// A warning when more people hold keys than the license has seats. Traffic is never blocked for it.
    pub fn seats_warning(&self, used: usize) -> Option<String> {
        let l = self.license.as_ref()?;
        (used > usize::try_from(l.seats).unwrap_or(usize::MAX)).then(|| {
            format!(
                "warning: {used} people hold keys and license {} has {} seats. Traffic is not blocked; ask Enterplace for more seats, or revoke keys no longer used.",
                l.id, l.seats
            )
        })
    }
}

/// Writes a new signing key (PKCS#8, base64url) to `out`, readable by this user only, and returns the public half.
/// It never overwrites: replacing the key would orphan every license already issued.
#[cfg(any(test, feature = "issuer"))]
pub fn keygen(out: &std::path::Path) -> Result<String, String> {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::io::Write;
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| "the system random source failed. Try again.".to_owned())?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "the new key did not read back. Try again.".to_owned())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(out).map_err(|e| {
        format!("could not create {}: {e}. Choose a path that does not exist yet, in a folder you can write.", out.display())
    })?;
    file.write_all(B64.encode(pkcs8.as_ref()).as_bytes())
        .map_err(|e| format!("could not write {}: {e}. Free space or fix permissions, delete the file, and run again.", out.display()))?;
    Ok(B64.encode(pair.public_key().as_ref()))
}

/// Signs `license` with the key in the file `key_path` (as `keygen` writes it).
#[cfg(any(test, feature = "issuer"))]
pub fn issue(key_path: &std::path::Path, license: &License) -> Result<String, String> {
    let text = std::fs::read_to_string(key_path).map_err(|e| {
        format!("could not read the signing key {}: {e}. Give the path of the file `license keygen` wrote.", key_path.display())
    })?;
    let pkcs8 = B64.decode(text.trim()).map_err(|_| {
        format!(
            "{} is not a signing key written by `license keygen`. Check the path.",
            key_path.display()
        )
    })?;
    sign(license, &pkcs8)
}

#[cfg(any(test, feature = "issuer"))]
fn sign(license: &License, pkcs8: &[u8]) -> Result<String, String> {
    // A license the binary would refuse must not reach a customer.
    if !dates_ok(license) || license.features.is_empty() {
        return Err("--issued and --expires are dates like 2027-11-13, and --features names at least one feature or all.".into());
    }
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| {
        "the signing key is not an Ed25519 PKCS#8 key. Use the file `license keygen` wrote."
            .to_owned()
    })?;
    let payload = serde_json::to_vec(license).map_err(|e| e.to_string())?;
    let signature = pair.sign(&payload);
    Ok(format!(
        "{}.{}",
        B64.encode(&payload),
        B64.encode(signature.as_ref())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::HashMap;

    const DAY: Duration = Duration::from_secs(86_400);

    fn day(t: SystemTime) -> String {
        date(t)
    }

    fn pair() -> Result<(Vec<u8>, Vec<u8>), String> {
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|e| e.to_string())?;
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|e| e.to_string())?;
        Ok((pkcs8.as_ref().to_vec(), pair.public_key().as_ref().to_vec()))
    }

    fn license(features: &[&str], expires: SystemTime) -> License {
        License {
            customer: "Acme".into(),
            id: "lic_1".into(),
            features: features.iter().map(|f| (*f).to_owned()).collect(),
            seats: 2,
            issued: "2026-11-13".into(),
            expires: day(expires),
        }
    }

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| vars.get(name).cloned()
    }

    fn status(token: &str, public: &[u8], now: SystemTime) -> Result<Status, String> {
        load(env(&[("ENTERPLACE_LICENSE", token)]), public, now)
    }

    #[test]
    fn valid_license_unlocks_its_features_only() -> Result<(), String> {
        let (private, public) = pair()?;
        let now = SystemTime::now();
        let token = sign(&license(&["scim"], now + 10 * DAY), &private)?;
        let s = status(&token, &public, now)?;
        assert_eq!(s.state, State::Valid);
        assert!(s.unlocked("scim"));
        assert!(!s.unlocked("siem"));
        let refused = s.require("siem").err().ok_or("siem should be refused")?;
        assert_eq!(refused.code, LICENSE_REQUIRED);
        assert!(
            refused.message.contains("does not include siem"),
            "{}",
            refused.message
        );
        assert!(s.require("scim").is_ok());
        Ok(())
    }

    #[test]
    fn all_unlocks_every_feature() -> Result<(), String> {
        let (private, public) = pair()?;
        let now = SystemTime::now();
        let token = sign(&license(&["all"], now + DAY), &private)?;
        let s = status(&token, &public, now)?;
        assert!(s.unlocked("scim") && s.unlocked("anything"));
        Ok(())
    }

    #[test]
    fn expired_within_grace_keeps_features_and_warns() -> Result<(), String> {
        let (private, public) = pair()?;
        let now = SystemTime::now();
        let token = sign(&license(&["scim"], now - 29 * DAY), &private)?;
        let s = status(&token, &public, now)?;
        assert_eq!(s.state, State::Grace);
        assert!(s.unlocked("scim"));
        assert!(s.describe().starts_with("warning:"), "{}", s.describe());
        // The day it expires is the first day of grace.
        let token = sign(&license(&["scim"], now), &private)?;
        assert_eq!(status(&token, &public, now)?.state, State::Grace);
        Ok(())
    }

    #[test]
    fn expired_past_grace_turns_features_off() -> Result<(), String> {
        let (private, public) = pair()?;
        let now = SystemTime::now();
        let token = sign(&license(&["all"], now - 30 * DAY), &private)?;
        let s = status(&token, &public, now)?;
        assert_eq!(s.state, State::Lapsed);
        assert!(!s.unlocked("scim"));
        let refused = s.require("scim").err().ok_or("scim should be refused")?;
        assert!(
            refused.message.contains("grace period is over"),
            "{}",
            refused.message
        );
        assert!(
            s.describe().contains("model traffic is still served"),
            "{}",
            s.describe()
        );
        Ok(())
    }

    #[test]
    fn tampered_payload_is_refused() -> Result<(), String> {
        let (private, public) = pair()?;
        let now = SystemTime::now();
        let token = sign(&license(&["scim"], now + DAY), &private)?;
        let (_, signature) = token.split_once('.').ok_or("no dot")?;
        let mut forged = license(&["all"], now + DAY);
        forged.seats = 1000;
        let forged = format!(
            "{}.{signature}",
            B64.encode(serde_json::to_vec(&forged).map_err(|e| e.to_string())?)
        );
        let err = status(&forged, &public, now)
            .err()
            .ok_or("forged accepted")?;
        assert!(err.contains("not signed by Enterplace"), "{err}");
        Ok(())
    }

    #[test]
    fn license_signed_with_another_key_is_refused() -> Result<(), String> {
        let (other, _) = pair()?;
        let (_, public) = pair()?;
        let now = SystemTime::now();
        let token = sign(&license(&["scim"], now + DAY), &other)?;
        let err = status(&token, &public, now).err().ok_or("accepted")?;
        assert!(err.contains("not signed by Enterplace"), "{err}");
        Ok(())
    }

    #[test]
    fn malformed_tokens_are_refused_with_the_fix() -> Result<(), String> {
        let (_, public) = pair()?;
        for token in ["hello", "a.b.c", "!!!.???", "e30.AAAA"] {
            let err = status(token, &public, SystemTime::now())
                .err()
                .ok_or(format!("{token} accepted"))?;
            assert!(err.contains("ENTERPLACE_LICENSE"), "{err}");
            assert!(err.contains("unset ENTERPLACE_LICENSE"), "{err}");
        }
        Ok(())
    }

    #[test]
    fn missing_license_runs_open_source_only() -> Result<(), String> {
        let (_, public) = pair()?;
        for vars in [&[][..], &[("ENTERPLACE_LICENSE", "  ")][..]] {
            let s = load(env(vars), &public, SystemTime::now())?;
            assert_eq!(s.state, State::Missing);
            assert!(!s.unlocked("scim"));
            let refused = s.require("scim").err().ok_or("scim should be refused")?;
            assert!(
                refused.message.contains("ENTERPLACE_LICENSE"),
                "{}",
                refused.message
            );
            assert!(s.describe().contains("open source features only"));
        }
        // Before start() runs, nothing is unlocked.
        assert!(!unlocked("scim"));
        Ok(())
    }

    #[test]
    fn license_file_is_read_and_both_sources_conflict() -> Result<(), String> {
        let (private, public) = pair()?;
        let now = SystemTime::now();
        let token = sign(&license(&["scim"], now + DAY), &private)?;
        let path = std::env::temp_dir().join(format!("enterplace-license-{}", std::process::id()));
        std::fs::write(&path, format!("{token}\n")).map_err(|e| e.to_string())?;
        let file = path.to_string_lossy().into_owned();
        let s = load(env(&[("ENTERPLACE_LICENSE_FILE", &file)]), &public, now)?;
        assert_eq!(s.state, State::Valid);
        let both = load(
            env(&[
                ("ENTERPLACE_LICENSE_FILE", &file),
                ("ENTERPLACE_LICENSE", &token),
            ]),
            &public,
            now,
        );
        assert!(both.is_err_and(|e| e.contains("both")));
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        let gone = load(env(&[("ENTERPLACE_LICENSE_FILE", &file)]), &public, now);
        assert!(gone.is_err_and(|e| e.contains("cannot be read")));
        Ok(())
    }

    #[test]
    fn seats_count_distinct_people_and_warn_over_the_limit() -> Result<(), String> {
        let (private, public) = pair()?;
        let now = SystemTime::now();
        let token = sign(&license(&["all"], now + DAY), &private)?;
        let s = status(&token, &public, now)?;
        let keys = "keys:\n\
            - { name: ana, team: a, sha256: '1111111111111111111111111111111111111111111111111111111111111111' }\n\
            - { name: ana, team: b, sha256: '2222222222222222222222222222222222222222222222222222222222222222' }\n\
            - { name: bo, team: a, sha256: '3333333333333333333333333333333333333333333333333333333333333333' }\n";
        assert_eq!(seats_used(keys)?, 2);
        assert!(s.seats_warning(2).is_none());
        let warning = s.seats_warning(3).ok_or("no warning at 3 of 2")?;
        assert!(
            warning.contains("3 people") && warning.contains("2 seats"),
            "{warning}"
        );
        Ok(())
    }

    #[test]
    fn issuer_round_trip() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("enterplace-keygen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let key = dir.join("signing-key");
        let public = keygen(&key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key)
                .map_err(|e| e.to_string())?
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(keygen(&key).is_err(), "keygen overwrote a key");
        let now = SystemTime::now();
        let issued = license(&["scim", "siem"], now + DAY);
        let token = issue(&key, &issued)?;
        assert!(!token.contains(char::is_whitespace));
        let public = B64.decode(public).map_err(|e| e.to_string())?;
        let s = status(&token, &public, now)?;
        assert_eq!(s.license, Some(issued));
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn embedded_public_key_is_a_key() -> Result<(), String> {
        assert_eq!(B64.decode(PUBLIC_KEY).map_err(|e| e.to_string())?.len(), 32);
        Ok(())
    }
}
