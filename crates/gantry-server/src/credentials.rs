//! Provider credentials kept in the store, sealed with AES-256-GCM under a master key the customer holds.
//!
//! The master key is read from GANTRY_MASTER_KEY or the file GANTRY_MASTER_KEY_FILE names, never from the policy and
//! never from the database: whoever reads the database alone reads only sealed bytes. Each value is sealed with its
//! credential's name as associated data, so a sealed value moved to another row does not open.

use std::path::Path;

use gantry_core::config::Loaded;
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};

pub const MASTER_ENV: &str = "GANTRY_MASTER_KEY";
pub const MASTER_FILE_ENV: &str = "GANTRY_MASTER_KEY_FILE";

/// What the console, the admin API and a start say when credentials are off because no master key is set.
pub const NO_MASTER: &str = "provider credentials are off on this gateway: GANTRY_MASTER_KEY is not set. Set it (or GANTRY_MASTER_KEY_FILE, a file that holds it) to 64 hex characters, made once with `openssl rand -hex 32`, the same on every gateway on this database, keep it in your secret manager, and restart. Until then keep provider keys in environment variables with key_env.";

/// The key every credential is sealed with. It cannot be printed.
pub struct MasterKey(LessSafeKey);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[master key]")
    }
}

impl MasterKey {
    /// The master key from GANTRY_MASTER_KEY or GANTRY_MASTER_KEY_FILE, as `env` reads them. `None` when neither
    /// is set.
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let set = |name: &str| env(name).filter(|v| !v.trim().is_empty());
        match (set(MASTER_ENV), set(MASTER_FILE_ENV)) {
            (Some(_), Some(_)) => Err(format!(
                "both {MASTER_ENV} and {MASTER_FILE_ENV} are set. Set one of them, and start again."
            )),
            (Some(text), None) => Self::from_hex(&text, MASTER_ENV).map(Some),
            (None, Some(path)) => {
                let text = std::fs::read_to_string(path.trim()).map_err(|err| {
                    format!(
                        "{MASTER_FILE_ENV} names {}, which cannot be read: {err}. Put the master key there, or fix the path, and start again.",
                        path.trim()
                    )
                })?;
                Self::from_hex(&text, MASTER_FILE_ENV).map(Some)
            }
            (None, None) => Ok(None),
        }
    }

    fn from_hex(text: &str, source: &str) -> Result<Self, String> {
        let text = text.trim();
        let bytes: Option<Vec<u8>> = (text.len() == 64 && text.is_ascii())
            .then(|| {
                (0..32)
                    .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
                    .collect()
            })
            .flatten();
        let wrong = || {
            format!(
                "{source} must be 64 hex characters (32 bytes), made once with `openssl rand -hex 32`. Set it to that, the same on every gateway on this database, and start again."
            )
        };
        let bytes = bytes.ok_or_else(wrong)?;
        let key = UnboundKey::new(&AES_256_GCM, &bytes).map_err(|_| wrong())?;
        Ok(Self(LessSafeKey::new(key)))
    }

    /// A random nonce, then the value sealed with `name` as associated data, then its tag.
    pub(crate) fn seal(&self, name: &str, value: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).map_err(|_| {
            "the system gave no randomness to seal the credential. Nothing was stored. Try again.".to_string()
        })?;
        let mut sealed = value.to_vec();
        self.0
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(name.as_bytes()),
                &mut sealed,
            )
            .map_err(|_| "the credential could not be sealed. Nothing was stored.".to_string())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// The value `seal` sealed for `name`, or an error if this key did not seal it or it was changed.
    pub(crate) fn open(&self, name: &str, sealed: &[u8]) -> Result<Vec<u8>, String> {
        let failed = || {
            format!(
                "credential \"{name}\" does not open with this gateway's {MASTER_ENV}: it was sealed with another master key, or changed in the database. Set the master key the other gateways use, or add the credential again."
            )
        };
        let (nonce, sealed) = sealed.split_at_checked(NONCE_LEN).ok_or_else(failed)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| failed())?;
        let mut buffer = sealed.to_vec();
        let opened = self
            .0
            .open_in_place(nonce, Aad::from(name.as_bytes()), &mut buffer)
            .map_err(|_| failed())?;
        Ok(opened.to_vec())
    }
}

/// Provider credentials sealed under the master key in `gantry-credentials.json` beside the policy, for a gateway
/// with no store: `gantry start` on a laptop takes a provider key in the console and keeps only sealed bytes.
pub(crate) struct FileVault {
    path: std::path::PathBuf,
    master: MasterKey,
    // One writer at a time in this process; the console is the only writer.
    lock: std::sync::Mutex<()>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Entry {
    name: String,
    provider: String,
    /// Hex of the nonce, the sealed value and its tag.
    sealed: String,
    fingerprint: String,
    created_by: String,
    created_at: String,
    #[serde(default)]
    rotated_by: Option<String>,
    #[serde(default)]
    rotated_at: Option<String>,
    #[serde(default)]
    generation: i64,
}

impl Entry {
    fn public(&self) -> gantry_core::store::Credential {
        gantry_core::store::Credential {
            name: self.name.clone(),
            provider: self.provider.clone(),
            fingerprint: self.fingerprint.clone(),
            created_by: self.created_by.clone(),
            created_at: self.created_at.clone(),
            rotated_by: self.rotated_by.clone(),
            rotated_at: self.rotated_at.clone(),
            generation: self.generation,
        }
    }
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    (text.len() % 2 == 0)
        .then(|| {
            (0..text.len() / 2)
                .map(|i| u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok())
                .collect()
        })
        .flatten()
}

impl FileVault {
    pub(crate) fn new(policy: &Path, master: MasterKey) -> Self {
        Self {
            path: gantry_core::store::credentials_file(policy),
            master,
            lock: std::sync::Mutex::new(()),
        }
    }

    fn read(&self) -> Result<Vec<Entry>, String> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|err| {
                format!(
                    "{} is not a credentials file Gantry wrote ({err}). Move it away and add the credentials again in the console.",
                    self.path.display()
                )
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(format!(
                "{} cannot be read: {err}. Give Gantry read access to it.",
                self.path.display()
            )),
        }
    }

    fn write(&self, entries: &[Entry]) -> Result<(), String> {
        let text = serde_json::to_string_pretty(entries).map_err(|err| err.to_string())?;
        let temp = self.path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(&temp)
            .and_then(|mut file| std::io::Write::write_all(&mut file, text.as_bytes()))
            .and_then(|()| std::fs::rename(&temp, &self.path))
            .map_err(|err| {
                format!(
                    "{} cannot be written ({err}). Give Gantry write access to the policy's folder. Nothing was changed.",
                    self.path.display()
                )
            })
    }

    fn change(
        &self,
        edit: impl FnOnce(&mut Vec<Entry>) -> Result<Option<Entry>, String>,
    ) -> Result<Option<gantry_core::store::Credential>, String> {
        let _held = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut entries = self.read()?;
        let changed = edit(&mut entries)?;
        if changed.is_some() {
            self.write(&entries)?;
        }
        Ok(changed.map(|e| e.public()))
    }
}

impl gantry_core::store::Credentials for FileVault {
    fn credentials(&self) -> Result<std::sync::Arc<Vec<gantry_core::store::Credential>>, String> {
        Ok(std::sync::Arc::new(
            self.read()?.iter().map(Entry::public).collect(),
        ))
    }

    fn add_credential(
        &self,
        name: &str,
        provider: &str,
        value: &str,
        by: &str,
    ) -> Result<Option<gantry_core::store::Credential>, String> {
        let sealed = gantry_core::id::hex(&self.master.seal(name, value.trim().as_bytes())?);
        self.change(|entries| {
            if entries.iter().any(|e| e.name == name) {
                return Ok(None);
            }
            let entry = Entry {
                name: name.into(),
                provider: provider.into(),
                sealed,
                fingerprint: gantry_core::store::fingerprint(value.trim()),
                created_by: by.into(),
                created_at: gantry_core::audit::timestamp(),
                rotated_by: None,
                rotated_at: None,
                generation: 1,
            };
            entries.push(entry.clone());
            Ok(Some(entry))
        })
    }

    fn rotate_credential(
        &self,
        name: &str,
        value: &str,
        by: &str,
    ) -> Result<Option<gantry_core::store::Credential>, String> {
        let sealed = gantry_core::id::hex(&self.master.seal(name, value.trim().as_bytes())?);
        self.change(|entries| {
            let Some(entry) = entries.iter_mut().find(|e| e.name == name) else {
                return Ok(None);
            };
            entry.sealed = sealed;
            entry.fingerprint = gantry_core::store::fingerprint(value.trim());
            entry.rotated_by = Some(by.into());
            entry.rotated_at = Some(gantry_core::audit::timestamp());
            entry.generation += 1;
            Ok(Some(entry.clone()))
        })
    }

    fn remove_credential(
        &self,
        name: &str,
    ) -> Result<Option<gantry_core::store::Credential>, String> {
        self.change(|entries| {
            let at = entries.iter().position(|e| e.name == name);
            Ok(at.map(|i| entries.remove(i)))
        })
    }

    fn credential_value(&self, name: &str) -> Result<Option<String>, String> {
        let entries = self.read()?;
        let Some(entry) = entries.iter().find(|e| e.name == name) else {
            return Ok(None);
        };
        let sealed = unhex(&entry.sealed).ok_or_else(|| {
            format!(
                "credential \"{name}\" in {} is damaged. Add it again in the console.",
                self.path.display()
            )
        })?;
        let value = self.master.open(name, &sealed)?;
        String::from_utf8(value).map(Some).map_err(|_| {
            format!("credential \"{name}\" is not text. Rotate it with the key's value.")
        })
    }
}

/// The providers of `loaded` that name a credential the store does not hold, one problem each, with the fix. The
/// store is opened as `gantry serve` opens it, from the variables `env` reads. `Err` when the names could not be
/// checked: no store to reach, or no master key to read it with.
pub fn credential_problems(
    policy_path: &Path,
    loaded: &Loaded,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<String>, String> {
    if loaded.providers.iter().all(|p| p.credential.is_none()) {
        return Ok(Vec::new());
    }
    let store = crate::open_store(policy_path, &loaded.keys_path, env)?
        .ok_or("the policy names credentials and has no store: section")?;
    let held = store.credentials()?;
    Ok(loaded
        .providers
        .iter()
        .filter_map(|p| p.credential.as_deref().map(|c| (p.name.as_str(), c)))
        .filter(|(_, name)| !held.iter().any(|c| c.name == *name))
        .map(|(provider, name)| unknown(policy_path, &loaded.policy_text, provider, name, &held))
        .collect())
}

/// The problem of a provider whose credential the store does not hold.
pub(crate) fn unknown(
    policy_path: &Path,
    text: &str,
    provider: &str,
    name: &str,
    held: &[gantry_core::store::Credential],
) -> String {
    let line = text
        .lines()
        .position(|l| {
            l.trim_start().starts_with("credential:")
                && l.split_once(':')
                    .is_some_and(|(_, v)| v.trim().trim_matches(['"', '\'']) == name)
        })
        .map_or(0, |i| i + 1);
    let names: Vec<&str> = held.iter().map(|c| c.name.as_str()).collect();
    let stored = if names.is_empty() {
        "The store holds no credentials yet.".to_string()
    } else {
        format!("The store holds: {}.", names.join(", "))
    };
    format!(
        "{}:{line}: provider \"{provider}\" takes its key from credential \"{name}\", which is not in the store. Add it in the console (Provider credentials) or with POST /admin/credentials, or name one the store holds. {stored}",
        policy_path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_value_opens_only_with_its_key_and_its_name() -> Result<(), String> {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let key = MasterKey::from_env(&|v| (v == MASTER_ENV).then(|| hex.to_string()))?
            .ok_or("no key")?;
        let sealed = key.seal("openai-prod", b"sk-secret-value")?;
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(key.open("openai-prod", &sealed)?, b"sk-secret-value");
        assert!(key.open("other-name", &sealed).is_err());
        let other = MasterKey::from_hex(&hex.replace('0', "1"), MASTER_ENV)?;
        assert!(other.open("openai-prod", &sealed).is_err());
        // Two seals of one value differ: each has its own nonce.
        assert_ne!(sealed, key.seal("openai-prod", b"sk-secret-value")?);
        let short = MasterKey::from_hex("abcd", MASTER_ENV)
            .err()
            .unwrap_or_default();
        assert!(short.contains("openssl rand -hex 32"), "{short}");
        let both = MasterKey::from_env(&|_| Some(hex.to_string()))
            .err()
            .unwrap_or_default();
        assert!(both.contains("Set one of them"), "{both}");
        assert!(MasterKey::from_env(&|_| None)?.is_none());
        Ok(())
    }

    #[test]
    fn the_file_vault_keeps_only_sealed_values_and_rotates_and_removes() -> Result<(), String> {
        use gantry_core::store::Credentials;
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let dir = std::env::temp_dir().join(format!("gantry-vault-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let policy = dir.join("gantry.policy.yaml");
        let vault = FileVault::new(&policy, MasterKey::from_hex(hex, MASTER_ENV)?);
        assert!(
            vault
                .add_credential("openai", "openai", " sk-vault-secret ", "admin")?
                .is_some()
        );
        assert!(
            vault
                .add_credential("openai", "openai", "sk-other", "admin")?
                .is_none()
        );
        let text = std::fs::read_to_string(dir.join("gantry-credentials.json"))
            .map_err(|e| e.to_string())?;
        assert!(!text.contains("sk-vault-secret"), "{text}");
        assert_eq!(
            vault.credential_value("openai")?.as_deref(),
            Some("sk-vault-secret")
        );
        let rotated = vault
            .rotate_credential("openai", "sk-new", "admin")?
            .ok_or("not rotated")?;
        assert_eq!(rotated.generation, 2);
        assert_eq!(vault.credential_value("openai")?.as_deref(), Some("sk-new"));
        // Another master key reads the names but opens no value.
        let other = FileVault::new(
            &policy,
            MasterKey::from_hex(&hex.replace('0', "1"), MASTER_ENV)?,
        );
        assert_eq!(other.credentials()?.len(), 1);
        assert!(other.credential_value("openai").is_err());
        assert!(vault.remove_credential("openai")?.is_some());
        assert!(vault.credential_value("openai")?.is_none());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
