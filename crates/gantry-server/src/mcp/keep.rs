//! What the MCP gateway keeps beyond one request: OAuth clients, codes and tokens, each person's credentials to
//! upstream servers (sealed), tool pins and the calls waiting for an admin's approval.
//!
//! With a `store:` in the policy it is a table in that Postgres, shared by every gateway on it. Without one it is a
//! JSON file beside the policy, read at start and written whole on each change. Tests run it in memory.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

use crate::{credentials::MasterKey, store::PgStore};

/// The MCP gateway's tables, applied once per database under their own namespace.
const MIGRATIONS: &[&str] = &["
CREATE TABLE gantry_mcp (
    kind text NOT NULL,
    id text NOT NULL,
    value text NOT NULL,
    exp bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, id)
);
"];

/// Seconds since 1970, as kept values count their expiry.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What seals each person's credentials: the store's master key, or the gateway's own from GANTRY_MASTER_KEY.
pub enum Sealer {
    None,
    Own(Arc<MasterKey>),
    Store(Arc<PgStore>),
}

enum Backend {
    Memory,
    File(PathBuf),
    Postgres(
        Arc<PgStore>,
        tokio::sync::Mutex<Option<tokio_postgres::Client>>,
    ),
}

type Map = BTreeMap<String, BTreeMap<String, Value>>;

pub(crate) struct Keep {
    backend: Backend,
    /// Everything, for the memory and file backends. Unused with Postgres.
    memory: Mutex<Map>,
    sealer: Sealer,
}

/// Where the MCP gateway keeps its state, as the server is configured.
#[derive(Clone, Default)]
pub struct McpSetup {
    /// The shared store, when the policy has `store:`.
    pub postgres: Option<Arc<PgStore>>,
    /// The file used without a store. `None` keeps everything in memory, for tests and embedders.
    pub file: Option<PathBuf>,
    /// Seals each person's credentials without a store. With one, the store's master key does.
    pub master: Option<Arc<MasterKey>>,
    /// Whether the policy lets people sign in with single sign-on for a personal key (`console.sso.self_issue`),
    /// which MCP clients' OAuth sign-in then offers.
    pub sso: bool,
    /// The audit log, which the console's MCP tools page reads to say who used each tool.
    pub audit_path: Option<PathBuf>,
}

impl std::fmt::Debug for McpSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpSetup")
            .field("postgres", &self.postgres.is_some())
            .field("file", &self.file)
            .field("master", &self.master.is_some())
            .field("sso", &self.sso)
            .finish_non_exhaustive()
    }
}

fn expired(value: &Value, at: u64) -> bool {
    value["exp"]
        .as_u64()
        .is_some_and(|exp| exp > 0 && exp <= at)
}

impl Keep {
    pub(crate) fn start(setup: McpSetup) -> Result<Self, String> {
        let (backend, sealer, memory) = match (setup.postgres, setup.file) {
            (Some(pg), _) => {
                pg.migrate("mcp", MIGRATIONS)?;
                (
                    Backend::Postgres(pg.clone(), tokio::sync::Mutex::new(None)),
                    Sealer::Store(pg),
                    Map::new(),
                )
            }
            (None, Some(file)) => {
                let memory = match std::fs::read_to_string(&file) {
                    Ok(text) => serde_json::from_str(&text).map_err(|err| {
                        format!(
                            "{} cannot be read as the MCP gateway's state: {err}. Move it aside to start with none (people sign in to MCP servers again, and tools are pinned again), and start again.",
                            file.display()
                        )
                    })?,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Map::new(),
                    Err(err) => {
                        return Err(format!(
                            "{} cannot be read: {err}. Give Gantry read and write access to it, and start again.",
                            file.display()
                        ));
                    }
                };
                let sealer = setup.master.map_or(Sealer::None, Sealer::Own);
                (Backend::File(file), sealer, memory)
            }
            (None, None) => (
                Backend::Memory,
                setup.master.map_or(Sealer::None, Sealer::Own),
                Map::new(),
            ),
        };
        Ok(Self {
            backend,
            memory: Mutex::new(memory),
            sealer,
        })
    }

    fn map(&self) -> std::sync::MutexGuard<'_, Map> {
        self.memory
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Writes the file after a change, without what has expired. Called with the map held.
    fn save(&self, map: &mut Map) -> Result<(), String> {
        let Backend::File(file) = &self.backend else {
            return Ok(());
        };
        let at = now();
        for values in map.values_mut() {
            values.retain(|_, v| !expired(v, at));
        }
        let text = serde_json::to_string(&*map).map_err(|err| err.to_string())?;
        let partial = file.with_extension("json.partial");
        std::fs::write(&partial, text)
            .and_then(|()| std::fs::rename(&partial, file))
            .map_err(|err| {
                format!(
                    "{} cannot be written: {err}. Give Gantry write access to it.",
                    file.display()
                )
            })
    }

    async fn client<'a>(
        pg: &PgStore,
        slot: &'a tokio::sync::Mutex<Option<tokio_postgres::Client>>,
    ) -> Result<tokio::sync::MutexGuard<'a, Option<tokio_postgres::Client>>, String> {
        let mut held = slot.lock().await;
        if held.as_ref().is_none_or(tokio_postgres::Client::is_closed) {
            *held = Some(pg.connect().await?);
        }
        Ok(held)
    }

    /// One statement on the store's database, returning its rows as (id, value, exp).
    async fn query(
        &self,
        sql: &str,
        kind: &str,
        id: Option<&str>,
        value: Option<(&str, i64)>,
    ) -> Result<Vec<(String, String, i64)>, String> {
        let Backend::Postgres(pg, slot) = &self.backend else {
            return Ok(Vec::new());
        };
        let held = Self::client(pg, slot).await?;
        let client = held.as_ref().ok_or("the store gave no connection")?;
        let id = id.unwrap_or_default();
        let rows = match value {
            Some((text, exp)) => {
                let params: [&(dyn tokio_postgres::types::ToSql + Sync); 4] =
                    [&kind, &id, &text, &exp];
                client.query(sql, &params).await
            }
            None if sql.contains("$2") => client.query(sql, &[&kind, &id]).await,
            None => client.query(sql, &[&kind]).await,
        }
        .map_err(|err| format!("the store could not be read or written: {err}"))?;
        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get(0).map_err(|e| e.to_string())?,
                    row.try_get(1).map_err(|e| e.to_string())?,
                    row.try_get(2).map_err(|e| e.to_string())?,
                ))
            })
            .collect()
    }

    fn parse(rows: Vec<(String, String, i64)>) -> Vec<(String, Value)> {
        let at = now();
        rows.into_iter()
            .filter_map(|(id, text, _)| serde_json::from_str(&text).ok().map(|v| (id, v)))
            .filter(|(_, v)| !expired(v, at))
            .collect()
    }

    pub(crate) async fn get(&self, kind: &str, id: &str) -> Result<Option<Value>, String> {
        if matches!(self.backend, Backend::Postgres(..)) {
            let rows = self
                .query(
                    "SELECT id, value, exp FROM gantry_mcp WHERE kind = $1 AND id = $2",
                    kind,
                    Some(id),
                    None,
                )
                .await?;
            return Ok(Self::parse(rows).pop().map(|(_, v)| v));
        }
        Ok(self
            .map()
            .get(kind)
            .and_then(|values| values.get(id))
            .filter(|v| !expired(v, now()))
            .cloned())
    }

    /// Keeps `value` under (`kind`, `id`). A value with `exp` (seconds since 1970) is gone after it.
    pub(crate) async fn put(&self, kind: &str, id: &str, value: Value) -> Result<(), String> {
        if matches!(self.backend, Backend::Postgres(..)) {
            let exp = value["exp"]
                .as_u64()
                .and_then(|e| i64::try_from(e).ok())
                .unwrap_or(0);
            if exp > 0 {
                // What expired is cleared as new short-lived values arrive, so the table holds only what is live.
                let at = i64::try_from(now()).unwrap_or(i64::MAX);
                self.query(
                    "DELETE FROM gantry_mcp WHERE kind = $1 AND exp > 0 AND exp < $2::text::bigint RETURNING id, value, exp",
                    kind,
                    Some(&at.to_string()),
                    None,
                )
                .await?;
            }
            self.query(
                "INSERT INTO gantry_mcp (kind, id, value, exp) VALUES ($1, $2, $3, $4) ON CONFLICT (kind, id) DO UPDATE SET value = excluded.value, exp = excluded.exp RETURNING id, value, exp",
                kind,
                Some(id),
                Some((&value.to_string(), exp)),
            )
            .await?;
            return Ok(());
        }
        let mut map = self.map();
        map.entry(kind.to_string())
            .or_default()
            .insert(id.to_string(), value);
        self.save(&mut map)
    }

    /// Removes and returns the value, so a one-use value (a code, a state) is used once even with two gateways.
    pub(crate) async fn take(&self, kind: &str, id: &str) -> Result<Option<Value>, String> {
        if matches!(self.backend, Backend::Postgres(..)) {
            let rows = self
                .query(
                    "DELETE FROM gantry_mcp WHERE kind = $1 AND id = $2 RETURNING id, value, exp",
                    kind,
                    Some(id),
                    None,
                )
                .await?;
            return Ok(Self::parse(rows).pop().map(|(_, v)| v));
        }
        let mut map = self.map();
        let taken = map.get_mut(kind).and_then(|values| values.remove(id));
        if taken.is_some() {
            self.save(&mut map)?;
        }
        Ok(taken.filter(|v| !expired(v, now())))
    }

    pub(crate) async fn list(&self, kind: &str) -> Result<Vec<(String, Value)>, String> {
        if matches!(self.backend, Backend::Postgres(..)) {
            let rows = self
                .query(
                    "SELECT id, value, exp FROM gantry_mcp WHERE kind = $1 ORDER BY id",
                    kind,
                    None,
                    None,
                )
                .await?;
            return Ok(Self::parse(rows));
        }
        let at = now();
        Ok(self
            .map()
            .get(kind)
            .map(|values| {
                values
                    .iter()
                    .filter(|(_, v)| !expired(v, at))
                    .map(|(id, v)| (id.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub(crate) fn can_seal(&self) -> bool {
        match &self.sealer {
            Sealer::None => false,
            Sealer::Own(_) => true,
            Sealer::Store(pg) => pg.master().is_ok(),
        }
    }

    /// `value` sealed under `name`, as hex. A sealed value moved to another name does not open.
    pub(crate) fn seal(&self, name: &str, value: &[u8]) -> Result<String, String> {
        let sealed = match &self.sealer {
            Sealer::None => return Err(NO_SEALER.to_string()),
            Sealer::Own(key) => key.seal(name, value)?,
            Sealer::Store(pg) => pg.master()?.seal(name, value)?,
        };
        Ok(sealed.iter().map(|b| format!("{b:02x}")).collect())
    }

    pub(crate) fn open(&self, name: &str, hex: &str) -> Result<Vec<u8>, String> {
        let bytes: Option<Vec<u8>> = (hex.len() % 2 == 0 && hex.is_ascii())
            .then(|| {
                (0..hex.len() / 2)
                    .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                    .collect()
            })
            .flatten();
        let bytes = bytes.ok_or_else(|| format!("credential \"{name}\" is not sealed bytes"))?;
        match &self.sealer {
            Sealer::None => Err(NO_SEALER.to_string()),
            Sealer::Own(key) => key.open(name, &bytes),
            Sealer::Store(pg) => pg.master()?.open(name, &bytes),
        }
    }
}

pub(crate) const NO_SEALER: &str = "each person's MCP credentials are sealed with a master key, and this gateway has none. Set GANTRY_MASTER_KEY (or GANTRY_MASTER_KEY_FILE) to 64 hex characters, made once with `openssl rand -hex 32`, and restart.";

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_file_keeps_values_across_opens_and_forgets_what_expired() -> Result<(), String> {
        let file = std::env::temp_dir().join(format!("gantry-keep-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let setup = || McpSetup {
            file: Some(file.clone()),
            ..McpSetup::default()
        };
        let keep = Keep::start(setup())?;
        keep.put("pin", "a/b", serde_json::json!({"sha256": "x"}))
            .await?;
        keep.put("code", "c1", serde_json::json!({"exp": 1}))
            .await?;
        keep.put("code", "c2", serde_json::json!({"exp": now() + 60}))
            .await?;
        let again = Keep::start(setup())?;
        assert_eq!(
            again.get("pin", "a/b").await?,
            Some(serde_json::json!({"sha256": "x"}))
        );
        assert_eq!(again.get("code", "c1").await?, None);
        assert!(again.take("code", "c2").await?.is_some());
        assert!(again.take("code", "c2").await?.is_none());
        assert!(!again.can_seal());
        assert!(again.seal("n", b"v").is_err());
        let _ = std::fs::remove_file(&file);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_store_keeps_values_for_every_gateway_and_seals_with_its_master_key()
    -> Result<(), String> {
        let Ok(url) = std::env::var("GANTRY_TEST_DATABASE_URL") else {
            eprintln!("skipped: set GANTRY_TEST_DATABASE_URL to run the MCP keep against Postgres");
            return Ok(());
        };
        // CI's Postgres offers no TLS, and the store refuses that unless the string says so, as the store tests do.
        let url = if url.contains("sslmode") {
            url
        } else if url.contains('?') {
            format!("{url}&sslmode=disable")
        } else if url.contains("://") {
            format!("{url}?sslmode=disable")
        } else {
            format!("{url} sslmode=disable")
        };
        let pg = crate::store::open("GANTRY_TEST_DATABASE_URL", &url)?;
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        if let Some(master) = MasterKey::from_env(&|v| {
            (v == crate::credentials::MASTER_ENV).then(|| hex.to_string())
        })? {
            pg.unlock(master)?;
        }
        let setup = || McpSetup {
            postgres: Some(pg.clone()),
            ..McpSetup::default()
        };
        let one = Keep::start(setup())?;
        let two = Keep::start(setup())?;
        let id = id_for_test();
        one.put("code", &id, serde_json::json!({"exp": now() + 60, "v": 1}))
            .await?;
        assert_eq!(
            two.get("code", &id).await?.map(|v| v["v"].clone()),
            Some(1.into())
        );
        assert!(two.list("code").await?.iter().any(|(i, _)| *i == id));
        // One use, whichever gateway asks first.
        assert!(two.take("code", &id).await?.is_some());
        assert!(one.take("code", &id).await?.is_none());
        one.put("code", &format!("{id}-old"), serde_json::json!({"exp": 1}))
            .await?;
        assert!(two.get("code", &format!("{id}-old")).await?.is_none());
        assert!(one.can_seal());
        let sealed = one.seal("mcp-credential:s:p", b"secret")?;
        assert_eq!(two.open("mcp-credential:s:p", &sealed)?, b"secret");
        assert!(two.open("mcp-credential:s:q", &sealed).is_err());
        Ok(())
    }

    fn id_for_test() -> String {
        format!("t{}-{}", std::process::id(), now())
    }
}
