//! The enterprise features, added to the open source gateway through its extension points
//! (`gantry_server::serve_policy_with`): routes, console pages, tables in the store's Postgres and /healthz fields.
//! A feature is added only when the license unlocks it; without one the gateway and console are the open source ones.
//!
//! How a feature registers is written up in docs/porting.md.

mod alerts;
mod capture;
pub(crate) mod devices;
mod members;
mod scim;
mod segments;
mod siem;
pub(crate) mod watch;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use gantry_server::{
    Extension, Host,
    store::{PgStore, tokio_postgres::Client},
};
use serde_json::json;

use crate::license::{self, State, Status};

/// Each feature's tables, one migration per entry, applied in order under the feature's own namespace (its own
/// version row in `gantry_migrations`), and only when the license unlocks the feature. Never edit an entry that has
/// shipped: add one.
const MEMBERS: &[&str] = &[members::MIGRATION];
/// Alters members' table, so it runs after `MEMBERS`, and only with members on.
const SCIM: &[&str] = &[scim::MIGRATION];
/// For siem and retention, which share their tables, and for alerting, which reads the audit table they keep.
/// Entry 2 is the captured text of audit export (`capture`).
const SIEM: &[&str] = &[siem::MIGRATION, capture::MIGRATION];
/// Enrolment tokens, device profiles, and what the device agents report.
const DEVICES: &[&str] = &[
    devices::MIGRATION,
    devices::MIGRATION_2,
    devices::MIGRATION_3,
];
/// Watch tokens, what tells a repeated export apart, and the daily sums of what Claude Code reported.
const WATCH: &[&str] = &[watch::MIGRATION];
/// Alert channels, rules and what fired. Runs after `SIEM`: alerting reads the records it ingests.
const ALERTS: &[&str] = &[alerts::MIGRATION, alerts::DAILY];

/// Before each feature had its namespace, every enterprise table was one list under `enterprise`: members, scim,
/// siem. On a database a binary of then wrote, this records the per-feature version that list's version implies, so
/// none of that DDL runs again. It runs once, as the namespace `enterprise.split`, before any feature's migrations;
/// on a new database it records nothing. The old row stays, so an older replica in a rolling upgrade still starts.
const SPLIT: &[&str] = &["
INSERT INTO gantry_migrations (namespace, version)
SELECT feature, 1
FROM gantry_migrations, (VALUES ('enterprise.members', 1), ('enterprise.scim', 2), ('enterprise.siem', 3)) AS old (feature, entry)
WHERE namespace = 'enterprise' AND version >= entry
ON CONFLICT (namespace) DO NOTHING;
"];

/// What the enterprise binary adds to the gateway it serves, for `status` (the license loaded at start).
pub fn extend(status: &Status, host: Host<'_>) -> Result<Extension, String> {
    extend_with(
        status,
        host,
        Arc::new(|variable| std::env::var(variable).ok()),
    )
}

/// `extend`, reading the environment through `env` (tests give theirs).
pub fn extend_with(
    status: &Status,
    host: Host<'_>,
    env: siem::sinks::Env,
) -> Result<Extension, String> {
    let mut extension = Extension {
        health: Some(health(status)),
        ..Extension::default()
    };
    let members_on = status.unlocked(members::FEATURE);
    let scim_on = members_on && status.unlocked(scim::FEATURE);
    let (siem_on, retention_on) = (
        status.unlocked(siem::SIEM),
        status.unlocked(siem::RETENTION),
    );
    if !members_on {
        members::locked(&mut extension, status);
    }
    // SCIM provisions the people that members keeps, so it needs both.
    if !scim_on {
        scim::locked(&mut extension, status);
    }
    let alerts_on = status.unlocked(alerts::FEATURE);
    if !siem_on && !retention_on {
        siem::locked(&mut extension, status);
    }
    if !alerts_on {
        alerts::locked(&mut extension, status);
    }
    let devices_on = status.unlocked(devices::FEATURE);
    if !devices_on {
        devices::locked(&mut extension, status);
    }
    // Retired on disk only through what the audit export has read, when it runs (for export or for alerting, which
    // reads the same table); through anything otherwise. With a store the request index must have copied it too.
    let export_reads = (siem_on || alerts_on) && host.postgres.is_some();
    let read_limit = || Arc::new(AtomicU64::new(if export_reads { 0 } else { u64::MAX }));
    let limit = read_limit();
    // Each organization's chain (`audit: { per_org: true }`) is exported, retained and shipped as the install's is,
    // each with its own read-through limit.
    let orgs: Vec<(gantry_server::OrgChain, Arc<AtomicU64>)> = host
        .org_chains
        .iter()
        .map(|chain| (chain.clone(), read_limit()))
        .collect();
    // Not behind the license: it is what keeps the audit chain whole where the disk does not last, a property the
    // gateway promises without one.
    let segment_store = segments::Store::from_env(&env)?.map(Arc::new);
    if let Some(store) = &segment_store {
        let mut shippers = Vec::new();
        let shipper = Arc::new(segments::Shipper::new(
            store.within(""),
            host.audit.clone(),
            host.audit_path.to_path_buf(),
            &env,
            limit.clone(),
            host.request_index.clone(),
        ));
        if let Some(token) = env(segments::READ_TOKEN_ENV).filter(|t| !t.trim().is_empty()) {
            extension.routes = std::mem::take(&mut extension.routes)
                .merge(segments::routes(shipper.clone(), token.trim().to_string()));
        }
        shippers.push(shipper);
        for (chain, limit) in &orgs {
            shippers.push(Arc::new(segments::Shipper::new(
                store.within(&org_prefix(&chain.org)),
                chain.log.clone(),
                chain.path.clone(),
                &env,
                limit.clone(),
                chain.request_index.clone(),
            )));
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            for shipper in &shippers {
                runtime.spawn(shipper.clone().run());
            }
        }
        SHIPPERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(shippers);
    }
    // An organization a reload adds is shipped from then on, as those open at start are.
    let org_hook = |siem: Option<OrgSiem>| -> Arc<dyn Fn(gantry_server::OrgChain) + Send + Sync> {
        let (segment_store, env) = (segment_store.clone(), env.clone());
        Arc::new(move |chain| {
            new_org(
                &chain,
                segment_store.as_deref(),
                &env,
                export_reads,
                siem.as_ref(),
            );
        })
    };
    extension.on_org = Some(org_hook(None));
    let watch_on = status.unlocked(watch::FEATURE);
    if !watch_on {
        watch::locked(&mut extension, status);
    }
    if !(members_on || siem_on || retention_on || alerts_on || devices_on || watch_on) {
        return Ok(extension);
    }
    // The license never stops traffic: a feature that cannot run says why and the gateway starts without it.
    let Some(pg) = host.postgres else {
        eprintln!(
            "warning: the license unlocks enterprise features (members, audit export, retention, alerts, devices, watch mode) that are kept in Postgres, but the policy has no store. Add `store: {{ postgres_url_env: DATABASE_URL }}` to the policy and restart; until then they are off and the console signs in with admin keys only."
        );
        return Ok(extension);
    };
    pg.migrate("enterprise.split", SPLIT)?;
    if members_on {
        pg.migrate("enterprise.members", MEMBERS)?;
    }
    if scim_on {
        pg.migrate("enterprise.scim", SCIM)?;
    }
    if siem_on || retention_on || alerts_on {
        pg.migrate("enterprise.siem", SIEM)?;
    }
    if alerts_on {
        pg.migrate("enterprise.alerts", ALERTS)?;
    }
    if devices_on {
        pg.migrate("enterprise.devices", DEVICES)?;
    }
    if watch_on {
        pg.migrate("enterprise.watch", WATCH)?;
    }
    let db = Arc::new(Db::new(pg.clone()));
    if watch_on {
        watch::register(
            &mut extension,
            db.clone(),
            host.keys.to_path_buf(),
            host.audit.clone(),
        );
    }
    if devices_on {
        devices::register(&mut extension, db.clone(), host.keys.to_path_buf());
    }
    if members_on {
        members::register(&mut extension, db.clone(), host.keys.to_path_buf());
    }
    if scim_on {
        scim::register(&mut extension, db.clone(), host.keys.to_path_buf());
    }
    if siem_on || retention_on || alerts_on {
        // Text is captured only for destinations that opt in; with audit export off there are none.
        let captures = siem_on.then(|| Arc::new(capture::Captures::default()));
        if let Some(captures) = &captures {
            extension.capture = Some(captures.clone());
        }
        let setup = |log: &Arc<gantry_core::audit::AuditLog>,
                     path: &Path,
                     read_through: &Arc<AtomicU64>| siem::Setup {
            db: db.clone(),
            log: log.clone(),
            audit_path: path.to_path_buf(),
            env: env.clone(),
            siem: siem_on,
            retention: retention_on,
            alerts: alerts_on,
            captures: captures.clone(),
            read_through: read_through.clone(),
        };
        let registered = siem::register(&mut extension, setup(host.audit, host.audit_path, &limit));
        match registered {
            Ok(exporter) if alerts_on => {
                alerts::register(
                    &mut extension,
                    &exporter,
                    &env,
                    host.policy_now.clone(),
                    host.keys.to_path_buf(),
                    host.policy.to_path_buf(),
                );
            }
            Ok(_) => {}
            Err(err) => eprintln!("warning: audit export, retention and alerts are off: {err}"),
        }
        // From here an added organization is exported, retained and alerted on too.
        extension.on_org = Some(org_hook(Some(OrgSiem {
            db: db.clone(),
            env: env.clone(),
            siem: siem_on,
            retention: retention_on,
            alerts: alerts_on,
            captures: captures.clone(),
            policy_now: host.policy_now.clone(),
            keys: host.keys.to_path_buf(),
            policy: host.policy.to_path_buf(),
        })));
        for (chain, read_through) in &orgs {
            match siem::chain(setup(&chain.log, &chain.path, read_through)) {
                Ok(exporter) if alerts_on => {
                    alerts::engine(
                        &exporter,
                        &env,
                        host.policy_now.clone(),
                        host.keys.to_path_buf(),
                        host.policy.to_path_buf(),
                        true,
                    );
                }
                Ok(_) => {}
                Err(err) => eprintln!(
                    "warning: audit export, retention and alerts are off for the chain of organization \"{}\": {err}",
                    chain.org
                ),
            }
        }
    }
    Ok(extension)
}

/// The shippers started, the install's chain's first, for the last pass when the gateway stops: those `extend`
/// started and those of organizations a reload added.
static SHIPPERS: std::sync::Mutex<Vec<Arc<segments::Shipper>>> = std::sync::Mutex::new(Vec::new());

/// What exports, retains and alerts on an organization's chain, when the license and the store allow it.
struct OrgSiem {
    db: Arc<Db>,
    env: siem::sinks::Env,
    siem: bool,
    retention: bool,
    alerts: bool,
    captures: Option<Arc<capture::Captures>>,
    policy_now: gantry_server::PolicyNow,
    /// The keys and policy files, for the rules on expiring keys and on regions.
    keys: std::path::PathBuf,
    policy: std::path::PathBuf,
}

/// The chain of an organization a policy reload added: shipped, exported, retained and alerted on as the chains
/// open at start are. Runs on the gateway's runtime, which the gateway entered.
fn new_org(
    chain: &gantry_server::OrgChain,
    segment_store: Option<&segments::Store>,
    env: &siem::sinks::Env,
    export_reads: bool,
    siem: Option<&OrgSiem>,
) {
    let read_through = Arc::new(AtomicU64::new(if export_reads { 0 } else { u64::MAX }));
    if let Some(store) = segment_store {
        let shipper = Arc::new(segments::Shipper::new(
            store.within(&org_prefix(&chain.org)),
            chain.log.clone(),
            chain.path.clone(),
            env,
            read_through.clone(),
            chain.request_index.clone(),
        ));
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(shipper.clone().run());
        }
        SHIPPERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(shipper);
    }
    let Some(o) = siem else {
        return;
    };
    let setup = siem::Setup {
        db: o.db.clone(),
        log: chain.log.clone(),
        audit_path: chain.path.clone(),
        env: o.env.clone(),
        siem: o.siem,
        retention: o.retention,
        alerts: o.alerts,
        captures: o.captures.clone(),
        read_through,
    };
    match siem::chain(setup) {
        Ok(exporter) if o.alerts => {
            alerts::engine(
                &exporter,
                &o.env,
                o.policy_now.clone(),
                o.keys.clone(),
                o.policy.clone(),
                true,
            );
        }
        Ok(_) => {}
        Err(err) => eprintln!(
            "warning: audit export, retention and alerts are off for the chain of organization \"{}\": {err}",
            chain.org
        ),
    }
}

/// Where an organization's segments go in the bucket, beside the install's: `orgs/<org>`, the name as its chain's
/// file has it.
fn org_prefix(org: &str) -> String {
    let file = gantry_core::audit::org_path(Path::new(""), org);
    let name = file
        .file_stem()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("orgs/{name}")
}

/// Before `serve` opens the audit log: on an empty disk, fetches the chain's newest segments from the store
/// `GANTRY_AUDIT_SEGMENTS_URL` names, so the gateway continues it. Nothing when it is unset.
pub fn restore_audit(policy: &Path, keys: Option<&Path>) -> Result<(), String> {
    let env: siem::sinks::Env = Arc::new(|variable| std::env::var(variable).ok());
    let Some(store) = segments::Store::from_env(&env)? else {
        return Ok(());
    };
    // A policy that does not load is reported by `serve` itself, with every error in it.
    let Ok(loaded) = gantry_core::config::load(policy, keys) else {
        return Ok(());
    };
    eprintln!(
        "audit segments: {}",
        segments::restore(&store, &loaded.audit_path)?
    );
    if loaded.audit_per_org {
        for org in loaded.policy.orgs() {
            eprintln!(
                "audit segments of organization {org}: {}",
                segments::restore(
                    &store.within(&org_prefix(org)),
                    &gantry_core::audit::org_path(&loaded.audit_path, org)
                )?
            );
        }
    }
    Ok(())
}

/// After the gateway stopped serving: seals the log and writes the rest to the store, so a graceful stop loses
/// no record.
pub fn finish_audit() {
    let shippers = SHIPPERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    for shipper in shippers {
        match shipper.pass(true) {
            Ok(wrote) => eprintln!("audit segments: wrote {wrote} on stop."),
            Err(err) => eprintln!("warning: audit segments: the last pass failed: {err}"),
        }
    }
}

/// The license as /healthz shows it: who it is for and until when, never the token.
fn health(status: &Status) -> gantry_server::Health {
    let state = match status.state {
        State::Missing => "missing",
        State::Valid => "valid",
        State::Grace => "grace",
        State::Lapsed => "lapsed",
    };
    let fields = json!({
        "state": state,
        "customer": status.license.as_ref().map(|l| &l.customer),
        "id": status.license.as_ref().map(|l| &l.id),
        "features": status.license.as_ref().map(|l| &l.features),
        "expires": status.license.as_ref().map(|l| &l.expires),
        "grace_days": license::GRACE_DAYS,
    });
    let mut map = serde_json::Map::new();
    map.insert("license".into(), fields);
    Arc::new(move || map.clone())
}

/// The enterprise features' connection to the store's database. Their own, apart from the gateway's, so it may hold
/// transactions.
// ponytail: one connection, so enterprise queries (console pages and sign-ins, not model traffic) wait in turn.
// A pool when a feature puts queries on the request path.
pub struct Db {
    pg: Arc<PgStore>,
    client: tokio::sync::Mutex<Option<Client>>,
}

impl Db {
    fn new(pg: Arc<PgStore>) -> Self {
        Self {
            pg,
            client: tokio::sync::Mutex::new(None),
        }
    }

    /// The connection, opened again if it was lost.
    pub async fn client(&self) -> Result<tokio::sync::MappedMutexGuard<'_, Client>, String> {
        let mut client = self.client.lock().await;
        if client.as_ref().is_none_or(Client::is_closed) {
            *client = Some(self.pg.connect().await?);
        }
        tokio::sync::MutexGuard::try_map(client, Option::as_mut)
            .map_err(|_| "the connection to Postgres was not opened".to_string())
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A gateway with the enterprise features, on a fresh database of the Postgres GANTRY_TEST_DATABASE_URL names.

    use std::path::PathBuf;

    use axum::{
        Router,
        body::Body,
        http::{HeaderMap, Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::license::{License, State, Status};

    pub type Error = Box<dyn std::error::Error>;
    pub const HOST: &str = "127.0.0.1:19870";
    pub const ADMIN_KEY: &str = "gantry_admin_0123456789abcdef0123456789";

    pub fn licensed(features: &[&str]) -> Status {
        Status {
            license: Some(License {
                customer: "Acme".into(),
                id: "lic_test".into(),
                features: features.iter().map(|f| (*f).to_string()).collect(),
                seats: 10,
                issued: "2026-11-01".into(),
                expires: "2099-01-01".into(),
            }),
            state: State::Valid,
        }
    }

    pub fn unlicensed() -> Status {
        Status {
            license: None,
            state: State::Missing,
        }
    }

    /// A fresh database, as a connection string. `None` (and a line saying so) when GANTRY_TEST_DATABASE_URL is not
    /// set, so a machine without Postgres skips these tests; CI sets it.
    pub async fn database(test: &str) -> Result<Option<String>, Error> {
        let Ok(url) = std::env::var("GANTRY_TEST_DATABASE_URL") else {
            eprintln!(
                "skipped {test}: GANTRY_TEST_DATABASE_URL is not set. Set it to a Postgres connection string to run the enterprise tests."
            );
            return Ok(None);
        };
        use gantry_server::store::tokio_postgres;
        let config: tokio_postgres::Config = url.parse()?;
        let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        let name = format!("gantry_ent_{}_{test}", std::process::id());
        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS {name}"))
            .await?;
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await?;
        let host = match config.get_hosts().first() {
            Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
            _ => "127.0.0.1".into(),
        };
        let password = config
            .get_password()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .unwrap_or_default();
        Ok(Some(format!(
            "host={host} port={} user={} password='{}' dbname={name} sslmode=disable",
            config.get_ports().first().copied().unwrap_or(5432),
            config.get_user().unwrap_or("postgres"),
            password.replace('\\', "\\\\").replace('\'', "\\'"),
        )))
    }

    pub struct Gateway {
        pub app: Router,
        pub keys: PathBuf,
        pub dir: PathBuf,
        /// The gateway's audit log, and its path.
        pub log: std::sync::Arc<gantry_core::audit::AuditLog>,
        pub audit: PathBuf,
        pub governed: gantry_server::Governed,
    }

    /// The gateway `serve` runs, with the enterprise features `status` unlocks, and one admin key, noa's.
    pub fn gateway(test: &str, url: &str, status: &Status) -> Result<Gateway, Error> {
        gateway_with(test, url, status, &[])
    }

    /// `gateway`, with the enterprise features reading `env` as their environment.
    /// The policy of every test gateway: one provider, one rule for everyone.
    pub const POLICY: &str = "version: 1\nstore: { postgres_url_env: GANTRY_STORE_URL }\nproviders:\n  - name: mock\n    kind: openai\n    url: http://127.0.0.1:9\n    allow_private: true\n    key_env: MOCK_KEY\n    models: [m]\nrules:\n  - name: all\n    principals: { any: true }\n    models: [m]\n";

    pub fn gateway_with(
        test: &str,
        url: &str,
        status: &Status,
        vars: &[(&str, &str)],
    ) -> Result<Gateway, Error> {
        gateway_policy(test, url, status, vars, POLICY)
    }

    /// `gateway_with`, serving `policy_text`.
    pub fn gateway_policy(
        test: &str,
        url: &str,
        status: &Status,
        vars: &[(&str, &str)],
        policy_text: &str,
    ) -> Result<Gateway, Error> {
        let dir = std::env::temp_dir().join(format!("gantry-ent-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        let policy = dir.join("gantry.policy.yaml");
        std::fs::write(&policy, policy_text)?;
        let url = url.to_string();
        let env = move |variable: &str| match variable {
            "GANTRY_STORE_URL" => Some(url.clone()),
            // Unset, as on a gateway that keeps no provider credentials in the store: a catch-all answer would set
            // both of these, which the gateway refuses.
            "GANTRY_MASTER_KEY" | "GANTRY_MASTER_KEY_FILE" => None,
            _ => Some("provider-secret".into()),
        };
        let vars: std::collections::HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let vars: super::siem::sinks::Env =
            std::sync::Arc::new(move |name| vars.get(name).cloned());
        let gw = gantry_server::governed_with(&policy, None, &env, &|host| {
            super::extend_with(status, host, vars.clone())
        })?;
        let keys = gw.loaded.keys_path.clone();
        gantry_core::keyfile::add_entry("noa", "platform", ADMIN_KEY, true, &keys)?;
        // In effect at once, so the admin API knows the key too, not only the console.
        gw.reloader.check(gantry_server::Trigger::FileChange);
        Ok(Gateway {
            app: gw.router.clone(),
            keys,
            dir,
            log: gw.log.clone(),
            audit: gw.loaded.audit_path.clone(),
            governed: gw,
        })
    }

    /// A browser: keeps the console cookie and sends forms from the console's own origin.
    #[derive(Default)]
    pub struct Browser {
        pub cookie: String,
    }

    pub struct Answer {
        pub status: StatusCode,
        pub location: String,
        pub text: String,
    }

    impl Browser {
        pub async fn go(
            &mut self,
            app: &Router,
            method: &str,
            path: &str,
            form: &[(&str, &str)],
        ) -> Result<Answer, Error> {
            let body = form
                .iter()
                .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
                .collect::<Vec<_>>()
                .join("&");
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, HOST)
                .header(header::ORIGIN, format!("http://{HOST}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if !self.cookie.is_empty() {
                request = request.header(header::COOKIE, &self.cookie);
            }
            let response = app.clone().oneshot(request.body(Body::from(body))?).await?;
            let (parts, body) = response.into_parts();
            self.keep(&parts.headers);
            let text = String::from_utf8_lossy(&body.collect().await?.to_bytes()).into_owned();
            Ok(Answer {
                status: parts.status,
                location: parts
                    .headers
                    .get(header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string(),
                text,
            })
        }

        fn keep(&mut self, headers: &HeaderMap) {
            for cookie in headers.get_all(header::SET_COOKIE) {
                if let Some(pair) = cookie.to_str().ok().and_then(|c| c.split(';').next())
                    && pair.starts_with("gantry_console=")
                {
                    self.cookie = pair.to_string();
                }
            }
        }

        /// Signs in with noa's admin key.
        pub async fn admin(app: &Router) -> Result<Self, Error> {
            let mut browser = Self::default();
            let signed = browser
                .go(app, "POST", "/console/sign-in", &[("key", ADMIN_KEY)])
                .await?;
            if signed.status != StatusCode::SEE_OTHER {
                return Err(format!("admin sign-in: {}", signed.status).into());
            }
            Ok(browser)
        }
    }

    fn enc(text: &str) -> String {
        text.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn healthz_shows_the_license_and_never_the_token() -> Result<(), Error> {
        let Some(url) = database("health").await? else {
            return Ok(());
        };
        let gw = gateway("health", &url, &licensed(&["members"]))?;
        let answer = Browser::default()
            .go(&gw.app, "GET", "/healthz", &[])
            .await?;
        assert_eq!(answer.status, StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&answer.text)?;
        assert_eq!(body["status"], "ok");
        let license = &body["license"];
        assert_eq!(license["customer"], "Acme");
        assert_eq!(license["expires"], "2099-01-01");
        assert_eq!(license["state"], "valid");
        assert_eq!(license["grace_days"], 30);
        assert!(license.get("token").is_none() && !answer.text.contains("signature"));
        Ok(())
    }

    #[tokio::test]
    async fn without_a_license_healthz_says_so() -> Result<(), Error> {
        let Some(url) = database("health_none").await? else {
            return Ok(());
        };
        let gw = gateway("health_none", &url, &unlicensed())?;
        let answer = Browser::default()
            .go(&gw.app, "GET", "/healthz", &[])
            .await?;
        let body: serde_json::Value = serde_json::from_str(&answer.text)?;
        assert_eq!(body["license"]["state"], "missing");
        assert!(body["license"]["customer"].is_null());
        Ok(())
    }
}

#[cfg(test)]
mod migration_tests {
    use super::testing::*;
    use gantry_server::store::tokio_postgres::{self, Client, NoTls};

    async fn connect(url: &str) -> Result<Client, Error> {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
        tokio::spawn(connection);
        Ok(client)
    }

    async fn versions(client: &Client) -> Result<Vec<(String, i32)>, Error> {
        let mut rows = Vec::new();
        for row in client
            .query(
                "SELECT namespace, version FROM gantry_migrations WHERE namespace LIKE 'enterprise%' ORDER BY namespace",
                &[],
            )
            .await?
        {
            rows.push((row.try_get(0)?, row.try_get(1)?));
        }
        Ok(rows)
    }

    /// The gateway started again on the same database, as a later start or another replica: `gateway` adds noa's
    /// admin key, which the store refuses twice.
    async fn restart(
        test: &str,
        url: &str,
        client: &Client,
        features: &[&str],
    ) -> Result<(), Error> {
        client.batch_execute("DELETE FROM gantry_keys").await?;
        gateway(test, url, &licensed(features))?;
        Ok(())
    }

    /// A database as a binary from before the per-feature namespaces left it: the first `ran` entries of the one
    /// `enterprise` list (members, scim, siem) applied, and its version row.
    async fn old_database(url: &str, ran: usize) -> Result<Client, Error> {
        let client = connect(url).await?;
        client
            .batch_execute(
                "CREATE TABLE gantry_migrations (namespace text PRIMARY KEY, version integer NOT NULL)",
            )
            .await?;
        let old = [
            super::members::MIGRATION,
            super::scim::MIGRATION,
            super::siem::MIGRATION,
        ];
        for sql in old.iter().take(ran) {
            client.batch_execute(sql).await?;
        }
        let version = i32::try_from(ran)?;
        client
            .execute(
                "INSERT INTO gantry_migrations VALUES ('enterprise', $1)",
                &[&version],
            )
            .await?;
        client
            .batch_execute("INSERT INTO enterprise_people (id, email, name, password_salt, password_hash, role) VALUES ('p1', 'old@acme.co', 'Old', 's', 'h', 'owner')")
            .await?;
        Ok(client)
    }

    #[tokio::test]
    async fn a_new_database_gets_one_version_per_unlocked_feature() -> Result<(), Error> {
        let Some(url) = database("mig_new").await? else {
            return Ok(());
        };
        gateway("mig_new", &url, &licensed(&["members", "siem"]))?;
        let client = connect(&url).await?;
        assert_eq!(
            versions(&client).await?,
            [
                ("enterprise.members".to_string(), 1),
                ("enterprise.siem".to_string(), 2),
                ("enterprise.split".to_string(), 1),
            ]
        );
        // Unlocking another feature later runs its migrations only.
        restart("mig_new", &url, &client, &["members", "scim", "siem"]).await?;
        assert!(
            versions(&client)
                .await?
                .contains(&("enterprise.scim".to_string(), 1))
        );
        // Alerting keeps its tables in its own namespace, after the audit table it reads.
        restart(
            "mig_new",
            &url,
            &client,
            &["members", "scim", "siem", "alerts"],
        )
        .await?;
        assert_eq!(
            versions(&client).await?,
            [
                // Entry 2 is the daily baseline of the unusual request, error and latency rules.
                ("enterprise.alerts".to_string(), 2),
                ("enterprise.members".to_string(), 1),
                ("enterprise.scim".to_string(), 1),
                ("enterprise.siem".to_string(), 2),
                ("enterprise.split".to_string(), 1),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_database_from_the_one_list_moves_forward_without_running_its_ddl_again()
    -> Result<(), Error> {
        let Some(url) = database("mig_old").await? else {
            return Ok(());
        };
        let client = old_database(&url, 3).await?;
        // Running any of the old DDL again would fail on a table that exists, and the gateway would not start.
        gateway(
            "mig_old",
            &url,
            &licensed(&["members", "scim", "siem", "retention"]),
        )?;
        assert_eq!(
            versions(&client).await?,
            [
                // Kept, so an older replica in a rolling upgrade still starts.
                ("enterprise".to_string(), 3),
                ("enterprise.members".to_string(), 1),
                ("enterprise.scim".to_string(), 1),
                ("enterprise.siem".to_string(), 2),
                ("enterprise.split".to_string(), 1),
            ]
        );
        let kept: i64 = client
            .query_one("SELECT count(*) FROM enterprise_people", &[])
            .await?
            .try_get(0)?;
        assert_eq!(kept, 1);
        // And again, as every later start does.
        restart("mig_old", &url, &client, &["members", "scim", "siem"]).await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_database_part_way_through_the_one_list_runs_only_what_it_lacks() -> Result<(), Error>
    {
        let Some(url) = database("mig_part").await? else {
            return Ok(());
        };
        let client = old_database(&url, 1).await?;
        gateway("mig_part", &url, &licensed(&["members", "siem"]))?;
        assert_eq!(
            versions(&client).await?,
            [
                ("enterprise".to_string(), 1),
                ("enterprise.members".to_string(), 1),
                ("enterprise.siem".to_string(), 2),
                ("enterprise.split".to_string(), 1),
            ]
        );
        let audit: i64 = client
            .query_one(
                "SELECT count(*) FROM information_schema.tables WHERE table_name = 'enterprise_audit'",
                &[],
            )
            .await?
            .try_get(0)?;
        assert_eq!(audit, 1);
        Ok(())
    }
}
