//! A gateway node managed by the Gantry control plane.
//!
//! The node pulls its policy and keys from the control plane, writes them where `gantry serve` reads them (Gantry
//! reloads a saved file within 2 seconds), runs the gateway as a child process, and ships audit metadata back.
//! Prompts, answers and provider keys never leave the node: the audit shipper sends only the fields in `SHIPPED`.
//! When the control plane cannot be reached the node keeps serving with the files it last wrote.

use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The only audit fields that leave a node. Request records hold no prompt text, but the list is the contract:
/// a field Gantry adds later stays on the node until it is named here.
const SHIPPED: &[&str] = &[
    "n",
    "event",
    "id",
    "time",
    "person",
    "team",
    "key",
    "method",
    "path",
    "model",
    "verdict",
    "code",
    "rule",
    "provider",
    "status",
    "ended",
    "input_tokens",
    "output_tokens",
    "cost_usd",
    "charged_usd",
    "trigger",
    "policy_sha256",
    "keys_sha256",
    "action",
    "prev",
    "hash",
];
const POLICY: &str = "gantry.policy.yaml";
const KEYS: &str = "gantry.keys.yaml";
const AUDIT: &str = "gantry-audit.jsonl";
const SHIPPED_OFFSET: &str = "shipped.offset";
const BATCH: usize = 200;

pub struct Options {
    pub control_plane: String,
    pub dir: PathBuf,
    pub listen: String,
    pub interval: Duration,
    pub secrets: Vec<crate::secrets::Secret>,
    pub secrets_interval: Duration,
    /// Extra environment variables the gateway may read, beyond the defaults (see `gateway_env`).
    pub pass_env: Vec<String>,
}

/// Variables every gateway gets when the node has them: what a process needs to run and to trust TLS.
const BASE_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "TZ",
    "LANG",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// The gateway's whole environment. It starts empty: a policy names environment variables (`key_env`), and the
/// policy comes from the control plane, so the gateway must not be able to read the node's credential or anything
/// else on the machine. It gets the base variables, every `*_PROVIDER_KEY`, the names in `--pass-env`, and on a
/// hosted gateway the org's provider keys from the control plane. A hybrid node ignores keys sent by the control
/// plane: at the customer, provider keys come from the customer's own machine.
fn gateway_env(
    opts: &Options,
    from_control_plane: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars()
        .filter(|(k, _)| {
            BASE_ENV.contains(&k.as_str())
                || k.ends_with("_PROVIDER_KEY")
                || opts.pass_env.iter().any(|p| p == k)
        })
        .filter(|(k, _)| !k.starts_with("GANTRY_NODE") && !k.starts_with("GANTRY_DEVICE"))
        .collect();
    if std::env::var("GANTRY_ORG").is_ok() {
        env.extend(
            from_control_plane
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
    }
    env
}

/// A policy may read a key from a file only where the node keeps managed keys (`secrets/`, written by `--secrets`).
fn file_problems(policy: &str) -> Vec<String> {
    policy
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let text = line.split('#').next().unwrap_or("");
            let at = text.find("_file:")?;
            let value = text[at + 6..].trim().trim_matches('"').trim_matches('\'');
            (!value.starts_with("secrets/") || value.contains("..")).then(|| {
                format!(
                    "line {}: {} is outside the node's secrets folder",
                    i + 1,
                    value
                )
            })
        })
        .collect()
}

#[derive(Clone)]
struct Client {
    agent: ureq::Agent,
    base: String,
    token: String,
    org: Option<String>,
}

#[derive(Clone, PartialEq)]
struct Config {
    version: String,
    policy: String,
    keys: String,
    env: BTreeMap<String, String>,
}

impl Client {
    fn get(&self, path: &str) -> ureq::Request {
        self.with_auth(self.agent.get(&format!("{}{path}", self.base)))
    }

    fn post(&self, path: &str) -> ureq::Request {
        self.with_auth(self.agent.post(&format!("{}{path}", self.base)))
    }

    fn with_auth(&self, req: ureq::Request) -> ureq::Request {
        let req = req.set("authorization", &format!("Bearer {}", self.token));
        match &self.org {
            Some(org) => req.set("x-gantry-org", org),
            None => req,
        }
    }

    /// `Ok(None)` when the control plane says the node already has `known`.
    fn config(&self, known: Option<&str>) -> Result<Option<Config>, String> {
        let mut req = self.get("/node/config");
        if let Some(version) = known {
            req = req.set("if-none-match", &format!("\"{version}\""));
        }
        let res = match req.call() {
            Ok(res) => res,
            Err(ureq::Error::Status(304, _)) => return Ok(None),
            Err(ureq::Error::Status(code, res)) => {
                return Err(format!(
                    "the control plane answered {code}: {}",
                    res.into_string().unwrap_or_default()
                ));
            }
            Err(err) => return Err(format!("the control plane could not be reached: {err}")),
        };
        let body: Value = res
            .into_json()
            .map_err(|err| format!("the control plane sent a config that is not JSON: {err}"))?;
        let text = |field: &str| {
            body.get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("the control plane's config has no `{field}`"))
        };
        let env = body
            .get("env")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Some(Config {
            version: text("version")?,
            policy: text("policy")?,
            keys: text("keys")?,
            env,
        }))
    }
}

/// Writes through a temporary file in the same folder, so Gantry never reads half a file.
fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text).map_err(|err| format!("could not write {}: {err}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|err| format!("could not replace {}: {err}", path.display()))
}

/// As `write_atomic`, readable by this user only: for provider keys.
pub(crate) fn write_private(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(&tmp)
        .and_then(|mut file| std::io::Write::write_all(&mut file, text.as_bytes()))
        .map_err(|err| format!("could not write {}: {err}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|err| format!("could not replace {}: {err}", path.display()))
}

fn apply(opts: &Options, config: &Config) -> Result<(), String> {
    let dir = &opts.dir;
    write_atomic(&dir.join(KEYS), &config.keys)?;
    // Managed keys are read from files the node rewrites, so they rotate without a gateway restart.
    let policy = crate::secrets::rewrite_policy(&config.policy, &opts.secrets);
    let problems = file_problems(&policy);
    if !problems.is_empty() {
        return Err(format!(
            "refused config {}: {}. Still serving the last config.",
            config.version,
            problems.join("; ")
        ));
    }
    write_atomic(&dir.join(POLICY), &policy)?;
    write_atomic(&dir.join("config.version"), &config.version)
}

fn spawn_gateway(opts: &Options, env: &BTreeMap<String, String>) -> Result<Child, String> {
    let exe = std::env::current_exe()
        .map_err(|err| format!("could not find this program's path: {err}"))?;
    Command::new(exe)
        .current_dir(&opts.dir)
        .args(["serve", POLICY, "--keys", KEYS, "--listen", &opts.listen])
        .env_clear()
        .envs(gateway_env(opts, env))
        .spawn()
        .map_err(|err| format!("could not start the gateway: {err}"))
}

/// Ships audit records written since the last shipped offset. Only whole lines are read, so a record being written
/// waits for the next round.
fn ship(client: &Client, dir: &Path) -> Result<usize, String> {
    let path = dir.join(AUDIT);
    let Ok(file) = fs::File::open(&path) else {
        return Ok(0);
    };
    let offset_path = dir.join(SHIPPED_OFFSET);
    let mut offset: u64 = fs::read_to_string(&offset_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if offset > len {
        offset = 0; // A new log after a restart: ship it from the start.
    }
    let mut reader = BufReader::new(file);
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|err| format!("could not read the audit log: {err}"))?;
    let mut shipped = 0;
    loop {
        let mut batch = Vec::new();
        let mut read = offset;
        let mut line = String::new();
        while batch.len() < BATCH {
            line.clear();
            let n = reader
                .read_line(&mut line)
                .map_err(|err| format!("could not read the audit log: {err}"))?;
            if n == 0 || !line.ends_with('\n') {
                break;
            }
            read += n as u64;
            if let Ok(Value::Object(record)) = serde_json::from_str::<Value>(&line) {
                let kept: Map<String, Value> = record
                    .into_iter()
                    .filter(|(k, _)| SHIPPED.contains(&k.as_str()))
                    .collect();
                batch.push(Value::Object(kept));
            }
        }
        if batch.is_empty() {
            return Ok(shipped);
        }
        client
            .post("/node/audit")
            .send_json(serde_json::json!({ "records": batch }))
            .map_err(|err| format!("could not ship audit records: {err}"))?;
        shipped += batch.len();
        offset = read;
        write_atomic(&offset_path, &offset.to_string())?;
    }
}

fn heartbeat(client: &Client, version: &str, shipped_total: u64, gateway_running: bool) {
    let _ = client.post("/node/heartbeat").send_json(serde_json::json!({
        "gantry_version": gantry_core::VERSION,
        "config_version": version,
        "shipped": shipped_total,
        "gateway_running": gateway_running,
    }));
}

pub fn run(opts: Options) -> Result<(), String> {
    let token = std::env::var("GANTRY_NODE_TOKEN").map_err(|_| {
        "GANTRY_NODE_TOKEN is not set. Put the node token the control plane issued in it."
            .to_owned()
    })?;
    let client = Client {
        agent: ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build(),
        base: opts.control_plane.trim_end_matches('/').to_owned(),
        token,
        org: std::env::var("GANTRY_ORG").ok(),
    };
    fs::create_dir_all(&opts.dir)
        .map_err(|err| format!("could not create {}: {err}", opts.dir.display()))?;

    // Start from the control plane when it answers, else from the files the node wrote last time.
    let mut config = match client.config(None) {
        Ok(Some(config)) => {
            apply(&opts, &config)?;
            eprintln!(
                "gantry node: config {} from {}",
                config.version, client.base
            );
            config
        }
        Ok(None) => return Err("the control plane sent no config".into()),
        Err(err) if opts.dir.join(POLICY).exists() => {
            eprintln!("gantry node: {err}. Serving the policy and keys written last time.");
            let version = fs::read_to_string(opts.dir.join("config.version")).unwrap_or_default();
            Config {
                version,
                policy: String::new(),
                keys: String::new(),
                env: BTreeMap::new(),
            }
        }
        Err(err) => {
            return Err(format!(
                "{err}. A node needs one config before it can serve."
            ));
        }
    };

    if !opts.secrets.is_empty() {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        let values = crate::secrets::load(&opts.dir, &opts.secrets, &agent)?;
        let (dir, interval) = (opts.dir.clone(), opts.secrets_interval);
        let secrets = opts.secrets.clone();
        std::thread::spawn(move || crate::secrets::watch(dir, secrets, values, interval, agent));
    }
    let child = Arc::new(Mutex::new(spawn_gateway(&opts, &config.env)?));
    let mut shipped_total: u64 = 0;
    loop {
        std::thread::sleep(opts.interval);
        match client.config(Some(&config.version)) {
            Ok(Some(next)) => {
                if let Err(err) = apply(&opts, &next) {
                    eprintln!("gantry node: {err}");
                } else {
                    eprintln!(
                        "gantry node: config {} applied; the gateway reloads it within 2 seconds",
                        next.version
                    );
                    if next.env != config.env {
                        // Provider keys are read when the gateway starts, so a changed secret needs a restart.
                        if let Ok(mut running) = child.lock() {
                            let _ = running.kill();
                            let _ = running.wait();
                            match spawn_gateway(&opts, &next.env) {
                                Ok(fresh) => *running = fresh,
                                Err(err) => eprintln!("gantry node: {err}"),
                            }
                        }
                    }
                    config = next;
                }
            }
            Ok(None) => {}
            Err(err) => eprintln!(
                "gantry node: {err}. Still serving the last config ({}).",
                config.version
            ),
        }
        match ship(&client, &opts.dir) {
            Ok(n) => shipped_total += n as u64,
            Err(err) => eprintln!("gantry node: {err}. Will retry."),
        }
        let running = match child.lock() {
            Ok(mut c) => match c.try_wait() {
                Ok(None) => true,
                _ => {
                    eprintln!("gantry node: the gateway stopped; starting it again");
                    match spawn_gateway(&opts, &config.env) {
                        Ok(fresh) => {
                            *c = fresh;
                            true
                        }
                        Err(err) => {
                            eprintln!("gantry node: {err}");
                            false
                        }
                    }
                }
            },
            Err(_) => false,
        };
        heartbeat(&client, &config.version, shipped_total, running);
    }
}
