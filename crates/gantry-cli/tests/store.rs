//! Two `gantry serve` processes on one Postgres database act as one gateway: a key made with `gantry key new` is
//! accepted by both, `gantry kill` through one stops the other, and `gantry key revoke` stops both. `gantry store
//! import` moves a keys file in.
//!
//! They need a real Postgres: set GANTRY_TEST_DATABASE_URL (CI runs a postgres:16 service). Without it each test
//! prints that it was skipped and passes.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Error = Box<dyn std::error::Error>;

const POLICY: &str = "\
version: 1
store: { postgres_url_env: DATABASE_URL }
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:9
    allow_private: true
    key_env: GANTRY_TEST_PROVIDER_KEY
    models: [model-a]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [model-a]
";

/// A fresh database for one test, as a connection string. `None` when GANTRY_TEST_DATABASE_URL is not set.
fn database(test: &str) -> Result<Option<String>, Error> {
    let Ok(url) = std::env::var("GANTRY_TEST_DATABASE_URL") else {
        eprintln!(
            "skipped {test}: GANTRY_TEST_DATABASE_URL is not set. Set it to a Postgres connection string to run the store tests."
        );
        return Ok(None);
    };
    let config: tokio_postgres::Config = url.parse()?;
    let name = format!("gantry_cli_{}_{test}", std::process::id());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS {name}"))
            .await?;
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
    })?;
    let quote = |s: &str| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"));
    let host = match config.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
        _ => "127.0.0.1".into(),
    };
    let password = config
        .get_password()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_default();
    Ok(Some(format!(
        "host={} port={} user={} password={} dbname={} sslmode=disable",
        quote(&host),
        config.get_ports().first().copied().unwrap_or(5432),
        quote(config.get_user().unwrap_or("postgres")),
        quote(&password),
        quote(&name)
    )))
}

fn workdir(name: &str) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("gantry-cli-store-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("gantry.policy.yaml"), POLICY)?;
    Ok(dir)
}

fn path(dir: &Path, file: &str) -> String {
    dir.join(file).display().to_string()
}

fn gantry(args: &[&str], env: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gantry"));
    command
        .args(args)
        .env_remove("GANTRY_ADDR")
        .env_remove("GANTRY_UPSTREAM");
    for (key, value) in env {
        command.env(key, value);
    }
    command.output()
}

/// Runs a command that must succeed and returns what it printed.
fn ok(args: &[&str], env: &[(&str, &str)]) -> Result<String, Error> {
    let out = gantry(args, env)?;
    if !out.status.success() {
        return Err(format!(
            "gantry {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// Stops the server when the test ends, whichever way it ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts `gantry serve` on the policy in `dir` and returns it with the address it listens on.
fn serve(dir: &Path, url: &str) -> Result<(Running, String), Error> {
    let stdout = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_gantry"))
        .args([
            "serve",
            &path(dir, "gantry.policy.yaml"),
            "--listen",
            "127.0.0.1:0",
        ])
        .env("GANTRY_TEST_PROVIDER_KEY", "provider-secret")
        .env("DATABASE_URL", url)
        .stdout(std::fs::File::create(&stdout)?)
        .stderr(std::fs::File::create(dir.join("stderr.txt"))?)
        .spawn()?;
    let running = Running(child);
    let start = Instant::now();
    loop {
        let text = std::fs::read_to_string(&stdout).unwrap_or_default();
        if let Some((_, addr)) = text
            .lines()
            .find_map(|l| l.split_once(" listening on http://"))
        {
            return Ok((running, addr.trim().to_string()));
        }
        if start.elapsed() > Duration::from_secs(10) {
            let stderr = std::fs::read_to_string(dir.join("stderr.txt")).unwrap_or_default();
            return Err(format!("the server never said where it listens: {text} {stderr}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Sends a chat request over a plain socket and returns the status line and body.
fn chat(addr: &str, key: &str) -> Result<String, Error> {
    use std::io::{Read, Write};
    let body = r#"{"model":"model-a","messages":[]}"#;
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(
        format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: gantry\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    Ok(text)
}

/// How long until the gateway at `addr` answered `key` as `wanted` says, or an error after `within`.
fn until(
    addr: &str,
    key: &str,
    within: Duration,
    wanted: impl Fn(&str) -> bool,
) -> Result<Duration, Error> {
    let start = Instant::now();
    loop {
        let answer = chat(addr, key)?;
        if wanted(&answer) {
            return Ok(start.elapsed());
        }
        if start.elapsed() > within {
            return Err(format!("not within {within:?}: {answer}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A key Gantry knows: the provider at 127.0.0.1:9 is not there, so the request fails after it was allowed.
fn known(answer: &str) -> bool {
    !answer.contains("unknown_key") && !answer.contains("\"code\":\"killed\"")
}

#[test]
fn two_serve_processes_on_one_database_share_keys_and_kill_switches() -> TestResult {
    let Some(url) = database("share")? else {
        return Ok(());
    };
    let (a_dir, b_dir) = (workdir("a")?, workdir("b")?);
    let db = [("DATABASE_URL", url.as_str())];
    // The policy beside the keys file has store:, so the key goes into the database, not a file.
    let a_keys = path(&a_dir, "gantry.keys.yaml");
    let admin = ok(
        &[
            "key", "new", "ops", "--team", "payments", "--admin", "--quiet", "--keys", &a_keys,
        ],
        &db,
    )?;
    let admin = admin.trim().to_string();
    assert!(
        !a_dir.join("gantry.keys.yaml").exists(),
        "no keys file is written"
    );
    let (_a, a) = serve(&a_dir, &url)?;
    let (_b, b) = serve(&b_dir, &url)?;
    let started = std::fs::read_to_string(b_dir.join("stdout.txt"))?;
    assert!(
        started.contains("shared through the store named by DATABASE_URL"),
        "{started}"
    );
    // The test database has no TLS, so the string says sslmode=disable, and serve says what that means.
    let warned = std::fs::read_to_string(b_dir.join("stderr.txt"))?;
    assert!(
        warned.contains("sslmode=disable") && warned.contains("not encrypted"),
        "{warned}"
    );

    let maya = ok(
        &[
            "key", "new", "maya", "--team", "payments", "--quiet", "--keys", &a_keys,
        ],
        &db,
    )?;
    let maya = maya.trim().to_string();
    let took = until(&b, &maya, Duration::from_secs(2), known)?;
    eprintln!("a key made with `gantry key new` was accepted by the other process after {took:?}");

    let home = path(&a_dir, "config");
    let a_url = format!("http://{a}");
    let admin_env = [
        ("XDG_CONFIG_HOME", home.as_str()),
        ("GANTRY_URL", a_url.as_str()),
        ("GANTRY_ADMIN_KEY", admin.as_str()),
    ];
    ok(
        &[
            "kill",
            "--person",
            "maya",
            "--reason",
            "looping on one ticket",
        ],
        &admin_env,
    )?;
    let took = until(&b, &maya, Duration::from_secs(1), |answer| {
        answer.starts_with("HTTP/1.1 403") && answer.contains("looping on one ticket")
    })?;
    eprintln!("`gantry kill` through one process stopped the other after {took:?}");
    ok(&["unkill", "--person", "maya"], &admin_env)?;
    until(&b, &maya, Duration::from_secs(1), known)?;

    // The other directory has no keys file: its key commands read and change the store too.
    let b_keys = path(&b_dir, "gantry.keys.yaml");
    let listed = ok(&["key", "list", "--keys", &b_keys], &db)?;
    assert!(
        listed.contains("maya\tpayments") && listed.contains("ops\tpayments"),
        "{listed}"
    );
    let prefix = &gantry_core::id::sha256_hex(maya.as_bytes())[..12];
    let revoked = ok(&["key", "revoke", prefix, "--keys", &b_keys], &db)?;
    assert!(revoked.contains("maya"), "{revoked}");
    for addr in [&a, &b] {
        let took = until(addr, &maya, Duration::from_secs(2), |answer| {
            answer.starts_with("HTTP/1.1 401") && answer.contains("unknown_key")
        })?;
        eprintln!("the revoked key was refused after {took:?}");
    }
    Ok(())
}

#[test]
fn store_import_moves_a_keys_file_in_once() -> TestResult {
    let Some(url) = database("import")? else {
        return Ok(());
    };
    let dir = workdir("import")?;
    let db = [("DATABASE_URL", url.as_str())];
    // Made in a folder without a policy: a plain keys file, as before the store.
    let old = workdir("import-old")?;
    std::fs::remove_file(old.join("gantry.policy.yaml"))?;
    let file = path(&old, "gantry.keys.yaml");
    ok(
        &[
            "key", "new", "rina", "--team", "payments", "--quiet", "--keys", &file,
        ],
        &[],
    )?;
    assert!(std::fs::read_to_string(&file)?.contains("name: rina"));

    let policy = path(&dir, "gantry.policy.yaml");
    let unset = gantry(
        &["store", "import", "--keys", &file, "--policy", &policy],
        &[],
    )?;
    assert_eq!(unset.status.code(), Some(2));
    assert!(String::from_utf8(unset.stderr)?.contains("DATABASE_URL"));

    let out = ok(
        &["store", "import", "--keys", &file, "--policy", &policy],
        &db,
    )?;
    assert!(out.contains("Imported 1 key"), "{out}");
    let again = ok(
        &["store", "import", "--keys", &file, "--policy", &policy],
        &db,
    )?;
    assert!(
        again.contains("Imported 0 keys") && again.contains("(1 key already there)"),
        "{again}"
    );
    let listed = ok(
        &["key", "list", "--keys", &path(&dir, "gantry.keys.yaml")],
        &db,
    )?;
    assert!(listed.contains("rina\tpayments"), "{listed}");
    // `check` validates the section without connecting.
    let checked = ok(&["check", &policy], &[])?;
    assert!(
        checked.contains("keys in the store named by DATABASE_URL"),
        "{checked}"
    );
    Ok(())
}
