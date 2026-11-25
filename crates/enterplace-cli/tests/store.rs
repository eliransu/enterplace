//! Two `enterplace serve` processes on one Postgres database act as one gateway: a key made with `enterplace key new` is
//! accepted by both, `enterplace kill` through one stops the other, and `enterplace key revoke` stops both. `enterplace store
//! import` moves a keys file in.
//!
//! They need a real Postgres: set ENTERPLACE_TEST_DATABASE_URL (CI runs a postgres:16 service). Without it each test
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
    key_env: ENTERPLACE_TEST_PROVIDER_KEY
    models: [model-a]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [model-a]
";

/// A fresh database for one test, as a connection string. `None` when ENTERPLACE_TEST_DATABASE_URL is not set.
fn database(test: &str) -> Result<Option<enterplace_server::store::TestDatabase>, Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(enterplace_server::store::TestDatabase::create(&format!(
            "enterplace_cli_{}_{test}",
            std::process::id()
        )))
}

fn workdir(name: &str) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-cli-store-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("enterplace.policy.yaml"), POLICY)?;
    Ok(dir)
}

fn path(dir: &Path, file: &str) -> String {
    dir.join(file).display().to_string()
}

fn enterplace(args: &[&str], env: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_enterplace"));
    command
        .args(args)
        .env_remove("ENTERPLACE_ADDR")
        .env_remove("ENTERPLACE_UPSTREAM");
    for (key, value) in env {
        command.env(key, value);
    }
    command.output()
}

/// Runs a command that must succeed and returns what it printed.
fn ok(args: &[&str], env: &[(&str, &str)]) -> Result<String, Error> {
    let out = enterplace(args, env)?;
    if !out.status.success() {
        return Err(format!(
            "enterplace {} failed: {}",
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

/// Starts `enterplace serve` on the policy in `dir` and returns it with the address it listens on.
fn serve(dir: &Path, url: &str) -> Result<(Running, String), Error> {
    let stdout = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .args([
            "serve",
            &path(dir, "enterplace.policy.yaml"),
            "--listen",
            "127.0.0.1:0",
        ])
        .env("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret")
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
            "POST /v1/chat/completions HTTP/1.1\r\nHost: enterplace\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

/// A key Enterplace knows: the provider at 127.0.0.1:9 is not there, so the request fails after it was allowed.
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
    let a_keys = path(&a_dir, "enterplace.keys.yaml");
    let admin = ok(
        &[
            "key", "new", "ops", "--team", "payments", "--admin", "--quiet", "--keys", &a_keys,
        ],
        &db,
    )?;
    let admin = admin.trim().to_string();
    assert!(
        !a_dir.join("enterplace.keys.yaml").exists(),
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
    eprintln!(
        "a key made with `enterplace key new` was accepted by the other process after {took:?}"
    );
    // The kill goes through `a`, which refuses a switch for a person it does not know yet: wait until it does.
    until(&a, &maya, Duration::from_secs(2), known)?;

    let home = path(&a_dir, "config");
    let a_url = format!("http://{a}");
    let admin_env = [
        ("XDG_CONFIG_HOME", home.as_str()),
        ("ENTERPLACE_URL", a_url.as_str()),
        ("ENTERPLACE_ADMIN_KEY", admin.as_str()),
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
    eprintln!("`enterplace kill` through one process stopped the other after {took:?}");
    ok(&["unkill", "--person", "maya"], &admin_env)?;
    until(&b, &maya, Duration::from_secs(1), known)?;

    // The other directory has no keys file: its key commands read and change the store too.
    let b_keys = path(&b_dir, "enterplace.keys.yaml");
    let listed = ok(&["key", "list", "--keys", &b_keys], &db)?;
    assert!(
        listed.contains("maya\tpayments") && listed.contains("ops\tpayments"),
        "{listed}"
    );
    let prefix = &enterplace_core::id::sha256_hex(maya.as_bytes())[..12];
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
    std::fs::remove_file(old.join("enterplace.policy.yaml"))?;
    let file = path(&old, "enterplace.keys.yaml");
    ok(
        &[
            "key", "new", "rina", "--team", "payments", "--quiet", "--keys", &file,
        ],
        &[],
    )?;
    assert!(std::fs::read_to_string(&file)?.contains("name: rina"));

    let policy = path(&dir, "enterplace.policy.yaml");
    let unset = enterplace(
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
        &["key", "list", "--keys", &path(&dir, "enterplace.keys.yaml")],
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

#[test]
fn check_names_a_credential_the_store_does_not_hold() -> TestResult {
    let Some(url) = database("check_credential")? else {
        return Ok(());
    };
    let dir = workdir("check-credential")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    std::fs::write(
        &policy,
        POLICY.replace(
            "key_env: ENTERPLACE_TEST_PROVIDER_KEY",
            "credential: openai-prod",
        ),
    )?;
    let master = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let out = enterplace(
        &["check", &policy],
        &[("DATABASE_URL", &url), ("ENTERPLACE_MASTER_KEY", master)],
    )?;
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{said}");
    assert!(
        said.contains("credential \"openai-prod\", which is not in the store")
            && said.contains("POST /admin/credentials"),
        "{said}"
    );
    // Without the store's variable the names cannot be checked: a warning, not a failure.
    let out = enterplace(&["check", &policy], &[("DATABASE_URL", "")])?;
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("credential names were not checked"), "{said}");
    Ok(())
}

#[test]
fn start_in_a_container_with_database_url_keeps_its_admin_key_in_the_store_once() -> TestResult {
    // What a one-click deploy runs: the image's default command with a provider key and the platform's DATABASE_URL,
    // on a disk that a restart may wipe.
    let Some(url) = database("start")? else {
        return Ok(());
    };
    let dir =
        std::env::temp_dir().join(format!("enterplace-cli-store-{}-start", std::process::id()));
    let start = |dir: &Path| {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir)?;
        let dir = dir.display().to_string();
        ok(
            &["start", "--container", "--no-serve", "--dir", &dir],
            &[
                ("DATABASE_URL", url.as_str()),
                ("OPENAI_API_KEY", "sk-test"),
            ],
        )
    };
    let first = start(&dir)?;
    assert_eq!(
        first.matches("export ENTERPLACE_KEY=enterplace_").count(),
        1,
        "{first}"
    );
    assert!(first.contains("the store"), "{first}");
    let policy = std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?;
    assert!(
        policy.contains("store: { postgres_url_env: DATABASE_URL, policy_from: store }"),
        "{policy}"
    );
    let db = [("DATABASE_URL", url.as_str())];
    let listed = ok(
        &["key", "list", "--keys", &path(&dir, "enterplace.keys.yaml")],
        &db,
    )?;
    // The admin key is named after the OS user, so count by the admin column, not the name.
    let admins = |listed: &str| {
        listed
            .lines()
            .skip(1)
            .filter(|row| row.split('\t').nth(3) == Some("admin"))
            .count()
    };
    assert_eq!(admins(&listed), 1, "{listed}");

    // The disk is wiped (a redeploy on Render, App Platform or Cloud Run): the policy is written again, the store
    // already holds an admin key, so no second one is made or printed.
    let again = start(&dir)?;
    assert!(!again.contains("export ENTERPLACE_KEY="), "{again}");
    assert!(again.contains("enterplace key new"), "{again}");
    let listed = ok(
        &["key", "list", "--keys", &path(&dir, "enterplace.keys.yaml")],
        &db,
    )?;
    assert_eq!(admins(&listed), 1, "{listed}");
    Ok(())
}

#[test]
fn migrate_is_a_step_of_its_own_and_serve_no_migrate_changes_no_table() -> TestResult {
    let Some(db) = database("migrate")? else {
        return Ok(());
    };
    let url = db.as_str().to_string();
    let dir = workdir("migrate")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    let env = [
        ("DATABASE_URL", url.as_str()),
        ("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret"),
    ];
    let no_migrate = ["serve", &policy, "--listen", "127.0.0.1:0", "--no-migrate"];

    // A new database: a gateway told not to migrate refuses to start, names the step to run, and made no table.
    let out = enterplace(&no_migrate, &env)?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("enterplace store migrate") && stderr.contains("--no-migrate"),
        "{stderr}"
    );
    let tables = |url: &str| -> Result<i64, Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls).await?;
            tokio::spawn(connection);
            let row = client
                .query_one(
                    "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'",
                    &[],
                )
                .await?;
            Ok(row.try_get(0)?)
        })
    };
    assert_eq!(tables(&url)?, 0, "--no-migrate created a table");

    // The step of its own: every table, the lazily made ones included; a second run changes nothing.
    let said = ok(&["store", "migrate", "--policy", &policy], &env)?;
    assert!(said.contains("up to date"), "{said}");
    let made = tables(&url)?;
    assert!(made > 10, "{made} tables");
    ok(&["store", "migrate", "--policy", &policy], &env)?;
    assert_eq!(tables(&url)?, made);

    // Now the gateway starts without migrating, and still makes no table.
    let stdout = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .args(no_migrate)
        .envs(env)
        .stdout(std::fs::File::create(&stdout)?)
        .stderr(std::fs::File::create(dir.join("stderr.txt"))?)
        .spawn()?;
    let _running = Running(child);
    let start = Instant::now();
    while !std::fs::read_to_string(&stdout)
        .unwrap_or_default()
        .contains(" listening on http://")
    {
        if start.elapsed() > Duration::from_secs(10) {
            let stderr = std::fs::read_to_string(dir.join("stderr.txt")).unwrap_or_default();
            return Err(
                format!("serve --no-migrate did not start on a migrated store: {stderr}").into(),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(tables(&url)?, made);

    // Without a store there is nothing to migrate, and the command says so.
    std::fs::write(
        dir.join("plain.yaml"),
        POLICY.replace("store: { postgres_url_env: DATABASE_URL }\n", ""),
    )?;
    let out = enterplace(
        &["store", "migrate", "--policy", &path(&dir, "plain.yaml")],
        &env,
    )?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("no store: section"));
    Ok(())
}

#[test]
fn diagnose_writes_a_bundle_with_health_and_counts_and_no_secret() -> TestResult {
    let Some(url) = database("diagnose")? else {
        return Ok(());
    };
    let dir = workdir("diagnose")?;
    // The admin address serves /metrics, which diagnose reads when no --metrics is given.
    let admin_port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    std::fs::write(
        dir.join("enterplace.policy.yaml"),
        format!("{POLICY}admin_listen: 127.0.0.1:{admin_port}\n"),
    )?;
    let db = [("DATABASE_URL", url.as_str())];
    let keys = path(&dir, "enterplace.keys.yaml");
    let admin = ok(
        &[
            "key", "new", "ops", "--team", "payments", "--admin", "--quiet", "--keys", &keys,
        ],
        &db,
    )?;
    let admin = admin.trim().to_string();
    let (_running, addr) = serve(&dir, &url)?;
    chat(&addr, "enterplace_not_a_key_at_all_0000000000")?;
    chat(&addr, &admin)?;

    let bundle = path(&dir, "bundle.tar.gz");
    let said = ok(
        &[
            "diagnose",
            "--policy",
            &path(&dir, "enterplace.policy.yaml"),
            "--out",
            &bundle,
        ],
        &[
            ("DATABASE_URL", url.as_str()),
            ("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret"),
        ],
    )?;
    assert!(said.contains("no key, password or token"), "{said}");
    let unpacked = dir.join("unpacked");
    std::fs::create_dir_all(&unpacked)?;
    let tar = Command::new("tar")
        .args(["-xzf", &bundle, "-C", &unpacked.display().to_string()])
        .output()?;
    assert!(
        tar.status.success(),
        "{}",
        String::from_utf8_lossy(&tar.stderr)
    );
    let read =
        |name: &str| std::fs::read_to_string(unpacked.join("enterplace-diagnose").join(name));

    let version: serde_json::Value = serde_json::from_str(&read("version.json")?)?;
    assert_eq!(version["enterplace"], enterplace_core::VERSION);
    let store: serde_json::Value = serde_json::from_str(&read("store.json")?)?;
    assert_eq!(store["reachable"], true, "{store}");
    assert_eq!(store["schema"], "current", "{store}");
    assert_eq!(store["admin_keys"], 1, "{store}");
    let audit: serde_json::Value = serde_json::from_str(&read("audit.json")?)?;
    assert_eq!(audit["chain"]["intact"], true, "{audit}");
    let errors: serde_json::Value = serde_json::from_str(&read("errors.json")?)?;
    assert_eq!(errors["by_code"]["unknown_key"], 1, "{errors}");
    let config: serde_json::Value = serde_json::from_str(&read("config.json")?)?;
    assert_eq!(config["loaded"]["valid"], true, "{config}");
    assert_eq!(
        config["environment"]["ENTERPLACE_TEST_PROVIDER_KEY"], "set",
        "{config}"
    );
    assert!(
        read("metrics.txt")?.contains("enterplace_"),
        "{}",
        read("metrics.txt")?
    );

    // Nothing secret in any file: not a key, its hash, the provider's key or the store's password.
    let everything: String = [
        "version.json",
        "config.json",
        "store.json",
        "audit.json",
        "errors.json",
        "metrics.txt",
    ]
    .iter()
    .map(|f| read(f).unwrap_or_default())
    .collect();
    let hash = enterplace_core::id::sha256_hex(admin.as_bytes());
    // The test store's connection string is `host=... password='...' dbname=...`.
    let password = url
        .split(' ')
        .find(|part| part.starts_with("password="))
        .unwrap_or_default()
        .to_string();
    for secret in [
        admin.as_str(),
        &hash[8..],
        "provider-secret",
        url.as_str(),
        password.as_str(),
    ] {
        assert!(
            !secret.is_empty() && !everything.contains(secret),
            "{secret} is in the bundle"
        );
    }
    Ok(())
}
