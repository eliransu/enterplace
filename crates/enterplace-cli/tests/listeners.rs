//! `admin_listen:` (or `--admin-listen`): the console, the admin API and /metrics get an address of their own, and
//! the address callers use serves the model routes alone.

use std::{
    io::{Read, Write},
    process::Command,
    time::{Duration, Instant},
};

type Error = Box<dyn std::error::Error>;

struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The status code and body of a GET over a plain socket.
fn get(addr: &str, path: &str) -> Result<(u16, String), Error> {
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: enterplace\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    let code = text
        .get(9..12)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("no status in {text}"))?;
    Ok((code, text))
}

fn serve(
    name: &str,
    policy_extra: &str,
    args: &[&str],
) -> Result<(Running, String, String), Error> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-listeners-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(
        &policy,
        format!(
            "version: 1\n{policy_extra}providers:\n  - name: mock\n    kind: openai\n    url: http://127.0.0.1:9\n    allow_private: true\n    key_env: ENTERPLACE_TEST_PROVIDER_KEY\n    models: [model-a]\nrules:\n  - name: ops\n    principals: {{ team: ops }}\n    models: [model-a]\n"
        ),
    )?;
    let stdout = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .arg("serve")
        .arg(&policy)
        .args(["--listen", "127.0.0.1:0"])
        .args(args)
        .current_dir(&dir)
        .env("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret")
        .stdout(std::fs::File::create(&stdout)?)
        .stderr(std::fs::File::create(dir.join("stderr.txt"))?)
        .spawn()?;
    let running = Running(child);
    let start = Instant::now();
    loop {
        let text = std::fs::read_to_string(&stdout).unwrap_or_default();
        let model = text
            .lines()
            .find_map(|l| l.split_once(" listening on http://"))
            .map(|(_, addr)| addr.trim().to_string());
        let admin = text
            .lines()
            .find(|l| l.starts_with("Admin:"))
            .and_then(|l| l.split_once("served on http://"))
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .map(str::to_string);
        // The audit line comes after both addresses were printed.
        if let (Some(model), true) = (&model, text.contains("Audit log:")) {
            return Ok((running, model.clone(), admin.unwrap_or_default()));
        }
        if start.elapsed() > Duration::from_secs(10) {
            let stderr = std::fs::read_to_string(dir.join("stderr.txt")).unwrap_or_default();
            return Err(format!("the server never said where it listens: {text} {stderr}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn split(model: &str, admin: &str) -> Result<(), Error> {
    assert!(!admin.is_empty() && admin != model, "{model} {admin}");
    // The address callers use: model routes and health checks, and no admin surface at all.
    assert_eq!(get(model, "/healthz")?.0, 200);
    // No key: refused by the gateway itself, so the route is served here.
    assert_eq!(get(model, "/v1/models")?.0, 401);
    for path in ["/console", "/console/sign-in", "/admin/keys", "/metrics"] {
        let (status, text) = get(model, path)?;
        assert_eq!(status, 404, "{path}: {text}");
        assert!(text.contains("not_on_this_listener"), "{path}: {text}");
        assert!(
            !text.contains(admin),
            "the admin address is not given away: {text}"
        );
    }
    // The admin address: the console, the admin API, metrics and health, and no model route.
    assert_eq!(get(admin, "/console/sign-in")?.0, 200);
    assert_eq!(get(admin, "/admin/keys")?.0, 401);
    let (status, metrics) = get(admin, "/metrics")?;
    assert_eq!(status, 200, "{metrics}");
    assert!(metrics.contains("enterplace_"), "{metrics}");
    assert_eq!(get(admin, "/healthz")?.0, 200);
    for path in ["/v1/models", "/v1/chat/completions", "/mcp"] {
        let (status, text) = get(admin, path)?;
        assert_eq!(status, 404, "{path}: {text}");
        assert!(text.contains("not_on_this_listener"), "{path}: {text}");
    }
    Ok(())
}

#[test]
fn the_policy_gives_the_console_and_admin_api_an_address_of_their_own() -> Result<(), Error> {
    let (_running, model, admin) = serve("policy", "admin_listen: 127.0.0.1:0\n", &[])?;
    split(&model, &admin)
}

#[test]
fn the_flag_does_the_same_and_without_either_one_address_serves_everything() -> Result<(), Error> {
    let (_running, model, admin) = serve("flag", "", &["--admin-listen", "127.0.0.1:0"])?;
    split(&model, &admin)?;
    let (_running, model, admin) = serve("one", "", &[])?;
    assert_eq!(admin, "");
    assert_eq!(get(&model, "/console/sign-in")?.0, 200);
    assert_eq!(get(&model, "/admin/keys")?.0, 401);
    assert_eq!(get(&model, "/v1/models")?.0, 401);
    Ok(())
}

#[test]
fn an_admin_address_that_is_not_one_or_is_taken_stops_the_start() -> Result<(), Error> {
    let dir = std::env::temp_dir().join(format!("enterplace-listeners-{}-bad", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(
        &policy,
        "version: 1\nadmin_listen: console.internal\nproviders: []\nrules: []\n",
    )?;
    let out = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .arg("check")
        .arg(&policy)
        .output()?;
    let said = String::from_utf8(out.stdout)? + &String::from_utf8(out.stderr)?;
    assert!(
        said.contains("admin_listen") && said.contains("127.0.0.1:9090"),
        "{said}"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .arg("serve")
        .arg(&policy)
        .args([
            "--listen",
            "127.0.0.1:8099",
            "--admin-listen",
            "127.0.0.1:8099",
        ])
        .output()?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("port of their own"));
    Ok(())
}
