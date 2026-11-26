//! Updates on the console's Health page, end to end against a release list served on localhost: only releases whose
//! SHA256SUMS the release key signed are offered, an update more than one minor version ahead is held back with the
//! version to stop at first, Update and Roll back are recorded in the audit log as admin records, and the steps are
//! the exact ones for this deployment.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

type Error = Box<dyn std::error::Error>;

/// The status, headers and body of one request over a plain socket.
fn http(
    addr: &str,
    method: &str,
    path: &str,
    extra: &str,
    body: &str,
) -> Result<(u16, String, String), Error> {
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    let code = text
        .get(9..12)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("no status in {text}"))?;
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    Ok((code, head.to_string(), body.to_string()))
}

fn ssh_keygen(args: &[&str], dir: &Path) -> Result<(), Error> {
    let out = Command::new("ssh-keygen")
        .args(args)
        .current_dir(dir)
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "ssh-keygen {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(())
}

/// A signed SHA256SUMS for `version`, as `scripts/signing.py sign` writes it.
fn signed(dir: &Path, version: &str) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let sums = format!(
        "{}  enterplace-{version}-abc-x86_64-unknown-linux-musl.tar.gz\n",
        "0".repeat(64)
    );
    let file = dir.join(format!("SUMS-{version}"));
    std::fs::write(&file, &sums)?;
    ssh_keygen(
        &[
            "-q",
            "-Y",
            "sign",
            "-f",
            "key",
            "-n",
            "enterplace-release",
            &format!("SUMS-{version}"),
        ],
        dir,
    )?;
    Ok((
        sums.into_bytes(),
        std::fs::read(dir.join(format!("SUMS-{version}.sig")))?,
    ))
}

/// Stops the gateway `enterplace start` ran in a folder, as `enterplace stop` does, when the test ends.
struct Stop(std::path::PathBuf);

impl Drop for Stop {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_enterplace"))
            .arg("stop")
            .arg("--dir")
            .arg(&self.0)
            .output();
    }
}

#[test]
fn health_offers_a_signed_release_one_step_at_a_time_and_records_update_and_rollback()
-> Result<(), Error> {
    let dir = std::env::temp_dir().join(format!("enterplace-update-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("gw"))?;
    ssh_keygen(
        &["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", "key"],
        &dir,
    )?;
    let public = std::fs::read_to_string(dir.join("key.pub"))?;
    let key: Vec<&str> = public.split_whitespace().take(2).collect();
    std::fs::write(
        dir.join("allowed_signers"),
        format!("release@enterplace {}\n", key.join(" ")),
    )?;

    let (major, minor) = {
        let v: Vec<u64> = env!("CARGO_PKG_VERSION")
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        (v[0], v[1])
    };
    let next = format!("{major}.{}.0", minor + 1);
    let tampered = format!("{major}.{}.1", minor + 1);
    let far = format!("{major}.{}.0", minor + 2);
    let digest = "c".repeat(64);
    let mut files = HashMap::new();
    let mut releases = vec![];
    for version in [&far, &tampered, &next] {
        let (sums, mut sig) = signed(&dir, version)?;
        if version == &tampered {
            // Signed, then changed: the signature no longer matches.
            sig = signed(&dir, &far)?.1;
        }
        files.insert(format!("/{version}/SHA256SUMS"), sums);
        files.insert(format!("/{version}/SHA256SUMS.sig"), sig);
    }
    // The release list names its files on the address it is served from.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    for version in [&far, &tampered, &next] {
        releases.push(json!({
            "tag_name": format!("v{version}"), "draft": false, "prerelease": false,
            "html_url": format!("https://github.com/eliransu/enterplace/releases/tag/v{version}"),
            "body": format!("Digest: `ghcr.io/eliransu/enterplace@sha256:{digest}` (amd64 and arm64).\n\n### Added\n\n- Updates from the console in {version}.\n- Another change.\n"),
            "assets": [
                { "name": "SHA256SUMS", "browser_download_url": format!("http://{addr}/{version}/SHA256SUMS") },
                { "name": "SHA256SUMS.sig", "browser_download_url": format!("http://{addr}/{version}/SHA256SUMS.sig") },
            ],
        }));
    }
    releases.push(json!({ "tag_name": "edge", "prerelease": true, "assets": [] }));
    files.insert("/releases".into(), serde_json::to_vec(&releases)?);
    serve(listener, files);

    let gw = dir.join("gw");
    let (_stop, _said, gateway, cookie) = start(
        &gw,
        &[
            ("ENTERPLACE_RELEASE_FEED", format!("http://{addr}/releases")),
            (
                "ENTERPLACE_ALLOWED_SIGNERS",
                dir.join("allowed_signers").display().to_string(),
            ),
            ("ENTERPLACE_DEPLOY_TARGET", "compose".into()),
        ],
    )?;

    let (status, _, body) = http(&gateway, "GET", "/console/api/updates", &cookie, "")?;
    assert_eq!(status, 200, "{body}");
    let view: Value = serde_json::from_str(&body)?;
    assert_eq!(view["running"], env!("CARGO_PKG_VERSION"));
    assert_eq!(view["newest"]["version"], far.as_str(), "{view}");
    assert_eq!(
        view["offer"]["version"],
        next.as_str(),
        "the one step every gateway can take: {view}"
    );
    assert!(
        view["held"].as_str().is_some_and(|h| h.contains("first")),
        "{view}"
    );
    assert!(
        view["skipped"].to_string().contains(&tampered)
            && view["skipped"]
                .to_string()
                .contains("changed after signing"),
        "a release whose signature fails is not offered: {view}"
    );
    let steps = &view["offer"]["steps"];
    assert_eq!(steps["label"], "Docker Compose");
    let command = steps["command"].as_str().unwrap_or_default();
    assert!(
        command.contains(&format!(
            "ENTERPLACE_IMAGE=ghcr.io/eliransu/enterplace:{next}@sha256:{digest}"
        )),
        "{command}"
    );
    assert!(
        steps["downtime"]
            .as_str()
            .unwrap_or_default()
            .contains("a few seconds"),
        "{steps}"
    );
    assert!(
        steps["agent"]
            .as_str()
            .unwrap_or_default()
            .contains("Goal: Update Enterplace from"),
        "{steps}"
    );
    assert_eq!(
        view["offer"]["summary"][0],
        format!("Updates from the console in {next}.")
    );
    assert_eq!(view["may_update"], true);

    let post = |payload: Value| {
        http(
            &gateway,
            "POST",
            "/console/api/updates",
            &format!("{cookie}Origin: http://{gateway}\r\nContent-Type: application/json\r\n"),
            &payload.to_string(),
        )
    };
    let (status, _, body) = post(json!({ "action": "update", "version": far }))?;
    assert_eq!(
        status, 409,
        "two minor versions at once cannot roll back: {body}"
    );
    assert!(body.contains("one minor version"), "{body}");
    let (status, _, body) = post(json!({ "action": "update", "version": next }))?;
    assert_eq!(status, 200, "{body}");
    let view: Value = serde_json::from_str(&body)?;
    assert_eq!(view["rollout"]["to"], next.as_str(), "{view}");
    assert_eq!(view["rollout"]["gateways"][0]["state"], "waiting", "{view}");
    assert!(
        view["rollout"]["rollback"]["steps"]["command"]
            .as_str()
            .is_some_and(|c| c.contains(&format!(
                "ENTERPLACE_IMAGE=ghcr.io/eliransu/enterplace:{}",
                env!("CARGO_PKG_VERSION")
            ))),
        "{view}"
    );
    let (status, _, body) = post(json!({ "action": "rollback" }))?;
    assert_eq!(status, 200, "{body}");

    let start = Instant::now();
    let audit = loop {
        let log = std::fs::read_to_string(gw.join("enterplace-audit.jsonl")).unwrap_or_default();
        if log.contains("\"rollback\"") || start.elapsed() > Duration::from_secs(10) {
            break log;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let records: Vec<Value> = audit
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let find = |action: &str, refused: bool| {
        records.iter().find(|r| {
            r["event"] == "admin"
                && r.to_string().contains(&format!("\"{action}\""))
                && (r["verdict"] == "refused") == refused
        })
    };
    let update = find("update", false).ok_or_else(|| format!("no update record in {audit}"))?;
    assert!(update.to_string().contains(&next), "{update}");
    assert!(
        find("update", true).is_some(),
        "the refused update is recorded too: {audit}"
    );
    assert!(find("rollback", false).is_some(), "{audit}");
    Ok(())
}

/// Serves `files` by path until the test ends.
fn serve(listener: TcpListener, files: HashMap<String, Vec<u8>>) {
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
            let (status, body) = match files.get(&path) {
                Some(body) => ("200 OK", body.clone()),
                None => ("404 Not Found", b"missing".to_vec()),
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(&body);
        }
    });
}

/// Runs `enterplace start` in `gw` with `env`, and signs in to its console with the admin key it prints. The gateway
/// stops when the first value is dropped; the second keeps its output open until then.
fn start(
    gw: &Path,
    env: &[(&str, String)],
) -> Result<
    (
        Stop,
        std::io::BufReader<std::process::ChildStdout>,
        String,
        String,
    ),
    Error,
> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .args(["start", "--dir"])
        .arg(gw)
        .args(["--listen", "127.0.0.1:0", "--no-open"])
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let _stop = Stop(gw.to_path_buf());
    let mut said = std::io::BufReader::new(child.stdout.take().ok_or("no stdout")?);
    let mut text = String::new();
    {
        use std::io::BufRead;
        for line in (&mut said).lines() {
            let line = line?;
            text.push_str(&line);
            text.push('\n');
            if line.contains("listening on") {
                break;
            }
        }
    }
    let admin = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("export ENTERPLACE_KEY="))
        .ok_or_else(|| format!("no admin key in {text}"))?
        .to_string();
    let gateway = text
        .lines()
        .find_map(|l| l.split_once(" listening on http://"))
        .map(|(_, a)| a.trim().to_string())
        .ok_or_else(|| format!("no address in {text}"))?;

    let (status, head, _) = http(
        &gateway,
        "POST",
        "/console/sign-in",
        &format!("Origin: http://{gateway}\r\nContent-Type: application/x-www-form-urlencoded\r\n"),
        &format!("key={admin}"),
    )?;
    assert!(status == 303 || status == 302, "{status} {head}");
    let cookie = head
        .lines()
        .find_map(|l| {
            l.strip_prefix("set-cookie: ")
                .or_else(|| l.strip_prefix("Set-Cookie: "))
        })
        .and_then(|c| c.split(';').next())
        .ok_or("no session cookie")?
        .to_string();
    let cookie = format!("Cookie: {cookie}\r\n");
    Ok((_stop, said, gateway, cookie))
}

#[test]
fn with_the_release_list_out_of_reach_nothing_is_offered_and_nothing_fails() -> Result<(), Error> {
    let gw = std::env::temp_dir().join(format!("enterplace-update-offline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&gw);
    std::fs::create_dir_all(&gw)?;
    // Port 9 (discard) answers nothing here: the network is closed.
    let (_stop, _said, gateway, cookie) = start(
        &gw,
        &[(
            "ENTERPLACE_RELEASE_FEED",
            "http://127.0.0.1:9/releases".into(),
        )],
    )?;
    let (status, _, body) = http(&gateway, "GET", "/console/api/updates", &cookie, "")?;
    assert_eq!(status, 200, "{body}");
    let view: Value = serde_json::from_str(&body)?;
    assert!(
        view["offer"].is_null() && view["newest"].is_null(),
        "{view}"
    );
    assert!(
        view["check"]
            .as_str()
            .unwrap_or_default()
            .contains("could not be read"),
        "{view}"
    );
    // Turned off, it does not look at all.
    drop((_stop, _said));
    let off = gw.join("off");
    std::fs::create_dir_all(&off)?;
    let (_stop, _said, gateway, cookie) =
        start(&off, &[("ENTERPLACE_UPDATE_CHECK", "off".into())])?;
    let (_, _, body) = http(&gateway, "GET", "/console/api/updates", &cookie, "")?;
    let view: Value = serde_json::from_str(&body)?;
    assert!(
        view["check"].as_str().unwrap_or_default().contains("off"),
        "{view}"
    );
    assert!(view["offer"].is_null(), "{view}");
    Ok(())
}
