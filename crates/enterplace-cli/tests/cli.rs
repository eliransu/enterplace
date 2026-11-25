//! The `enterplace` binary: every argument form either does what it says or fails with exit code 2 and the reason.

use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

#[test]
fn version_prints_the_version_the_source_hash_and_the_build_date() -> TestResult {
    // BLK-1: two builds of one version must be told apart in a bug report, and there is no git to ask.
    for arg in ["version", "--version"] {
        let out = enterplace(&[arg], &[])?;
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout)?;
        let rest = text
            .trim()
            .strip_prefix(&format!("enterplace {} (src ", env!("CARGO_PKG_VERSION")))
            .ok_or(format!("{arg}: {text}"))?;
        let (hash, date) = rest
            .strip_suffix(')')
            .and_then(|r| r.split_once(", built "))
            .ok_or(format!("{arg}: {text}"))?;
        assert!(
            hash.len() == 12 && hash.chars().all(|c| c.is_ascii_hexdigit()),
            "{text}"
        );
        let bytes = date.as_bytes();
        assert!(
            date.len() == 10 && bytes[4] == b'-' && bytes[7] == b'-',
            "{text}"
        );
    }
    Ok(())
}

#[test]
fn an_unknown_argument_is_an_error_not_ignored() -> TestResult {
    // UX11 n12: no command at all is an error too.
    let out = enterplace(&[], &[])?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(stderr.contains("Usage: enterplace <command>"));
    // A newcomer who types `enterplace` alone sees the one command to run first, before the other thirty.
    let (start, check) = (
        stderr.find("\n  start [").ok_or("start")?,
        stderr.find("\n  check <policy>").ok_or("check")?,
    );
    assert!(
        start < check && stderr.contains("New here? Run `enterplace start`"),
        "{stderr}"
    );
    for args in [
        &["serve", "--port", "1"][..],
        &["serve", "--unchecked", "extra"],
        &["sirve"],
        &["serve", "policy.yaml", "--listen"],
        &["check"],
        &["key", "new", "maya"],
        &["audit", "verify", "a", "b"],
        &["version", "now"],
    ] {
        let out = enterplace(args, &[])?;
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8(out.stderr)?;
        assert!(
            stderr.contains("is not a command Enterplace knows")
                || stderr.contains("Usage: enterplace "),
            "{args:?}: {stderr}"
        );
    }
    Ok(())
}

#[test]
fn serve_refuses_to_forward_unchecked_unless_asked_by_name() -> TestResult {
    let out = enterplace(&["serve"], &[])?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("enterplace serve enterplace.policy.yaml")
            && stderr.contains("enterplace serve --unchecked"),
        "the error must say how to proceed: {stderr}"
    );
    Ok(())
}

#[test]
fn unchecked_serving_is_refused_on_an_address_other_machines_can_reach() -> TestResult {
    let out = enterplace(
        &["serve", "--unchecked"],
        &[("ENTERPLACE_ADDR", "0.0.0.0:18099")],
    )?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("loopback"));
    Ok(())
}

#[test]
fn a_bad_address_or_upstream_stops_startup_with_the_reason() -> TestResult {
    let out = enterplace(&["serve", "--unchecked"], &[("ENTERPLACE_ADDR", "nope")])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("ENTERPLACE_ADDR"));
    // UX3-19: a host name gets the IP address to use instead.
    let out = enterplace(
        &["serve", "--unchecked"],
        &[("ENTERPLACE_ADDR", "localhost:20461")],
    )?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(stderr.contains("use 127.0.0.1:20461"), "{stderr}");

    let out = enterplace(
        &["serve", "--unchecked"],
        &[("ENTERPLACE_UPSTREAM", "http://user:S3cret@127.0.0.1:9")],
    )?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("ENTERPLACE_UPSTREAM") && !stderr.contains("S3cret"),
        "{stderr}"
    );
    Ok(())
}

const POLICY: &str = "\
version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:9
    allow_private: true
    key_env: ENTERPLACE_TEST_PROVIDER_KEY
    models: [model-a, model-b]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [model-a]
";

fn workdir(name: &str) -> std::io::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("enterplace-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("enterplace.policy.yaml"), POLICY)?;
    Ok(dir)
}

fn path(dir: &std::path::Path, file: &str) -> String {
    dir.join(file).display().to_string()
}

#[test]
fn check_names_the_line_and_the_word_and_exits_1() -> TestResult {
    let dir = workdir("check")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    let out = enterplace(&["check", &policy], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(String::from_utf8(out.stdout)?.contains("is valid: 1 rule, 0 keys"));

    std::fs::write(&policy, POLICY.replace("    models:", "    modles:"))?;
    let out = enterplace(&["check", &policy], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("enterplace.policy.yaml:12") && stderr.contains("Did you mean \"models\"?"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn a_new_key_is_printed_once_and_only_its_hash_is_saved() -> TestResult {
    let dir = workdir("key")?;
    let keys = path(&dir, "enterplace.keys.yaml");
    let mut printed = Vec::new();
    for name in ["maya.cohen", "svc-invoice-bot"] {
        let out = enterplace(
            &["key", "new", name, "--team", "payments", "--keys", &keys],
            &[],
        )?;
        assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
        let stdout = String::from_utf8(out.stdout)?;
        let key = stdout
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("enterplace_"))
            .ok_or("no key was printed")?
            .to_string();
        assert_eq!(key.len(), "enterplace_".len() + 64);
        printed.push(key);
    }
    let saved = std::fs::read_to_string(&keys)?;
    for key in &printed {
        assert!(!saved.contains(key), "the key itself was saved");
        assert!(saved.contains(&enterplace_core::id::sha256_hex(key.as_bytes())));
    }
    let out = enterplace(&["check", &path(&dir, "enterplace.policy.yaml")], &[])?;
    assert!(String::from_utf8(out.stdout)?.contains("2 keys"));

    let out = enterplace(
        &[
            "key", "new", "bad name", "--team", "payments", "--keys", &keys,
        ],
        &[],
    )?;
    assert_eq!(out.status.code(), Some(2));
    Ok(())
}

#[test]
fn serve_refuses_to_start_on_a_bad_file_a_missing_provider_key_or_a_broken_audit_log() -> TestResult
{
    let dir = workdir("serve")?;
    let policy = path(&dir, "enterplace.policy.yaml");

    let out = enterplace(&["serve", &path(&dir, "missing.yaml")], &[])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("cannot be read"));

    let out = enterplace(&["serve", &policy], &[])?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("export ENTERPLACE_TEST_PROVIDER_KEY="),
        "{stderr}"
    );

    std::fs::write(dir.join("enterplace-audit.jsonl"), "{\"n\":1,\"cut")?;
    let secret = [("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret-1234")];
    let out = enterplace(&["serve", &policy], &secret)?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("enterplace audit verify") && !stderr.contains("provider-secret"),
        "{stderr}"
    );

    std::fs::remove_file(dir.join("enterplace-audit.jsonl"))?;
    let out = enterplace(&["serve", &policy, "--listen", "nope"], &secret)?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("--listen"));
    Ok(())
}

#[test]
fn audit_verify_reports_the_count_or_the_first_broken_record() -> TestResult {
    let dir = workdir("audit")?;
    let log_path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B"] {
        log.append(&enterplace_core::audit::Entry {
            id,
            method: "POST",
            path: "/v1/chat/completions",
            ..Default::default()
        })?;
    }
    let file = log_path.display().to_string();
    let out = enterplace(&["audit", "verify", &file], &[])?;
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)?.contains("2 records"));

    std::fs::write(
        &log_path,
        std::fs::read_to_string(&log_path)?.replacen("\"id\":\"A\"", "\"id\":\"Z\"", 1),
    )?;
    let out = enterplace(&["audit", "verify", &file], &[])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)?.contains("record 1"));
    Ok(())
}

#[test]
fn audit_coverage_counts_requests_per_person_and_tool_and_names_who_was_not_seen() -> TestResult {
    let dir = workdir("coverage")?;
    let log_path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&log_path)?;
    let request = |id, person, user_agent, allowed| enterplace_core::audit::Entry {
        id,
        person: Some(person),
        team: Some("payments"),
        user_agent,
        allowed,
        method: "POST",
        path: "/v1/messages",
        ..Default::default()
    };
    for entry in [
        request("A", "ana", Some("claude-cli/2.0.14 (external, cli)"), true),
        request("B", "ana", Some("claude-cli/2.0.14 (external, cli)"), false),
        request(
            "C",
            "ana",
            Some("codex_cli_rs/0.46.0 (Mac OS 26.0; arm64)"),
            true,
        ),
        request("D", "ben", Some("OpenAI/JS 5.20.0"), true),
        request("E", "ben", None, true),
    ] {
        log.append(&entry)?;
    }
    // An admin record has a verdict too, and is not a request.
    let mut admin = serde_json::Map::new();
    admin.insert("event".into(), "admin".into());
    admin.insert("person".into(), "ana".into());
    admin.insert("verdict".into(), "allow".into());
    log.append_record(&admin)?;
    // A usage record is not a request and is not counted.
    let mut usage = serde_json::Map::new();
    usage.insert("usage_of".into(), "A".into());
    log.append_record(&usage)?;
    drop(log);
    let keys = path(&dir, "enterplace.keys.yaml");
    for name in ["ana", "cara"] {
        let out = enterplace(
            &[
                "key", "new", name, "--team", "payments", "--keys", &keys, "--quiet",
            ],
            &[],
        )?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let file = log_path.display().to_string();
    let out = enterplace(&["audit", "coverage", &file, "--keys", &keys], &[])?;
    let text = String::from_utf8(out.stdout)?;
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: Vec<Vec<&str>> = text.lines().map(|l| l.split('\t').collect()).collect();
    let row = |person: &str, tool: &str| {
        rows.iter()
            .find(|r| r.first() == Some(&person) && r.get(2) == Some(&tool))
            .map(|r| r[3..5].join(" "))
    };
    assert_eq!(
        rows.first().map(|r| r.join(" ")).as_deref(),
        Some("person team tool requests refused last_seen")
    );
    assert_eq!(row("ana", "claude-code").as_deref(), Some("2 1"), "{text}");
    assert_eq!(row("ana", "codex").as_deref(), Some("1 0"), "{text}");
    // A tool Enterplace does not know by name is shown by the product in its user agent, here an SDK.
    assert_eq!(row("ben", "OpenAI/JS").as_deref(), Some("1 0"), "{text}");
    assert_eq!(row("ben", "unknown").as_deref(), Some("1 0"), "{text}");
    // Holds a key, sent nothing.
    assert_eq!(row("cara", "-").as_deref(), Some("0 0"), "{text}");
    assert!(text.contains("cara\tpayments\t-\t0\t0\tnever"), "{text}");
    Ok(())
}

#[test]
fn audit_coverage_with_device_reports_counts_devices_and_tools_going_direct() -> TestResult {
    let dir = workdir("coverage-devices")?;
    let log_path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&log_path)?;
    log.append(&enterplace_core::audit::Entry {
        id: "A",
        person: Some("ana"),
        team: Some("payments"),
        user_agent: Some("claude-cli/2.0.14 (external, cli)"),
        allowed: true,
        method: "POST",
        path: "/v1/messages",
        ..Default::default()
    })?;
    drop(log);
    // As the console's Devices page downloads it (devices.json).
    let devices = dir.join("devices.json");
    std::fs::write(
        &devices,
        serde_json::json!([
            {"person": "ana", "team": "payments", "device_id": "mbp:ana", "hostname": "mbp", "last_seen": "2026-11-14T06:00:00Z",
             "tools": [{"tool": "claude-code", "state": "enterplace"}, {"tool": "codex", "state": "direct", "endpoints": ["https://api.openai.com/v1"]}],
             "os": "macos", "apps": [{"app": "chatgpt", "status": "denied", "running": true}, {"app": "cursor", "status": "allowed"}], "mcp": [
                {"tool": "cursor", "server": "github", "transport": "http", "target": "https://api.githubcopilot.com/mcp", "via_enterplace": false, "decision": "blocked"},
                {"tool": "claude-code", "server": "enterplace", "transport": "http", "target": "https://gw.example.com/mcp", "via_enterplace": true, "decision": "pending"}]},
            {"person": "ana", "team": "payments", "device_id": "air:ana", "hostname": "air", "last_seen": "2026-11-14T06:00:00Z",
             "tools": [{"tool": "codex", "state": "installed"}]},
            {"person": "dan", "team": "web", "device_id": "pc:dan", "hostname": "pc", "last_seen": "2026-11-14T06:00:00Z",
             "tools": [{"tool": "cursor", "state": "not_installed"}]}
        ])
        .to_string(),
    )?;
    let out = enterplace(
        &[
            "audit",
            "coverage",
            &log_path.display().to_string(),
            "--devices",
            &devices.display().to_string(),
        ],
        &[],
    )?;
    let text = String::from_utf8(out.stdout)?;
    assert!(
        out.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some("person\tteam\ttool\trequests\trefused\tlast_seen\tdevices\tdirect")
    );
    // Seen in traffic and configured for Enterplace on one device.
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("ana\tpayments\tclaude-code\t1\t0\t") && l.ends_with("\t1\t0")),
        "{text}"
    );
    // Never reached Enterplace: installed on two devices, going to OpenAI directly on one.
    assert!(
        lines.contains(&"ana\tpayments\tcodex\t0\t0\tnever\t2\t1"),
        "{text}"
    );
    // An enrolled device with no tool installed still shows the person.
    assert!(lines.contains(&"dan\tweb\t-\t0\t0\tnever\t1\t0"), "{text}");
    // Per person: tools through Enterplace, tools going direct, denied apps, blocked MCP servers still configured.
    assert!(
        lines.contains(&"person\tteam\tvia_enterplace\tdirect\tdenied_apps\tblocked_mcp"),
        "{text}"
    );
    assert!(
        lines.contains(
            &"ana\tpayments\tclaude-code\tcodex on mbp\tchatgpt on mbp\tgithub in cursor on mbp"
        ),
        "{text}"
    );
    assert!(lines.contains(&"dan\tweb\t-\t-\t-\t-"), "{text}");
    // Then each device's MCP servers, and whether each goes through Enterplace.
    assert!(
        lines.contains(
            &"device\tperson\tos\ttool\tserver\ttransport\ttarget\tvia_enterplace\tdecision"
        ),
        "{text}"
    );
    assert!(
        lines.contains(&"mbp:ana\tana\tmacos\tcursor\tgithub\thttp\thttps://api.githubcopilot.com/mcp\tno\tblocked"),
        "{text}"
    );
    assert!(
        lines.contains(&"mbp:ana\tana\tmacos\tclaude-code\tenterplace\thttp\thttps://gw.example.com/mcp\tyes\tpending"),
        "{text}"
    );

    std::fs::write(&devices, "not json")?;
    let out = enterplace(
        &[
            "audit",
            "coverage",
            &log_path.display().to_string(),
            "--devices",
            &devices.display().to_string(),
        ],
        &[],
    )?;
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("devices.json"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn audit_verify_says_what_was_retired_and_that_the_rest_holds() -> TestResult {
    let dir = workdir("audit-retired")?;
    let log_path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B", "C"] {
        log.append(&enterplace_core::audit::Entry {
            id,
            ..Default::default()
        })?;
    }
    log.seal()?;
    log.append(&enterplace_core::audit::Entry {
        id: "D",
        ..Default::default()
    })?;
    enterplace_core::audit::retire(&log, &log_path, 3)?;
    log.flush();
    let file = log_path.display().to_string();
    let out = enterplace(&["audit", "verify", &file], &[])?;
    let text = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains("2 records in an unbroken chain from record 4 to record 5"),
        "{text}"
    );
    assert!(
        text.contains("Records 1 to 3 were retired on purpose: record 5 (audit_retired"),
        "{text}"
    );
    Ok(())
}

#[test]
fn audit_repair_shows_then_removes_only_a_cut_last_line_and_records_it() -> TestResult {
    // QA10-11: a write that failed on a full disk leaves a cut last line, and serve refuses to start on it.
    let dir = workdir("repair")?;
    let log_path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B"] {
        log.append(&enterplace_core::audit::Entry {
            id,
            method: "POST",
            path: "/v1/chat/completions",
            ..Default::default()
        })?;
    }
    drop(log);
    let file = log_path.display().to_string();
    let whole = std::fs::read(&log_path)?;
    let mut cut = whole.clone();
    cut.extend_from_slice(b"{\"n\":3,\"id\":\"C\",\"pa");
    std::fs::write(&log_path, &cut)?;

    // The start refuses and names the exact command.
    let err = enterplace_core::audit::AuditLog::open(&log_path)
        .err()
        .ok_or("a cut log was opened")?;
    assert!(
        err.contains(&format!("enterplace audit repair {file}")),
        "{err}"
    );

    // Without --yes it only shows what it would remove.
    let out = enterplace(&["audit", "repair", &file], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        stdout.contains("\"id\":\"C\",\"pa") && stdout.contains("--yes"),
        "{stdout}"
    );
    assert_eq!(std::fs::read(&log_path)?, cut);

    let out = enterplace(&["audit", "repair", &file, "--yes"], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let text = std::fs::read_to_string(&log_path)?;
    assert!(text.starts_with(std::str::from_utf8(&whole)?));
    let last = text.lines().last().ok_or("no last line")?;
    for field in [
        r#""event":"audit_repaired""#,
        r#""removed_bytes":19"#,
        r#""removed_text":"{\"n\":3,\"id\":\"C\",\"pa""#,
    ] {
        assert!(last.contains(field), "{field} missing from {last}");
    }
    let out = enterplace(&["audit", "verify", &file], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(String::from_utf8(out.stdout)?.contains("3 records"));

    // A whole log has nothing to repair, and a broken record that is not the last line is never removed.
    let out = enterplace(&["audit", "repair", &file, "--yes"], &[])?;
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)?.contains("nothing to repair"));
    std::fs::write(
        &log_path,
        format!(
            "{}{{\"n\":9,\"cut",
            text.replacen("\"id\":\"A\"", "\"id\":\"Z\"", 1)
        ),
    )?;
    let before = std::fs::read(&log_path)?;
    let out = enterplace(&["audit", "repair", &file, "--yes"], &[])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)?.contains("record 1"));
    assert_eq!(std::fs::read(&log_path)?, before);

    // UX11 n8: a record changed in the middle, last line whole. Repair is not "nothing to do": it fails and says why.
    std::fs::write(&log_path, text.replacen("\"id\":\"B\"", "\"id\":\"Y\"", 1))?;
    let before = std::fs::read(&log_path)?;
    let out = enterplace(&["audit", "repair", &file, "--yes"], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("record 2") && stderr.contains("only removes a last line cut short"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(&log_path)?, before);

    // Verify on a cut last line points at repair; on a folder it says it is a folder, not a broken record.
    std::fs::write(&log_path, &cut)?;
    let out = enterplace(&["audit", "verify", &file], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains(&format!("enterplace audit repair {file}")),
        "{stderr}"
    );
    let folder = dir.display().to_string();
    let out = enterplace(&["audit", "verify", &folder], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("is a folder, not an audit log") && !stderr.contains("record 1"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn key_new_never_replaces_a_keys_file_it_cannot_read() -> TestResult {
    let dir = workdir("unreadable")?;
    let keys = dir.join("enterplace.keys.yaml");
    // One byte that is not text: the file exists, holds keys, and cannot be read as text.
    let mut original = b"keys:\n  - name: a\n    team: t\n    sha256: ".to_vec();
    original.extend(enterplace_core::id::sha256_hex(b"k").as_bytes());
    original.extend(b"\n# \xff\n");
    std::fs::write(&keys, &original)?;
    let out = enterplace(
        &[
            "key",
            "new",
            "maya",
            "--team",
            "payments",
            "--keys",
            &keys.display().to_string(),
        ],
        &[],
    )?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("cannot be read"));
    assert_eq!(std::fs::read(&keys)?, original, "the keys file was changed");

    let out = enterplace(&["check", &path(&dir, "enterplace.policy.yaml")], &[])?;
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unreadable keys file passed as an empty one"
    );
    Ok(())
}

#[test]
fn check_lists_every_unknown_key_at_once() -> TestResult {
    let dir = workdir("many")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    std::fs::write(
        &policy,
        POLICY.replace(
            "    models: [model-a]",
            "    modles: [model-a]\n    colour: blue\n    principls: { taem: x }",
        ),
    )?;
    let out = enterplace(&["check", &policy], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    for expected in [
        "\"modles\"",
        "\"colour\"",
        "\"principls\"",
        "\"taem\"",
        "4 problems",
    ] {
        assert!(stderr.contains(expected), "missing {expected}: {stderr}");
    }
    Ok(())
}

#[test]
fn key_new_does_not_add_to_a_keys_file_enterplace_could_not_load() -> TestResult {
    let dir = workdir("unparseable")?;
    let keys = dir.join("enterplace.keys.yaml");
    for broken in [
        "keys: [oops\n",
        "keys:\n  - name: a\n    team: t\n    sha256: abc\n",
    ] {
        std::fs::write(&keys, broken)?;
        let out = enterplace(
            &[
                "key",
                "new",
                "maya",
                "--team",
                "payments",
                "--keys",
                &keys.display().to_string(),
            ],
            &[],
        )?;
        assert_eq!(out.status.code(), Some(2), "{broken:?}");
        let stderr = String::from_utf8(out.stderr)?;
        assert!(stderr.contains("no key was added"), "{broken:?}: {stderr}");
        assert_eq!(
            std::fs::read_to_string(&keys)?,
            broken,
            "the file was changed"
        );
    }
    Ok(())
}

#[test]
fn a_quoted_key_is_judged_like_an_unquoted_one() -> TestResult {
    let dir = workdir("quoted")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    std::fs::write(
        &policy,
        POLICY.replace("    models: [model-a]", "    \"modles\": [model-a]"),
    )?;
    let out = enterplace(&["check", &policy], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("\"modles\"") && stderr.contains("Did you mean \"models\"?"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn key_new_starts_the_list_in_a_file_that_has_none_yet() -> TestResult {
    let dir = workdir("empty-list")?;
    for (i, start) in [
        "# our keys\n",
        "keys: []\n",
        "# our keys\nkeys: []  # none yet\n",
    ]
    .iter()
    .enumerate()
    {
        let keys = dir.join(format!("keys-{i}.yaml"));
        std::fs::write(&keys, start)?;
        let out = enterplace(
            &[
                "key",
                "new",
                "maya",
                "--team",
                "payments",
                "--keys",
                &keys.display().to_string(),
            ],
            &[],
        )?;
        assert!(
            out.status.success(),
            "{start:?}: {}",
            String::from_utf8(out.stderr)?
        );
        let out = enterplace(
            &[
                "check",
                &path(&dir, "enterplace.policy.yaml"),
                "--keys",
                &keys.display().to_string(),
            ],
            &[],
        )?;
        assert!(
            String::from_utf8(out.stdout)?.contains("1 key,"),
            "{start:?}"
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_new_keys_file_is_private_and_no_temporary_file_is_left() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let dir = workdir("private")?;
    let keys = dir.join("enterplace.keys.yaml");
    let out = enterplace(
        &[
            "key",
            "new",
            "maya",
            "--team",
            "payments",
            "--keys",
            &keys.display().to_string(),
        ],
        &[],
    )?;
    assert!(out.status.success());
    assert_eq!(
        std::fs::metadata(&keys)?.permissions().mode() & 0o777,
        0o600
    );
    let left: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
    Ok(())
}

#[test]
fn audit_verify_prints_the_hash_of_the_last_record() -> TestResult {
    let dir = workdir("lasthash")?;
    let log_path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B", "C"] {
        log.append(&enterplace_core::audit::Entry {
            id,
            method: "POST",
            path: "/v1/chat/completions",
            ..Default::default()
        })?;
    }
    let text = std::fs::read_to_string(&log_path)?;
    let last = text.lines().last().ok_or("empty log")?;
    let hash = &last[last.len() - 66..last.len() - 2];
    let out = enterplace(&["audit", "verify", &log_path.display().to_string()], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(stdout.contains(&format!("Last hash: {hash}")), "{stdout}");
    assert!(stdout.contains("3 records"), "{stdout}");
    Ok(())
}

#[test]
fn serve_does_not_start_on_an_audit_log_with_a_record_missing() -> TestResult {
    let dir = workdir("gap")?;
    let log_path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B", "C"] {
        log.append(&enterplace_core::audit::Entry {
            id,
            method: "POST",
            path: "/v1/chat/completions",
            ..Default::default()
        })?;
    }
    drop(log);
    // The middle record is removed. The last record is whole, so only a full check sees the gap.
    let text = std::fs::read_to_string(&log_path)?;
    let kept: String = text
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, l)| format!("{l}\n"))
        .collect();
    std::fs::write(&log_path, kept)?;
    let out = enterplace(
        &["serve", &path(&dir, "enterplace.policy.yaml")],
        &[("ENTERPLACE_TEST_PROVIDER_KEY", "k")],
    )?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("record 2") && stderr.contains("does not start"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn check_warns_without_failing_on_a_rule_model_no_provider_serves() -> TestResult {
    let dir = workdir("unserved")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    std::fs::write(
        &policy,
        POLICY.replace(
            "    models: [model-a]\n",
            "    models: [model-a, model-z]\n",
        ),
    )?;
    let out = enterplace(&["check", &policy], &[])?;
    let stderr = String::from_utf8(out.stderr)?;
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("warning")
            && stderr.contains("enterplace.policy.yaml:12")
            && stderr.contains("\"model-z\""),
        "{stderr}"
    );
    let out = enterplace(&["check", &path(&dir, "enterplace.policy.yaml")], &[])?;
    assert!(String::from_utf8(out.stdout)?.contains("is valid"));
    Ok(())
}

#[test]
fn key_new_says_the_key_works_within_two_seconds() -> TestResult {
    let dir = workdir("wording")?;
    let out = enterplace(
        &[
            "key",
            "new",
            "maya",
            "--team",
            "payments",
            "--keys",
            &path(&dir, "enterplace.keys.yaml"),
        ],
        &[],
    )?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(stdout.contains("within 2 seconds"), "{stdout}");
    assert!(!stdout.contains("restart"), "{stdout}");
    Ok(())
}

/// The hash of each record, read from its line.
fn hashes(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line[line.len() - 66..line.len() - 2].to_string())
        .collect()
}

#[test]
fn audit_verify_expect_last_finds_a_kept_hash_or_says_what_happened() -> TestResult {
    let dir = workdir("expect")?;
    let log_path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B", "C", "D", "E"] {
        log.append(&enterplace_core::audit::Entry {
            id,
            person: Some("maya"),
            method: "POST",
            path: "/v1/chat/completions",
            ..Default::default()
        })?;
    }
    drop(log);
    let original = std::fs::read_to_string(&log_path)?;
    let kept = hashes(&original)[2].clone();
    let file = log_path.display().to_string();

    let out = enterplace(&["audit", "verify", &file, "--expect-last", &kept], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(stdout.contains("record 3"), "{stdout}");

    let made_up = "ab".repeat(32);
    let out = enterplace(&["audit", "verify", &file, "--expect-last", &made_up], &[])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)?.contains("not in this file"));

    let without_first_three: String = original.lines().skip(3).map(|l| format!("{l}\n")).collect();
    std::fs::write(&log_path, without_first_three)?;
    let out = enterplace(&["audit", "verify", &file, "--expect-last", &kept], &[])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)?.contains("not in this file"));

    std::fs::write(
        &log_path,
        original.replacen("\"id\":\"B\"", "\"id\":\"X\"", 1),
    )?;
    let out = enterplace(&["audit", "verify", &file, "--expect-last", &kept], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("chain broken before it") && stderr.contains("record 2"),
        "{stderr}"
    );
    Ok(())
}

/// Asks the server for /healthz over a plain socket. `None` while it is not listening yet.
fn healthz(addr: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).ok()?;
    // A server that accepts and never answers must fail the test, not hang it.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok()?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: enterplace\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut text = String::new();
    stream.read_to_string(&mut text).ok()?;
    Some(text)
}

fn config_records(log: &std::path::Path, event: &str) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains(&format!("\"event\":\"{event}\"")))
        .map(String::from)
        .collect()
}

/// Stops the server when the test ends, whichever way it ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The address a server started with `--listen 127.0.0.1:0` says it listens on, waiting up to 10 seconds.
fn listening(stdout: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    loop {
        let text = std::fs::read_to_string(stdout).unwrap_or_default();
        let found = text
            .lines()
            .find_map(|l| l.split_once(" listening on http://"))
            .map(|(_, addr)| addr.trim().to_string());
        if let Some(addr) = found {
            return Ok(addr);
        }
        if start.elapsed() > std::time::Duration::from_secs(10) {
            return Err(format!("the server never said where it listens: {text}").into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(unix)]
#[test]
fn serve_reloads_at_once_on_sighup_and_reports_a_bad_save_once() -> TestResult {
    let dir = workdir("sighup")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    let log = dir.join("enterplace-audit.jsonl");
    let out = enterplace(
        &[
            "key",
            "new",
            "maya",
            "--team",
            "payments",
            "--keys",
            &path(&dir, "enterplace.keys.yaml"),
        ],
        &[],
    )?;
    assert!(out.status.success());
    let stderr_path = dir.join("stderr.txt");
    let stdout_path = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .args(["serve", &policy, "--listen", "127.0.0.1:0"])
        .env("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret")
        .stdout(std::fs::File::create(&stdout_path)?)
        .stderr(std::fs::File::create(&stderr_path)?)
        .spawn()?;
    let server = Running(child);
    let pid = server.0.id().to_string();
    let addr = &listening(&stdout_path)?;
    let start = std::time::Instant::now();
    while healthz(addr).is_none() {
        if start.elapsed() > std::time::Duration::from_secs(10) {
            return Err(format!(
                "the server did not start: {}",
                std::fs::read_to_string(&stderr_path)?
            )
            .into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // UX11 m1: the start lines name the console's address.
    let started = std::fs::read_to_string(&stdout_path)?;
    assert!(
        started.contains(&format!("Console: http://{addr}/console")),
        "{started}"
    );
    assert_eq!(config_records(&log, "config_loaded").len(), 1);

    // The once-a-second check could see the change before the signal does, so this tries again until the signal wins.
    let mut by_signal = false;
    for attempt in 0..5 {
        std::fs::write(&policy, format!("{POLICY}# change {attempt}\n"))?;
        Command::new("kill").args(["-HUP", &pid]).status()?;
        let sent = std::time::Instant::now();
        while config_records(&log, "config_loaded").len() < attempt + 2 {
            assert!(
                sent.elapsed() < std::time::Duration::from_secs(2),
                "no record after the signal"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let last = config_records(&log, "config_loaded")
            .pop()
            .unwrap_or_default();
        if last.contains("\"trigger\":\"signal\"") {
            assert!(
                sent.elapsed() < std::time::Duration::from_millis(900),
                "{:?}",
                sent.elapsed()
            );
            by_signal = true;
            break;
        }
    }
    assert!(by_signal, "SIGHUP never reloaded before the timer");

    std::fs::write(
        &policy,
        POLICY.replace("    models: [model-a]\n", "    modles: [model-a]\n"),
    )?;
    std::thread::sleep(std::time::Duration::from_millis(3200));
    assert_eq!(config_records(&log, "config_rejected").len(), 1);
    let stderr = std::fs::read_to_string(&stderr_path)?;
    assert!(
        stderr.contains("enterplace.policy.yaml:12") && stderr.contains("\"modles\""),
        "{stderr}"
    );
    let health = healthz(addr).ok_or("the server stopped")?;
    assert!(
        health.contains("200 OK") && health.contains("\"rejected\":{"),
        "{health}"
    );
    drop(server);

    let out = enterplace(&["audit", "verify", &log.display().to_string()], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("0 requests") && stdout.contains("configuration records"),
        "{stdout}"
    );
    Ok(())
}

/// A stop signal while an answer is on its way: the answer finishes, and its usage record is in the log before the
/// process ends, although the record is made after the answer's last byte.
#[cfg(unix)]
#[test]
fn a_stop_signal_keeps_the_usage_record_of_an_answer_in_flight() -> TestResult {
    use std::io::{Read, Write};
    let dir = workdir("stop-usage")?;
    // A provider that sends half its answer, waits, then sends the rest.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let upstream = listener.local_addr()?.to_string();
    std::fs::write(
        dir.join("enterplace.policy.yaml"),
        POLICY.replace("http://127.0.0.1:9", &format!("http://{upstream}")),
    )?;
    let policy = path(&dir, "enterplace.policy.yaml");
    let log = dir.join("enterplace-audit.jsonl");
    let out = enterplace(
        &[
            "key",
            "new",
            "maya",
            "--team",
            "payments",
            "--keys",
            &path(&dir, "enterplace.keys.yaml"),
        ],
        &[],
    )?;
    let stdout = String::from_utf8(out.stdout)?;
    let key = stdout
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("enterplace_"))
        .ok_or("no key printed")?
        .to_string();
    let provider = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut conn, _) = listener.accept()?;
        conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !String::from_utf8_lossy(&got).contains("\"messages\"") {
            let n = conn.read(&mut buf)?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let body = r#"{"id":"c1","object":"chat.completion","model":"model-a","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#;
        let (first, rest) = body.split_at(20);
        write!(
            conn,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{first}",
            body.len()
        )?;
        conn.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(800));
        conn.write_all(rest.as_bytes())?;
        conn.flush()
    });
    let stdout_path = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .args(["serve", &policy, "--listen", "127.0.0.1:0"])
        .env("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret")
        .stdout(std::fs::File::create(&stdout_path)?)
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let mut server = Running(child);
    let addr = &listening(&stdout_path)?;
    let start = std::time::Instant::now();
    while healthz(addr).is_none() {
        if start.elapsed() > std::time::Duration::from_secs(10) {
            return Err("the server did not start".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut client = std::net::TcpStream::connect(addr)?;
    client.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let request = r#"{"model":"model-a","messages":[]}"#;
    write!(
        client,
        "POST /v1/chat/completions HTTP/1.1\r\nHost: enterplace\r\nAuthorization: Bearer {key}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nConnection: close\r\n\r\n{request}",
        request.len()
    )?;
    let mut first = [0u8; 64];
    let n = client.read(&mut first)?;
    assert!(String::from_utf8_lossy(&first[..n]).contains("200"));
    // The answer has started and not ended: stop now.
    Command::new("kill")
        .args(["-TERM", &server.0.id().to_string()])
        .status()?;
    let mut rest = String::new();
    client.read_to_string(&mut rest)?;
    assert!(rest.contains("total_tokens"), "the answer was cut: {rest}");
    let stopped = std::time::Instant::now();
    let status = loop {
        if let Some(status) = server.0.try_wait()? {
            break status;
        }
        if stopped.elapsed() > std::time::Duration::from_secs(10) {
            return Err("the server did not stop".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert!(status.success(), "{status:?}");
    provider
        .join()
        .map_err(|_| "the provider thread failed")??;
    let text = std::fs::read_to_string(&log)?;
    assert_eq!(text.matches("\"event\":\"usage\"").count(), 1, "{text}");
    let out = enterplace(&["audit", "verify", &log.display().to_string()], &[])?;
    assert!(out.status.success());
    Ok(())
}

#[test]
fn help_after_a_command_prints_its_usage_and_succeeds() -> TestResult {
    for args in [
        &["check", "--help"][..],
        &["key", "new", "-h"],
        &["serve", "--help"],
    ] {
        let out = enterplace(args, &[])?;
        assert!(out.status.success(), "{args:?}");
        assert!(
            String::from_utf8(out.stdout)?.starts_with("Usage: enterplace "),
            "{args:?}"
        );
    }
    Ok(())
}

#[test]
fn key_new_makes_the_first_admin_and_prints_an_env_block_to_paste() -> TestResult {
    let dir = workdir("admin-env")?;
    let keys = path(&dir, "enterplace.keys.yaml");
    let out = enterplace(
        &[
            "key",
            "new",
            "noa",
            "--team",
            "platform",
            "--admin",
            "--keys",
            &keys,
            "--url",
            "http://gw.internal:8080",
        ],
        &[],
    )?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let stdout = String::from_utf8(out.stdout)?;
    let key = stdout
        .split_whitespace()
        .find(|w| w.starts_with("enterplace_"))
        .ok_or("no key printed")?
        .trim_matches('\'');
    for line in [
        "export ANTHROPIC_BASE_URL=http://gw.internal:8080\n".to_string(),
        format!("export ANTHROPIC_API_KEY={key}\n"),
        "export OPENAI_BASE_URL=http://gw.internal:8080/v1\n".to_string(),
        format!("export OPENAI_API_KEY={key}\n"),
        // UX11 n13: the console's full address, not a path alone.
        "console at http://gw.internal:8080/console".to_string(),
        "https://docs.enterplace.dev/integrations/codex/".to_string(),
    ] {
        assert!(stdout.contains(&line), "{line} missing from:\n{stdout}");
    }
    let entries = enterplace_core::config::key_entries(
        std::path::Path::new(&keys),
        &std::fs::read_to_string(&keys)?,
    )
    .map_err(|e| e.join("\n"))?;
    assert!(entries[0].admin, "the first admin needs no hand edit");

    // --quiet prints the key alone, for a pipe into a secret manager.
    let out = enterplace(
        &[
            "key",
            "new",
            "ci",
            "--team",
            "platform",
            "--quiet",
            "--keys",
            &keys,
            "--expires",
            "2099-01-01",
            "--budget",
            "20/month",
        ],
        &[],
    )?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let quiet = String::from_utf8(out.stdout)?;
    assert!(
        quiet.starts_with("enterplace_") && quiet.trim_end().lines().count() == 1,
        "{quiet}"
    );

    let out = enterplace(
        &[
            "key",
            "new",
            "tiny",
            "--team",
            "platform",
            "--quiet",
            "--keys",
            &keys,
            "--budget",
            "0.0001/day",
        ],
        &[],
    )?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    // PM13 MIN-1: a key's own model list and TPM limit, from flags.
    let out = enterplace(
        &[
            "key",
            "new",
            "agent",
            "--team",
            "platform",
            "--quiet",
            "--keys",
            &keys,
            "--models",
            "gpt-4o-mini,o3",
            "--tpm",
            "5000",
        ],
        &[],
    )?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let out = enterplace(&["key", "list", "--keys", &keys], &[])?;
    assert!(out.status.success());
    let list = String::from_utf8(out.stdout)?;
    assert!(
        list.starts_with("name\tteam\tkey\tadmin\texpires\tbudget\tmodels\ttpm\n"),
        "{list}"
    );
    assert!(list.contains("\tgpt-4o-mini,o3\t5000\n"), "{list}");
    // PM11 MIN-2: a budget under a cent is not printed as $0.00.
    assert!(list.contains("$0.0001 a day"), "{list}");
    assert!(list.contains("noa") && list.contains("admin"), "{list}");
    assert!(
        list.contains("2099-01-01") && list.contains("$20.00 a month"),
        "{list}"
    );
    assert!(!list.contains(key), "a key value was listed");
    // QA11-6: a key whose date passed (an edit by hand) is listed as expired.
    let mut text = std::fs::read_to_string(&keys)?;
    text.push_str(&format!(
        "  - name: old\n    team: t\n    sha256: {}\n    expires: 2020-01-01\n",
        "ab".repeat(32)
    ));
    std::fs::write(&keys, text)?;
    let out = enterplace(&["key", "list", "--keys", &keys], &[])?;
    let list = String::from_utf8(out.stdout)?;
    assert!(
        list.contains("2020-01-01 (expired)") && list.contains("2099-01-01\t"),
        "{list}"
    );

    for (bad, says) in [
        (&["--expires", "soon"][..], "It takes a UTC date"),
        (&["--budget", "20/fortnight"], "--budget is"),
        (
            &["--budget", "20/day@Mars/Olympus"],
            "not a time zone Enterplace knows",
        ),
        // UX11 n3: a key that is refused on its first request is never issued.
        (&["--expires", "2020-01-01"], "has passed"),
        (&["--expires", "2026-02-30"], "2026-02-30 is not a date"),
        (&["--tpm", "0"], "--tpm is"),
        (&["--models", ","], "--models is"),
    ] {
        let mut args = vec!["key", "new", "x", "--team", "t", "--keys", &keys];
        args.extend_from_slice(bad);
        let out = enterplace(&args, &[])?;
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
        let stderr = String::from_utf8(out.stderr)?;
        assert!(stderr.contains(says), "{bad:?}: {stderr}");
    }
    let listed = std::fs::read_to_string(&keys)?;
    assert!(!listed.contains("name: x\n"), "a refused key was written");

    // `check` refuses the same dates in a keys file written by hand, each on its line.
    let dir = workdir("check-expiry")?;
    std::fs::write(dir.join("enterplace.policy.yaml"), POLICY)?;
    let entry = |name: &str, hex: &str, date: &str| {
        format!(
            "  - name: {name}\n    team: t\n    sha256: {}\n    expires: {date}\n",
            hex.repeat(64)
        )
    };
    let keys_file = dir.join("enterplace.keys.yaml");
    std::fs::write(
        &keys_file,
        format!("keys:\n{}", entry("odd", "d", "2026-11-31")),
    )?;
    let out = enterplace(&["check", &path(&dir, "enterplace.policy.yaml")], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("enterplace.keys.yaml:4") && stderr.contains("2026-11-31 is not a date"),
        "{stderr}"
    );
    std::fs::write(
        &keys_file,
        format!(
            "keys:\n{}{}",
            entry("new", "c", "2099-01-01"),
            entry("old", "e", "2020-01-01")
        ),
    )?;
    // UX12-4: an expired key is a warning on its line, not a failure; serving still refuses the key.
    let out = enterplace(&["check", &path(&dir, "enterplace.policy.yaml")], &[])?;
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("enterplace.keys.yaml:8")
            && stderr.contains("\"old\"")
            && stderr.contains("2020-01-01 has passed")
            && !stderr.contains("\"new\""),
        "{stderr}"
    );
    Ok(())
}

/// Sends a request over a plain socket and returns the whole answer.
fn post(
    addr: &str,
    path: &str,
    key: &str,
    body: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.write_all(
        format!(
            "POST {path} HTTP/1.1\r\nHost: enterplace\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    Ok(text)
}

#[test]
fn kill_unkill_and_logout_name_what_is_missing() -> TestResult {
    let dir = workdir("kill-args")?;
    let home = path(&dir, "config");
    let env = [
        ("XDG_CONFIG_HOME", home.as_str()),
        ("ENTERPLACE_URL", "http://127.0.0.1:9"),
    ];
    for (args, says) in [
        (&["kill", "--person", "maya"][..], "needs --reason"),
        (
            &["kill", "--person", "maya", "--reason", " "],
            "needs --reason",
        ),
        (&["kill", "--reason", "loop"], "exactly one of"),
        (
            &["kill", "--person", "a", "--team", "b", "--reason", "r"],
            "exactly one of",
        ),
        (&["unkill", "--all", "--model", "m"], "exactly one of"),
        (&["kill", "--all", "--reason", "r"], "ENTERPLACE_ADMIN_KEY"),
        (&["logout"], "not signed in"),
        (
            &["login", "http://enterplace.example.com"],
            "not an address a key may be sent to",
        ),
    ] {
        let out = enterplace(args, &env)?;
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8(out.stderr)?;
        assert!(stderr.contains(says), "{args:?}: {stderr}");
    }
    let out = enterplace(&["unkill", "--person", "a", "--reason", "r"], &env)?;
    assert!(String::from_utf8(out.stderr)?.contains("Usage: enterplace unkill"));
    Ok(())
}

#[test]
fn kill_stops_a_person_with_the_reason_unkill_restores_and_logout_revokes_the_saved_key()
-> TestResult {
    let dir = workdir("kill")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    let keys = path(&dir, "enterplace.keys.yaml");
    let new_key = |name: &str, admin: bool| -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec![
            "key", "new", name, "--team", "payments", "--quiet", "--keys", &keys,
        ];
        if admin {
            args.push("--admin");
        }
        let out = enterplace(&args, &[])?;
        assert!(out.status.success());
        Ok(String::from_utf8(out.stdout)?.trim().to_string())
    };
    let (admin, maya) = (new_key("ops", true)?, new_key("maya", false)?);
    let stdout_path = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .args(["serve", &policy, "--listen", "127.0.0.1:0"])
        .env("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret")
        .stdout(std::fs::File::create(&stdout_path)?)
        .stderr(std::fs::File::create(dir.join("stderr.txt"))?)
        .spawn()?;
    let _server = Running(child);
    let addr = listening(&stdout_path)?;
    let url = format!("http://{addr}");
    let home = path(&dir, "config");
    let env = [
        ("XDG_CONFIG_HOME", home.as_str()),
        ("ENTERPLACE_URL", url.as_str()),
        ("ENTERPLACE_ADMIN_KEY", admin.as_str()),
    ];
    let chat = r#"{"model":"model-a","messages":[]}"#;
    let out = enterplace(
        &[
            "kill",
            "--person",
            "maya",
            "--reason",
            "looping on one ticket",
        ],
        &env,
    )?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let refused = post(&addr, "/v1/chat/completions", &maya, chat)?;
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    assert!(
        refused.contains(r#""code":"killed""#)
            && refused.contains("looping on one ticket")
            && refused.contains("set by ops"),
        "{refused}"
    );
    // `enterplace start` prints the admin key as `export ENTERPLACE_KEY=...`: the admin commands take it from there too.
    let env = [
        ("XDG_CONFIG_HOME", home.as_str()),
        ("ENTERPLACE_URL", url.as_str()),
        ("ENTERPLACE_KEY", admin.as_str()),
    ];
    let out = enterplace(&["unkill", "--person", "maya"], &env)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!post(&addr, "/v1/chat/completions", &maya, chat)?.contains("killed"));
    let out = enterplace(&["unkill", "--person", "maya"], &env)?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("no kill switch is on"));

    // What `enterplace login` saves, for maya: logout revokes that key with the key itself, then deletes the file.
    let saved = dir.join("config").join("enterplace").join("credentials");
    std::fs::create_dir_all(saved.parent().ok_or("no folder")?)?;
    std::fs::write(&saved, format!("url={url}\nkey={maya}\nname=maya\n"))?;
    let out = enterplace(&["logout"], &env[..1])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!saved.exists());
    let left = std::fs::read_to_string(&keys)?;
    assert!(
        left.contains("name: ops") && !left.contains("name: maya"),
        "{left}"
    );
    Ok(())
}

#[test]
fn key_info_update_and_rotate_go_through_the_admin_api_of_a_running_gateway() -> TestResult {
    let dir = workdir("key-admin")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    let keys = path(&dir, "enterplace.keys.yaml");
    let new_key = |name: &str, admin: bool| -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec![
            "key", "new", name, "--team", "payments", "--quiet", "--keys", &keys,
        ];
        if admin {
            args.push("--admin");
        }
        let out = enterplace(&args, &[])?;
        assert!(out.status.success());
        Ok(String::from_utf8(out.stdout)?.trim().to_string())
    };
    let (admin, maya) = (new_key("ops", true)?, new_key("maya", false)?);
    let prefix = enterplace_core::id::sha256_hex(maya.as_bytes())[..8].to_string();
    let stdout_path = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .args(["serve", &policy, "--listen", "127.0.0.1:0"])
        .env("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret")
        .stdout(std::fs::File::create(&stdout_path)?)
        .stderr(std::fs::File::create(dir.join("stderr.txt"))?)
        .spawn()?;
    let _server = Running(child);
    let addr = listening(&stdout_path)?;
    let url = format!("http://{addr}");
    let home = path(&dir, "config");
    let env = [
        ("XDG_CONFIG_HOME", home.as_str()),
        ("ENTERPLACE_URL", url.as_str()),
        ("ENTERPLACE_ADMIN_KEY", admin.as_str()),
    ];
    let out = enterplace(
        &[
            "key",
            "update",
            &prefix,
            "--rpm",
            "30",
            "--tags",
            "eval,batch",
            "--metadata",
            "owner=maya,ticket=OPS-1",
        ],
        &env,
    )?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = enterplace(&["key", "info", &prefix], &env)?;
    let info = String::from_utf8(out.stdout)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        info.contains("rpm: 30") && info.contains("eval") && info.contains("OPS-1"),
        "{info}"
    );
    assert!(info.contains("Spend (counted by this gateway)"), "{info}");
    let out = enterplace(&["key", "update", &prefix, "--rpm", "none"], &env)?;
    assert!(out.status.success());
    let out = enterplace(&["key", "update", &prefix, "--rpm", "0"], &env)?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("rpm is a whole number"));
    let out = enterplace(&["key", "update", &prefix], &env)?;
    assert_eq!(
        out.status.code(),
        Some(2),
        "an update with no change is a usage error"
    );
    let out = enterplace(&["key", "rotate", &prefix, "--grace", "2h"], &env)?;
    let said = String::from_utf8(out.stdout)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("keeps working until") && said.contains("enterplace_"),
        "{said}"
    );
    let chat = r#"{"model":"model-a","messages":[]}"#;
    // The old key is still let through in its grace (the test provider may not answer, but no key refusal comes).
    let used = post(&addr, "/v1/chat/completions", &maya, chat)?;
    assert!(
        !used.contains("unknown_key") && !used.contains("key_expired"),
        "{used}"
    );
    let log = std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?;
    for action in [
        "\"update_key\"",
        "\"key_info\"",
        "\"rotate_key\"",
        "\"key_rotated\"",
    ] {
        assert!(log.contains(action), "{action} is not in the audit log");
    }
    Ok(())
}

#[test]
fn check_warns_on_an_expired_key_and_key_prune_removes_only_expired_entries() -> TestResult {
    let dir = workdir("prune")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    let keys = path(&dir, "enterplace.keys.yaml");
    std::fs::write(
        &keys,
        format!(
            "keys:\n  - name: lior@example.com\n    team: payments\n    sha256: {}\n    expires: 2020-01-01\n  - name: noa\n    team: payments\n    sha256: {}\n",
            "ab".repeat(32),
            "cd".repeat(32)
        ),
    )?;
    // UX12-4: a login key that lapsed is not a broken policy, so a CI check before a deploy still passes.
    let out = enterplace(&["check", &policy], &[])?;
    let stderr = String::from_utf8(out.stderr.clone())?;
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("lior@example.com") && stderr.contains("enterplace key prune"),
        "{stderr}"
    );
    let out = enterplace(&["key", "prune", "--keys", &keys], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(String::from_utf8(out.stdout)?.contains("lior@example.com"));
    let text = std::fs::read_to_string(&keys)?;
    assert!(
        !text.contains(&"ab".repeat(32)) && text.contains(&"cd".repeat(32)),
        "{text}"
    );
    let out = enterplace(&["key", "prune", "--keys", &keys], &[])?;
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)?.contains("No key has expired"));
    let out = enterplace(&["check", &policy], &[])?;
    assert!(out.stderr.is_empty(), "{}", String::from_utf8(out.stderr)?);
    Ok(())
}

#[test]
fn prices_names_the_price_used_and_where_it_came_from() -> TestResult {
    let out = enterplace(&["prices", "claude-opus-4-5"], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("LiteLLM price map") && stdout.contains("input 5, output 25"),
        "{stdout}"
    );
    let dir = workdir("prices")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    std::fs::write(
        &policy,
        format!("{POLICY}prices:\n  claude-opus-4-5: {{ input: 1, output: 2 }}\n"),
    )?;
    let out = enterplace(&["prices", "claude-opus-4-5", "--policy", &policy], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        stdout.contains("the policy's prices:") && stdout.contains("input 1, output 2"),
        "{stdout}"
    );
    // UX13 q1: an alias is charged at its deployments' prices, and says so.
    std::fs::write(
        &policy,
        format!(
            "{POLICY}aliases:\n  - name: smart\n    deployments: [{{ provider: mock, model: model-a }}]\nprices:\n  model-a: {{ input: 1, output: 2 }}\n"
        ),
    )?;
    let out = enterplace(&["prices", "smart", "--policy", &policy], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8(out.stderr)?
    );
    assert!(
        stdout.contains("smart is an alias")
            && stdout.contains("mock/model-a: from the policy's prices:")
            && stdout.contains("input 1, output 2"),
        "{stdout}"
    );
    let out = enterplace(&["prices", "no-such-model"], &[])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("prices:"));
    Ok(())
}

#[test]
fn import_litellm_writes_a_policy_that_checks_and_never_replaces_one() -> TestResult {
    let dir = workdir("import")?;
    let config = path(&dir, "config.yaml");
    std::fs::write(
        &config,
        "model_list:\n  - model_name: gpt-4o\n    litellm_params:\n      model: openai/gpt-4o\n      api_key: os.environ/OPENAI_API_KEY\ngeneral_settings:\n  master_key: os.environ/LITELLM_MASTER_KEY\n",
    )?;
    let out_file = path(&dir, "imported.policy.yaml");
    let out = enterplace(&["import", "litellm", &config, "--out", &out_file], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8(out.stderr)?
    );
    assert!(
        stdout.contains("is valid: 1 rule") && stdout.contains("master_key"),
        "{stdout}"
    );
    assert!(std::fs::read_to_string(&out_file)?.contains("key_env: OPENAI_API_KEY"));
    let out = enterplace(&["import", "litellm", &config, "--out", &out_file], &[])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("never replaced"));
    Ok(())
}

/// A LiteLLM proxy's management API as its docs describe it, on a thread: every route needs the master key.
fn litellm_proxy(master: &'static str) -> std::io::Result<u16> {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let path = line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let mut authorized = false;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                    break;
                }
                if header.to_ascii_lowercase().trim()
                    == format!("authorization: bearer {master}").to_ascii_lowercase()
                {
                    authorized = true;
                }
            }
            let (status, body) = match path.as_str() {
                _ if !authorized => ("401 Unauthorized", r#"{"error":{"message":"Authentication Error"}}"#.to_string()),
                "/model/info" => ("200 OK", r#"{"data":[{"model_name":"gpt-4o","litellm_params":{"model":"openai/gpt-4o","api_key":"os.environ/OPENAI_API_KEY"},"model_info":{"id":"m1"}},{"model_name":"gpt-4o-mini","litellm_params":{"model":"openai/gpt-4o-mini","api_key":"os.environ/OPENAI_API_KEY"},"model_info":{"id":"m2"}}]}"#.to_string()),
                p if p.starts_with("/key/list") => ("200 OK", r#"{"keys":[{"token":"88dc28d0f030c55ed4ab77ed8faf098196cb1c05df778539800c9f1243fe6b4b","key_alias":"maya","team_id":"t-1","models":["gpt-4o","dall-e-3"],"max_budget":20,"budget_duration":"30d","tpm_limit":1000},{"token":"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9","user_id":"dana","team_id":"t-2","models":[]}],"total_count":2,"current_page":1,"total_pages":1}"#.to_string()),
                "/team/list" => ("200 OK", r#"[{"team_id":"t-1","team_alias":"payments","max_budget":500,"budget_duration":"30d","models":["gpt-4o"]},{"team_id":"t-2","team_alias":"search","max_budget":10,"budget_duration":"7d"}]"#.to_string()),
                _ => ("404 Not Found", r#"{"detail":"Not Found"}"#.to_string()),
            };
            let mut stream = &stream;
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    Ok(port)
}

#[test]
fn import_litellm_reads_a_running_proxy_and_reissues_its_keys() -> TestResult {
    const MASTER: &str = "sk-litellm-master-0123456789";
    let port = litellm_proxy(MASTER)?;
    let dir = workdir("import-proxy")?;
    let (out_file, keys_file) = (
        path(&dir, "from-proxy.policy.yaml"),
        path(&dir, "from-proxy.keys.yaml"),
    );
    let url = format!("http://127.0.0.1:{port}");
    let args = [
        "import",
        "litellm",
        "--url",
        &url,
        "--master-key-env",
        "LITELLM_MASTER_KEY",
        "--out",
        &out_file,
        "--keys-out",
        &keys_file,
    ];
    let out = enterplace(
        &args,
        &[
            ("OPENAI_API_KEY", "sk-test"),
            ("LITELLM_MASTER_KEY", "wrong"),
        ],
    )?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("HTTP 401"));
    let out = enterplace(
        &args,
        &[
            ("OPENAI_API_KEY", "sk-test"),
            ("LITELLM_MASTER_KEY", MASTER),
        ],
    )?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8(out.stderr)?
    );
    assert!(!stdout.contains(MASTER), "the master key is never printed");
    assert!(
        stdout.contains("Read 2 models from the proxy, 2 keys and 2 teams"),
        "{stdout}"
    );
    let policy = std::fs::read_to_string(&out_file)?;
    assert!(
        policy.contains("gpt-4o-mini") && policy.contains("key_env: OPENAI_API_KEY"),
        "{policy}"
    );
    assert!(
        policy.contains("team: payments") && policy.contains("usd: 500"),
        "{policy}"
    );
    // A 7d budget is a calendar week in both.
    assert!(
        policy.contains("team: search") && policy.contains("per: week"),
        "{policy}"
    );
    // One Enterplace key per LiteLLM key, printed beside the key it replaces, its hash in the new keys file.
    let line = stdout
        .lines()
        .find(|l| l.contains("maya (token 88dc28d0f030...) -> maya (team payments): enterplace_"))
        .ok_or(format!("no mapping in {stdout}"))?;
    let key = line.rsplit(' ').next().unwrap_or_default();
    let keys = std::fs::read_to_string(&keys_file)?;
    assert!(
        keys.contains(&enterplace_core::id::sha256_hex(key.as_bytes())),
        "{keys}"
    );
    assert!(keys.contains("models: [\"gpt-4o\"]"), "{keys}");
    assert!(
        stdout.contains("dana (token a1b2c3d4e5f6...) -> dana (team search)"),
        "{stdout}"
    );
    assert!(stdout.contains("is valid"), "{stdout}");
    // Never over an existing keys file.
    let again = enterplace(
        &[
            "import",
            "litellm",
            "--url",
            &url,
            "--master-key-env",
            "LITELLM_MASTER_KEY",
            "--out",
            &path(&dir, "other.yaml"),
            "--keys-out",
            &keys_file,
        ],
        &[("LITELLM_MASTER_KEY", MASTER)],
    )?;
    assert_eq!(again.status.code(), Some(2));
    assert!(String::from_utf8(again.stderr)?.contains("never changed by an import"));
    Ok(())
}

#[test]
fn providers_lists_the_catalog_with_id_name_kind_and_url() -> TestResult {
    let out = enterplace(&["providers"], &[])?;
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout)?;
    let groq = text
        .lines()
        .find(|line| line.starts_with("groq "))
        .ok_or(format!("no groq line: {text}"))?;
    let words: Vec<&str> = groq.split_whitespace().collect();
    assert_eq!(
        words,
        ["groq", "Groq", "openai", "https://api.groq.com/openai/v1"]
    );
    assert!(text.lines().count() > 100, "{text}");
    assert!(text.contains("http://localhost:11434/v1 (local, needs allow_private: true)"));
    Ok(())
}

#[test]
fn guardrail_test_backtests_a_defined_guardrail_on_a_corpus() -> TestResult {
    let dir = workdir("guardrail-test")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    // A guardrail no rule uses yet: the point is to try it before it goes live. `enterplace check` accepts it.
    std::fs::write(
        &policy,
        format!(
            "{POLICY}guardrails:\n  - name: tickets\n    type: regex\n    action: block\n    shadow_until: 2999-01-01\n    patterns:\n      ticket_id: 'TKT-[0-9]{{6}}'\n"
        ),
    )?;
    let out = enterplace(&["check", &policy], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let corpus = path(&dir, "corpus.jsonl");
    std::fs::write(
        &corpus,
        "{\"text\": \"fix TKT-123456\", \"expect\": true}\n{\"text\": \"nothing\", \"expect\": false}\n{\"text\": \"TKT-654321\", \"expect\": false}\n",
    )?;
    let out = enterplace(
        &[
            "guardrail",
            "test",
            "tickets",
            "--policy",
            &policy,
            "--corpus",
            &corpus,
        ],
        &[],
    )?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(
        stdout.contains("on 3 requests: would hit 2 (66.7%)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("ticket_id: 2") && stdout.contains("TK******56"),
        "{stdout}"
    );
    assert!(
        stdout.contains("precision 50.0%") && stdout.contains("recall 100.0%"),
        "{stdout}"
    );
    assert!(!stdout.contains("TKT-123456"), "{stdout}");
    // --since needs captured bodies, which the audit log never holds; an unknown name lists the defined ones.
    let out = enterplace(
        &[
            "guardrail",
            "test",
            "tickets",
            "--policy",
            &policy,
            "--since",
            "7d",
        ],
        &[],
    )?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("holds no prompt text"));
    let out = enterplace(
        &[
            "guardrail",
            "test",
            "nope",
            "--policy",
            &policy,
            "--corpus",
            &corpus,
        ],
        &[],
    )?;
    assert!(String::from_utf8(out.stderr)?.contains("It defines: tickets."));
    let out = enterplace(&["guardrail", "test"], &[])?;
    assert!(String::from_utf8(out.stderr)?.contains("Usage: enterplace guardrail test <name>"));
    Ok(())
}

#[test]
fn key_new_writes_hierarchy_fields_and_explain_names_each_limit_and_its_source() -> TestResult {
    let dir = std::env::temp_dir().join(format!("enterplace-cli-explain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    let keys = dir.join("enterplace.keys.yaml");
    std::fs::write(
        &policy,
        "version: 1
providers:
  - name: openai
    kind: openai
    url: https://api.openai.com
    key_env: OPENAI_API_KEY
    models: [gpt-4o-mini]
orgs: [acme]
rules:
  - name: other-org
    org: other
    principals: { any: true }
    models: []
  - name: shop
    principals: { team: shop }
    models: [gpt-4o-mini]
    customers: [\"*\"]
limits:
  - { customer: \"*\", budget: { usd: 5, per: day } }
  - { customer: \"*\", org: acme, budget: { usd: 9, per: day } }
",
    )?;
    let (p, k) = (policy.to_string_lossy(), keys.to_string_lossy());
    let out = enterplace(&["check", &p], &[])?;
    // A rule for an organization the policy does not list is refused by name.
    assert!(
        String::from_utf8(out.stderr)?.contains("organization \"other\" is not listed under orgs")
    );
    std::fs::write(
        &policy,
        std::fs::read_to_string(&policy)?.replace("orgs: [acme]", "orgs: [acme, other]"),
    )?;
    let out = enterplace(
        &[
            "key",
            "new",
            "backend",
            "--team",
            "shop",
            "--org",
            "acme",
            "--tags",
            "web,search",
            "--parallel",
            "4",
            "--budget",
            "100/month@America/New_York",
            "--quiet",
            "--keys",
            &k,
        ],
        &[],
    )?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let saved = std::fs::read_to_string(&keys)?;
    assert!(
        saved.contains("tz: America/New_York")
            && saved.contains("org: acme")
            && saved.contains("parallel: 4"),
        "{saved}"
    );
    let out = enterplace(
        &[
            "explain",
            &p,
            "--keys",
            &k,
            "--key",
            "backend",
            "--model",
            "gpt-4o-mini",
            "--customer",
            "globex",
        ],
        &[],
    )?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let explained: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(explained["verdict"], "allow");
    assert_eq!(
        explained["skipped"][0]["why"],
        "is for organization \"other\""
    );
    let limits = explained["limits"].as_array().ok_or("no limits")?;
    let customer = limits
        .iter()
        .find(|l| l["of"] == "customer")
        .ok_or("no customer limit")?;
    assert_eq!(customer["usd"], 9.0);
    assert!(
        customer["overrides"][0]
            .as_str()
            .is_some_and(|o| o.contains("customer: *")),
        "{customer}"
    );
    assert!(
        limits
            .iter()
            .any(|l| l["of"] == "key" && l["per"] == "month@America/New_York")
    );
    assert!(
        limits
            .iter()
            .any(|l| l["of"] == "key" && l["limit"] == "parallel")
    );
    Ok(())
}

/// What a cleared environment must keep on Windows: without SYSTEMROOT, Winsock cannot start and the gateway never
/// listens. Elsewhere it is unset and this adds nothing.
fn windows_root() -> Option<(&'static str, std::ffi::OsString)> {
    std::env::var_os("SYSTEMROOT").map(|v| ("SYSTEMROOT", v))
}

/// `enterplace start` with only the variables given: a provider key in the developer's own shell must not leak in.
fn start(dir: &std::path::Path, extra: &[&str], env: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_enterplace"));
    command
        .env_clear()
        .envs(windows_root())
        .args(["start", "--dir", &dir.display().to_string(), "--no-serve"])
        .args(extra);
    for (key, value) in env {
        command.env(key, value);
    }
    command.output()
}

fn start_dir(name: &str) -> std::io::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-cli-start-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

const BOTH_KEYS: &[(&str, &str)] = &[
    ("OPENAI_API_KEY", "sk-test-openai"),
    ("ANTHROPIC_API_KEY", "sk-ant-test"),
];

/// Every `enterplace_` key (64 hex characters after the prefix) in `text`.
fn printed_keys(text: &str) -> Vec<&str> {
    text.match_indices("enterplace_")
        .filter_map(|(at, _)| text.get(at..at + 11 + 64))
        .filter(|key| key[11..].chars().all(|c| c.is_ascii_hexdigit()))
        .collect()
}

#[test]
fn start_writes_an_observe_policy_with_the_demo_model_and_the_env_keys() -> TestResult {
    let dir = start_dir("observe")?;
    let out = start(&dir, &[], BOTH_KEYS)?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);

    let policy = std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?;
    // The policy reads the provider name, so the tool lines can set OPENAI_API_KEY to the Enterplace key in one shell.
    for line in [
        "mode: observe\n",
        "preset: demo\n",
        "models: [enterplace-demo]\n",
        "key_env: OPENAI_PROVIDER_KEY\n",
        "key_env: ANTHROPIC_PROVIDER_KEY\n",
        "models: [\"*\"]\n",
    ] {
        assert!(policy.contains(line), "{line}: {policy}");
    }
    assert_eq!(policy.matches("principals:").count(), 1, "{policy}");

    // The admin key is printed once and only its hash is kept.
    let keys = printed_keys(&stdout);
    assert_eq!(keys.len(), 1, "{stdout}");
    let file = std::fs::read_to_string(dir.join("enterplace.keys.yaml"))?;
    assert!(!file.contains(keys[0]), "{file}");
    assert!(file.contains("admin: true"), "{file}");
    // No paragraph about exporting provider keys: the gateway gets them, and the dashboard shows the rest.
    assert!(!stdout.contains("_PROVIDER_KEY"), "{stdout}");

    // The master key that seals provider keys pasted in the console: made once, private, named.
    let master = dir.join("enterplace-master.key");
    assert!(stdout.contains("enterplace-master.key"), "{stdout}");
    assert_eq!(std::fs::read_to_string(&master)?.trim().len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&master)?.permissions().mode() & 0o777,
            0o600
        );
    }

    let keys_file = path(&dir, "enterplace.keys.yaml");
    let out = enterplace(
        &[
            "check",
            &path(&dir, "enterplace.policy.yaml"),
            "--keys",
            &keys_file,
        ],
        &[
            ("OPENAI_PROVIDER_KEY", "sk-test-openai"),
            ("ANTHROPIC_PROVIDER_KEY", "sk-ant-test"),
        ],
    )?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(
        // The admin key and the person token of whoever ran start.
        String::from_utf8(out.stdout)?.contains("1 rule, 2 keys, 4 providers"),
        "check"
    );
    Ok(())
}

#[test]
fn start_needs_no_provider_key() -> TestResult {
    let dir = start_dir("nokey")?;
    let out = start(&dir, &[], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let policy = std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?;
    assert!(policy.contains("preset: demo\n"), "{policy}");
    assert!(!policy.contains("preset: openai"), "{policy}");
    // Claude Code on the developers' own Claude subscriptions works with no Anthropic key at all.
    for line in [
        "auth: passthrough\n",
        "identity: required\n",
        "url: https://api.anthropic.com\n",
    ] {
        assert!(policy.contains(line), "{line}: {policy}");
    }
    assert!(!policy.contains("key_env: ANTHROPIC"), "{policy}");
    assert_eq!(printed_keys(&String::from_utf8(out.stdout)?).len(), 1);
    let out = enterplace(&["check", &path(&dir, "enterplace.policy.yaml")], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);

    // A provider asked for by name still needs its key, and the error names its variable.
    let dir = start_dir("nokey-named")?;
    let out = start(&dir, &["--providers", "anthropic"], BOTH_KEYS[..1].as_ref())?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("ANTHROPIC_PROVIDER_KEY"));
    Ok(())
}

#[test]
fn start_names_every_request_and_hands_its_runner_a_person_token() -> TestResult {
    let dir = start_dir("named")?;
    let out = start(&dir, &[], &[("USER", "sarah.miller")])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let stdout = String::from_utf8(out.stdout)?;
    let policy = std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?;
    assert!(policy.contains("identity: required\n"), "{policy}");
    assert!(!policy.contains("identity: optional"), "{policy}");

    // The exact lines to paste before running claude: the gateway and the person token, shown once.
    assert!(
        stdout.contains("  export ANTHROPIC_BASE_URL=http://127.0.0.1:8080\n"),
        "{stdout}"
    );
    let token = stdout
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("export ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: ")
        })
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or("no person token line")?
        .to_string();
    assert!(token.starts_with("enterplace_u_"), "{stdout}");
    assert!(stdout.contains("sarah.miller"), "{stdout}");
    let keys = std::fs::read_to_string(dir.join("enterplace.keys.yaml"))?;
    assert!(
        keys.contains("name: sarah.miller")
            && keys.contains(&enterplace_core::id::sha256_hex(token.as_bytes()))
            && !keys.contains(&token),
        "only the token's hash is kept: {keys}"
    );
    let out = enterplace(&["check", &path(&dir, "enterplace.policy.yaml")], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);

    // A second start keeps everything: no second token.
    let out = start(&dir, &[], &[("USER", "sarah.miller")])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let stdout = String::from_utf8(out.stdout)?;
    assert!(!stdout.contains("enterplace_u_"), "{stdout}");
    assert_eq!(
        std::fs::read_to_string(dir.join("enterplace.keys.yaml"))?,
        keys
    );

    // No user name to take: the token is the admin's.
    let dir = start_dir("named-admin")?;
    let out = start(&dir, &[], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let keys = std::fs::read_to_string(dir.join("enterplace.keys.yaml"))?;
    assert_eq!(keys.matches("name: admin").count(), 2, "{keys}");
    Ok(())
}

#[test]
fn start_points_a_provider_at_the_url_enterplace_openai_base_url_names() -> TestResult {
    let dir = start_dir("base-url")?;
    let mut env = BOTH_KEYS[..1].to_vec();
    env.push(("ENTERPLACE_OPENAI_BASE_URL", "http://127.0.0.1:9/v1"));
    let out = start(&dir, &[], &env)?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let policy = std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?;
    assert!(
        policy.contains("    url: http://127.0.0.1:9/v1\n    allow_private: true\n"),
        "{policy}"
    );
    Ok(())
}

#[test]
fn start_again_keeps_the_policy_and_makes_no_second_admin_key_unless_forced() -> TestResult {
    let dir = start_dir("force")?;
    assert!(start(&dir, &[], BOTH_KEYS)?.status.success());
    let before = std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?;
    let master = std::fs::read_to_string(dir.join("enterplace-master.key"))?;
    std::fs::write(dir.join("enterplace.policy.yaml"), "# edited\n")?;

    let out = start(&dir, &[], BOTH_KEYS)?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let stdout = String::from_utf8(out.stdout)?;
    assert!(stdout.contains("is kept"), "{stdout}");
    assert!(printed_keys(&stdout).is_empty(), "{stdout}");
    assert_eq!(
        std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?,
        "# edited\n"
    );

    let out = start(&dir, &["--force"], BOTH_KEYS)?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert_eq!(
        std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?,
        before
    );
    // The master key is never replaced: credentials sealed with it would no longer open.
    assert_eq!(
        std::fs::read_to_string(dir.join("enterplace-master.key"))?,
        master
    );
    Ok(())
}

#[test]
fn start_in_a_container_writes_once_then_serves_what_it_wrote() -> TestResult {
    // What the image runs with no policy mounted: the first start writes the policy and prints the admin key.
    let dir = start_dir("container")?;
    let out = start(&dir, &["--container"], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let stdout = String::from_utf8(out.stdout)?;
    assert_eq!(printed_keys(&stdout).len(), 1, "{stdout}");
    assert!(stdout.contains("docker restart enterplace"), "{stdout}");
    assert!(!stdout.contains("--force"), "{stdout}");
    let policy = std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?;
    assert!(policy.contains("mode: observe\n"), "{policy}");

    // A restart on the same volume serves that policy and keys: no second key, nothing rewritten.
    let out = start(&dir, &["--container"], BOTH_KEYS[..1].as_ref())?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let stdout = String::from_utf8(out.stdout)?;
    assert!(printed_keys(&stdout).is_empty(), "{stdout}");
    assert!(stdout.contains("enterplace.policy.yaml"), "{stdout}");
    assert_eq!(
        std::fs::read_to_string(dir.join("enterplace.policy.yaml"))?,
        policy
    );
    Ok(())
}

/// Sends one HTTP/1.1 request over a plain socket and returns the whole answer.
fn http(addr: &str, request: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok()?;
    stream.write_all(request.as_bytes()).ok()?;
    let mut text = String::new();
    stream.read_to_string(&mut text).ok()?;
    Some(text)
}

#[test]
fn start_prints_the_dashboard_link_first_and_it_signs_in_once() -> TestResult {
    use std::io::BufRead;
    let dir = start_dir("link")?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let addr = format!("127.0.0.1:{port}");
    // Anthropic, as the subscription provider reaches it: one answer to the first request.
    let anthropic = std::net::TcpListener::bind("127.0.0.1:0")?;
    let anthropic_url = format!("http://{}", anthropic.local_addr()?);
    let mock = std::thread::spawn(move || -> Option<String> {
        use std::io::{Read, Write};
        let (mut stream, _) = anthropic.accept().ok()?;
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).ok()?;
            seen.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&seen).to_string();
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().to_string())
                    })
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                if seen.len() >= end + 4 + length || n == 0 {
                    break;
                }
            } else if n == 0 {
                break;
            }
        }
        let body = r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":1}}"#;
        let answer = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(answer.as_bytes()).ok()?;
        Some(String::from_utf8_lossy(&seen).to_string())
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .env_clear()
        .envs(windows_root())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("USER", "sarah.miller")
        .env("ENTERPLACE_ANTHROPIC_BASE_URL", &anthropic_url)
        .args([
            "start",
            "--no-open",
            "--dir",
            &dir.display().to_string(),
            "--listen",
            &addr,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut lines = std::io::BufReader::new(stdout).lines();
    let mut head = Vec::new();
    for line in lines.by_ref() {
        let line = line?;
        let done = line.contains("export ANTHROPIC_CUSTOM_HEADERS=");
        head.push(line);
        if done || head.len() > 40 {
            break;
        }
    }
    let first = head
        .iter()
        .find(|l| !l.trim().is_empty())
        .cloned()
        .unwrap_or_default();
    let link = head
        .iter()
        .find_map(|l| {
            l.trim()
                .strip_prefix(&format!("http://{addr}"))
                .map(str::to_string)
        })
        .unwrap_or_default();
    let key = head
        .iter()
        .find_map(|l| {
            l.trim()
                .strip_prefix("export ENTERPLACE_KEY=")
                .map(str::to_string)
        })
        .unwrap_or_default();
    let token = head
        .iter()
        .find_map(|l| {
            l.trim()
                .strip_prefix("export ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: ")
                .and_then(|rest| rest.strip_suffix('"'))
                .map(str::to_string)
        })
        .unwrap_or_default();
    let base_line = format!("  export ANTHROPIC_BASE_URL=http://{addr}");
    let get = |path: &str, extra: &str| {
        http(
            &addr,
            &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{extra}Connection: close\r\n\r\n"),
        )
        .unwrap_or_default()
    };
    let signed = get(&link, "");
    // A browser at the gateway's own address lands on the console; an API client keeps the JSON answer.
    let root_html = get("/", "Accept: text/html\r\n");
    let root_api = get("/", "");
    let again = get(&link, "");
    let body = r#"{"model":"enterplace-demo","messages":[{"role":"user","content":"hi"}]}"#;
    let demo = http(
        &addr,
        &format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .unwrap_or_default();
    let post = |path: &str, body: &str| {
        http(
            &addr,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {key}\r\nanthropic-version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .unwrap_or_default()
    };
    // Claude Code with a Enterplace key on a new install: the demo answers messages too.
    let claude = post(
        "/v1/messages",
        r#"{"model":"enterplace-demo","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}"#,
    );
    // Codex streams the Responses API and drops a text delta that no output item was opened for.
    let codex = post(
        "/v1/responses",
        r#"{"model":"enterplace-demo","stream":true,"input":"hi"}"#,
    );
    // Claude Code on a Claude subscription, set up with the lines start printed: its first request carries a name.
    let subscription = |person: &str| {
        let body = r#"{"model":"claude-sonnet-4-5","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}"#;
        http(
            &addr,
            &format!(
                "POST /v1/messages HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer sk-ant-oat01-FAKE-login\r\n{person}anthropic-version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .unwrap_or_default()
    };
    let unnamed = subscription("");
    let named = subscription(&format!("x-enterplace-user: {token}\r\n"));
    let _ = child.kill();
    let _ = child.wait();
    assert!(head.contains(&base_line), "{head:?}");
    assert!(token.starts_with("enterplace_u_"), "{head:?}");
    assert!(
        !unnamed.starts_with("HTTP/1.1 200") && unnamed.contains("x-enterplace-user"),
        "a request without a name is refused: {unnamed}"
    );
    assert!(named.starts_with("HTTP/1.1 200"), "{named}");
    let sent = mock.join().map_err(|_| "the mock provider failed")?;
    assert!(
        sent.is_some_and(|s| s.contains("sk-ant-oat01-FAKE-login") && !s.contains(&token)),
        "the login goes on, the token does not"
    );
    let audit = std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?;
    assert!(
        audit.lines().any(|l| l.contains(r#""auth":"passthrough""#)
            && l.contains(r#""person":"sarah.miller""#)
            && l.contains(r#""verdict":"allow""#)),
        "{audit}"
    );
    assert!(claude.starts_with("HTTP/1.1 200"), "{claude}");
    assert!(claude.contains("Enterplace demo model"), "{claude}");
    let order: Vec<&str> = codex
        .lines()
        .filter_map(|l| l.strip_prefix("event: "))
        .collect();
    let at = |name: &str| order.iter().position(|e| *e == name);
    assert!(
        at("response.output_item.added") < at("response.content_part.added")
            && at("response.content_part.added").is_some()
            && at("response.content_part.added") < at("response.output_text.delta")
            && at("response.output_text.done") > at("response.output_text.delta")
            && at("response.output_item.done") > at("response.output_text.done")
            && at("response.completed") > at("response.output_item.done"),
        "{order:?}"
    );
    assert_eq!(
        first, "Enterplace is running. Open the dashboard:",
        "{head:?}"
    );
    assert!(link.starts_with("/console/sign-in/"), "{head:?}");
    assert!(signed.starts_with("HTTP/1.1 303"), "{signed}");
    assert!(signed.contains("location: /console/start"), "{signed}");
    assert!(signed.contains("enterplace_console="), "{signed}");
    assert!(
        again.starts_with("HTTP/1.1 403"),
        "the link works once: {again}"
    );
    assert!(root_html.contains("location: /console"), "{root_html}");
    assert!(root_api.contains("no_key"), "{root_api}");
    assert!(demo.starts_with("HTTP/1.1 200"), "{demo}");
    assert!(demo.contains("Enterplace demo model"), "{demo}");
    let audit = std::fs::read_to_string(dir.join("enterplace-audit.jsonl"))?;
    assert!(audit.contains(r#""via":"start_link""#), "{audit}");
    assert!(audit.contains(r#""provider":"demo""#), "{audit}");
    Ok(())
}

#[test]
fn audit_verify_checks_each_organizations_chain_and_one_with_org() -> TestResult {
    let dir = workdir("per-org")?;
    let log_path = dir.join("enterplace-audit.jsonl");
    let log = enterplace_core::audit::AuditLog::open(&log_path)?.per_org(&[])?;
    for (id, org) in [("A", "acme"), ("B", "globex"), ("C", ""), ("D", "acme")] {
        let mut record = serde_json::Map::new();
        record.insert("id".into(), id.into());
        if !org.is_empty() {
            record.insert("org".into(), org.into());
        }
        log.append_record(&record)?;
    }
    log.flush();
    drop(log);
    let file = log_path.display().to_string();
    let out = enterplace(&["audit", "verify", &file], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(
        stdout.contains("Organization acme:") && stdout.contains("Organization globex:"),
        "{stdout}"
    );
    let out = enterplace(&["audit", "verify", &file, "--org", "acme"], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        stdout.contains("2 records in an unbroken chain"),
        "{stdout}"
    );
    let out = enterplace(&["audit", "verify", &file, "--org", "initech"], &[])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)?.contains("has no audit chain"));
    // A changed record in one organization's chain fails the whole check.
    let acme = enterplace_core::audit::org_path(&log_path, "acme");
    std::fs::write(
        &acme,
        std::fs::read_to_string(&acme)?.replacen("\"id\":\"A\"", "\"id\":\"X\"", 1),
    )?;
    let out = enterplace(&["audit", "verify", &file], &[])?;
    assert_eq!(out.status.code(), Some(1));
    Ok(())
}

#[test]
fn check_prints_each_alias_s_worst_wait_across_retries_timeouts_and_fallbacks() -> TestResult {
    let dir = workdir("worst")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    std::fs::write(
        &policy,
        "version: 1
providers:
  - name: a
    kind: openai
    url: http://127.0.0.1:9
    allow_private: true
    retries: 2
    timeouts: { first_byte_ms: 10000 }
    models: [m1]
  - name: b
    kind: openai
    url: http://127.0.0.1:9
    allow_private: true
    models: [m2]
aliases:
  - name: smart
    timeouts: { total_ms: 60000 }
    fallbacks: [m2]
    deployments:
      - { provider: a, model: m1 }
      - { provider: b, model: m2, timeouts: { first_byte_ms: 5000 } }
rules:
  - name: all
    principals: { any: true }
    models: [smart, m1, m2]
",
    )?;
    let out = enterplace(&["check", &policy], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    // a: 3 tries of 10 s with pauses of 0.2 and 0.4 s; b: 5 s; then the fallback m2 at b's own 120 s default.
    assert!(
        stdout
            .contains("alias smart: a caller waits at most 155.6 s for the first byte (5 attempts"),
        "{stdout}"
    );
    assert!(
        stdout.contains("then at most 1800 s for the answer"),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn usage_prints_tables_or_csv_and_budget_status_says_what_a_key_has_left() -> TestResult {
    let dir = workdir("usage")?;
    let policy = path(&dir, "enterplace.policy.yaml");
    let keys = path(&dir, "enterplace.keys.yaml");
    std::fs::write(
        &policy,
        format!("{POLICY}limits:\n  - {{ team: payments, budget: {{ usd: 5, per: month }} }}\n"),
    )?;
    let new_key = |name: &str, admin: bool| -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec![
            "key", "new", name, "--team", "payments", "--quiet", "--keys", &keys,
        ];
        if admin {
            args.push("--admin");
        }
        let out = enterplace(&args, &[])?;
        assert!(out.status.success());
        Ok(String::from_utf8(out.stdout)?.trim().to_string())
    };
    let (admin, maya) = (new_key("ops", true)?, new_key("maya", false)?);
    let stdout_path = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .args(["serve", &policy, "--listen", "127.0.0.1:0"])
        .env("ENTERPLACE_TEST_PROVIDER_KEY", "provider-secret")
        .stdout(std::fs::File::create(&stdout_path)?)
        .stderr(std::fs::File::create(dir.join("stderr.txt"))?)
        .spawn()?;
    let _server = Running(child);
    let addr = listening(&stdout_path)?;
    let url = format!("http://{addr}");
    let home = path(&dir, "config");
    let env = [
        ("XDG_CONFIG_HOME", home.as_str()),
        ("ENTERPLACE_URL", url.as_str()),
        ("ENTERPLACE_ADMIN_KEY", admin.as_str()),
        ("ENTERPLACE_KEY", maya.as_str()),
    ];
    // One request by maya: whatever becomes of it, it is a request of team payments for model-a.
    post(
        &addr,
        "/v1/chat/completions",
        &maya,
        r#"{"model":"model-a","max_tokens":5,"messages":[]}"#,
    )?;

    let out = enterplace(&["usage", "--since", "1d"], &env)?;
    let tables = String::from_utf8(out.stdout)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for wanted in [
        "counted by this gateway",
        "By team:",
        "By person:",
        "By model:",
        "payments",
        "maya",
        "model-a",
        "spend USD",
        "total",
    ] {
        assert!(tables.contains(wanted), "{wanted} missing from:\n{tables}");
    }
    let out = enterplace(&["usage", "--group-by", "team", "--csv"], &env)?;
    let csv = String::from_utf8(out.stdout)?;
    assert!(out.status.success());
    let mut lines = csv.lines();
    assert_eq!(
        lines.next(),
        Some(
            "group_by,value,requests,refused,errors,input_tokens,output_tokens,total_tokens,spend_usd,latency_p50_ms,latency_p95_ms"
        )
    );
    assert!(
        lines
            .next()
            .is_some_and(|l| l.starts_with("team,\"payments\",1,")),
        "{csv}"
    );
    let out = enterplace(&["usage", "--since", "soon"], &env)?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("7d, 24h or 30m"));
    let out = enterplace(&["usage", "--group-by", "shoe-size"], &env)?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("Group by day, hour or one of"));

    // The budget of maya's own key, with her key and no admin's.
    let out = enterplace(&["budget", "status"], &env)?;
    let status = String::from_utf8(out.stdout)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        status.contains("maya (team payments), rule payments-team")
            && status.contains("left of $5.00 a month")
            && status.contains("resets"),
        "{status}"
    );
    let out = enterplace(&["budget", "status", "--short"], &env)?;
    let line = String::from_utf8(out.stdout)?;
    assert!(
        line.starts_with("$5.00 left (resets ") && line.trim_end().ends_with("00:00 UTC)"),
        "{line}"
    );
    assert_eq!(line.lines().count(), 1, "one line, for a status line");
    let out = enterplace(&["budget", "status"], &env[..2])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("ENTERPLACE_KEY"));
    Ok(())
}

#[test]
fn an_identity_only_token_is_a_person_token_with_the_claude_code_lines() -> TestResult {
    let dir = workdir("person-token")?;
    let keys = path(&dir, "enterplace.keys.yaml");
    let out = enterplace(
        &[
            "key",
            "new",
            "maya.cohen",
            "--team",
            "payments",
            "--identity-only",
            "--keys",
            &keys,
            "--url",
            "http://gw.internal:8080",
        ],
        &[],
    )?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    let stdout = String::from_utf8(out.stdout)?;
    let token = stdout
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("enterplace_u_"))
        .ok_or("no person token was printed")?;
    assert!(
        stdout.contains("export ANTHROPIC_BASE_URL=http://gw.internal:8080"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "export ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: {token}\""
        )),
        "{stdout}"
    );
    assert!(
        !stdout.contains("ANTHROPIC_API_KEY="),
        "no API key: {stdout}"
    );
    let saved = std::fs::read_to_string(&keys)?;
    assert!(!saved.contains(token));
    assert!(saved.contains(&enterplace_core::id::sha256_hex(token.as_bytes())));

    let out = enterplace(
        &[
            "key",
            "new",
            "dana",
            "--team",
            "payments",
            "--identity-only",
            "--admin",
            "--keys",
            &keys,
        ],
        &[],
    )?;
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)?.contains("--identity-only makes a person token"));
    Ok(())
}

#[test]
fn start_on_a_taken_port_writes_nothing_and_stop_stops_the_gateway_of_a_folder() -> TestResult {
    use std::io::BufRead;
    let dir = start_dir("stop")?;
    let dir_s = dir.display().to_string();
    // A port something else holds: start says so before it writes a policy or makes an admin key, which would be
    // made, never shown, and reused by the next start.
    let held = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = held.local_addr()?.to_string();
    let out = enterplace(
        &["start", "--no-open", "--dir", &dir_s, "--listen", &addr],
        &[],
    )?;
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8(out.stderr)?.contains("could not listen on"));
    assert!(
        !dir.join("enterplace.keys.yaml").exists() && !dir.join("enterplace.policy.yaml").exists()
    );
    // Nothing runs from the folder yet: stop says so, and that is no error.
    let out = enterplace(&["stop", "--dir", &dir_s], &[])?;
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8(out.stdout)?.contains("No Enterplace is running"));
    drop(held);
    let mut child = Command::new(env!("CARGO_BIN_EXE_enterplace"))
        .env_clear()
        .envs(windows_root())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .args(["start", "--no-open", "--dir", &dir_s, "--listen", &addr])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut said_stop = false;
    for line in std::io::BufReader::new(stdout).lines() {
        let line = line?;
        said_stop |= line.contains("enterplace stop");
        if line.contains("listening on") {
            break;
        }
    }
    assert!(said_stop, "the start block names enterplace stop");
    let out = enterplace(&["stop", "--dir", &dir_s], &[])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8(out.stdout)?.contains("Stopped Enterplace"));
    // The gateway is gone: the process start ran has ended, and the port is free again.
    let status = child.wait()?;
    assert!(status.code().is_some() || !status.success(), "{status:?}");
    assert!(std::net::TcpListener::bind(&addr).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
