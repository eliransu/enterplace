//! The `gantry` binary: every argument form either does what it says or fails with exit code 2 and the reason.

use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

#[test]
fn version_prints_the_version_the_source_hash_and_the_build_date() -> TestResult {
    // BLK-1: two builds of one version must be told apart in a bug report, and there is no git to ask.
    for arg in ["version", "--version"] {
        let out = gantry(&[arg], &[])?;
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout)?;
        let rest = text
            .trim()
            .strip_prefix(&format!("gantry {} (src ", env!("CARGO_PKG_VERSION")))
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
    let out = gantry(&[], &[])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("Usage: gantry <command>"));
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
        let out = gantry(args, &[])?;
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8(out.stderr)?;
        assert!(
            stderr.contains("is not a command Gantry knows") || stderr.contains("Usage: gantry "),
            "{args:?}: {stderr}"
        );
    }
    Ok(())
}

#[test]
fn serve_refuses_to_forward_unchecked_unless_asked_by_name() -> TestResult {
    let out = gantry(&["serve"], &[])?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("gantry serve gantry.policy.yaml")
            && stderr.contains("gantry serve --unchecked"),
        "the error must say how to proceed: {stderr}"
    );
    Ok(())
}

#[test]
fn unchecked_serving_is_refused_on_an_address_other_machines_can_reach() -> TestResult {
    let out = gantry(
        &["serve", "--unchecked"],
        &[("GANTRY_ADDR", "0.0.0.0:18099")],
    )?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("loopback"));
    Ok(())
}

#[test]
fn a_bad_address_or_upstream_stops_startup_with_the_reason() -> TestResult {
    let out = gantry(&["serve", "--unchecked"], &[("GANTRY_ADDR", "nope")])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("GANTRY_ADDR"));
    // UX3-19: a host name gets the IP address to use instead.
    let out = gantry(
        &["serve", "--unchecked"],
        &[("GANTRY_ADDR", "localhost:20461")],
    )?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(stderr.contains("use 127.0.0.1:20461"), "{stderr}");

    let out = gantry(
        &["serve", "--unchecked"],
        &[("GANTRY_UPSTREAM", "http://user:S3cret@127.0.0.1:9")],
    )?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("GANTRY_UPSTREAM") && !stderr.contains("S3cret"),
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
    key_env: GANTRY_TEST_PROVIDER_KEY
    models: [model-a, model-b]
rules:
  - name: payments-team
    principals: { team: payments }
    models: [model-a]
";

fn workdir(name: &str) -> std::io::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("gantry-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("gantry.policy.yaml"), POLICY)?;
    Ok(dir)
}

fn path(dir: &std::path::Path, file: &str) -> String {
    dir.join(file).display().to_string()
}

#[test]
fn check_names_the_line_and_the_word_and_exits_1() -> TestResult {
    let dir = workdir("check")?;
    let policy = path(&dir, "gantry.policy.yaml");
    let out = gantry(&["check", &policy], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(String::from_utf8(out.stdout)?.contains("is valid: 1 rule, 0 keys"));

    std::fs::write(&policy, POLICY.replace("    models:", "    modles:"))?;
    let out = gantry(&["check", &policy], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("gantry.policy.yaml:12") && stderr.contains("Did you mean \"models\"?"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn a_new_key_is_printed_once_and_only_its_hash_is_saved() -> TestResult {
    let dir = workdir("key")?;
    let keys = path(&dir, "gantry.keys.yaml");
    let mut printed = Vec::new();
    for name in ["maya.cohen", "svc-invoice-bot"] {
        let out = gantry(
            &["key", "new", name, "--team", "payments", "--keys", &keys],
            &[],
        )?;
        assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
        let stdout = String::from_utf8(out.stdout)?;
        let key = stdout
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("gantry_"))
            .ok_or("no key was printed")?
            .to_string();
        assert_eq!(key.len(), "gantry_".len() + 64);
        printed.push(key);
    }
    let saved = std::fs::read_to_string(&keys)?;
    for key in &printed {
        assert!(!saved.contains(key), "the key itself was saved");
        assert!(saved.contains(&gantry_core::id::sha256_hex(key.as_bytes())));
    }
    let out = gantry(&["check", &path(&dir, "gantry.policy.yaml")], &[])?;
    assert!(String::from_utf8(out.stdout)?.contains("2 keys"));

    let out = gantry(
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
    let policy = path(&dir, "gantry.policy.yaml");

    let out = gantry(&["serve", &path(&dir, "missing.yaml")], &[])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("cannot be read"));

    let out = gantry(&["serve", &policy], &[])?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("export GANTRY_TEST_PROVIDER_KEY="),
        "{stderr}"
    );

    std::fs::write(dir.join("gantry-audit.jsonl"), "{\"n\":1,\"cut")?;
    let secret = [("GANTRY_TEST_PROVIDER_KEY", "provider-secret-1234")];
    let out = gantry(&["serve", &policy], &secret)?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("gantry audit verify") && !stderr.contains("provider-secret"),
        "{stderr}"
    );

    std::fs::remove_file(dir.join("gantry-audit.jsonl"))?;
    let out = gantry(&["serve", &policy, "--listen", "nope"], &secret)?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("--listen"));
    Ok(())
}

#[test]
fn audit_verify_reports_the_count_or_the_first_broken_record() -> TestResult {
    let dir = workdir("audit")?;
    let log_path = dir.join("gantry-audit.jsonl");
    let log = gantry_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B"] {
        log.append(&gantry_core::audit::Entry {
            id,
            method: "POST",
            path: "/v1/chat/completions",
            ..Default::default()
        })?;
    }
    let file = log_path.display().to_string();
    let out = gantry(&["audit", "verify", &file], &[])?;
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)?.contains("2 records"));

    std::fs::write(
        &log_path,
        std::fs::read_to_string(&log_path)?.replacen("\"id\":\"A\"", "\"id\":\"Z\"", 1),
    )?;
    let out = gantry(&["audit", "verify", &file], &[])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)?.contains("record 1"));
    Ok(())
}

#[test]
fn audit_repair_shows_then_removes_only_a_cut_last_line_and_records_it() -> TestResult {
    // QA10-11: a write that failed on a full disk leaves a cut last line, and serve refuses to start on it.
    let dir = workdir("repair")?;
    let log_path = dir.join("gantry-audit.jsonl");
    let log = gantry_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B"] {
        log.append(&gantry_core::audit::Entry {
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
    let err = gantry_core::audit::AuditLog::open(&log_path)
        .err()
        .ok_or("a cut log was opened")?;
    assert!(
        err.contains(&format!("gantry audit repair {file}")),
        "{err}"
    );

    // Without --yes it only shows what it would remove.
    let out = gantry(&["audit", "repair", &file], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout)?;
    assert!(
        stdout.contains("\"id\":\"C\",\"pa") && stdout.contains("--yes"),
        "{stdout}"
    );
    assert_eq!(std::fs::read(&log_path)?, cut);

    let out = gantry(&["audit", "repair", &file, "--yes"], &[])?;
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
    let out = gantry(&["audit", "verify", &file], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(String::from_utf8(out.stdout)?.contains("3 records"));

    // A whole log has nothing to repair, and a broken record that is not the last line is never removed.
    let out = gantry(&["audit", "repair", &file, "--yes"], &[])?;
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
    let out = gantry(&["audit", "repair", &file, "--yes"], &[])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)?.contains("record 1"));
    assert_eq!(std::fs::read(&log_path)?, before);

    // UX11 n8: a record changed in the middle, last line whole. Repair is not "nothing to do": it fails and says why.
    std::fs::write(&log_path, text.replacen("\"id\":\"B\"", "\"id\":\"Y\"", 1))?;
    let before = std::fs::read(&log_path)?;
    let out = gantry(&["audit", "repair", &file, "--yes"], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("record 2") && stderr.contains("only removes a last line cut short"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(&log_path)?, before);

    // Verify on a cut last line points at repair; on a folder it says it is a folder, not a broken record.
    std::fs::write(&log_path, &cut)?;
    let out = gantry(&["audit", "verify", &file], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains(&format!("gantry audit repair {file}")),
        "{stderr}"
    );
    let folder = dir.display().to_string();
    let out = gantry(&["audit", "verify", &folder], &[])?;
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
    let keys = dir.join("gantry.keys.yaml");
    // One byte that is not text: the file exists, holds keys, and cannot be read as text.
    let mut original = b"keys:\n  - name: a\n    team: t\n    sha256: ".to_vec();
    original.extend(gantry_core::id::sha256_hex(b"k").as_bytes());
    original.extend(b"\n# \xff\n");
    std::fs::write(&keys, &original)?;
    let out = gantry(
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

    let out = gantry(&["check", &path(&dir, "gantry.policy.yaml")], &[])?;
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unreadable keys file passed as an empty one"
    );
    Ok(())
}

#[test]
fn check_lists_every_unknown_and_unenforced_key_at_once() -> TestResult {
    let dir = workdir("many")?;
    let policy = path(&dir, "gantry.policy.yaml");
    std::fs::write(
        &policy,
        POLICY.replace(
            "    models: [model-a]",
            "    modles: [model-a]\n    tools: { allow: [x] }\n    principls: { taem: x }",
        ),
    )?;
    let out = gantry(&["check", &policy], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    for expected in [
        "\"modles\"",
        "\"tools\" is not enforced",
        "\"principls\"",
        "\"taem\"",
        "4 problems",
    ] {
        assert!(stderr.contains(expected), "missing {expected}: {stderr}");
    }
    assert!(
        !stderr.contains("\"allow\"") || stderr.contains("5 problem"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn key_new_does_not_add_to_a_keys_file_gantry_could_not_load() -> TestResult {
    let dir = workdir("unparseable")?;
    let keys = dir.join("gantry.keys.yaml");
    for broken in [
        "keys: [oops\n",
        "keys:\n  - name: a\n    team: t\n    sha256: abc\n",
    ] {
        std::fs::write(&keys, broken)?;
        let out = gantry(
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
    let policy = path(&dir, "gantry.policy.yaml");
    std::fs::write(
        &policy,
        POLICY.replace(
            "    models: [model-a]",
            "    models: [model-a]\n    \"tools\": { allow: [x] }",
        ),
    )?;
    let out = gantry(&["check", &policy], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("\"tools\" is not enforced") && !stderr.contains("Did you mean"),
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
        let out = gantry(
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
        let out = gantry(
            &[
                "check",
                &path(&dir, "gantry.policy.yaml"),
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
    let keys = dir.join("gantry.keys.yaml");
    let out = gantry(
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
    let log_path = dir.join("gantry-audit.jsonl");
    let log = gantry_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B", "C"] {
        log.append(&gantry_core::audit::Entry {
            id,
            method: "POST",
            path: "/v1/chat/completions",
            ..Default::default()
        })?;
    }
    let text = std::fs::read_to_string(&log_path)?;
    let last = text.lines().last().ok_or("empty log")?;
    let hash = &last[last.len() - 66..last.len() - 2];
    let out = gantry(&["audit", "verify", &log_path.display().to_string()], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(stdout.contains(&format!("Last hash: {hash}")), "{stdout}");
    assert!(stdout.contains("3 records"), "{stdout}");
    Ok(())
}

#[test]
fn serve_does_not_start_on_an_audit_log_with_a_record_missing() -> TestResult {
    let dir = workdir("gap")?;
    let log_path = dir.join("gantry-audit.jsonl");
    let log = gantry_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B", "C"] {
        log.append(&gantry_core::audit::Entry {
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
    let out = gantry(
        &["serve", &path(&dir, "gantry.policy.yaml")],
        &[("GANTRY_TEST_PROVIDER_KEY", "k")],
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
    let policy = path(&dir, "gantry.policy.yaml");
    std::fs::write(
        &policy,
        POLICY.replace(
            "    models: [model-a]\n",
            "    models: [model-a, model-z]\n",
        ),
    )?;
    let out = gantry(&["check", &policy], &[])?;
    let stderr = String::from_utf8(out.stderr)?;
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("warning")
            && stderr.contains("gantry.policy.yaml:12")
            && stderr.contains("\"model-z\""),
        "{stderr}"
    );
    let out = gantry(&["check", &path(&dir, "gantry.policy.yaml")], &[])?;
    assert!(String::from_utf8(out.stdout)?.contains("is valid"));
    Ok(())
}

#[test]
fn key_new_says_the_key_works_within_two_seconds() -> TestResult {
    let dir = workdir("wording")?;
    let out = gantry(
        &[
            "key",
            "new",
            "maya",
            "--team",
            "payments",
            "--keys",
            &path(&dir, "gantry.keys.yaml"),
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
    let log_path = dir.join("gantry-audit.jsonl");
    let log = gantry_core::audit::AuditLog::open(&log_path)?;
    for id in ["A", "B", "C", "D", "E"] {
        log.append(&gantry_core::audit::Entry {
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

    let out = gantry(&["audit", "verify", &file, "--expect-last", &kept], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(stdout.contains("record 3"), "{stdout}");

    let made_up = "ab".repeat(32);
    let out = gantry(&["audit", "verify", &file, "--expect-last", &made_up], &[])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)?.contains("not in this file"));

    let without_first_three: String = original.lines().skip(3).map(|l| format!("{l}\n")).collect();
    std::fs::write(&log_path, without_first_three)?;
    let out = gantry(&["audit", "verify", &file, "--expect-last", &kept], &[])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)?.contains("not in this file"));

    std::fs::write(
        &log_path,
        original.replacen("\"id\":\"B\"", "\"id\":\"X\"", 1),
    )?;
    let out = gantry(&["audit", "verify", &file, "--expect-last", &kept], &[])?;
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
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: gantry\r\nConnection: close\r\n\r\n")
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
    let policy = path(&dir, "gantry.policy.yaml");
    let log = dir.join("gantry-audit.jsonl");
    let out = gantry(
        &[
            "key",
            "new",
            "maya",
            "--team",
            "payments",
            "--keys",
            &path(&dir, "gantry.keys.yaml"),
        ],
        &[],
    )?;
    assert!(out.status.success());
    let stderr_path = dir.join("stderr.txt");
    let stdout_path = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_gantry"))
        .args(["serve", &policy, "--listen", "127.0.0.1:0"])
        .env("GANTRY_TEST_PROVIDER_KEY", "provider-secret")
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
        stderr.contains("gantry.policy.yaml:12") && stderr.contains("\"modles\""),
        "{stderr}"
    );
    let health = healthz(addr).ok_or("the server stopped")?;
    assert!(
        health.contains("200 OK") && health.contains("\"rejected\":{"),
        "{health}"
    );
    drop(server);

    let out = gantry(&["audit", "verify", &log.display().to_string()], &[])?;
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
        dir.join("gantry.policy.yaml"),
        POLICY.replace("http://127.0.0.1:9", &format!("http://{upstream}")),
    )?;
    let policy = path(&dir, "gantry.policy.yaml");
    let log = dir.join("gantry-audit.jsonl");
    let out = gantry(
        &[
            "key",
            "new",
            "maya",
            "--team",
            "payments",
            "--keys",
            &path(&dir, "gantry.keys.yaml"),
        ],
        &[],
    )?;
    let stdout = String::from_utf8(out.stdout)?;
    let key = stdout
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("gantry_"))
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
    let child = Command::new(env!("CARGO_BIN_EXE_gantry"))
        .args(["serve", &policy, "--listen", "127.0.0.1:0"])
        .env("GANTRY_TEST_PROVIDER_KEY", "provider-secret")
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
        "POST /v1/chat/completions HTTP/1.1\r\nHost: gantry\r\nAuthorization: Bearer {key}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nConnection: close\r\n\r\n{request}",
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
    let out = gantry(&["audit", "verify", &log.display().to_string()], &[])?;
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
        let out = gantry(args, &[])?;
        assert!(out.status.success(), "{args:?}");
        assert!(
            String::from_utf8(out.stdout)?.starts_with("Usage: gantry "),
            "{args:?}"
        );
    }
    Ok(())
}

#[test]
fn key_new_makes_the_first_admin_and_prints_an_env_block_to_paste() -> TestResult {
    let dir = workdir("admin-env")?;
    let keys = path(&dir, "gantry.keys.yaml");
    let out = gantry(
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
        .find(|w| w.starts_with("gantry_"))
        .ok_or("no key printed")?
        .trim_matches('\'');
    for line in [
        "export ANTHROPIC_BASE_URL=http://gw.internal:8080\n".to_string(),
        format!("export ANTHROPIC_API_KEY={key}\n"),
        "export OPENAI_BASE_URL=http://gw.internal:8080/v1\n".to_string(),
        format!("export OPENAI_API_KEY={key}\n"),
        // UX11 n13: the console's full address, not a path alone.
        "console at http://gw.internal:8080/console".to_string(),
        "docs/codex.md".to_string(),
    ] {
        assert!(stdout.contains(&line), "{line} missing from:\n{stdout}");
    }
    let entries = gantry_core::config::key_entries(
        std::path::Path::new(&keys),
        &std::fs::read_to_string(&keys)?,
    )
    .map_err(|e| e.join("\n"))?;
    assert!(entries[0].admin, "the first admin needs no hand edit");

    // --quiet prints the key alone, for a pipe into a secret manager.
    let out = gantry(
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
        quiet.starts_with("gantry_") && quiet.trim_end().lines().count() == 1,
        "{quiet}"
    );

    let out = gantry(
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
    let out = gantry(
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
    let out = gantry(&["key", "list", "--keys", &keys], &[])?;
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
    let out = gantry(&["key", "list", "--keys", &keys], &[])?;
    let list = String::from_utf8(out.stdout)?;
    assert!(
        list.contains("2020-01-01 (expired)") && list.contains("2099-01-01\t"),
        "{list}"
    );

    for (bad, says) in [
        (&["--expires", "soon"][..], "It takes a UTC date"),
        (&["--budget", "20/week"], "--budget is"),
        // UX11 n3: a key that is refused on its first request is never issued.
        (&["--expires", "2020-01-01"], "has passed"),
        (&["--expires", "2026-02-30"], "2026-02-30 is not a date"),
        (&["--tpm", "0"], "--tpm is"),
        (&["--models", ","], "--models is"),
    ] {
        let mut args = vec!["key", "new", "x", "--team", "t", "--keys", &keys];
        args.extend_from_slice(bad);
        let out = gantry(&args, &[])?;
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
        let stderr = String::from_utf8(out.stderr)?;
        assert!(stderr.contains(says), "{bad:?}: {stderr}");
    }
    let listed = std::fs::read_to_string(&keys)?;
    assert!(!listed.contains("name: x\n"), "a refused key was written");

    // `check` refuses the same dates in a keys file written by hand, each on its line.
    let dir = workdir("check-expiry")?;
    std::fs::write(dir.join("gantry.policy.yaml"), POLICY)?;
    let entry = |name: &str, hex: &str, date: &str| {
        format!(
            "  - name: {name}\n    team: t\n    sha256: {}\n    expires: {date}\n",
            hex.repeat(64)
        )
    };
    let keys_file = dir.join("gantry.keys.yaml");
    std::fs::write(
        &keys_file,
        format!("keys:\n{}", entry("odd", "d", "2026-11-31")),
    )?;
    let out = gantry(&["check", &path(&dir, "gantry.policy.yaml")], &[])?;
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("gantry.keys.yaml:4") && stderr.contains("2026-11-31 is not a date"),
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
    let out = gantry(&["check", &path(&dir, "gantry.policy.yaml")], &[])?;
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("gantry.keys.yaml:8")
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
            "POST {path} HTTP/1.1\r\nHost: gantry\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        ("GANTRY_URL", "http://127.0.0.1:9"),
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
        (&["kill", "--all", "--reason", "r"], "GANTRY_ADMIN_KEY"),
        (&["logout"], "not signed in"),
        (
            &["login", "http://gantry.example.com"],
            "not an address a key may be sent to",
        ),
    ] {
        let out = gantry(args, &env)?;
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8(out.stderr)?;
        assert!(stderr.contains(says), "{args:?}: {stderr}");
    }
    let out = gantry(&["unkill", "--person", "a", "--reason", "r"], &env)?;
    assert!(String::from_utf8(out.stderr)?.contains("Usage: gantry unkill"));
    Ok(())
}

#[test]
fn kill_stops_a_person_with_the_reason_unkill_restores_and_logout_revokes_the_saved_key()
-> TestResult {
    let dir = workdir("kill")?;
    let policy = path(&dir, "gantry.policy.yaml");
    let keys = path(&dir, "gantry.keys.yaml");
    let new_key = |name: &str, admin: bool| -> Result<String, Box<dyn std::error::Error>> {
        let mut args = vec![
            "key", "new", name, "--team", "payments", "--quiet", "--keys", &keys,
        ];
        if admin {
            args.push("--admin");
        }
        let out = gantry(&args, &[])?;
        assert!(out.status.success());
        Ok(String::from_utf8(out.stdout)?.trim().to_string())
    };
    let (admin, maya) = (new_key("ops", true)?, new_key("maya", false)?);
    let stdout_path = dir.join("stdout.txt");
    let child = Command::new(env!("CARGO_BIN_EXE_gantry"))
        .args(["serve", &policy, "--listen", "127.0.0.1:0"])
        .env("GANTRY_TEST_PROVIDER_KEY", "provider-secret")
        .stdout(std::fs::File::create(&stdout_path)?)
        .stderr(std::fs::File::create(dir.join("stderr.txt"))?)
        .spawn()?;
    let _server = Running(child);
    let addr = listening(&stdout_path)?;
    let url = format!("http://{addr}");
    let home = path(&dir, "config");
    let env = [
        ("XDG_CONFIG_HOME", home.as_str()),
        ("GANTRY_URL", url.as_str()),
        ("GANTRY_ADMIN_KEY", admin.as_str()),
    ];
    let chat = r#"{"model":"model-a","messages":[]}"#;
    let out = gantry(
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
    let out = gantry(&["unkill", "--person", "maya"], &env)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!post(&addr, "/v1/chat/completions", &maya, chat)?.contains("killed"));
    let out = gantry(&["unkill", "--person", "maya"], &env)?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("no kill switch is on"));

    // What `gantry login` saves, for maya: logout revokes that key with the key itself, then deletes the file.
    let saved = dir.join("config").join("gantry").join("credentials");
    std::fs::create_dir_all(saved.parent().ok_or("no folder")?)?;
    std::fs::write(&saved, format!("url={url}\nkey={maya}\nname=maya\n"))?;
    let out = gantry(&["logout"], &env[..1])?;
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
fn check_warns_on_an_expired_key_and_key_prune_removes_only_expired_entries() -> TestResult {
    let dir = workdir("prune")?;
    let policy = path(&dir, "gantry.policy.yaml");
    let keys = path(&dir, "gantry.keys.yaml");
    std::fs::write(
        &keys,
        format!(
            "keys:\n  - name: lior@example.com\n    team: payments\n    sha256: {}\n    expires: 2020-01-01\n  - name: noa\n    team: payments\n    sha256: {}\n",
            "ab".repeat(32),
            "cd".repeat(32)
        ),
    )?;
    // UX12-4: a login key that lapsed is not a broken policy, so a CI check before a deploy still passes.
    let out = gantry(&["check", &policy], &[])?;
    let stderr = String::from_utf8(out.stderr.clone())?;
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("lior@example.com") && stderr.contains("gantry key prune"),
        "{stderr}"
    );
    let out = gantry(&["key", "prune", "--keys", &keys], &[])?;
    assert!(out.status.success(), "{}", String::from_utf8(out.stderr)?);
    assert!(String::from_utf8(out.stdout)?.contains("lior@example.com"));
    let text = std::fs::read_to_string(&keys)?;
    assert!(
        !text.contains(&"ab".repeat(32)) && text.contains(&"cd".repeat(32)),
        "{text}"
    );
    let out = gantry(&["key", "prune", "--keys", &keys], &[])?;
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout)?.contains("No key has expired"));
    let out = gantry(&["check", &policy], &[])?;
    assert!(out.stderr.is_empty(), "{}", String::from_utf8(out.stderr)?);
    Ok(())
}

#[test]
fn prices_names_the_price_used_and_where_it_came_from() -> TestResult {
    let out = gantry(&["prices", "claude-opus-4-5"], &[])?;
    let stdout = String::from_utf8(out.stdout)?;
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("LiteLLM price map") && stdout.contains("input 5, output 25"),
        "{stdout}"
    );
    let dir = workdir("prices")?;
    let policy = path(&dir, "gantry.policy.yaml");
    std::fs::write(
        &policy,
        format!("{POLICY}prices:\n  claude-opus-4-5: {{ input: 1, output: 2 }}\n"),
    )?;
    let out = gantry(&["prices", "claude-opus-4-5", "--policy", &policy], &[])?;
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
    let out = gantry(&["prices", "smart", "--policy", &policy], &[])?;
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
    let out = gantry(&["prices", "no-such-model"], &[])?;
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
    let out = gantry(&["import", "litellm", &config, "--out", &out_file], &[])?;
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
    let out = gantry(&["import", "litellm", &config, "--out", &out_file], &[])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("never replaced"));
    Ok(())
}
