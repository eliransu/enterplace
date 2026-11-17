//! One binary does everything: the enterprise `enterplace` runs every open source `enterplace` command as `enterplace` does, and keeps
//! its own commands. The self-hosted image holds this binary alone, so admin tasks run with it.

use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_enterplace-enterprise"))
        .args(args)
        .env_remove("ENTERPLACE_LICENSE")
        .env_remove("ENTERPLACE_LICENSE_FILE")
        .output()
}

#[test]
fn the_open_source_commands_run_as_enterplace_runs_them() -> TestResult {
    let dir =
        std::env::temp_dir().join(format!("enterplace-enterprise-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    let keys = dir.join("enterplace.keys.yaml");
    let (policy_s, keys_s) = (policy.to_str().ok_or("path")?, keys.to_str().ok_or("path")?);

    let out = run(&["init", "--out", policy_s])?;
    assert!(out.status.success(), "{out:?}");

    let out = run(&[
        "key",
        "new",
        "maya.cohen",
        "--team",
        "payments",
        "--keys",
        keys_s,
        "--quiet",
    ])?;
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8(out.stdout)?
            .trim()
            .starts_with("enterplace_")
    );

    let out = run(&["key", "list", "--keys", keys_s])?;
    assert!(String::from_utf8(out.stdout)?.contains("maya.cohen\tpayments"));

    let out = run(&["check", policy_s, "--keys", keys_s])?;
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8(out.stdout)?.contains("is valid: 1 rule, 1 key"));

    let log = dir.join("enterplace-audit.jsonl");
    std::fs::write(&log, "")?;
    let out = run(&["audit", "verify", log.to_str().ok_or("path")?])?;
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8(out.stdout)?.contains("no records yet"));

    let out = run(&["version"])?;
    assert!(String::from_utf8(out.stdout)?.starts_with("enterplace "));

    // A mistake gets the open source command line's own answer and exit code.
    let out = run(&["key", "new", "maya"])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("Usage: enterplace key new"));

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn the_enterprise_commands_keep_precedence() -> TestResult {
    let out = run(&["license", "show"])?;
    assert!(out.status.success(), "{out:?}");
    // `serve` with no policy is the enterprise usage, never the open source server started without a license check.
    for args in [&["serve"][..], &[]] {
        let out = run(args)?;
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8(out.stderr)?.contains("enterplace node --control-plane"),
            "{args:?}"
        );
    }
    // Asked for, help is no error and lists every command: start first among them, then the enterprise ones.
    for args in [&["help"][..], &["--help"]] {
        let out = run(args)?;
        assert!(out.status.success(), "{args:?}");
        let help = String::from_utf8(out.stdout)?;
        assert!(
            help.contains("  start [") && help.contains("enterplace node --control-plane"),
            "{args:?}: {help}"
        );
    }
    Ok(())
}

#[test]
fn a_secret_manager_reference_without_the_secrets_feature_stops_serve_with_the_fix() -> TestResult {
    let dir = std::env::temp_dir().join(format!(
        "enterplace-enterprise-secrets-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    std::fs::write(
        &policy,
        "version: 1\nproviders:\n  - name: openai\n    kind: openai\n    url: https://api.openai.com\n    key_env: OPENAI_KEY\n    models: [m]\nrules:\n  - name: everyone\n    principals: { any: true }\n    models: [m]\n",
    )?;
    let out = Command::new(env!("CARGO_BIN_EXE_enterplace-enterprise"))
        .args([
            "serve",
            policy.to_str().ok_or("path")?,
            "--listen",
            "127.0.0.1:0",
        ])
        .env_remove("ENTERPLACE_LICENSE")
        .env_remove("ENTERPLACE_LICENSE_FILE")
        .env("OPENAI_KEY", "vault://secret/data/enterplace#openai")
        .output()?;
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains("OPENAI_KEY holds a secret manager reference")
            && stderr.contains("license that has `secrets`"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
