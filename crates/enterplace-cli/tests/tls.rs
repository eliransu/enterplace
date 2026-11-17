//! `enterplace serve --tls-cert --tls-key`: both or neither, and a bad file stops the start before anything is written.

use std::process::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn tls_needs_both_files_and_a_bad_one_stops_the_start() -> TestResult {
    let dir = std::env::temp_dir().join(format!("enterplace-cli-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let policy = dir.join("enterplace.policy.yaml");
    let policy = policy.to_str().ok_or("temp path is not text")?;
    let missing = dir.join("missing.pem");
    let missing = missing.to_str().ok_or("temp path is not text")?;
    let enterplace = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_enterplace"))
            .args(args)
            .output()
    };

    let out = enterplace(&["serve", policy, "--tls-cert", missing])?;
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr)?.contains("--tls-key <pem>"));

    let out = enterplace(&[
        "serve",
        policy,
        "--tls-cert",
        missing,
        "--tls-key",
        missing,
        "--listen",
        "127.0.0.1:0",
    ])?;
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr)?;
    assert!(
        stderr.contains(missing) && stderr.contains("--tls-cert"),
        "{stderr}"
    );
    assert!(!dir.join("enterplace-audit.jsonl").exists());
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
