//! Acceptance check 11 of slice 3: changes to the policy and keys files under load cost no request,
//! and every request record names a version recorded before it. Ports are picked by the system.

use std::time::Duration;

use enterplace_bench::{BENCH_KEY, BoxError, Load, run_load, spawn_mock_upstream};
use enterplace_core::id::sha256_hex;
use enterplace_server::{Reload, Trigger};

const POLICY: &str = "version: 1
providers:
  - name: mock
    kind: openai
    url: http://127.0.0.1:PORT
    allow_private: true
    key_env: MOCK_PROVIDER_KEY
    models: [mock-model]
rules:
  - name: everyone
    principals: { any: true }
    models: [mock-model]
";

#[tokio::test(flavor = "multi_thread")]
async fn ten_changes_at_1000_requests_a_second_cost_no_request() -> Result<(), BoxError> {
    let upstream = spawn_mock_upstream("127.0.0.1:0".parse()?).await?;
    let policy_text = POLICY.replace("PORT", &upstream.port().to_string());
    let dir = std::env::temp_dir().join(format!("enterplace-bench-reload-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let (policy, keys) = (
        dir.join("enterplace.policy.yaml"),
        dir.join("enterplace.keys.yaml"),
    );
    let entry = |name: &str, key: &str| {
        format!(
            "  - name: {name}\n    team: t\n    sha256: {}\n",
            sha256_hex(key.as_bytes())
        )
    };
    let base_keys = format!("keys:\n{}", entry("bench", BENCH_KEY));
    std::fs::write(&policy, &policy_text)?;
    std::fs::write(&keys, &base_keys)?;
    let gw = enterplace_server::governed(&policy, None, &|_| Some("mock-provider-key".into()))
        .map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let gateway = listener.local_addr()?;
    tokio::spawn(enterplace_server::serve_on(
        listener,
        gw.router.clone(),
        enterplace_server::Timeouts::default(),
        std::future::pending(),
    ));

    let reloader = gw.reloader.clone();
    let changes = tokio::task::spawn_blocking(move || -> Result<(), String> {
        for i in 0..10 {
            std::thread::sleep(Duration::from_millis(250));
            let written = if i % 2 == 0 {
                std::fs::write(&policy, format!("{policy_text}# change {i}\n"))
            } else {
                std::fs::write(
                    &keys,
                    format!(
                        "{base_keys}{}",
                        entry(&format!("extra{i}"), &format!("k{i}"))
                    ),
                )
            };
            written.map_err(|e| e.to_string())?;
            if !matches!(reloader.check(Trigger::FileChange), Reload::Loaded) {
                return Err(format!("change {i} was not loaded"));
            }
        }
        Ok(())
    });
    let report = run_load(
        gateway,
        Load {
            rps: 1000,
            duration: Duration::from_secs(3),
            stream: false,
            messages: false,
        },
    )
    .await?;
    changes.await??;
    assert_eq!(report.sent, 3000);
    assert_eq!(report.ok, 3000, "a request failed during a change");

    let log = dir.join("enterplace-audit.jsonl");
    // A usage record is written as its answer ends, so the last few may still be on their way.
    let mut summary = enterplace_core::audit::verify_full(&log, None)?;
    for _ in 0..50 {
        if summary.usage == 3000 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        summary = enterplace_core::audit::verify_full(&log, None)?;
    }
    assert_eq!(summary.requests, 3000);
    assert_eq!(summary.configuration, 11);
    assert_eq!(summary.usage, 3000);
    assert_eq!(summary.records, 6011);
    let mut versions: Vec<(String, String)> = Vec::new();
    for line in std::fs::read_to_string(&log)?.lines() {
        let record: serde_json::Value = serde_json::from_str(line)?;
        let pair = (
            record["policy_sha256"].to_string(),
            record["keys_sha256"].to_string(),
        );
        if record["event"] == "config_loaded" {
            versions.push(pair);
        } else if record["event"].is_null() {
            assert!(
                versions.contains(&pair),
                "a record names no version before it: {line}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
