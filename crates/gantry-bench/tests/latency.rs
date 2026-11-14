//! Acceptance test for the mock upstream's latency, which reproduces the setup Bifrost publishes: every answer
//! waits a fixed time, and the gateway's self-time must not include that wait.

use std::time::Duration;

use gantry_bench::{BoxError, Load, run_load, spawn_gateway, spawn_mock_upstream_with_latency};

#[tokio::test(flavor = "multi_thread")]
async fn the_mock_waits_and_self_time_leaves_the_wait_out() -> Result<(), BoxError> {
    let wait = Duration::from_millis(200);
    let upstream = spawn_mock_upstream_with_latency("127.0.0.1:0".parse()?, wait).await?;
    let (gateway, _) = spawn_gateway(upstream, true).await?;
    let load = Load {
        rps: 100,
        duration: Duration::from_millis(300),
        stream: false,
        messages: false,
    };
    let direct = run_load(upstream, load).await?;
    assert_eq!(direct.ok, 30);
    assert!(
        direct.latency.p50 >= wait,
        "the upstream answered before its wait"
    );
    let through = run_load(gateway, load).await?;
    assert_eq!(through.ok, 30);
    assert!(through.latency.p50 >= wait);
    let own = through
        .own
        .ok_or("the gateway sent no Server-Timing header")?;
    assert!(
        own.p99 < wait / 4,
        "self-time counted the upstream's wait: {own:?}"
    );
    Ok(())
}
