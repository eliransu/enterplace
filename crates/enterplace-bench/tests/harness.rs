//! Acceptance test for the harness: it reports latency for the upstream alone and through the gateway,
//! and the gateway's own time when the gateway is the target.

use std::time::Duration;

use enterplace_bench::{BoxError, Load, run_load, spawn_gateway, spawn_mock_upstream};

#[tokio::test(flavor = "multi_thread")]
async fn reports_latency_direct_and_through_the_gateway() -> Result<(), BoxError> {
    let upstream = spawn_mock_upstream("127.0.0.1:0".parse()?).await?;
    let (unchecked, _) = spawn_gateway(upstream, false).await?;
    let (checked, audit) = spawn_gateway(upstream, true).await?;
    let audit = audit.ok_or("the checked gateway must write an audit log")?;

    for stream in [false, true] {
        let load = Load {
            rps: 200,
            duration: Duration::from_millis(500),
            stream,
            messages: false,
        };
        for (target, is_gateway) in [(upstream, false), (unchecked, true), (checked, true)] {
            let report = run_load(target, load).await?;
            assert_eq!(report.sent, 100);
            assert_eq!(
                report.ok, 100,
                "every request must succeed, stream={stream}"
            );
            assert!(
                report.latency.p50 > Duration::ZERO
                    && report.latency.p50 <= report.latency.p99
                    && report.latency.p99 <= report.latency.max
            );
            // Only the gateway reports its own time. If this fails, the Server-Timing header is gone.
            assert_eq!(report.own.is_some(), is_gateway, "stream={stream}");
            if let Some(own) = report.own {
                assert!(own.p50 > Duration::ZERO && own.p99 < report.latency.max);
            }
        }
    }
    // Claude Code's route through the checked gateway, streamed and not.
    for stream in [false, true] {
        let load = Load {
            rps: 200,
            duration: Duration::from_millis(500),
            stream,
            messages: true,
        };
        let report = run_load(checked, load).await?;
        assert_eq!(
            report.ok, 100,
            "every messages request must succeed, stream={stream}"
        );
    }
    // Four runs of 100 requests went through the checked gateway: one decision and one usage record each, and the
    // chain holds. A usage record is written as its answer ends, so the last few may still be on their way.
    let mut summary = enterplace_core::audit::verify_full(&audit, None)?;
    for _ in 0..50 {
        if summary.usage == 400 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        summary = enterplace_core::audit::verify_full(&audit, None)?;
    }
    assert_eq!((summary.requests, summary.usage), (400, 400));
    Ok(())
}
