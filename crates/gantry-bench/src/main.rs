//! `gantry-bench`: prints what the gateway adds to a request at a given rate.

use std::{process::ExitCode, time::Duration};

use gantry_bench::{
    BoxError, Load, Report, load_client, ramp, run_load, run_load_on, spawn_events_sink,
    spawn_gateway_watched, spawn_mock_upstream_with_latency,
};

const USAGE: &str = "\
Usage: gantry-bench [--rps N] [--secs N] [--stream] [--messages] [--no-policy] [--events]
                    [--upstream-ms N] [--max-p99-overhead-us N]

Runs a mock model server and the gateway in this process, sends the same load to each, and prints
what the gateway adds, two ways:
  added      latency through the gateway minus latency to the upstream alone, as the client sees it.
             It can be negative: both runs carry noise, and the difference is small.
  self-time  time the gateway reports spending on each request itself (its Server-Timing header).
Defaults: --rps 5000 --secs 10. The gateway checks every request against a policy of 1,000 keys
unless --no-policy is given. --events adds an events guardrail in observe mode to every rule, delivering
to a plugin service in this process, and prints how many envelopes it received. --messages sends to Claude Code's route, /v1/messages, which needs the policy.
--upstream-ms makes the mock wait N milliseconds before each answer, as a provider does (Bifrost's
published setup: --rps 5000 --upstream-ms 1500). Self-time leaves that wait out.
With --max-p99-overhead-us the exit code is 1 when added latency is above N microseconds at p99, or
when the upstream alone has a p99 above N (a run too noisy to measure what the gateway adds).
Self-time covers identifying, deciding and recording only, so it is shown and not gated.
With the policy on, the run also fails unless the audit log holds exactly one decision record and one
usage record per request.

Read the numbers as a comparison between builds on one machine. The mock, the gateway and the load
generator share this process and its CPU, so this is not a benchmark of the gateway alone.";

struct Args {
    load: Load,
    check_policy: bool,
    gate_us: Option<u64>,
    upstream: Duration,
    events: bool,
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = Args {
        load: Load {
            rps: 5000,
            duration: Duration::from_secs(10),
            stream: false,
            messages: false,
        },
        check_policy: true,
        gate_us: None,
        upstream: Duration::ZERO,
        events: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut number = |name: &str| -> Result<u64, String> {
            let raw = it
                .next()
                .ok_or_else(|| format!("{name} needs a number after it."))?;
            raw.parse::<u64>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("{name} is \"{raw}\". Use a whole number above zero."))
        };
        match flag.as_str() {
            "--rps" => {
                args.load.rps = u32::try_from(number("--rps")?)
                    .map_err(|_| "--rps is too large.".to_string())?
            }
            "--secs" => args.load.duration = Duration::from_secs(number("--secs")?),
            "--upstream-ms" => args.upstream = Duration::from_millis(number("--upstream-ms")?),
            "--max-p99-overhead-us" => args.gate_us = Some(number("--max-p99-overhead-us")?),
            "--stream" => args.load.stream = true,
            "--messages" => args.load.messages = true,
            "--no-policy" => args.check_policy = false,
            "--events" => args.events = true,
            "--help" | "-h" => return Ok(None),
            other => return Err(format!("\"{other}\" is not an option.")),
        }
    }
    if args.load.messages && !args.check_policy {
        return Err(
            "--messages needs the policy: without it Gantry forwards the chat route only.".into(),
        );
    }
    if args.events && !args.check_policy {
        return Err("--events needs the policy: an events guardrail is a rule's.".into());
    }
    Ok(Some(args))
}

fn us(d: Duration) -> i128 {
    i128::try_from(d.as_micros()).unwrap_or(i128::MAX)
}

fn line(name: &str, r: &Report) {
    println!(
        "{name:<10} sent {:>7}  ok {:>7}  latency p50 {:>6} us  p99 {:>6} us  max {:>7} us   sent late by p99 {:>5} us",
        r.sent,
        r.ok,
        us(r.latency.p50),
        us(r.latency.p99),
        us(r.latency.max),
        us(r.lag.p99)
    );
}

async fn run(args: &Args) -> Result<bool, BoxError> {
    let upstream = spawn_mock_upstream_with_latency("127.0.0.1:0".parse()?, args.upstream).await?;
    let sink = match args.events {
        true => Some(spawn_events_sink().await?),
        false => None,
    };
    let (gateway, audit) =
        spawn_gateway_watched(upstream, args.check_policy, sink.as_ref().map(|s| s.0)).await?;

    println!(
        "{} requests per second for {} s, upstream waits {} ms, {}, policy check {}",
        args.load.rps,
        args.load.duration.as_secs(),
        args.upstream.as_millis(),
        if args.load.stream {
            "streamed"
        } else {
            "not streamed"
        },
        if args.check_policy { "on" } else { "off" }
    );
    let (direct, through, warm_sent) = if args.upstream.is_zero() {
        let warmup = Load {
            duration: Duration::from_secs(1),
            ..args.load
        };
        run_load(upstream, warmup).await?;
        let warm = run_load(gateway, warmup).await?;
        (
            run_load(upstream, args.load).await?,
            run_load(gateway, args.load).await?,
            warm.sent,
        )
    } else {
        // A slow upstream keeps rate times latency requests in flight, each on a connection of its own. Each
        // target is warmed on the client that measures it, and the first client's connections are closed and
        // left to expire before the second run, so the two runs together stay inside this machine's ephemeral
        // ports (about 16,000 on macOS).
        // ponytail: a fixed 35 s pause (macOS TIME_WAIT is 30 s); a second source address would avoid it.
        let client = load_client();
        ramp(&client, upstream, args.load).await?;
        let direct = run_load_on(&client, upstream, args.load).await?;
        drop(client);
        tokio::time::sleep(Duration::from_secs(35)).await;
        let client = load_client();
        let warm_sent = ramp(&client, gateway, args.load).await?;
        (
            direct,
            run_load_on(&client, gateway, args.load).await?,
            warm_sent,
        )
    };
    line("upstream", &direct);
    line("gateway", &through);

    let added_p50 = us(through.latency.p50) - us(direct.latency.p50);
    let added_p99 = us(through.latency.p99) - us(direct.latency.p99);
    println!(
        "added      p50 {added_p50:+} us  p99 {added_p99:+} us   (client side, gateway minus upstream)"
    );
    let own_p99 = match through.own {
        Some(own) => {
            println!(
                "self-time  p50 {} us  p99 {} us  max {} us   (reported by the gateway)",
                us(own.p50),
                us(own.p99),
                us(own.max)
            );
            Some(us(own.p99))
        }
        None => {
            println!("self-time  not reported: the gateway sent no Server-Timing header");
            None
        }
    };

    if let Some((_, received)) = &sink {
        // Two envelopes a request: its events, and its answer's. What the queue could not hold was dropped, as
        // observe mode promises, and is not waited for.
        tokio::time::sleep(Duration::from_millis(500)).await;
        println!(
            "events     {} envelopes received by the plugin for {} requests (observe mode: queued, batched, dropped when the queue is full)",
            received.load(std::sync::atomic::Ordering::Relaxed),
            warm_sent + through.sent
        );
    }
    let complete = through.ok == through.sent && direct.ok == direct.sent;
    if !complete {
        println!(
            "FAILED     some requests did not succeed, so the numbers above are not a valid measurement"
        );
    }
    let mut recorded = true;
    if let Some(path) = &audit {
        // With the policy on, every request must have exactly one decision record and one usage record, and the chain
        // must hold. A usage record is written as its answer ends, so the last few may still be on their way.
        let expected = u64::try_from(warm_sent + through.sent)?;
        let mut checked = gantry_core::audit::verify_full(path, None);
        for _ in 0..50 {
            if !matches!(&checked, Ok(s) if s.usage < expected) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            checked = gantry_core::audit::verify_full(path, None);
        }
        match checked {
            Ok(summary) => {
                recorded = summary.requests == expected && summary.usage == expected;
                println!(
                    "audit      {} decision and {} usage records for {expected} requests, chain verified: {}",
                    summary.requests,
                    summary.usage,
                    if recorded { "ok" } else { "FAIL" }
                );
            }
            Err(err) => {
                recorded = false;
                println!("audit      FAIL: {err}");
            }
        }
        let _ = std::fs::remove_file(path);
    }
    let mut within = true;
    if let Some(limit) = args.gate_us {
        let limit = i128::from(limit);
        // The gate is on what the client sees. Self-time is a breakdown of part of the gateway's work, so it
        // cannot stand in for the whole, but if it vanishes the gate fails: a measurement must not go missing quietly.
        // The added figure is a difference of two noisy runs. When the mock upstream alone has a p99 above the
        // limit, a tail in that run can make the difference small or negative and pass anything: such a run
        // measures nothing and fails.
        let quiet = us(direct.latency.p99) <= limit;
        within = quiet && added_p99 <= limit && own_p99.is_some();
        println!(
            "gate       limit {limit} us added at p99: {}",
            if within { "pass" } else { "FAIL" }
        );
        if !quiet {
            println!(
                "FAILED     the upstream alone had a p99 of {} us, over the limit: the machine is too busy for this run to measure anything. Run it again on a quieter machine.",
                us(direct.latency.p99)
            );
        }
    }
    Ok(complete && within && recorded)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&args).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
