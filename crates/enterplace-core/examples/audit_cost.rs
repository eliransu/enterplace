//! Prints what one audit record costs to write, alone and from several threads at once.
use std::{sync::Arc, time::Instant};

use enterplace_core::audit::{AuditLog, Entry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!(
        "enterplace-audit-cost-{}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let log = Arc::new(AuditLog::open(&path)?);
    let entry = |id| Entry {
        id,
        person: Some("p"),
        team: Some("t"),
        method: "POST",
        path: "/v1/chat/completions",
        model: Some("m"),
        allowed: true,
        provider: "mock",
        ..Entry::default()
    };
    let started = Instant::now();
    for _ in 0..20_000 {
        log.append(&entry("01JCM8XXXXXXXXXXXXXXXXXXXX"))?;
    }
    println!(
        "one thread: {} us per record",
        started.elapsed().as_micros() / 20_000
    );
    let started = Instant::now();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let log = log.clone();
            std::thread::spawn(move || {
                for _ in 0..5_000 {
                    let _ = log.append(&entry("01JCM8XXXXXXXXXXXXXXXXXXXX"));
                }
            })
        })
        .collect();
    for thread in threads {
        let _ = thread.join();
    }
    println!(
        "eight threads: {} us per record (wall time over all records)",
        started.elapsed().as_micros() / 40_000
    );
    // Paced like real traffic: 5,000 a second, so each write starts from an idle thread.
    let mut spent = std::time::Duration::ZERO;
    for _ in 0..5_000 {
        std::thread::sleep(std::time::Duration::from_micros(200));
        let at = Instant::now();
        log.append(&entry("01JCM8XXXXXXXXXXXXXXXXXXXX"))?;
        spent += at.elapsed();
    }
    println!(
        "paced at 5,000 a second: {} us per record",
        spent.as_micros() / 5_000
    );
    // The same pace spread over eight threads, as a server's worker threads would write.
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let log = log.clone();
            std::thread::spawn(move || {
                let mut spent = std::time::Duration::ZERO;
                for _ in 0..600 {
                    std::thread::sleep(std::time::Duration::from_micros(1600));
                    let at = Instant::now();
                    let _ = log.append(&entry("01JCM8XXXXXXXXXXXXXXXXXXXX"));
                    spent += at.elapsed();
                }
                spent.as_micros() / 600
            })
        })
        .collect();
    let per: Vec<u128> = threads.into_iter().filter_map(|t| t.join().ok()).collect();
    println!("paced over eight threads: {per:?} us per record");
    let started = Instant::now();
    for _ in 0..20_000 {
        std::hint::black_box(enterplace_core::id::decision_id());
    }
    println!("decision id: {} ns", started.elapsed().as_nanos() / 20_000);
    std::fs::remove_file(&path)?;
    Ok(())
}
