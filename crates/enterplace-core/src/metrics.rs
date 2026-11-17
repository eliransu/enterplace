//! A latency histogram in the Prometheus text format, with atomics so the request path never waits on a lock.

use std::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

/// Upper bounds of the buckets, in microseconds: 100 us to 60 s.
const BOUNDS_US: [u64; 18] = [
    100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_500_000, 5_000_000, 10_000_000, 30_000_000, 60_000_000,
];

#[derive(Debug, Default)]
pub struct Histogram {
    /// Count per bucket, not cumulative; the last one is above every bound.
    buckets: [AtomicU64; BOUNDS_US.len() + 1],
    sum_us: AtomicU64,
}

impl Histogram {
    pub fn observe(&self, took: Duration) {
        let us = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        let at = BOUNDS_US.partition_point(|bound| *bound < us);
        self.buckets[at].fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
    }

    /// Writes `<name>_bucket`, `_sum` and `_count` lines. `labels` is empty or `key="value",...` without braces.
    pub fn render(&self, out: &mut String, name: &str, labels: &str) {
        let sep = if labels.is_empty() { "" } else { "," };
        let mut total = 0;
        for (i, bucket) in self.buckets.iter().enumerate() {
            total += bucket.load(Ordering::Relaxed);
            let le = BOUNDS_US
                .get(i)
                .map_or("+Inf".to_string(), |us| format!("{}", *us as f64 / 1e6));
            let _ = writeln!(out, "{name}_bucket{{{labels}{sep}le=\"{le}\"}} {total}");
        }
        let braces = if labels.is_empty() {
            String::new()
        } else {
            format!("{{{labels}}}")
        };
        let sum = self.sum_us.load(Ordering::Relaxed) as f64 / 1e6;
        let _ = writeln!(out, "{name}_sum{braces} {sum}");
        let _ = writeln!(out, "{name}_count{braces} {total}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_cumulative_and_end_in_the_count() {
        let h = Histogram::default();
        h.observe(Duration::from_micros(50));
        h.observe(Duration::from_micros(100));
        h.observe(Duration::from_millis(3));
        h.observe(Duration::from_secs(120));
        let mut out = String::new();
        h.render(&mut out, "x_seconds", "a=\"b\"");
        assert!(
            out.contains("x_seconds_bucket{a=\"b\",le=\"0.0001\"} 2\n"),
            "{out}"
        );
        assert!(
            out.contains("x_seconds_bucket{a=\"b\",le=\"0.005\"} 3\n"),
            "{out}"
        );
        assert!(
            out.contains("x_seconds_bucket{a=\"b\",le=\"60\"} 3\n"),
            "{out}"
        );
        assert!(
            out.contains("x_seconds_bucket{a=\"b\",le=\"+Inf\"} 4\n"),
            "{out}"
        );
        assert!(out.contains("x_seconds_count{a=\"b\"} 4\n"), "{out}");
        assert!(out.contains("x_seconds_sum{a=\"b\"} 120.00315\n"), "{out}");
    }
}
