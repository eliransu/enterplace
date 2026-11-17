//! The one way the console writes money and time. Every page goes through these, so a figure reads the same on
//! Requests, Audit, Spend, Analytics, Models and Start.

use crate::html::thousands;

/// The column header word for a cost that is an estimate.
pub(crate) const EST_HEADER: &str = "est.";

/// The one sentence that explains an estimate, wherever a figure is marked as one.
pub(crate) const EST_TIP: &str = "Estimate: what this would cost at API prices. A subscription pays by the seat, not by the request.";

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Dollars with cents, always: "$0.00", "$1,604.12". A spend under a cent keeps four places so it is not shown as
/// nothing.
pub(crate) fn money(usd: f64) -> String {
    if usd > 0.0 && usd < 0.01 {
        return format!("${usd:.4}");
    }
    let cents = (usd.max(0.0) * 100.0).round() as u64;
    format!(
        "${}.{:02}",
        thousands(usize::try_from(cents / 100).unwrap_or(usize::MAX)),
        cents % 100
    )
}

/// Dollars that are an estimate: "~$0.42".
pub(crate) fn money_est(usd: f64) -> String {
    format!("~{}", money(usd))
}

/// The day and month and the clock of an RFC 3339 time, with the year and the fraction of a second when `full`.
fn parts(time: &str, full: bool) -> Option<String> {
    let part = |range: std::ops::Range<usize>| time.get(range)?.parse::<usize>().ok();
    let (year, month, day) = (part(0..4)?, part(5..7)?, part(8..10)?);
    let month = MONTHS.get(month.checked_sub(1)?)?;
    Some(if full {
        format!("{day} {month} {year}, {} UTC", time.get(11..23)?)
    } else {
        format!("{day} {month} {}", time.get(11..19)?)
    })
}

/// A time in a list: "16 Nov 12:15:28", UTC. A value that is not a time is returned as it is.
pub(crate) fn time_list(time: &str) -> String {
    parts(time, false).unwrap_or_else(|| time.to_string())
}

/// A time on a detail sheet, written in full once: "16 Nov 2026, 12:15:28.467 UTC".
pub(crate) fn time_full(time: &str) -> String {
    parts(time, true).unwrap_or_else(|| time.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_always_has_a_dollar_sign_and_cents() {
        assert_eq!(money(0.0), "$0.00");
        assert_eq!(money(3912.0), "$3,912.00");
        assert_eq!(money(1604.119), "$1,604.12");
        assert_eq!(money(0.42), "$0.42");
        assert_eq!(money(0.0042), "$0.0042");
        assert_eq!(money(-1.0), "$0.00");
    }

    #[test]
    fn an_estimate_is_marked_with_a_tilde() {
        assert_eq!(money_est(0.42), "~$0.42");
        assert_eq!(money_est(0.0), "~$0.00");
    }

    #[test]
    fn list_times_drop_the_year_and_the_fraction() {
        assert_eq!(time_list("2026-11-16T12:15:28.467Z"), "16 Nov 12:15:28");
        assert_eq!(time_list("2026-11-16T12:15:28Z"), "16 Nov 12:15:28");
        assert_eq!(time_list("garbled"), "garbled");
        assert_eq!(time_list("2026-13-16T12:15:28Z"), "2026-13-16T12:15:28Z");
    }

    #[test]
    fn detail_times_are_written_in_full() {
        assert_eq!(
            time_full("2026-11-13T01:03:03.467Z"),
            "13 Nov 2026, 01:03:03.467 UTC"
        );
        assert_eq!(time_full("garbled"), "garbled");
    }

    #[test]
    fn one_wording_for_estimates() {
        assert_eq!(EST_HEADER, "est.");
        assert!(EST_TIP.starts_with("Estimate:"));
    }
}
