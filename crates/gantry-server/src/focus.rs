//! Usage as a FOCUS cost and usage file (FinOps Open Cost and Usage Specification, version 1.2,
//! https://focus.finops.org/focus-specification/v1-2/), for the FinOps tools that read it.
//!
//! One line is what one team's requests to one model at one provider cost in one UTC day. Gantry counts cost from
//! the provider's reported tokens and one price a model, so the four cost columns hold the same number; it issues no
//! invoice, so the provider is named as the invoice issuer. What FOCUS has no column for goes in `x_` columns, as the
//! specification asks of a generator's own columns. The docs page `operations/cost-export` lists the mapping.

use std::fmt::Write;

use gantry_core::insights::CostLine;

use crate::manage::csv_field;

/// The columns, in file order. The FOCUS ones first, by their column IDs, then Gantry's own.
pub(crate) const COLUMNS: [&str; 32] = [
    "BilledCost",
    "BillingAccountId",
    "BillingAccountName",
    "BillingCurrency",
    "BillingPeriodStart",
    "BillingPeriodEnd",
    "ChargeCategory",
    "ChargeClass",
    "ChargeDescription",
    "ChargeFrequency",
    "ChargePeriodStart",
    "ChargePeriodEnd",
    "ConsumedQuantity",
    "ConsumedUnit",
    "ContractedCost",
    "EffectiveCost",
    "InvoiceIssuerName",
    "ListCost",
    "PricingCategory",
    "PricingQuantity",
    "PricingUnit",
    "ProviderName",
    "PublisherName",
    "ServiceCategory",
    "ServiceName",
    "SkuId",
    "SubAccountId",
    "SubAccountName",
    "Tags",
    "x_Requests",
    "x_InputTokens",
    "x_OutputTokens",
];

/// The start of the day after `day` (`2026-11-30` gives `2026-12-01`), and of the month after it.
fn day_and_month_after(day: &str) -> Option<(String, String)> {
    let secs = gantry_core::insights::unix_secs(day)?;
    let next = gantry_core::audit::rfc3339(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs + 86_400),
    );
    let (year, month): (u32, u32) = (day.get(..4)?.parse().ok()?, day.get(5..7)?.parse().ok()?);
    let (year, month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    Some((
        next.get(..10)?.to_string(),
        format!("{year:04}-{month:02}-01"),
    ))
}

/// A dollar sum without float noise, as `/metrics` writes one.
fn usd(usd: f64) -> String {
    let text = format!("{usd:.9}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

pub(crate) fn csv(lines: &[CostLine]) -> String {
    let mut out = COLUMNS.join(",");
    out.push('\n');
    for line in lines {
        let Some((next_day, next_month)) = day_and_month_after(&line.day) else {
            continue;
        };
        let midnight = |date: &str| format!("{date}T00:00:00Z");
        // An install without organizations is one billing account.
        let account = if line.org.is_empty() {
            "default"
        } else {
            &line.org
        };
        let cost = usd(line.cost_usd);
        let tokens = (line.input_tokens + line.output_tokens).to_string();
        let mut tags = serde_json::Map::new();
        for (name, value) in [("org", &line.org), ("team", &line.team)] {
            if !value.is_empty() {
                tags.insert(name.into(), value.as_str().into());
            }
        }
        let text = |value: &str| csv_field(value);
        let cells = [
            cost.clone(),
            text(account),
            text(account),
            "USD".into(),
            midnight(&format!("{}-01", &line.day[..7])),
            midnight(&next_month),
            "Usage".into(),
            // Null: Gantry writes no corrections of earlier periods.
            String::new(),
            text(&format!(
                "{} requests to {} at {}",
                line.requests, line.model, line.provider
            )),
            "Usage-Based".into(),
            midnight(&line.day),
            midnight(&next_day),
            tokens.clone(),
            "Tokens".into(),
            cost.clone(),
            cost.clone(),
            text(&line.provider),
            cost,
            "Standard".into(),
            tokens,
            "Tokens".into(),
            text(&line.provider),
            text(&line.provider),
            text("AI and Machine Learning"),
            text(&line.provider),
            text(&line.model),
            text(&line.team),
            text(&line.team),
            text(&serde_json::Value::Object(tags).to_string()),
            line.requests.to_string(),
            line.input_tokens.to_string(),
            line.output_tokens.to_string(),
        ];
        let _ = writeln!(out, "{}", cells.join(","));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_fills_every_column_and_periods_end_where_the_next_starts() {
        let text = csv(&[CostLine {
            day: "2026-12-31".into(),
            org: String::new(),
            team: "payments".into(),
            provider: "openai".into(),
            model: "gpt-4o".into(),
            requests: 3,
            input_tokens: 1000,
            output_tokens: 500,
            cost_usd: 0.007_500_000_000_000_001,
        }]);
        let mut lines = text.lines();
        let header: Vec<&str> = lines.next().unwrap_or_default().split(',').collect();
        assert_eq!(header.len(), COLUMNS.len());
        let row = lines.next().unwrap_or_default();
        for wanted in [
            "0.0075,\"default\",\"default\",USD,2026-12-01T00:00:00Z,2027-01-01T00:00:00Z,Usage,,",
            "Usage-Based,2026-12-31T00:00:00Z,2027-01-01T00:00:00Z,1500,Tokens,0.0075,0.0075,\"openai\",0.0075,Standard,1500,Tokens,",
            "\"AI and Machine Learning\",\"openai\",\"gpt-4o\",\"payments\",\"payments\",\"{\"\"team\"\":\"\"payments\"\"}\",3,1000,500",
        ] {
            assert!(row.contains(wanted), "{wanted} missing from {row}");
        }
        assert!(lines.next().is_none());
    }
}
