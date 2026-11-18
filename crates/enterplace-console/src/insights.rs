//! What the console app's Requests and Analytics APIs (`requests.rs`, `analytics.rs`) share: the rows of the
//! request log, kept to what the signed-in role may see, and their figures and links.
//!
//! Rows come from the store's index when the gateway has one (every replica), else from the local chain.

use enterplace_core::insights::{self, Query, Row};

use crate::{
    Admin, Console,
    html::{enc, thousands},
};

/// Keeps a person whose role is kept to an organization, teams or customers to their requests.
pub(crate) fn scoped(admin: &Admin, query: &mut Query) {
    if let Some(org) = &admin.org {
        query.labels.push(("org".into(), org.clone()));
    }
    if !admin.teams.is_empty() {
        query.within.push(("team".into(), admin.teams.clone()));
    }
    if !admin.customers.is_empty() {
        query
            .within
            .push(("customer".into(), admin.customers.clone()));
    }
}

pub(crate) fn ms(v: Option<u64>) -> String {
    match v {
        None => "-".into(),
        Some(v) if v >= 10_000 => format!("{:.1} s", v as f64 / 1000.0),
        Some(v) => format!("{} ms", thousands(usize::try_from(v).unwrap_or(usize::MAX))),
    }
}

pub(crate) fn count(v: u64) -> String {
    thousands(usize::try_from(v).unwrap_or(usize::MAX))
}

/// The rows a query asks for: from the index of every gateway on the store, or from the local chain.
pub(crate) async fn rows(console: &Console, query: &Query) -> Result<Vec<Row>, String> {
    let audit = console.config().audit.clone();
    if let Some(index) = insights::attached(&audit).index {
        return index.rows(query).await;
    }
    let query = query.clone();
    // ponytail: the whole chain is folded on every page, as the audit page reads it. The store's index answers
    // when logs grow large.
    tokio::task::spawn_blocking(move || insights::fold_chain(&audit).map(|all| query.select(&all)))
        .await
        .map_err(|err| format!("the request log stopped before it finished: {err}."))?
}

pub(crate) fn href(base: &str, pairs: &[(String, String)]) -> String {
    let query: Vec<String> = pairs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect();
    if query.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", query.join("&"))
    }
}

pub(crate) fn with(query: &Query, name: &str, value: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = query
        .pairs()
        .into_iter()
        .filter(|(k, _)| k != name)
        .collect();
    pairs.push((name.to_string(), value.to_string()));
    pairs
}
