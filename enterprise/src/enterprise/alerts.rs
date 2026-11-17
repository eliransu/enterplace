//! Alerting (license feature `alerts`): rules kept in Postgres and edited in the console, evaluated against the
//! audit records every replica reads into `enterprise_audit`, sent to Slack, Microsoft Teams, PagerDuty, email or a
//! signed webhook.
//!
//! Each replica evaluates its own records once (a cursor per replica, moved in the same transaction as what they
//! count), and the counts, spend and known addresses live in shared tables, so a rule sees every replica. An alert
//! fires once per rule and subject until the rule's quiet period has passed (once per period for a budget, once ever
//! for a kill switch or a new address), and at most `max_per_hour` times an hour per rule. Each alert lists the audit
//! records behind it, is written to the audit chain as an `alert` record, and is kept with its delivery outcome.
//! Records older than an hour when first read (a new install, a replica catching up) count but never fire.
//!
//! Every change to a channel or rule is an admin record, written before the change.

#[cfg(test)]
pub(crate) mod tests;

pub mod api;
pub mod channels;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::{
    Extension as Ext,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
};
use enterplace_console::{
    Admin, Console, Form, bare_page, foreign,
    html::{self, esc},
    redirect, same_origin,
};
use enterplace_core::audit::{self, AuditLog};
use enterplace_core::policy::{Budget, Limit, Period, Principal};
use serde_json::{Value, json};

use super::Db;
use super::siem::sinks::{Env, Sinks, parse_time};
use super::siem::{
    Role, banner, db_error, hidden, input, open_secret, random_hex, role_of, seal_secret, section,
    small_button,
};
use crate::license::Status;
use channels::{Alert, Channel, Kind as ChannelKind, Severity};

pub const FEATURE: &str = "alerts";

pub const MIGRATION: &str = "
CREATE TABLE enterprise_alert_channels (
    id bigserial PRIMARY KEY,
    kind text NOT NULL,
    name text NOT NULL,
    url text NOT NULL DEFAULT '',
    secret text NOT NULL DEFAULT '',
    options text NOT NULL DEFAULT '{}',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_success_at timestamptz,
    last_error text,
    last_error_at timestamptz,
    sent bigint NOT NULL DEFAULT 0
);
CREATE TABLE enterprise_alert_rules (
    id bigserial PRIMARY KEY,
    name text NOT NULL,
    kind text NOT NULL,
    params text NOT NULL DEFAULT '{}',
    channels text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    cooldown_minutes integer NOT NULL DEFAULT 60,
    max_per_hour integer NOT NULL DEFAULT 10,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enterprise_alert_cursors (
    replica text PRIMARY KEY,
    n bigint NOT NULL
);
CREATE TABLE enterprise_alert_counts (
    rule bigint NOT NULL,
    key text NOT NULL,
    minute timestamptz NOT NULL,
    count bigint NOT NULL,
    PRIMARY KEY (rule, key, minute)
);
CREATE TABLE enterprise_alert_spend (
    scope text NOT NULL,
    period text NOT NULL,
    usd double precision NOT NULL,
    PRIMARY KEY (scope, period)
);
CREATE TABLE enterprise_alert_seen (
    key text NOT NULL,
    client text NOT NULL,
    first_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (key, client)
);
CREATE TABLE enterprise_alert_state (
    rule bigint NOT NULL,
    key text NOT NULL,
    last_at timestamptz NOT NULL,
    suppressed bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (rule, key)
);
CREATE TABLE enterprise_alerts (
    id bigserial PRIMARY KEY,
    rule bigint NOT NULL,
    rule_name text NOT NULL,
    kind text NOT NULL,
    key text NOT NULL,
    summary text NOT NULL,
    evidence text NOT NULL DEFAULT '[]',
    fired_at timestamptz NOT NULL DEFAULT now(),
    delivery text NOT NULL DEFAULT ''
);
CREATE INDEX enterprise_alerts_rule ON enterprise_alerts (rule, fired_at);
";

/// Requests, errors and latency per scope and day: the 14-day baseline of the unusual request, error and latency
/// rules.
pub const DAILY: &str = "
CREATE TABLE enterprise_alert_daily (
    scope text NOT NULL,
    day text NOT NULL,
    requests bigint NOT NULL DEFAULT 0,
    errors bigint NOT NULL DEFAULT 0,
    latency_ms bigint NOT NULL DEFAULT 0,
    timed bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, day)
);
";

const NAV: &str = "Alerts";
const READ: i64 = 2000;
/// Records older than this when first read count, but do not fire.
const STALE: Duration = Duration::from_secs(3600);
/// Most audit records listed in one alert.
const EVIDENCE: usize = 20;
/// Request records kept in memory to join usage, attempts and answer records to them.
const RECENT: usize = 50_000;
/// "Once" rules never fire twice for the same subject: a quiet period of a century.
const FOREVER: i32 = 52_560_000;

// ---------------------------------------------------------------- rules

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    Budget,
    RateLimit,
    Refusals,
    ProviderErrors,
    Latency,
    GuardrailBlock,
    KillSwitch,
    NewIp,
    AfterHours,
    UnusualSpend,
    System,
    UnusualRequests,
    UnusualErrors,
    UnusualLatency,
    DeploymentDown,
    KeyExpiring,
    CredentialFailing,
    GuardrailVendorFailing,
    ExportLagging,
    DailyDigest,
    RegionOutage,
    ConfigRejected,
    KillCleared,
    CircuitOpen,
}

pub const RULE_KINDS: [RuleKind; 24] = [
    RuleKind::Budget,
    RuleKind::RateLimit,
    RuleKind::Refusals,
    RuleKind::ProviderErrors,
    RuleKind::Latency,
    RuleKind::GuardrailBlock,
    RuleKind::KillSwitch,
    RuleKind::NewIp,
    RuleKind::AfterHours,
    RuleKind::UnusualSpend,
    RuleKind::System,
    RuleKind::UnusualRequests,
    RuleKind::UnusualErrors,
    RuleKind::UnusualLatency,
    RuleKind::DeploymentDown,
    RuleKind::KeyExpiring,
    RuleKind::CredentialFailing,
    RuleKind::GuardrailVendorFailing,
    RuleKind::ExportLagging,
    RuleKind::DailyDigest,
    RuleKind::RegionOutage,
    RuleKind::ConfigRejected,
    RuleKind::KillCleared,
    RuleKind::CircuitOpen,
];

impl RuleKind {
    pub fn word(self) -> &'static str {
        match self {
            Self::Budget => "budget",
            Self::RateLimit => "rate_limit",
            Self::Refusals => "refusals",
            Self::ProviderErrors => "provider_errors",
            Self::Latency => "latency",
            Self::GuardrailBlock => "guardrail_block",
            Self::KillSwitch => "kill_switch",
            Self::NewIp => "new_ip",
            Self::AfterHours => "after_hours",
            Self::UnusualSpend => "unusual_spend",
            Self::System => "system",
            Self::UnusualRequests => "unusual_requests",
            Self::UnusualErrors => "unusual_errors",
            Self::UnusualLatency => "unusual_latency",
            Self::DeploymentDown => "deployment_down",
            Self::KeyExpiring => "key_expiring",
            Self::CredentialFailing => "credential_failing",
            Self::GuardrailVendorFailing => "guardrail_vendor_failing",
            Self::ExportLagging => "export_lagging",
            Self::DailyDigest => "daily_digest",
            Self::RegionOutage => "region_outage",
            Self::ConfigRejected => "config_rejected",
            Self::KillCleared => "kill_cleared",
            Self::CircuitOpen => "circuit_open",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Budget => {
                "Spend reaches an amount or a percent of a policy budget, or is forecast to by the period's end"
            }
            Self::RateLimit => "Rate limits hit",
            Self::Refusals => "Refusals with chosen codes",
            Self::ProviderErrors => "Provider errors",
            Self::Latency => "Slow requests",
            Self::GuardrailBlock => "Guardrail blocks",
            Self::KillSwitch => "Kill switch set",
            Self::NewIp => "A key used from a new address",
            Self::AfterHours => "A key used after hours",
            Self::UnusualSpend => "Unusual spend by a person",
            Self::System => "Audit log, store or secret manager trouble",
            Self::UnusualRequests => "Unusual request volume against the last 14 days",
            Self::UnusualErrors => "Unusual error rate against the last 14 days",
            Self::UnusualLatency => "Unusual latency against the last 14 days",
            Self::DeploymentDown => "A deployment fails every request",
            Self::KeyExpiring => "A key nears its expiry",
            Self::CredentialFailing => "A provider refuses its credential",
            Self::GuardrailVendorFailing => "A guardrail service cannot be reached",
            Self::ExportLagging => "Audit export falls behind",
            Self::DailyDigest => "A daily digest of spend, refusals, top users and alerts",
            Self::RegionOutage => "Every deployment of a region fails",
            Self::ConfigRejected => "A policy change is refused",
            Self::KillCleared => "Kill switch cleared",
            Self::CircuitOpen => "A deployment is put to cool down",
        }
    }

    pub fn parse(word: &str) -> Option<Self> {
        RULE_KINDS.into_iter().find(|k| k.word() == word)
    }

    fn severity(self) -> Severity {
        match self {
            Self::System
            | Self::KillSwitch
            | Self::GuardrailBlock
            | Self::NewIp
            | Self::DeploymentDown
            | Self::RegionOutage
            | Self::CredentialFailing
            | Self::GuardrailVendorFailing => Severity::Critical,
            _ => Severity::Warning,
        }
    }

    /// Fires once per subject (the subject names the period or the event), never again after a quiet period.
    fn once(self) -> bool {
        matches!(
            self,
            Self::Budget
                | Self::KillSwitch
                | Self::NewIp
                | Self::AfterHours
                | Self::UnusualSpend
                | Self::UnusualRequests
                | Self::UnusualErrors
                | Self::UnusualLatency
                | Self::KeyExpiring
                | Self::DailyDigest
                | Self::ConfigRejected
                | Self::KillCleared
        )
    }

    /// Fires when enough matching records fall in a window.
    fn windowed(self) -> bool {
        matches!(
            self,
            Self::RateLimit
                | Self::Refusals
                | Self::ProviderErrors
                | Self::Latency
                | Self::GuardrailBlock
                | Self::DeploymentDown
                | Self::CredentialFailing
                | Self::GuardrailVendorFailing
        )
    }

    /// Compared with the same scope's last 14 days, one alert per scope and day.
    fn unusual(self) -> bool {
        matches!(
            self,
            Self::UnusualRequests | Self::UnusualErrors | Self::UnusualLatency
        )
    }
}

/// The parameters a rule may have, as the form names them.
const PARAMS: [&str; 17] = [
    "scope", "name", "period", "usd", "percent", "forecast", "count", "minutes", "by", "codes",
    "provider", "ms", "hours", "factor", "days", "at", "region",
];

/// The scope kinds a budget of the policy may be set for, as `Policy::applied` names their counters.
const POLICY_SCOPES: [&str; 8] = [
    "global", "org", "team", "person", "key", "customer", "tag", "model",
];

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: i64,
    pub name: String,
    pub kind: RuleKind,
    pub params: Value,
    pub channels: Vec<i64>,
    pub enabled: bool,
    pub cooldown: i32,
    pub max_per_hour: i32,
}

impl Rule {
    fn text(&self, name: &str) -> &str {
        self.params[name].as_str().unwrap_or_default().trim()
    }

    fn number(&self, name: &str, default: f64) -> f64 {
        self.text(name).parse().unwrap_or(default)
    }

    fn count(&self) -> i64 {
        self.number("count", 1.0).max(1.0) as i64
    }

    fn minutes(&self) -> i32 {
        self.number("minutes", 5.0).clamp(1.0, 1440.0) as i32
    }

    /// A budget rule on a percent of the policy's budget: the percent.
    fn percent(&self) -> Option<f64> {
        self.text("percent").parse().ok().filter(|p: &f64| *p > 0.0)
    }

    /// The counter a percent rule watches, as `Policy::applied` names it: `team:payments`, or a kind alone
    /// (`team`) for each one of it. `all` is `global`.
    fn policy_scope(&self) -> String {
        policy_scope(self.text("scope"), self.text("name"))
    }

    fn codes(&self) -> Vec<String> {
        match self.kind {
            RuleKind::RateLimit => vec!["rate_limited".into()],
            _ => self
                .text("codes")
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }

    /// What the rule groups by on a record: person, team, key, or everyone.
    fn group(&self, record: &Value, joined: Option<&Value>) -> String {
        let by = match self.text("by") {
            "" => "all",
            by => by,
        };
        if by == "all" {
            return "all".into();
        }
        let from = |r: &Value| r[by].as_str().map(str::to_string);
        format!(
            "{by}:{}",
            from(record)
                .or_else(|| joined.and_then(from))
                .unwrap_or_else(|| "unknown".into())
        )
    }

    /// The rule's params checked, as stored. The error says which one and why.
    fn check(kind: RuleKind, form: &Form) -> Result<Value, String> {
        let get = |n: &str| form.get(n).trim().to_string();
        let number = |n: &str, min: f64, max: f64| -> Result<(), String> {
            let v = get(n);
            if v.is_empty() {
                return Ok(());
            }
            match v.parse::<f64>() {
                Ok(x) if x.is_finite() && (min..=max).contains(&x) => Ok(()),
                _ => Err(format!("{n} must be a number from {min} to {max}.")),
            }
        };
        number("count", 1.0, 100_000.0)?;
        number("minutes", 1.0, 1440.0)?;
        number("ms", 1.0, 3_600_000.0)?;
        number("factor", 1.0, 1000.0)?;
        number("days", 1.0, 365.0)?;
        if kind.unusual() {
            if !matches!(get("by").as_str(), "" | "team" | "key" | "provider") {
                return Err("Compare by team, key or provider.".into());
            }
        } else if !matches!(get("by").as_str(), "" | "all" | "person" | "team" | "key") {
            return Err("Group by is all, person, team or key.".into());
        }
        match kind {
            RuleKind::Budget if !get("percent").is_empty() => {
                number("percent", 1.0, 1000.0)?;
                let scope = policy_scope(&get("scope"), &get("name"));
                let kind = scope.split(':').next().unwrap_or_default();
                if !POLICY_SCOPES.contains(&kind) {
                    return Err("With a percent, scope is global, or org, team, person, key, customer, tag or model, alone for each one or with a name such as team:payments (team:acme/payments inside organization acme).".into());
                }
            }
            RuleKind::Budget => {
                if !matches!(get("scope").as_str(), "all" | "team" | "person" | "key") {
                    return Err("Scope is all, team, person or key.".into());
                }
                if !matches!(get("period").as_str(), "day" | "month") {
                    return Err("Period is day or month.".into());
                }
                if !get("usd")
                    .parse::<f64>()
                    .is_ok_and(|x| x.is_finite() && x > 0.0)
                {
                    return Err("Enter the amount in US dollars, more than 0.".into());
                }
            }
            RuleKind::Refusals if get("codes").is_empty() => {
                return Err("Enter the refusal codes, comma-separated, such as budget_exceeded,key_expired.".into());
            }
            RuleKind::Latency if get("ms").is_empty() => {
                return Err("Enter the milliseconds a request must take to count as slow.".into());
            }
            RuleKind::AfterHours => {
                let hours = get("hours");
                if parse_hours(&hours).is_none() {
                    return Err("Working hours look like 08-19 or 08-19+0200 (UTC by default), days Monday to Friday.".into());
                }
            }
            RuleKind::UnusualSpend if !get("usd").is_empty() => number("usd", 0.0, 1e9)?,
            RuleKind::DailyDigest if parse_at(&get("at")).is_none() => {
                return Err("Send the digest at a time such as 09:00, or 09:00+0200 for an offset from UTC (UTC by default).".into());
            }
            RuleKind::RegionOutage
                if !get("region").is_empty()
                    && !enterplace_core::config::valid_name(&get("region")) =>
            {
                return Err("Region is a label an alias deployment's region: gives, such as eu or eu-west-1. Empty: every region.".into());
            }
            _ => {}
        }
        let mut params = serde_json::Map::new();
        for name in PARAMS {
            let value = get(name);
            if !value.is_empty() {
                params.insert(name.into(), Value::from(value));
            }
        }
        if form.get("forecast") == "on" {
            params.insert("forecast".into(), Value::from("on"));
        }
        // `team:payments` is kept as the form shows it: scope team, name payments.
        if kind == RuleKind::Budget && !get("percent").is_empty() {
            if let Some((scope, name)) = get("scope").split_once(':') {
                params.insert("scope".into(), Value::from(scope));
                params.insert("name".into(), Value::from(name));
            }
        }
        Ok(Value::Object(params))
    }

    fn describe(&self) -> String {
        let p = |n: &str, d: &str| {
            let v = self.text(n);
            if v.is_empty() {
                d.to_string()
            } else {
                v.to_string()
            }
        };
        match self.kind {
            RuleKind::Budget if self.percent().is_some() => format!(
                "{} {} spend {} {}% of each budget the policy sets for it",
                self.policy_scope(),
                if self.text("forecast") == "on" {
                    "forecast"
                } else {
                    "actual"
                },
                if self.text("forecast") == "on" {
                    "to reach"
                } else {
                    "reaches"
                },
                p("percent", "?"),
            ),
            RuleKind::Budget => format!(
                "{} {} {} spend {} ${} this {}",
                p("scope", "all"),
                p("name", "(each)"),
                if self.text("forecast") == "on" {
                    "forecast"
                } else {
                    "actual"
                },
                if self.text("forecast") == "on" {
                    "to reach"
                } else {
                    "reaches"
                },
                p("usd", "?"),
                p("period", "month")
            ),
            RuleKind::Latency => format!(
                "{} requests slower than {} ms in {} minutes, by provider",
                self.count(),
                p("ms", "?"),
                self.minutes()
            ),
            RuleKind::ProviderErrors => format!(
                "{} provider errors in {} minutes, by provider",
                self.count(),
                self.minutes()
            ),
            RuleKind::RateLimit | RuleKind::Refusals | RuleKind::GuardrailBlock => format!(
                "{} in {} minutes, by {}{}",
                self.count(),
                self.minutes(),
                p("by", "all"),
                if self.kind == RuleKind::Refusals {
                    format!(", codes {}", p("codes", ""))
                } else {
                    String::new()
                }
            ),
            RuleKind::AfterHours => format!("outside {} on weekdays", p("hours", "08-19")),
            RuleKind::UnusualSpend => format!(
                "a person's spend today is {} times their daily average of the last 14 days, and at least ${}",
                p("factor", "3"),
                p("usd", "5")
            ),
            RuleKind::UnusualRequests => format!(
                "a {}'s requests today are {} times its daily average of the last 14 days, and at least {}",
                p("by", "team"),
                p("factor", "3"),
                p("count", "100")
            ),
            RuleKind::UnusualErrors => format!(
                "a {}'s error rate today is {} times its rate over the last 14 days, with at least {} errors",
                p("by", "team"),
                p("factor", "3"),
                p("count", "10")
            ),
            RuleKind::UnusualLatency => format!(
                "a {}'s average latency today is {} times its average over the last 14 days, over at least {} requests",
                p("by", "team"),
                p("factor", "2"),
                p("count", "20")
            ),
            RuleKind::DeploymentDown => format!(
                "{} failures and no answer in {} minutes, by provider",
                self.count(),
                self.minutes()
            ),
            RuleKind::CredentialFailing => format!(
                "a provider refuses its credential (401 or 403) {} times in {} minutes",
                self.count(),
                self.minutes()
            ),
            RuleKind::GuardrailVendorFailing => format!(
                "a guardrail service cannot be reached {} times in {} minutes",
                self.count(),
                self.minutes()
            ),
            RuleKind::KeyExpiring => format!("a key expires within {} days", p("days", "7")),
            RuleKind::ExportLagging => format!(
                "an audit export destination is more than {} minutes behind",
                p("minutes", "15")
            ),
            RuleKind::DailyDigest => format!(
                "every day at {}: the last 24 hours of spend, refusals, top users and alerts",
                p("at", "09:00")
            ),
            RuleKind::RegionOutage => format!(
                "every deployment of {} has {} failures and no answer in {} minutes",
                p("region", "a region"),
                self.count(),
                self.minutes()
            ),
            RuleKind::ConfigRejected => {
                "a reload refuses a policy or keys change, or a policy version is refused as invalid".into()
            }
            RuleKind::KillCleared => "an admin clears a kill switch".into(),
            RuleKind::CircuitOpen => {
                "an alias deployment fails and is passed over for its cooldown, by deployment".into()
            }
            _ => String::new(),
        }
    }
}

/// A percent rule's scope, from the form's scope (`team`, or `team:payments`) and name (`payments`).
fn policy_scope(scope: &str, name: &str) -> String {
    let scope = match scope {
        "" | "all" => "global",
        s => s,
    };
    if scope.contains(':') || name.is_empty() || scope == "global" {
        scope.to_string()
    } else {
        format!("{scope}:{name}")
    }
}

/// A percent rule's subject: the counter, its period and the period it is in, so it fires once per period. A
/// sliding window has no periods: its subject is the counter, quiet for the rule's quiet period after each alert.
fn share_subject(scope: &str, per: Period, time: &str) -> String {
    if per.sliding {
        format!("{scope}|{}", per.word())
    } else {
        format!("{scope}|{}|{}", per.word(), per.label(time))
    }
}

fn sliding_subject(key: &str) -> bool {
    let mut parts = key.split('|');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(_), Some(per), None) => Period::from_word(per).is_some_and(|p| p.sliding),
        _ => false,
    }
}

/// Whether a budget counter of the policy (`team:payments`, `team:payments models:m1`) is one a percent rule
/// watches: the same counter, or any of its kind when the rule names the kind alone.
fn watches(want: &str, counter: &str) -> bool {
    let base = counter.split(' ').next().unwrap_or_default();
    base == want || (!want.contains(':') && base.split(':').next() == Some(want))
}

/// `08-19` or `08-19+0200`: working hours and the offset from UTC in minutes.
fn parse_hours(text: &str) -> Option<(u32, u32, i64)> {
    let text = if text.is_empty() { "08-19" } else { text };
    let (hours, offset) = match text.find(['+', '-']).filter(|i| *i > 2) {
        Some(i) => (&text[..i], &text[i..]),
        None => (text, "+0000"),
    };
    let (start, end) = hours.split_once('-')?;
    let (start, end): (u32, u32) = (start.parse().ok()?, end.parse().ok()?);
    let sign = if offset.starts_with('-') { -1 } else { 1 };
    let digits = offset.get(1..)?;
    if digits.len() != 4 {
        return None;
    }
    let minutes = digits[..2].parse::<i64>().ok()? * 60 + digits[2..].parse::<i64>().ok()?;
    (start < end && end <= 24 && minutes <= 14 * 60).then_some((start, end, sign * minutes))
}

/// `09:00` or `09:00+0200`: the digest's minute of the day and the offset from UTC in minutes.
fn parse_at(text: &str) -> Option<(u32, i64)> {
    let text = if text.is_empty() { "09:00" } else { text };
    let (time, offset) = match text.find(['+', '-']) {
        Some(i) => (&text[..i], &text[i..]),
        None => (text, "+0000"),
    };
    let (hour, minute) = time.split_once(':')?;
    let (hour, minute): (u32, u32) = (hour.parse().ok()?, minute.parse().ok()?);
    let sign = if offset.starts_with('-') { -1 } else { 1 };
    let digits = offset.get(1..).filter(|d| d.len() == 4)?;
    let offset =
        digits.get(..2)?.parse::<i64>().ok()? * 60 + digits.get(2..)?.parse::<i64>().ok()?;
    (hour < 24 && minute < 60 && offset <= 14 * 60).then_some((hour * 60 + minute, sign * offset))
}

/// The local date (`2026-11-14`) whose digest is due at `now`: once the day's local time has reached `at`.
fn digest_due(now: SystemTime, at: (u32, i64)) -> Option<String> {
    let shift = Duration::from_secs(at.1.unsigned_abs() * 60);
    let local = if at.1 >= 0 {
        now + shift
    } else {
        now.checked_sub(shift)?
    };
    let stamp = audit::rfc3339(local);
    let hour: u32 = stamp.get(11..13)?.parse().ok()?;
    let minute: u32 = stamp.get(14..16)?.parse().ok()?;
    (hour * 60 + minute >= at.0).then(|| stamp[..10].to_string())
}

/// Whether a time is outside working hours on a weekday, or on a weekend, at the offset.
fn after_hours(time: SystemTime, hours: (u32, u32, i64)) -> bool {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
        + hours.2 * 60;
    let days = secs.div_euclid(86_400);
    let hour = (secs.rem_euclid(86_400) / 3600) as u32;
    // 1970-01-01 was a Thursday: 0 is Monday.
    let weekday = (days + 3).rem_euclid(7);
    weekday >= 5 || hour < hours.0 || hour >= hours.1
}

// ---------------------------------------------------------------- the engine

/// A request record, kept to join the records that follow it.
#[derive(Clone)]
struct Seen {
    time: String,
    decision: Value,
}

/// Something a record set off, to be checked and maybe fired once the tick's counts are stored.
struct Candidate {
    rule: Rule,
    key: String,
    summary: String,
    evidence: Vec<Value>,
    /// A percent rule: the policy budget's amount, in US dollars, and its period.
    budget: Option<Budget>,
}

pub struct Engine {
    /// An organization's chain: trouble with the store is the install engine's to report.
    org: bool,
    db: Arc<Db>,
    replica: String,
    log: Arc<AuditLog>,
    key: Option<[u8; 32]>,
    sinks: Arc<Sinks>,
    console: String,
    /// The policy in force, for the budgets a percent rule is a share of.
    policy: enterplace_server::PolicyNow,
    recent: Mutex<(HashMap<String, Seen>, std::collections::VecDeque<String>)>,
    /// The last rules and channels read, for alerts about the store itself when it cannot be read.
    cache: Mutex<(Vec<Rule>, Vec<Channel>)>,
    /// When each system alert last went out while the store was down, by rule and problem.
    offline: Mutex<HashMap<(i64, String), Instant>>,
    said: Mutex<String>,
    /// The keys file (or the store's keys), for the rule on keys nearing their expiry.
    keys: std::path::PathBuf,
    /// The policy file, for the region labels of alias deployments.
    policy_file: std::path::PathBuf,
    /// When the state checks last ran: once a minute.
    checked: Mutex<Option<Instant>>,
}

#[derive(Clone)]
struct Alerts {
    engine: Arc<Engine>,
}

/// Adds the alerts page and the engine, which runs on the exporter's tick after each read of the chain.
pub fn register(
    extension: &mut enterplace_server::Extension,
    exporter: &Arc<super::siem::Exporter>,
    env: &Env,
    policy: enterplace_server::PolicyNow,
    keys: std::path::PathBuf,
    policy_file: std::path::PathBuf,
) -> Arc<Engine> {
    let engine = engine(exporter, env, policy, keys, policy_file, false);
    extension.admin = Some(Arc::new(api::AlertsApi::On(engine.clone())));
    let console = &mut extension.console;
    console.nav.push(("/console/alerts".into(), NAV.into()));
    console.routes = std::mem::take(&mut console.routes)
        .route("/alerts", get(page).post(act))
        .layer(Ext(Alerts {
            engine: engine.clone(),
        }));
    engine
}

/// The engine of one chain, on its exporter's tick: the install's, or an organization's (`org`), whose alerts go
/// to its own chain. An organization's engine leaves trouble with the store to the install's, so it is said once.
pub fn engine(
    exporter: &Arc<super::siem::Exporter>,
    env: &Env,
    policy: enterplace_server::PolicyNow,
    keys: std::path::PathBuf,
    policy_file: std::path::PathBuf,
    org: bool,
) -> Arc<Engine> {
    let engine = Arc::new(Engine {
        org,
        db: exporter.db.clone(),
        replica: exporter.replica.clone(),
        log: exporter.log.clone(),
        key: exporter.key,
        sinks: exporter.sinks.clone(),
        policy,
        console: env("ENTERPLACE_CONSOLE_URL")
            .map(|u| {
                u.trim()
                    .trim_end_matches('/')
                    .trim_end_matches("/console")
                    .to_string()
            })
            .unwrap_or_default(),
        recent: Mutex::new(Default::default()),
        cache: Mutex::new(Default::default()),
        offline: Mutex::new(HashMap::new()),
        said: Mutex::new(String::new()),
        keys,
        policy_file,
        checked: Mutex::new(None),
    });
    let _ = exporter.alerts.set(engine.clone());
    engine
}

/// Without the feature the page says why, and there is no nav entry.
pub fn locked(extension: &mut enterplace_server::Extension, status: &Status) {
    let Err(refused) = status.require(FEATURE) else {
        return;
    };
    let (code, message) = (refused.code, refused.message);
    extension.admin = Some(Arc::new(api::AlertsApi::Locked {
        code,
        message: message.clone(),
    }));
    let page = move || {
        let message = message.clone();
        async move {
            bare_page(
                StatusCode::FORBIDDEN,
                "Alerts need a license",
                &format!(
                    r#"<h1 class="t-lg" style="margin: 0">Alerts need a license</h1><p class="t-lead g-muted" style="margin: 0">{}</p><p class="t-small g-muted" style="margin: 0">Code: {code}</p>"#,
                    esc(&message)
                ),
            )
        }
    };
    let console = &mut extension.console;
    console.routes = std::mem::take(&mut console.routes).route("/alerts", get(page));
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn evidence(record: &Value, replica: &str) -> Value {
    json!({ "replica": replica, "n": record["n"], "hash": record["hash"], "id": record["id"] })
}

fn fresh(record: &Value) -> bool {
    record["time"]
        .as_str()
        .and_then(parse_time)
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_none_or(|age| age < STALE)
}

fn millis(time: &str) -> Option<u128> {
    parse_time(time)?
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis())
}

/// Whether an attempt's outcome is the provider failing: a 5xx, a 429, or no answer.
fn failed_outcome(outcome: &str) -> bool {
    match outcome.parse::<u16>() {
        Ok(status) => status >= 500 || status == 429,
        Err(_) => outcome.starts_with("upstream_"),
    }
}

/// The alias deployments (`provider/model`) a record shows being tried, and whether each failed. Attempts records
/// name every try of a request that needed more than one; a usage record names the deployment that gave the answer.
fn deployment_outcomes(event: &str, record: &Value) -> Vec<(String, bool)> {
    match event {
        "attempts" => record["attempts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                let label = a["provider"].as_str().filter(|p| p.contains('/'))?;
                let outcome = a["outcome"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| a["outcome"].to_string());
                Some((label.to_string(), failed_outcome(&outcome)))
            })
            .collect(),
        "usage" if record["alias"].is_string() => match (
            record["provider"].as_str(),
            record["model"].as_str(),
            record["status"].as_u64(),
        ) {
            (Some(provider), Some(model), Some(status)) => vec![(
                format!("{provider}/{model}"),
                status >= 500 || status == 429,
            )],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// The first 12 hex characters of a hash in a record, or `?`.
fn short(hash: &Value) -> String {
    hash.as_str()
        .and_then(|h| h.get(..12))
        .unwrap_or("?")
        .to_string()
}

impl Engine {
    fn say(&self, line: &str) {
        let mut said = lock(&self.said);
        if *said != line {
            eprintln!("enterplace: {line}");
            *said = line.to_string();
        }
    }

    async fn load(&self) -> Result<(Vec<Rule>, Vec<Channel>), String> {
        let client = self.db.client().await?;
        let rows = client
            .query(
                "SELECT id, name, kind, params, channels, enabled, cooldown_minutes, max_per_hour FROM enterprise_alert_rules ORDER BY id",
                &[],
            )
            .await
            .map_err(db_error)?;
        let mut rules = Vec::new();
        for r in rows {
            let text = |i| r.try_get::<_, String>(i).map_err(db_error);
            let Some(kind) = RuleKind::parse(&text(2)?) else {
                continue;
            };
            rules.push(Rule {
                id: r.try_get(0).map_err(db_error)?,
                name: text(1)?,
                kind,
                params: serde_json::from_str(&text(3)?).unwrap_or(Value::Null),
                channels: text(4)?
                    .split(',')
                    .filter_map(|c| c.trim().parse().ok())
                    .collect(),
                enabled: r.try_get(5).map_err(db_error)?,
                cooldown: r.try_get(6).map_err(db_error)?,
                max_per_hour: r.try_get(7).map_err(db_error)?,
            });
        }
        let rows = client
            .query(
                "SELECT id, kind, name, url, secret, options FROM enterprise_alert_channels ORDER BY id",
                &[],
            )
            .await
            .map_err(db_error)?;
        let mut channels = Vec::new();
        for r in rows {
            let text = |i| r.try_get::<_, String>(i).map_err(db_error);
            let Some(kind) = ChannelKind::parse(&text(1)?) else {
                continue;
            };
            // A secret that does not open is left empty: delivery then fails and says so on the page.
            channels.push(Channel {
                id: r.try_get(0).map_err(db_error)?,
                kind,
                name: text(2)?,
                url: text(3)?,
                secret: open_secret(self.key.as_ref(), &text(4)?).unwrap_or_default(),
                options: serde_json::from_str(&text(5)?).unwrap_or(Value::Null),
            });
        }
        *lock(&self.cache) = (rules.clone(), channels.clone());
        Ok((rules, channels))
    }

    /// One pass after the exporter read the chain: evaluates the new records, then the state of the audit log and
    /// the store. `read` is the error of that read, if it failed.
    pub async fn tick(&self, read: Option<&String>) {
        let mut trouble: Vec<(String, String)> = Vec::new();
        if self.log.is_broken() {
            trouble.push((
                "audit_broken".into(),
                "The audit log cannot be written: requests are refused with audit_unavailable. Check the disk and the log file, then restart the gateway.".into(),
            ));
        }
        if let Some(err) = read {
            trouble.push((
                "audit_unreadable".into(),
                format!("This replica's audit records cannot be read into Postgres: {err}"),
            ));
        }
        let due = {
            let mut checked = lock(&self.checked);
            let due = checked.is_none_or(|at| at.elapsed() >= Duration::from_secs(60));
            if due {
                *checked = Some(Instant::now());
            }
            due
        };
        if due {
            if let Err(err) = self.checks().await {
                self.say(&format!("alerts: {err}"));
            }
        }
        match self.evaluate().await {
            Ok(()) => {}
            Err(err) if self.org => self.say(&format!("alerts: {err}")),
            Err(err) => {
                self.say(&format!("alerts: {err}"));
                trouble.push((
                    "store".into(),
                    format!("The alert tables in Postgres cannot be read or written: {err}"),
                ));
            }
        }
        if !trouble.is_empty() {
            self.system(&trouble).await;
        }
    }

    /// Alerts about the audit log or the store, to every system rule. Kept in the store when it answers; when it
    /// does not, sent from the last rules and channels read, at most once per quiet period.
    async fn system(&self, trouble: &[(String, String)]) {
        let rules = match self.load().await {
            Ok((rules, _)) => Some(rules),
            Err(_) => None,
        };
        let online = rules.is_some();
        let (rules, channels) = match rules {
            Some(rules) => (rules, lock(&self.cache).1.clone()),
            None => lock(&self.cache).clone(),
        };
        for rule in rules
            .iter()
            .filter(|r| r.enabled && r.kind == RuleKind::System)
        {
            for (problem, text) in trouble {
                let key = format!("{}:{problem}", self.replica);
                if online {
                    let _ = self.fire(rule, &key, text, Vec::new(), &channels).await;
                    continue;
                }
                let due = {
                    let mut offline = lock(&self.offline);
                    let last = offline.get(&(rule.id, key.clone()));
                    let wait =
                        Duration::from_secs(u64::try_from(rule.cooldown.max(1)).unwrap_or(60) * 60);
                    let due = last.is_none_or(|at| at.elapsed() >= wait);
                    if due {
                        offline.insert((rule.id, key.clone()), Instant::now());
                    }
                    due
                };
                if due {
                    let alert = Alert {
                        id: 0,
                        rule: rule.name.clone(),
                        kind: rule.kind.word(),
                        severity: Severity::Critical,
                        key: key.clone(),
                        summary: text.clone(),
                        time: audit::timestamp(),
                        evidence: Vec::new(),
                        console: self.console.clone(),
                    };
                    let _ = self.deliver(rule, &alert, &channels).await;
                }
            }
        }
    }

    /// Each alias deployment with a `region:` label, as `provider/model` (as attempts records name it), and its region.
    /// Empty when the policy does not load: `enterplace check` says why.
    // ponytail: the policy is read on each tick that has a region rule; keep it from the reload if that shows up.
    async fn regions(&self) -> HashMap<String, String> {
        let path = self.policy_file.clone();
        tokio::task::spawn_blocking(move || {
            enterplace_core::config::policy_text(&path)
                .ok()
                .and_then(|text| enterplace_core::config::load_texts(&path, &text, &path, "").ok())
                .map(|loaded| {
                    loaded
                        .aliases
                        .iter()
                        .flat_map(|a| &a.deployments)
                        .filter_map(|d| {
                            d.region
                                .clone()
                                .map(|r| (format!("{}/{}", d.provider, d.model), r))
                        })
                        .collect()
                })
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default()
    }

    async fn cursor(&self) -> Result<i64, String> {
        let client = self.db.client().await?;
        // A replica new to alerting starts 14 days before this month, so month-to-date spend and the unusual spend
        // baseline are whole from the start. Those records count and never fire.
        client
            .execute(
                "INSERT INTO enterprise_alert_cursors (replica, n) \
                 SELECT $1, coalesce(max(n), 0) FROM enterprise_audit \
                 WHERE replica = $1 AND time < date_trunc('month', now()) - interval '14 days' ON CONFLICT DO NOTHING",
                &[&self.replica],
            )
            .await
            .map_err(db_error)?;
        client
            .query_one(
                "SELECT n FROM enterprise_alert_cursors WHERE replica = $1",
                &[&self.replica],
            )
            .await
            .map_err(db_error)?
            .try_get(0)
            .map_err(db_error)
    }

    fn remember(&self, record: &Value) {
        let Some(id) = record["id"].as_str() else {
            return;
        };
        let mut recent = lock(&self.recent);
        let (map, order) = &mut *recent;
        map.insert(
            id.to_string(),
            Seen {
                time: record["time"].as_str().unwrap_or_default().to_string(),
                decision: record.clone(),
            },
        );
        order.push_back(id.to_string());
        while order.len() > RECENT {
            if let Some(old) = order.pop_front() {
                map.remove(&old);
            }
        }
    }

    /// The request record of a decision: from memory, else from the table.
    async fn decision(&self, id: &str) -> Option<Seen> {
        if let Some(seen) = lock(&self.recent).0.get(id).cloned() {
            return Some(seen);
        }
        let client = self.db.client().await.ok()?;
        let row = client
            .query_opt(
                "SELECT line FROM enterprise_audit WHERE replica = $1 AND (line::jsonb)->>'id' = $2 AND (line::jsonb)->>'event' IS NULL LIMIT 1",
                &[&self.replica, &id],
            )
            .await
            .ok()??;
        let line: String = row.try_get(0).ok()?;
        let decision: Value = serde_json::from_str(&line).ok()?;
        Some(Seen {
            time: decision["time"].as_str().unwrap_or_default().to_string(),
            decision,
        })
    }

    /// Reads this replica's records past its cursor, counts what they add, and fires what they set off.
    pub(crate) async fn evaluate(&self) -> Result<(), String> {
        let (rules, channels) = self.load().await?;
        let rules: Vec<Rule> = rules.into_iter().filter(|r| r.enabled).collect();
        let after = self.cursor().await?;
        let rows = {
            let client = self.db.client().await?;
            client
                .query(
                    "SELECT n, line FROM enterprise_audit WHERE replica = $1 AND n > $2 ORDER BY n LIMIT $3",
                    &[&self.replica, &after, &READ],
                )
                .await
                .map_err(db_error)?
        };
        let Some(last) = rows
            .last()
            .map(|r| r.try_get::<_, i64>(0))
            .transpose()
            .map_err(db_error)?
        else {
            return Ok(());
        };
        let records: Vec<Value> = rows
            .iter()
            .map(|r| {
                r.try_get::<_, String>(1)
                    .map(|l| serde_json::from_str(&l).unwrap_or(Value::Null))
                    .map_err(db_error)
            })
            .collect::<Result<_, _>>()?;

        // What the records add, stored in one transaction with the cursor.
        let mut spend: BTreeMap<(String, String), f64> = BTreeMap::new();
        let mut counts: BTreeMap<(i64, String, String), i64> = BTreeMap::new();
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut shares: Vec<Candidate> = Vec::new();
        let percent_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.kind == RuleKind::Budget && r.percent().is_some())
            .collect();
        let mut addresses: Vec<(String, String)> = Vec::new();
        // (scope, day): requests, errors, latency in ms, requests timed. Kept for every scope, rule or not, so a
        // rule added later has its baseline.
        let mut daily: BTreeMap<(String, String), [i64; 4]> = BTreeMap::new();
        // Answers a deployment gave, counted beside its failures: a deployment that answers is not down.
        let mut oks: BTreeMap<(i64, String, String), i64> = BTreeMap::new();
        let regions = if rules.iter().any(|r| r.kind == RuleKind::RegionOutage) {
            self.regions().await
        } else {
            HashMap::new()
        };
        // Failures and answers of each alias deployment in a region, for the region rules.
        let mut region_counts: BTreeMap<(i64, String, String), i64> = BTreeMap::new();
        let new_ip = rules.iter().any(|r| r.kind == RuleKind::NewIp);
        let (mut known_keys, mut known_pairs) = (HashSet::new(), HashSet::new());
        if new_ip {
            let keys: Vec<String> = records
                .iter()
                .filter(|r| r.get("event").is_none())
                .filter_map(|r| r["key"].as_str().map(str::to_string))
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let client = self.db.client().await?;
            for row in client
                .query(
                    "SELECT key, client FROM enterprise_alert_seen WHERE key = ANY($1)",
                    &[&keys],
                )
                .await
                .map_err(db_error)?
            {
                let (k, c): (String, String) = (
                    row.try_get(0).map_err(db_error)?,
                    row.try_get(1).map_err(db_error)?,
                );
                known_keys.insert(k.clone());
                known_pairs.insert((k, c));
            }
        }

        for record in &records {
            let event = record["event"].as_str().unwrap_or("request");
            let live = fresh(record);
            let time = record["time"].as_str().unwrap_or_default().to_string();
            let minute = time
                .get(..16)
                .map(|m| format!("{m}:00Z"))
                .unwrap_or_default();
            let joined = match event {
                "request" => {
                    self.remember(record);
                    None
                }
                "usage" | "attempts" | "answer_guardrails" | "upstream_error" => {
                    match record["id"].as_str() {
                        Some(id) => self.decision(id).await,
                        None => None,
                    }
                }
                _ => None,
            };
            let decision = joined.as_ref().map(|s| &s.decision);
            let day = time.get(..10).unwrap_or_default().to_string();
            {
                let failed = match event {
                    "usage" => record["status"]
                        .as_u64()
                        .is_some_and(|s| s >= 500 || s == 429),
                    "upstream_error" => true,
                    _ => false,
                };
                let timed = (event == "usage")
                    .then(|| record["latency_ms"].as_i64())
                    .flatten();
                if event == "request" || failed || timed.is_some() {
                    for by in ["team", "key", "provider"] {
                        let value = record[by]
                            .as_str()
                            .or_else(|| decision.and_then(|d| d[by].as_str()))
                            .filter(|v| !v.is_empty());
                        let Some(value) = value else { continue };
                        let slot = daily
                            .entry((format!("{by}:{value}"), day.clone()))
                            .or_default();
                        slot[0] += i64::from(event == "request");
                        slot[1] += i64::from(failed);
                        if let Some(ms) = timed {
                            slot[2] += ms;
                            slot[3] += 1;
                        }
                    }
                }
            }
            let unusual_scope = |rule: &Rule, record: &Value| -> Option<String> {
                let by = match rule.text("by") {
                    "" => "team",
                    by => by,
                };
                record[by]
                    .as_str()
                    .or_else(|| decision.and_then(|d| d[by].as_str()))
                    .filter(|v| !v.is_empty())
                    .map(|v| format!("{by}:{v}:{day}"))
            };
            let provider_of = |record: &Value| {
                record["provider"]
                    .as_str()
                    .or_else(|| decision.and_then(|d| d["provider"].as_str()))
                    .unwrap_or("unknown")
                    .to_string()
            };
            let mut hit = |rule: &Rule, key: String, summary: String, count: i64| {
                if rule.kind.windowed() {
                    *counts
                        .entry((rule.id, key.clone(), minute.clone()))
                        .or_default() += count;
                }
                if live {
                    candidates.push(Candidate {
                        rule: rule.clone(),
                        key,
                        summary,
                        evidence: vec![evidence(record, &self.replica)],
                        budget: None,
                    });
                }
            };
            // A share of a policy budget: each budget the policy counted this cost against, as it is in force now.
            if event == "usage"
                && live
                && !percent_rules.is_empty()
                && record["charged_usd"].as_f64().unwrap_or(0.0) > 0.0
                && record["budget"] != "not_counted"
            {
                for (scope, budget) in self.policy_budgets(record) {
                    for rule in percent_rules
                        .iter()
                        .filter(|r| watches(&r.policy_scope(), &scope))
                    {
                        shares.push(Candidate {
                            rule: (*rule).clone(),
                            key: share_subject(&scope, budget.per, &time),
                            summary: String::new(),
                            evidence: vec![evidence(record, &self.replica)],
                            budget: Some(budget),
                        });
                    }
                }
            }
            if spends(event) {
                let charged = charged(event, record);
                if charged > 0.0 && charged.is_finite() {
                    let scopes = [
                        "all".to_string(),
                        format!("team:{}", record["team"].as_str().unwrap_or_default()),
                        format!("person:{}", record["person"].as_str().unwrap_or_default()),
                        format!("key:{}", record["key"].as_str().unwrap_or_default()),
                    ];
                    // A watched request has no key, and no team when its token names none.
                    for scope in scopes
                        .into_iter()
                        .filter(|s| event == "usage" || !s.ends_with(':'))
                    {
                        for period in [time.get(..10), time.get(..7)].into_iter().flatten() {
                            *spend
                                .entry((scope.clone(), period.to_string()))
                                .or_default() += charged;
                        }
                    }
                }
            }
            for rule in &rules {
                match (rule.kind, event) {
                    (RuleKind::Budget, "usage" | "watch")
                        if rule.percent().is_none() && charged(event, record) > 0.0 =>
                    {
                        let scope = rule.text("scope");
                        let value = match scope {
                            "all" => "all".to_string(),
                            s => record[s].as_str().unwrap_or_default().to_string(),
                        };
                        if !rule.text("name").is_empty() && rule.text("name") != value {
                            continue;
                        }
                        let period = if rule.text("period") == "day" {
                            time.get(..10)
                        } else {
                            time.get(..7)
                        };
                        let key = format!("{scope}:{value}:{}", period.unwrap_or_default());
                        hit(rule, key, String::new(), 0);
                    }
                    (RuleKind::RateLimit | RuleKind::Refusals, "request")
                        if record["code"]
                            .as_str()
                            .is_some_and(|c| rule.codes().iter().any(|w| w == c)) =>
                    {
                        let code = record["code"].as_str().unwrap_or_default();
                        hit(
                            rule,
                            rule.group(record, None),
                            format!("refused with {code}"),
                            1,
                        );
                    }
                    (RuleKind::GuardrailBlock, "request")
                        if record["code"] == "guardrail_blocked" =>
                    {
                        hit(
                            rule,
                            rule.group(record, None),
                            "a request was blocked by a guardrail".into(),
                            1,
                        );
                    }
                    (RuleKind::GuardrailBlock, "answer_guardrails")
                        if record["verdict"] == "block" =>
                    {
                        hit(
                            rule,
                            rule.group(record, decision),
                            "an answer was withheld by a guardrail".into(),
                            1,
                        );
                    }
                    (RuleKind::ProviderErrors, "usage")
                        if record["status"]
                            .as_u64()
                            .is_some_and(|s| s >= 500 || s == 429) =>
                    {
                        let provider = record["provider"].as_str().unwrap_or("unknown");
                        if !rule.text("provider").is_empty() && rule.text("provider") != provider {
                            continue;
                        }
                        hit(
                            rule,
                            format!("provider:{provider}"),
                            format!("{provider} answered {}", record["status"]),
                            1,
                        );
                    }
                    // No provider answered, retried or not: the last try, named by the record.
                    (RuleKind::ProviderErrors, "upstream_error")
                        if record["code"]
                            .as_str()
                            .is_some_and(|c| c.starts_with("upstream_")) =>
                    {
                        let provider = match record["provider"].as_str() {
                            Some(p) if !p.is_empty() => p,
                            _ => "unknown",
                        };
                        if !rule.text("provider").is_empty() && rule.text("provider") != provider {
                            continue;
                        }
                        hit(
                            rule,
                            format!("provider:{provider}"),
                            format!(
                                "{provider} gave no answer ({})",
                                record["code"].as_str().unwrap_or_default()
                            ),
                            1,
                        );
                    }
                    (RuleKind::ProviderErrors, "attempts") => {
                        let tries = record["attempts"].as_array().cloned().unwrap_or_default();
                        // The last try's outcome is in the usage record, or the upstream error record when no
                        // provider answered; count the failed tries before it.
                        for attempt in tries.iter().rev().skip(1) {
                            let provider = attempt["provider"].as_str().unwrap_or("unknown");
                            let outcome = attempt["outcome"]
                                .as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| attempt["outcome"].to_string());
                            if failed_outcome(&outcome)
                                && (rule.text("provider").is_empty()
                                    || rule.text("provider") == provider)
                            {
                                hit(
                                    rule,
                                    format!("provider:{provider}"),
                                    format!("{provider} failed with {outcome}"),
                                    1,
                                );
                            }
                        }
                    }
                    (RuleKind::Latency, "usage") => {
                        let Some(start) = joined.as_ref().and_then(|s| millis(&s.time)) else {
                            continue;
                        };
                        let took = millis(&time).unwrap_or(start).saturating_sub(start);
                        let provider = record["provider"].as_str().unwrap_or("unknown");
                        if took as f64 > rule.number("ms", f64::MAX)
                            && (rule.text("provider").is_empty()
                                || rule.text("provider") == provider)
                        {
                            hit(
                                rule,
                                format!("provider:{provider}"),
                                format!("a request to {provider} took {took} ms"),
                                1,
                            );
                        }
                    }
                    (RuleKind::KillSwitch, "admin")
                        if record["verdict"] == "allow" && record["action"] == "set_kill" =>
                    {
                        let t = &record["target"];
                        hit(
                            rule,
                            record["id"].as_str().unwrap_or_default().to_string(),
                            format!(
                                "{} set a kill switch on {} {}: {}",
                                record["person"].as_str().unwrap_or("someone"),
                                t["scope"].as_str().unwrap_or("?"),
                                t["value"].as_str().unwrap_or("?"),
                                t["reason"].as_str().unwrap_or("no reason given")
                            ),
                            0,
                        );
                    }
                    (RuleKind::NewIp, "request") => {
                        let (Some(key), Some(client)) =
                            (record["key"].as_str(), record["client"].as_str())
                        else {
                            continue;
                        };
                        if record["person"] == "unknown" {
                            continue;
                        }
                        let pair = (key.to_string(), client.to_string());
                        if known_pairs.contains(&pair) {
                            continue;
                        }
                        // The first addresses of a key are learned, not alerted on.
                        if known_keys.contains(key) {
                            hit(
                                rule,
                                format!("{key}:{client}"),
                                format!(
                                    "key {key} of {} was used from {client}, an address it has not used before",
                                    record["person"].as_str().unwrap_or("?")
                                ),
                                0,
                            );
                        }
                        known_keys.insert(key.to_string());
                        known_pairs.insert(pair.clone());
                        addresses.push(pair);
                    }
                    (RuleKind::AfterHours, "request") if record["verdict"] == "allow" => {
                        let (Some(key), Some(hours), Some(at)) = (
                            record["key"].as_str(),
                            parse_hours(rule.text("hours")),
                            parse_time(&time),
                        ) else {
                            continue;
                        };
                        if after_hours(at, hours) {
                            hit(
                                rule,
                                format!("{key}:{}", time.get(..10).unwrap_or_default()),
                                format!(
                                    "key {key} of {} was used after working hours, at {time}",
                                    record["person"].as_str().unwrap_or("?")
                                ),
                                0,
                            );
                        }
                    }
                    (RuleKind::UnusualSpend, "usage" | "watch") if charged(event, record) > 0.0 => {
                        let person = record["person"].as_str().unwrap_or_default();
                        hit(
                            rule,
                            format!("{person}:{}", time.get(..10).unwrap_or_default()),
                            String::new(),
                            0,
                        );
                    }
                    (RuleKind::System, "secret_refresh_failed") => {
                        let variable = record["variable"].as_str().unwrap_or("?");
                        hit(
                            rule,
                            format!("{}:secret:{variable}", self.replica),
                            format!(
                                "{variable} ({}) could not be read again from {}: {}. The gateway keeps the value it read before; fix access to the secret manager before that value is revoked.",
                                record["reference"].as_str().unwrap_or("?"),
                                record["source"].as_str().unwrap_or("its secret manager"),
                                record["reason"].as_str().unwrap_or("no reason given")
                            ),
                            0,
                        );
                    }
                    (RuleKind::UnusualRequests, "request") => {
                        if let Some(key) = unusual_scope(rule, record) {
                            hit(rule, key, String::new(), 0);
                        }
                    }
                    (RuleKind::UnusualErrors, "usage" | "upstream_error")
                        if event == "upstream_error"
                            || record["status"]
                                .as_u64()
                                .is_some_and(|s| s >= 500 || s == 429) =>
                    {
                        if let Some(key) = unusual_scope(rule, record) {
                            hit(rule, key, String::new(), 0);
                        }
                    }
                    (RuleKind::UnusualLatency, "usage") if record["latency_ms"].is_number() => {
                        if let Some(key) = unusual_scope(rule, record) {
                            hit(rule, key, String::new(), 0);
                        }
                    }
                    (RuleKind::DeploymentDown, "usage" | "upstream_error") => {
                        let provider = provider_of(record);
                        let failed = event == "upstream_error"
                            || record["status"]
                                .as_u64()
                                .is_some_and(|s| s >= 500 || s == 429);
                        if failed {
                            hit(
                                rule,
                                format!("deployment:{provider}"),
                                format!("{provider} gave no answer"),
                                1,
                            );
                        } else {
                            *oks.entry((
                                rule.id,
                                format!("ok:deployment:{provider}"),
                                minute.clone(),
                            ))
                            .or_default() += 1;
                        }
                    }
                    (RuleKind::DeploymentDown, "attempts") => {
                        let tries = record["attempts"].as_array().cloned().unwrap_or_default();
                        for attempt in tries.iter().rev().skip(1) {
                            let provider = attempt["provider"].as_str().unwrap_or("unknown");
                            let outcome = attempt["outcome"]
                                .as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| attempt["outcome"].to_string());
                            if failed_outcome(&outcome) {
                                hit(
                                    rule,
                                    format!("deployment:{provider}"),
                                    format!("{provider} failed with {outcome}"),
                                    1,
                                );
                            }
                        }
                    }
                    (RuleKind::CredentialFailing, "usage")
                        if matches!(record["status"].as_u64(), Some(401 | 403)) =>
                    {
                        let provider = provider_of(record);
                        hit(
                            rule,
                            format!("provider:{provider}"),
                            format!(
                                "{provider} refused Enterplace's credential with {}",
                                record["status"]
                            ),
                            1,
                        );
                    }
                    (RuleKind::CredentialFailing, "attempts") => {
                        let tries = record["attempts"].as_array().cloned().unwrap_or_default();
                        for attempt in tries.iter().rev().skip(1) {
                            let provider = attempt["provider"].as_str().unwrap_or("unknown");
                            let outcome = attempt["outcome"]
                                .as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| attempt["outcome"].to_string());
                            if matches!(outcome.as_str(), "401" | "403") {
                                hit(
                                    rule,
                                    format!("provider:{provider}"),
                                    format!(
                                        "{provider} refused Enterplace's credential with {outcome}"
                                    ),
                                    1,
                                );
                            }
                        }
                    }
                    (RuleKind::GuardrailVendorFailing, "request" | "answer_guardrails") => {
                        for found in record["guardrails"].as_array().into_iter().flatten() {
                            if found["kind"] == "unavailable" {
                                let guardrail = found["guardrail"].as_str().unwrap_or("unknown");
                                hit(
                                    rule,
                                    format!("guardrail:{guardrail}"),
                                    format!(
                                        "guardrail \"{guardrail}\" ({}) could not be reached and was {}",
                                        found["detector"].as_str().unwrap_or("its service"),
                                        if found["action"] == "block" {
                                            "failed closed"
                                        } else {
                                            "skipped"
                                        }
                                    ),
                                    1,
                                );
                            }
                        }
                    }
                    (RuleKind::KillCleared, "admin")
                        if record["verdict"] == "allow" && record["action"] == "clear_kill" =>
                    {
                        let t = &record["target"];
                        hit(
                            rule,
                            record["id"].as_str().unwrap_or_default().to_string(),
                            format!(
                                "{} cleared the kill switch on {} {}: the traffic it stopped is let through again",
                                record["person"].as_str().unwrap_or("someone"),
                                t["scope"].as_str().unwrap_or("?"),
                                t["value"].as_str().unwrap_or("?")
                            ),
                            0,
                        );
                    }
                    (RuleKind::ConfigRejected, "config_rejected") => {
                        let problems = record["problems"].as_array();
                        hit(
                            rule,
                            format!(
                                "config:{}:{}",
                                short(&record["policy_sha256"]),
                                short(&record["keys_sha256"])
                            ),
                            format!(
                                "a {} reload refused a change to the policy or keys ({} problems) and keeps deciding with policy {}; the first problem: {}. Fix it and save again, `enterplace check` says what passes",
                                record["trigger"].as_str().unwrap_or("config"),
                                problems.map_or(0, Vec::len),
                                short(&record["policy_sha256_before"]),
                                problems
                                    .and_then(|p| p.first())
                                    .and_then(Value::as_str)
                                    .unwrap_or("not recorded")
                            ),
                            0,
                        );
                    }
                    (RuleKind::ConfigRejected, "admin")
                        if record["verdict"] != "allow" && record["code"] == "invalid_policy" =>
                    {
                        hit(
                            rule,
                            record["id"].as_str().unwrap_or_default().to_string(),
                            format!(
                                "{} sent a policy version that does not pass `enterplace check` ({}), refused as invalid_policy; the live version is unchanged",
                                record["person"].as_str().unwrap_or("someone"),
                                record["action"].as_str().unwrap_or("a policy change")
                            ),
                            0,
                        );
                    }
                    (RuleKind::CircuitOpen, "attempts" | "usage") => {
                        for (label, failed) in deployment_outcomes(event, record) {
                            if failed {
                                hit(
                                    rule,
                                    format!("deployment:{label}"),
                                    format!(
                                        "{label} failed and is passed over for its alias's cooldown_seconds, twice as long each time it fails again"
                                    ),
                                    0,
                                );
                            }
                        }
                    }
                    (RuleKind::RegionOutage, "attempts" | "usage") => {
                        for (label, failed) in deployment_outcomes(event, record) {
                            let Some(region) = regions.get(&label) else {
                                continue;
                            };
                            if !rule.text("region").is_empty() && rule.text("region") != region {
                                continue;
                            }
                            let key = if failed {
                                format!("deployment:{label}")
                            } else {
                                format!("ok:deployment:{label}")
                            };
                            *region_counts
                                .entry((rule.id, key, minute.clone()))
                                .or_default() += 1;
                            if failed {
                                hit(
                                    rule,
                                    format!("region:{region}"),
                                    format!("{label} failed"),
                                    0,
                                );
                            }
                        }
                    }
                    (RuleKind::System, "request")
                        if matches!(
                            record["code"].as_str(),
                            Some("store_unavailable" | "kills_unreadable")
                        ) =>
                    {
                        hit(
                            rule,
                            format!(
                                "{}:{}",
                                self.replica,
                                record["code"].as_str().unwrap_or_default()
                            ),
                            format!(
                                "requests are refused with {}",
                                record["code"].as_str().unwrap_or_default()
                            ),
                            0,
                        );
                    }
                    _ => {}
                }
            }
        }

        for (slot, n) in region_counts {
            *counts.entry(slot).or_default() += n;
        }
        {
            let mut client = self.db.client().await?;
            let tx = client.transaction().await.map_err(db_error)?;
            for ((scope, period), usd) in &spend {
                tx.execute(
                    "INSERT INTO enterprise_alert_spend (scope, period, usd) VALUES ($1, $2, $3) \
                     ON CONFLICT (scope, period) DO UPDATE SET usd = enterprise_alert_spend.usd + EXCLUDED.usd",
                    &[scope, period, usd],
                )
                .await
                .map_err(db_error)?;
            }
            for ((rule, key, minute), count) in &counts {
                tx.execute(
                    "INSERT INTO enterprise_alert_counts (rule, key, minute, count) VALUES ($1, $2, CAST($3::text AS timestamptz), $4) \
                     ON CONFLICT (rule, key, minute) DO UPDATE SET count = enterprise_alert_counts.count + EXCLUDED.count",
                    &[rule, key, minute, count],
                )
                .await
                .map_err(db_error)?;
            }
            for ((scope, day), [requests, errors, latency, timed]) in &daily {
                tx.execute(
                    "INSERT INTO enterprise_alert_daily (scope, day, requests, errors, latency_ms, timed) VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (scope, day) DO UPDATE SET requests = enterprise_alert_daily.requests + EXCLUDED.requests, \
                     errors = enterprise_alert_daily.errors + EXCLUDED.errors, latency_ms = enterprise_alert_daily.latency_ms + EXCLUDED.latency_ms, \
                     timed = enterprise_alert_daily.timed + EXCLUDED.timed",
                    &[scope, day, requests, errors, latency, timed],
                )
                .await
                .map_err(db_error)?;
            }
            for ((rule, key, minute), count) in &oks {
                tx.execute(
                    "INSERT INTO enterprise_alert_counts (rule, key, minute, count) VALUES ($1, $2, CAST($3::text AS timestamptz), $4) \
                     ON CONFLICT (rule, key, minute) DO UPDATE SET count = enterprise_alert_counts.count + EXCLUDED.count",
                    &[rule, key, minute, count],
                )
                .await
                .map_err(db_error)?;
            }
            for (key, client_ip) in &addresses {
                tx.execute(
                    "INSERT INTO enterprise_alert_seen (key, client) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    &[key, client_ip],
                )
                .await
                .map_err(db_error)?;
            }
            tx.execute(
                "UPDATE enterprise_alert_cursors SET n = $2 WHERE replica = $1",
                &[&self.replica, &last],
            )
            .await
            .map_err(db_error)?;
            // Old counts are of no window any more.
            tx.execute(
                "DELETE FROM enterprise_alert_counts WHERE minute < now() - interval '2 days'",
                &[],
            )
            .await
            .map_err(db_error)?;
            tx.commit().await.map_err(db_error)?;
        }

        // One check per rule and subject, with the records of every hit.
        candidates.extend(shares);
        let mut merged: Vec<Candidate> = Vec::new();
        for c in candidates {
            match merged
                .iter_mut()
                .find(|m| m.rule.id == c.rule.id && m.key == c.key)
            {
                Some(m) => {
                    if m.evidence.len() < EVIDENCE {
                        m.evidence.extend(c.evidence);
                    }
                    // Two budgets on one counter and period: the smaller is reached first.
                    if let (Some(b), Some(other)) = (m.budget.as_mut(), c.budget) {
                        b.usd = b.usd.min(other.usd);
                    }
                    if m.summary.is_empty() {
                        m.summary = c.summary;
                    }
                }
                None => merged.push(c),
            }
        }
        for c in merged {
            if let Some(summary) = self.holds(&c).await? {
                self.fire(&c.rule, &c.key, &summary, c.evidence, &channels)
                    .await?;
            }
        }
        Ok(())
    }

    async fn spent(&self, scope: &str, period: &str) -> Result<f64, String> {
        let client = self.db.client().await?;
        Ok(client
            .query_opt(
                "SELECT usd FROM enterprise_alert_spend WHERE scope = $1 AND period = $2",
                &[&scope, &period],
            )
            .await
            .map_err(db_error)?
            .map(|r| r.try_get::<_, f64>(0))
            .transpose()
            .map_err(db_error)?
            .unwrap_or(0.0))
    }

    /// Whether a candidate's condition holds now, and what the alert says. `None`: it does not.
    async fn holds(&self, c: &Candidate) -> Result<Option<String>, String> {
        let rule = &c.rule;
        if rule.kind.windowed() {
            let client = self.db.client().await?;
            let total: i64 = client
                .query_one(
                    "SELECT coalesce(sum(count), 0)::bigint FROM enterprise_alert_counts \
                     WHERE rule = $1 AND key = $2 AND minute >= date_trunc('minute', now()) - make_interval(mins => $3)",
                    &[&rule.id, &c.key, &rule.minutes()],
                )
                .await
                .map_err(db_error)?
                .try_get(0)
                .map_err(db_error)?;
            if total < rule.count() {
                return Ok(None);
            }
            if rule.kind == RuleKind::DeploymentDown {
                let answered: i64 = client
                    .query_one(
                        "SELECT coalesce(sum(count), 0)::bigint FROM enterprise_alert_counts \
                         WHERE rule = $1 AND key = $2 AND minute >= date_trunc('minute', now()) - make_interval(mins => $3)",
                        &[&rule.id, &format!("ok:{}", c.key), &rule.minutes()],
                    )
                    .await
                    .map_err(db_error)?
                    .try_get(0)
                    .map_err(db_error)?;
                if answered > 0 {
                    return Ok(None);
                }
            }
            return Ok(Some(format!(
                "{total} in the last {} minutes for {} (threshold {}); the latest: {}.",
                rule.minutes(),
                c.key,
                rule.count(),
                c.summary
            )));
        }
        match rule.kind {
            RuleKind::Budget if c.budget.is_some() => self.share(c).await,
            RuleKind::Budget => {
                let mut parts = c.key.rsplitn(2, ':');
                let period = parts.next().unwrap_or_default().to_string();
                let scope = parts.next().unwrap_or_default();
                let ledger = if scope.starts_with("all:") {
                    "all".to_string()
                } else {
                    scope.to_string()
                };
                let spent = self.spent(&ledger, &period).await?;
                let limit = rule.number("usd", f64::MAX);
                if rule.text("forecast") == "on" {
                    let elapsed = elapsed_fraction(&period);
                    // Too early in the period for a forecast to mean anything.
                    if elapsed < 0.1 {
                        return Ok(None);
                    }
                    let projected = spent / elapsed;
                    return Ok((projected >= limit).then(|| {
                        format!(
                            "{ledger} has spent ${spent:.2} so far in {period} and is forecast to spend ${projected:.2} by its end, past ${limit:.2}."
                        )
                    }));
                }
                Ok((spent >= limit).then(|| {
                    format!("{ledger} has spent ${spent:.2} in {period}, reaching ${limit:.2}.")
                }))
            }
            RuleKind::UnusualSpend => {
                let (person, day) = c.key.rsplit_once(':').unwrap_or_default();
                let today = self.spent(&format!("person:{person}"), day).await?;
                let client = self.db.client().await?;
                let past: f64 = client
                    .query_one(
                        "SELECT coalesce(sum(usd), 0) FROM enterprise_alert_spend WHERE scope = $1 \
                         AND period ~ '^\\d{4}-\\d{2}-\\d{2}$' AND period < $2 AND period >= to_char(CAST($2 AS date) - 14, 'YYYY-MM-DD')",
                        &[&format!("person:{person}"), &day],
                    )
                    .await
                    .map_err(db_error)?
                    .try_get(0)
                    .map_err(db_error)?;
                let average = past / 14.0;
                let (factor, floor) = (rule.number("factor", 3.0), rule.number("usd", 5.0));
                Ok((today >= floor && today >= factor * average).then(|| {
                    format!(
                        "{person} has spent ${today:.2} today, against a daily average of ${average:.2} over the last 14 days."
                    )
                }))
            }
            kind if kind.unusual() => self.unusual(rule, &c.key).await,
            RuleKind::RegionOutage => self.region_down(rule, &c.key, &c.summary).await,
            _ => Ok(Some(c.summary.clone())),
        }
    }

    /// The budgets the policy in force counts a usage record's cost against, by counter: what the gateway reserved
    /// and settled it under (`Policy::applied`, for the caller, its rule, customer, tags and model).
    fn policy_budgets(&self, record: &Value) -> Vec<(String, Budget)> {
        let text = |key: &str| record[key].as_str().unwrap_or_default();
        let who = Principal {
            name: text("person").to_string(),
            team: text("team").to_string(),
            key: text("key").to_string(),
            org: text("org").to_string(),
            ..Principal::default()
        };
        let tags: Vec<String> = record["tags"]
            .as_array()
            .map(|t| {
                t.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        self.policy
            .with(|policy| {
                // The key's own entry carries its budget; a key gone since is read as the record names it.
                let identified = policy
                    .entries()
                    .find(|(_, p)| p.key == who.key)
                    .map_or(who.clone(), |(_, p)| p.clone());
                let Some(rule) = policy.rule_for(&identified) else {
                    return Vec::new();
                };
                let sent = match text("alias") {
                    "" => text("model"),
                    alias => alias,
                };
                policy
                    .applied(
                        &identified,
                        rule,
                        enterplace_core::policy::Context {
                            sent,
                            model: text("model"),
                            customer: record["customer"].as_str(),
                            tags: &tags,
                        },
                    )
                    .into_iter()
                    .filter_map(|a| match a.limit {
                        Limit::Budget(b) => Some((a.scope, b)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What a budget counter has spent in a period, across every gateway on the store: the gateway's own counter,
    /// which enforcement reads. A sliding window sums its slots back to the window's start.
    async fn counter_spent(&self, scope: &str, per: Period, label: &str) -> Result<f64, String> {
        let client = self.db.client().await?;
        let row = if per.sliding {
            let from = per.window_start_label(label);
            client
                .query_one(
                    "SELECT coalesce(sum(spent), 0) FROM enterplace_spend WHERE scope = $1 AND per = $2 AND period >= $3 AND period <= $4",
                    &[&scope, &per.word(), &from, &label],
                )
                .await
        } else {
            client
                .query_one(
                    "SELECT coalesce(sum(spent), 0) FROM enterplace_spend WHERE scope = $1 AND per = $2 AND period = $3",
                    &[&scope, &per.word(), &label],
                )
                .await
        };
        row.map_err(db_error)?.try_get(0).map_err(db_error)
    }

    /// Whether a counter's spend reaches the rule's percent of its policy budget, or is forecast to by the end of
    /// the period. Subject: `scope|per|period`, or `scope|per` for a sliding window, read up to now.
    async fn share(&self, c: &Candidate) -> Result<Option<String>, String> {
        let (rule, Some(budget)) = (&c.rule, c.budget) else {
            return Ok(None);
        };
        let mut parts = c.key.split('|');
        let scope = parts.next().unwrap_or_default();
        let label = match parts.nth(1) {
            Some(label) => label.to_string(),
            None => budget.per.label(&audit::timestamp()),
        };
        let label = label.as_str();
        let percent = rule.percent().unwrap_or(100.0);
        let spent = self.counter_spent(scope, budget.per, label).await?;
        let threshold = budget.usd * percent / 100.0;
        let length = budget.per.describe();
        let length = length.trim_end_matches(", sliding");
        let of = if budget.per.sliding {
            format!("its ${:.2} budget for any {length}", budget.usd)
        } else {
            format!("its ${:.2} budget per {length}", budget.usd)
        };
        let share = |usd: f64| usd / budget.usd * 100.0;
        // A sliding window never ends, so there is no end to forecast to: the rule reads what is spent.
        if rule.text("forecast") == "on" && !budget.per.sliding {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            let (start, end) = budget.per.window(now);
            let elapsed = ((now - start) as f64 / (end - start).max(1) as f64).clamp(0.0, 1.0);
            // Too early in the period for a forecast to mean anything.
            if elapsed < 0.1 {
                return Ok(None);
            }
            let projected = spent / elapsed;
            return Ok((projected >= threshold).then(|| {
                format!(
                    "{scope} has spent ${spent:.2} of {of} so far in {label} ({:.0}%) and is forecast to spend ${projected:.2} ({:.0}%) by its end, past {percent}%.",
                    share(spent),
                    share(projected)
                )
            }));
        }
        let window = if budget.per.sliding {
            format!("the last {length}")
        } else {
            label.to_string()
        };
        Ok((spent >= threshold).then(|| {
            format!(
                "{scope} has spent ${spent:.2} of {of} in {window} ({:.0}%), reaching {percent}%.",
                share(spent)
            )
        }))
    }

    /// Whether every deployment of a region (`region:eu`) failed at least the rule's count in its window and answered
    /// nothing. One deployment of the region that answers, or has not failed enough, keeps the alert back.
    async fn region_down(
        &self,
        rule: &Rule,
        key: &str,
        latest: &str,
    ) -> Result<Option<String>, String> {
        let region = key.strip_prefix("region:").unwrap_or_default();
        let mut labels: Vec<String> = self
            .regions()
            .await
            .into_iter()
            .filter(|(_, r)| r == region)
            .map(|(label, _)| label)
            .collect();
        labels.sort();
        if labels.is_empty() {
            return Ok(None);
        }
        let client = self.db.client().await?;
        let mut failed = Vec::new();
        for label in &labels {
            let mut sums = [0i64; 2];
            for (i, slot) in [
                format!("deployment:{label}"),
                format!("ok:deployment:{label}"),
            ]
            .iter()
            .enumerate()
            {
                sums[i] = client
                    .query_one(
                        "SELECT coalesce(sum(count), 0)::bigint FROM enterprise_alert_counts \
                         WHERE rule = $1 AND key = $2 AND minute >= date_trunc('minute', now()) - make_interval(mins => $3)",
                        &[&rule.id, slot, &rule.minutes()],
                    )
                    .await
                    .map_err(db_error)?
                    .try_get(0)
                    .map_err(db_error)?;
            }
            if sums[0] < rule.count() || sums[1] > 0 {
                return Ok(None);
            }
            failed.push(format!("{label} ({})", sums[0]));
        }
        Ok(Some(format!(
            "every deployment of region {region} failed in the last {} minutes and none answered: {}; the latest: {latest}. Requests kept to {region} by a rule's regions: are refused until one recovers.",
            rule.minutes(),
            failed.join(", ")
        )))
    }

    /// The daily digest's text: the last 24 hours across every replica.
    async fn digest(&self) -> Result<String, String> {
        let client = self.db.client().await?;
        let totals = client
            .query_one(
                "SELECT coalesce(sum(CASE WHEN j->>'event' = 'usage' THEN (j->>'charged_usd')::float8 END), 0)::float8, \
                 count(*) FILTER (WHERE j->>'event' IS NULL), \
                 count(*) FILTER (WHERE j->>'event' IS NULL AND j->>'verdict' IS DISTINCT FROM 'allow'), \
                 coalesce(sum(CASE WHEN j->>'event' = 'watch' AND j->>'kind' = 'api_request' THEN (j->>'cost_usd')::float8 END), 0)::float8, \
                 count(*) FILTER (WHERE j->>'event' = 'watch' AND j->>'kind' = 'api_request') \
                 FROM (SELECT line::jsonb AS j FROM enterprise_audit WHERE time > now() - interval '24 hours') a",
                &[],
            )
            .await
            .map_err(db_error)?;
        let spent: f64 = totals.try_get(0).map_err(db_error)?;
        let requests: i64 = totals.try_get(1).map_err(db_error)?;
        let refused: i64 = totals.try_get(2).map_err(db_error)?;
        // What Claude Code reported for people on Claude seats (watch records): part of the spend, as `charged`
        // counts it for the rules, and said apart because it is an estimate that never passed the gateway.
        let watched: f64 = totals.try_get(3).map_err(db_error)?;
        let watched_requests: i64 = totals.try_get(4).map_err(db_error)?;
        let codes = client
            .query(
                "SELECT j->>'code', count(*) FROM (SELECT line::jsonb AS j FROM enterprise_audit WHERE time > now() - interval '24 hours') a \
                 WHERE j->>'event' IS NULL AND j->>'verdict' IS DISTINCT FROM 'allow' AND j->>'code' IS NOT NULL \
                 GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 3",
                &[],
            )
            .await
            .map_err(db_error)?;
        let users = client
            .query(
                "SELECT coalesce(j->>'person', 'unknown'), sum(usd)::float8 AS usd FROM (\
                 SELECT j, CASE WHEN j->>'event' = 'usage' THEN (j->>'charged_usd')::float8 \
                 WHEN j->>'event' = 'watch' AND j->>'kind' = 'api_request' THEN (j->>'cost_usd')::float8 END AS usd \
                 FROM (SELECT line::jsonb AS j FROM enterprise_audit WHERE time > now() - interval '24 hours') a) b \
                 WHERE usd > 0 GROUP BY 1 ORDER BY usd DESC, 1 LIMIT 5",
                &[],
            )
            .await
            .map_err(db_error)?;
        let alerts = client
            .query(
                "SELECT kind, count(*) FROM enterprise_alerts WHERE fired_at > now() - interval '24 hours' \
                 AND kind <> 'daily_digest' GROUP BY 1 ORDER BY 2 DESC, 1",
                &[],
            )
            .await
            .map_err(db_error)?;
        let list = |rows: &[enterplace_server::store::tokio_postgres::Row],
                    money: bool|
         -> Result<String, String> {
            let mut out = Vec::new();
            for row in rows {
                let name: String = row.try_get(0).map_err(db_error)?;
                out.push(if money {
                    format!("{name} ${:.2}", row.try_get::<_, f64>(1).map_err(db_error)?)
                } else {
                    format!("{name} {}", row.try_get::<_, i64>(1).map_err(db_error)?)
                });
            }
            Ok(if out.is_empty() {
                "none".into()
            } else {
                out.join(", ")
            })
        };
        let watched_line = if watched_requests > 0 {
            format!(
                "\nWatched: ${watched:.2} of the spend is what Claude Code reported for {watched_requests} requests on Claude seats, an estimate at list price that did not pass through Enterplace."
            )
        } else {
            String::new()
        };
        Ok(format!(
            "The last 24 hours: ${:.2} spent over {requests} requests; {refused} refused (most: {}). Top users by spend: {}. Alerts fired: {}.{watched_line}",
            spent + watched,
            list(&codes, false)?,
            list(&users, true)?,
            list(&alerts, false)?
        ))
    }

    /// Today's requests, error rate or average latency of a scope (`team:payments:2026-11-14`) against its last 14
    /// days. `None` while it is within the rule's factor or below its floor.
    async fn unusual(&self, rule: &Rule, key: &str) -> Result<Option<String>, String> {
        let (scope, day) = key.rsplit_once(':').unwrap_or_default();
        let client = self.db.client().await?;
        let sum = |row: &enterplace_server::store::tokio_postgres::Row,
                   i: usize|
         -> Result<f64, String> {
            Ok(row.try_get::<_, i64>(i).map_err(db_error)? as f64)
        };
        let today = client
            .query_one(
                "SELECT coalesce(sum(requests), 0)::bigint, coalesce(sum(errors), 0)::bigint, coalesce(sum(latency_ms), 0)::bigint, \
                 coalesce(sum(timed), 0)::bigint FROM enterprise_alert_daily WHERE scope = $1 AND day = $2",
                &[&scope, &day],
            )
            .await
            .map_err(db_error)?;
        let past = client
            .query_one(
                "SELECT coalesce(sum(requests), 0)::bigint, coalesce(sum(errors), 0)::bigint, coalesce(sum(latency_ms), 0)::bigint, \
                 coalesce(sum(timed), 0)::bigint FROM enterprise_alert_daily WHERE scope = $1 AND day < $2 \
                 AND day >= to_char(CAST($2 AS date) - 14, 'YYYY-MM-DD')",
                &[&scope, &day],
            )
            .await
            .map_err(db_error)?;
        let (requests, errors, latency, timed) = (
            sum(&today, 0)?,
            sum(&today, 1)?,
            sum(&today, 2)?,
            sum(&today, 3)?,
        );
        let (p_requests, p_errors, p_latency, p_timed) = (
            sum(&past, 0)?,
            sum(&past, 1)?,
            sum(&past, 2)?,
            sum(&past, 3)?,
        );
        Ok(match rule.kind {
            RuleKind::UnusualRequests => {
                let (factor, floor) = (rule.number("factor", 3.0), rule.number("count", 100.0));
                let average = p_requests / 14.0;
                (requests >= floor && requests >= factor * average).then(|| format!(
                    "{scope} has sent {requests} requests today, against a daily average of {average:.1} over the last 14 days."
                ))
            }
            RuleKind::UnusualErrors => {
                let (factor, floor) = (rule.number("factor", 3.0), rule.number("count", 10.0));
                let rate = errors / requests.max(1.0);
                let baseline = p_errors / p_requests.max(1.0);
                (errors >= floor && rate >= factor * baseline).then(|| format!(
                    "{scope} has had {errors} errors today, {:.1}% of its requests, against {:.1}% over the last 14 days.",
                    rate * 100.0,
                    baseline * 100.0
                ))
            }
            _ => {
                let (factor, floor) = (rule.number("factor", 2.0), rule.number("count", 20.0));
                let average = latency / timed.max(1.0);
                let baseline = p_latency / p_timed.max(1.0);
                (timed >= floor && p_timed > 0.0 && average >= factor * baseline).then(|| format!(
                    "{scope} has averaged {average:.0} ms a request today, against {baseline:.0} ms over the last 14 days."
                ))
            }
        })
    }

    /// The rules that watch state rather than records: keys nearing their expiry, and audit export destinations
    /// behind the chain. Run once a minute on the tick.
    pub(crate) async fn checks(&self) -> Result<(), String> {
        let (rules, channels) = self.load().await?;
        for rule in rules.iter().filter(|r| r.enabled) {
            match rule.kind {
                RuleKind::KeyExpiring => {
                    let days = rule.number("days", 7.0).clamp(1.0, 365.0);
                    let now = audit::timestamp();
                    let horizon = audit::rfc3339(
                        SystemTime::now() + Duration::from_secs_f64(days * 86_400.0),
                    );
                    let path = self.keys.clone();
                    let entries = tokio::task::spawn_blocking(move || {
                        enterplace_core::config::read_keys(&path).map(|text| {
                            text.map(|t| {
                                enterplace_core::config::key_entries(&path, &t).unwrap_or_default()
                            })
                            .unwrap_or_default()
                        })
                    })
                    .await
                    .map_err(|err| format!("the keys could not be read: {err}"))??;
                    for entry in entries {
                        let Some(at) = &entry.expires else { continue };
                        if enterplace_core::policy::expiry_passed(at, &now)
                            || !enterplace_core::policy::expiry_passed(at, &horizon)
                        {
                            continue;
                        }
                        let prefix = entry.sha256.get(..8).unwrap_or_default();
                        self.fire(
                            rule,
                            &format!("{prefix}:{at}"),
                            &format!(
                                "key {prefix} of {} (team {}) expires at {at}. Rotate it with POST /admin/keys/{prefix}/rotate or enterplace key rotate before then.",
                                entry.name, entry.team
                            ),
                            Vec::new(),
                            &channels,
                        )
                        .await?;
                    }
                }
                RuleKind::DailyDigest => {
                    let Some(day) =
                        parse_at(rule.text("at")).and_then(|at| digest_due(SystemTime::now(), at))
                    else {
                        continue;
                    };
                    let key = format!("digest:{day}");
                    // Sent (or held back by the hourly cap) already today: no need to sum the day again.
                    let sent = self
                        .db
                        .client()
                        .await?
                        .query_opt(
                            "SELECT 1 FROM enterprise_alert_state WHERE rule = $1 AND key = $2",
                            &[&rule.id, &key],
                        )
                        .await
                        .map_err(db_error)?
                        .is_some();
                    if !sent {
                        let summary = self.digest().await?;
                        self.fire(rule, &key, &summary, Vec::new(), &channels)
                            .await?;
                    }
                }
                RuleKind::ExportLagging => {
                    let minutes = rule.number("minutes", 15.0).clamp(1.0, 10_080.0);
                    let client = self.db.client().await?;
                    let rows = client
                        .query(
                            "SELECT d.id, d.kind, coalesce(c.n, 0), \
                             (SELECT count(*) FROM enterprise_audit a WHERE a.replica = $1 AND a.n > coalesce(c.n, 0)), \
                             (SELECT coalesce(extract(epoch FROM now() - min(a.time)), 0)::float8 FROM enterprise_audit a \
                              WHERE a.replica = $1 AND a.n > coalesce(c.n, 0)) \
                             FROM enterprise_export_destinations d \
                             LEFT JOIN enterprise_export_cursors c ON c.destination = d.id AND c.replica = $1",
                            &[&self.replica],
                        )
                        .await
                        .map_err(db_error)?;
                    drop(client);
                    for row in rows {
                        let id: i64 = row.try_get(0).map_err(db_error)?;
                        let kind: String = row.try_get(1).map_err(db_error)?;
                        let waiting: i64 = row.try_get(3).map_err(db_error)?;
                        let age: f64 = row.try_get(4).map_err(db_error)?;
                        if waiting == 0 || age < minutes * 60.0 {
                            continue;
                        }
                        self.fire(
                            rule,
                            &format!("{}:destination:{id}", self.replica),
                            &format!(
                                "audit export destination {id} ({kind}) is {:.0} minutes behind replica {}: {waiting} records wait. Its last error is on the Audit export page.",
                                age / 60.0,
                                self.replica
                            ),
                            Vec::new(),
                            &channels,
                        )
                        .await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Fires an alert unless the rule fired for this subject within its quiet period or too often this hour. Each
    /// alert is kept, written to the audit chain and sent to the rule's channels.
    async fn fire(
        &self,
        rule: &Rule,
        key: &str,
        summary: &str,
        evidence: Vec<Value>,
        channels: &[Channel],
    ) -> Result<(), String> {
        let quiet = if rule.kind.once() && !sliding_subject(key) {
            FOREVER
        } else {
            rule.cooldown.max(0)
        };
        let (id, time) = {
            let client = self.db.client().await?;
            let fresh = client
                .query_opt(
                    "INSERT INTO enterprise_alert_state (rule, key, last_at) VALUES ($1, $2, now()) \
                     ON CONFLICT (rule, key) DO UPDATE SET last_at = now() \
                     WHERE enterprise_alert_state.last_at < now() - make_interval(mins => $3) RETURNING rule",
                    &[&rule.id, &key, &quiet],
                )
                .await
                .map_err(db_error)?;
            let this_hour: i64 = client
                .query_one(
                    "SELECT count(*) FROM enterprise_alerts WHERE rule = $1 AND fired_at > now() - interval '1 hour'",
                    &[&rule.id],
                )
                .await
                .map_err(db_error)?
                .try_get(0)
                .map_err(db_error)?;
            if fresh.is_none() || this_hour >= i64::from(rule.max_per_hour) {
                client
                    .execute(
                        "UPDATE enterprise_alert_state SET suppressed = suppressed + 1 WHERE rule = $1 AND key = $2",
                        &[&rule.id, &key],
                    )
                    .await
                    .map_err(db_error)?;
                return Ok(());
            }
            let row = client
                .query_one(
                    "INSERT INTO enterprise_alerts (rule, rule_name, kind, key, summary, evidence) VALUES ($1, $2, $3, $4, $5, $6) \
                     RETURNING id, to_char(fired_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')",
                    &[&rule.id, &rule.name, &rule.kind.word(), &key, &summary, &Value::from(evidence.clone()).to_string()],
                )
                .await
                .map_err(db_error)?;
            (
                row.try_get::<_, i64>(0).map_err(db_error)?,
                row.try_get::<_, String>(1).map_err(db_error)?,
            )
        };
        let alert = Alert {
            id,
            rule: rule.name.clone(),
            kind: rule.kind.word(),
            severity: rule.kind.severity(),
            key: key.to_string(),
            summary: summary.to_string(),
            time,
            evidence,
            console: self.console.clone(),
        };
        let mut notes = vec![self.chain(rule, &alert).await];
        notes.extend(self.deliver(rule, &alert, channels).await);
        let client = self.db.client().await?;
        client
            .execute(
                "UPDATE enterprise_alerts SET delivery = $2 WHERE id = $1",
                &[&id, &notes.join("; ")],
            )
            .await
            .map_err(db_error)?;
        Ok(())
    }

    /// The alert as an `alert` record in this replica's chain, naming the records behind it.
    async fn chain(&self, rule: &Rule, alert: &Alert) -> String {
        let mut record = serde_json::Map::new();
        record.insert("event".into(), "alert".into());
        record.insert("id".into(), enterplace_core::id::decision_id().into());
        record.insert("time".into(), audit::timestamp().into());
        record.insert("alert".into(), alert.id.into());
        record.insert("rule".into(), rule.name.clone().into());
        record.insert("rule_id".into(), rule.id.into());
        record.insert("kind".into(), rule.kind.word().into());
        record.insert("subject".into(), alert.key.clone().into());
        record.insert("summary".into(), alert.summary.clone().into());
        record.insert("records".into(), Value::from(alert.evidence.clone()));
        let (tell, told) = tokio::sync::oneshot::channel();
        self.log.append_record_then(&record, move |result| {
            let _ = tell.send(result);
        });
        match told.await {
            Ok(Ok(())) => "recorded in the audit log".into(),
            Ok(Err(err)) => format!("not recorded in the audit log: {err}"),
            Err(_) => "not recorded in the audit log: the writer stopped".into(),
        }
    }

    /// Sends to each of the rule's channels, up to three tries each. Returns a note per channel.
    async fn deliver(&self, rule: &Rule, alert: &Alert, channels: &[Channel]) -> Vec<String> {
        let mut notes = Vec::new();
        for channel in channels.iter().filter(|c| rule.channels.contains(&c.id)) {
            let (sinks, ch, a) = (self.sinks.clone(), channel.clone(), alert.clone());
            let result = tokio::task::spawn_blocking(move || {
                let mut last = Err(String::new());
                for wait in [0, 1, 2] {
                    std::thread::sleep(Duration::from_secs(wait));
                    last = channels::deliver(&sinks, &ch, &a);
                    if last.is_ok() {
                        break;
                    }
                }
                last
            })
            .await
            .unwrap_or_else(|err| Err(format!("the sender stopped: {err}")));
            let _ = self.outcome(channel.id, &result).await;
            notes.push(match result {
                Ok(()) => format!("sent to {} ({})", channel.name, channel.kind.word()),
                Err(err) => format!(
                    "failed on {} ({}): {err}",
                    channel.name,
                    channel.kind.word()
                ),
            });
        }
        if notes.is_empty() {
            notes.push("the rule has no channel".into());
        }
        notes
    }

    async fn outcome(&self, id: i64, result: &Result<(), String>) -> Result<(), String> {
        let client = self.db.client().await?;
        match result {
            Ok(()) => client
                .execute(
                    "UPDATE enterprise_alert_channels SET last_success_at = now(), sent = sent + 1 WHERE id = $1",
                    &[&id],
                )
                .await,
            Err(err) => client
                .execute(
                    "UPDATE enterprise_alert_channels SET last_error = $2, last_error_at = now() WHERE id = $1",
                    &[&id, err],
                )
                .await,
        }
        .map_err(db_error)?;
        Ok(())
    }
}

/// How much of a day (`2026-11-14`) or month (`2026-11`) has passed, from 0 to 1.
fn elapsed_fraction(period: &str) -> f64 {
    let now = SystemTime::now();
    let (start, end) = if period.len() == 10 {
        let start = parse_time(&format!("{period}T00:00:00.000Z"));
        (start, start.map(|s| s + Duration::from_secs(86_400)))
    } else {
        let (y, m) = period.split_once('-').unwrap_or_default();
        let (y, m): (i32, u32) = (y.parse().unwrap_or(1970), m.parse().unwrap_or(1));
        let next = if m == 12 {
            format!("{}-01", y + 1)
        } else {
            format!("{y}-{:02}", m + 1)
        };
        (
            parse_time(&format!("{period}-01T00:00:00.000Z")),
            parse_time(&format!("{next}-01T00:00:00.000Z")),
        )
    };
    match (start, end) {
        (Some(start), Some(end)) => {
            let total = end.duration_since(start).map_or(1.0, |d| d.as_secs_f64());
            let done = now.duration_since(start).map_or(0.0, |d| d.as_secs_f64());
            (done / total).clamp(0.0, 1.0)
        }
        _ => 1.0,
    }
}

// ---------------------------------------------------------------- the page

fn form_for(action: &str, inner: &str) -> String {
    format!(
        r#"<form method="post" action="/console/alerts" class="g-stack">{}{inner}</form>"#,
        hidden("action", action)
    )
}

fn select(name: &str, label: &str, options: &[(&str, &str)], chosen: &str) -> String {
    let options: String = options
        .iter()
        .map(|(value, text)| {
            format!(
                r#"<option value="{value}"{}>{}</option>"#,
                if *value == chosen { " selected" } else { "" },
                esc(text)
            )
        })
        .collect();
    format!(
        r#"<div class="g-select-wrap"><select class="g-input g-select t-body" name="{name}" aria-label="{label}">{options}</select>{}</div>"#,
        html::icon("down")
    )
}

async fn page(
    State(console): State<Console>,
    Ext(alerts): Ext<Alerts>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(admin) = console.signed_in(&headers).await else {
        return redirect("/console/sign-in");
    };
    let edit = uri
        .query()
        .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("edit=")))
        .and_then(|id| id.parse().ok());
    show(&console, &alerts, &admin, &uri, "", false, "", edit).await
}

#[allow(clippy::too_many_arguments)]
async fn show(
    console: &Console,
    alerts: &Alerts,
    admin: &Admin,
    uri: &Uri,
    notice: &str,
    error: bool,
    once: &str,
    edit: Option<i64>,
) -> Response {
    match main(alerts, admin, notice, error, once, edit).await {
        Ok(main) => console.page(StatusCode::OK, admin, NAV, uri, &main),
        Err(err) => console.page(
            StatusCode::SERVICE_UNAVAILABLE,
            admin,
            NAV,
            uri,
            &format!("{}{}", html::head(NAV, "", ""), banner(&err, true)),
        ),
    }
}

async fn main(
    alerts: &Alerts,
    admin: &Admin,
    notice: &str,
    error: bool,
    once: &str,
    edit: Option<i64>,
) -> Result<String, String> {
    let engine = &alerts.engine;
    let can_edit = role_of(admin) != Role::Viewer;
    let (rules, channels) = engine.load().await?;
    let mut out = html::head(
        NAV,
        "Rules on spend, limits, providers and security events, sent to Slack, Teams, PagerDuty, email or a signed webhook. Each alert names the audit records behind it and is itself recorded.",
        "",
    );
    if !notice.is_empty() {
        out += &banner(notice, error);
    }
    out += once;
    if rules.is_empty() && channels.is_empty() {
        out += &enterplace_console::empty_page(
            "Alerts",
            &enterplace_console::request_base(),
            can_edit,
        );
    }

    // Channels.
    let client = engine.db.client().await?;
    let stats = client
        .query(
            "SELECT id, url, sent, coalesce(to_char(last_success_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS \"UTC\"'), 'never'), \
             coalesce(last_error, '') FROM enterprise_alert_channels ORDER BY id",
            &[],
        )
        .await
        .map_err(db_error)?;
    let recent = client
        .query(
            "SELECT id, rule_name, kind, key, summary, evidence, to_char(fired_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS \"UTC\"'), delivery \
             FROM enterprise_alerts ORDER BY id DESC LIMIT 50",
            &[],
        )
        .await
        .map_err(db_error)?;
    drop(client);
    let mut list = String::new();
    for row in &stats {
        let id: i64 = row.try_get(0).map_err(db_error)?;
        let Some(channel) = channels.iter().find(|c| c.id == id) else {
            continue;
        };
        let text = |i| row.try_get::<_, String>(i).map_err(db_error);
        let sent: i64 = row.try_get(2).map_err(db_error)?;
        let target = match channel.kind {
            ChannelKind::Slack | ChannelKind::Teams => "webhook URL kept encrypted".to_string(),
            ChannelKind::PagerDuty => "routing key kept encrypted".to_string(),
            ChannelKind::Email => format!(
                "{} to {}",
                text(1)?,
                channel.options["to"].as_str().unwrap_or_default()
            ),
            ChannelKind::Webhook => text(1)?,
        };
        let facts = html::facts(&[
            ("Sent", format!(r#"<span id="sent-{id}">{sent}</span>"#)),
            ("Last success", esc(&text(3)?)),
            (
                "Last error",
                format!(
                    r#"<span id="channel-error-{id}">{}</span>"#,
                    esc(&match text(4)? {
                        e if e.is_empty() => "none".into(),
                        e => e,
                    })
                ),
            ),
        ]);
        let end = if can_edit {
            format!(
                "{}{}",
                form_for(
                    "channel_test",
                    &format!(
                        "{}{}",
                        hidden("id", &id.to_string()),
                        small_button("Send a test alert")
                    )
                ),
                form_for(
                    "channel_remove",
                    &format!(
                        "{}{}",
                        hidden("id", &id.to_string()),
                        small_button("Remove")
                    )
                )
            )
        } else {
            String::new()
        };
        list += &html::row(
            &format!(
                "{id}. {} ({})",
                esc(&channel.name),
                esc(channel.kind.label())
            ),
            &format!("{}{facts}", esc(&target)),
            &end,
            false,
        );
    }
    if list.is_empty() {
        list = r#"<p class="t-body g-muted">No channel yet. Alerts are still kept and listed below.</p>"#.into();
    }
    out += &section(
        "Channels",
        &format!(r#"<section class="g-list">{list}</section>"#),
    );
    if can_edit {
        let kinds: Vec<(&str, &str)> = channels::KINDS
            .iter()
            .map(|k| (k.word(), k.label()))
            .collect();
        out += r#"<span id="add-channel"></span>"#;
        out += &section(
            "Add a channel",
            &form_for(
                "channel_save",
                &format!(
                    "{}{}{}{}{}{}{}{}",
                    select("kind", "Kind", &kinds, "slack"),
                    input(
                        "name",
                        "Name",
                        "",
                        " required",
                        "How rules and alerts name it, such as #platform-alerts."
                    ),
                    input(
                        "url",
                        "URL",
                        "",
                        "",
                        "Slack and Teams: the webhook URL (kept encrypted, it is the credential). Email: smtps://host:465 or smtp://host:587 (STARTTLS). Webhook: your HTTPS endpoint. PagerDuty: leave empty."
                    ),
                    input(
                        "secret",
                        "Secret",
                        "",
                        r#" type="password" autocomplete="off""#,
                        "PagerDuty: the integration's routing key. Email: the SMTP password. Leave empty for a webhook: Enterplace makes its signing secret."
                    ),
                    input(
                        "username",
                        "SMTP username",
                        "",
                        r#" autocomplete="off""#,
                        "Email only. Empty: no AUTH."
                    ),
                    input("from", "From", "", "", "Email only: the sender address."),
                    input(
                        "to",
                        "To",
                        "",
                        "",
                        "Email only: recipients, comma-separated."
                    ),
                    html::button("Save channel", "", "submit", "")
                ),
            ),
        );
    }

    // Rules.
    let mut list = String::new();
    for rule in &rules {
        let names: Vec<String> = rule
            .channels
            .iter()
            .map(|id| {
                channels
                    .iter()
                    .find(|c| c.id == *id)
                    .map_or(format!("{id} (removed)"), |c| c.name.clone())
            })
            .collect();
        let facts = html::facts(&[
            ("Kind", esc(rule.kind.label())),
            ("When", esc(&rule.describe())),
            (
                "Channels",
                esc(&if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                }),
            ),
            (
                "Quiet period",
                if rule.kind.once() {
                    "once per subject".into()
                } else {
                    format!("{} minutes", rule.cooldown)
                },
            ),
            ("At most", format!("{} an hour", rule.max_per_hour)),
            (
                "State",
                format!(
                    r#"<span id="rule-state-{}">{}</span>"#,
                    rule.id,
                    if rule.enabled { "on" } else { "off" }
                ),
            ),
        ]);
        let end = if can_edit {
            let id = rule.id.to_string();
            format!(
                r#"<a class="g-btn g-btn--quiet g-btn--sm t-small" href="/console/alerts?edit={id}">Edit</a>{}{}"#,
                form_for(
                    if rule.enabled {
                        "rule_disable"
                    } else {
                        "rule_enable"
                    },
                    &format!(
                        "{}{}",
                        hidden("id", &id),
                        small_button(if rule.enabled { "Turn off" } else { "Turn on" })
                    )
                ),
                form_for(
                    "rule_remove",
                    &format!("{}{}", hidden("id", &id), small_button("Remove"))
                )
            )
        } else {
            String::new()
        };
        list += &html::row(
            &format!("{}. {}", rule.id, esc(&rule.name)),
            &facts,
            &end,
            false,
        );
    }
    if list.is_empty() {
        list = r#"<p class="t-body g-muted">No rule yet.</p>"#.into();
    }
    out += &section(
        "Rules",
        &format!(r#"<section class="g-list">{list}</section>"#),
    );
    if can_edit {
        let editing = edit.and_then(|id| rules.iter().find(|r| r.id == id));
        let v = |n: &str| editing.map(|r| r.text(n).to_string()).unwrap_or_default();
        let kinds: Vec<(&str, &str)> = RULE_KINDS.iter().map(|k| (k.word(), k.label())).collect();
        let chosen = editing.map_or("budget", |r| r.kind.word());
        let channel_ids = editing
            .map(|r| {
                r.channels
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        out += &section(
            if editing.is_some() {
                "Edit the rule"
            } else {
                "Add a rule"
            },
            &form_for(
                "rule_save",
                &format!(
                    r#"{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}<label class="t-body"><input type="checkbox" name="forecast"{}> Forecast: fire when spend at the current rate would reach the amount or percent by the period's end</label>{}"#,
                    hidden("id", &editing.map(|r| r.id.to_string()).unwrap_or_default()),
                    select("kind", "Kind", &kinds, chosen),
                    input(
                        "name_rule",
                        "Rule name",
                        &editing.map(|r| r.name.clone()).unwrap_or_default(),
                        " required",
                        ""
                    ),
                    input(
                        "channels",
                        "Channels",
                        &channel_ids,
                        "",
                        "Channel numbers, comma-separated, such as 1,3."
                    ),
                    input(
                        "cooldown",
                        "Quiet period in minutes",
                        &editing.map_or("60".into(), |r| r.cooldown.to_string()),
                        r#" type="number" min="0" max="10080""#,
                        "After an alert, the same rule and subject stay quiet this long. Budgets, kill switches, new addresses, after hours and unusual spend fire once per subject."
                    ),
                    input(
                        "max_per_hour",
                        "At most per hour",
                        &editing.map_or("10".into(), |r| r.max_per_hour.to_string()),
                        r#" type="number" min="1" max="1000""#,
                        "Alerts of this rule past this many an hour are counted and not sent."
                    ),
                    select(
                        "scope",
                        "Budget scope",
                        &[
                            ("all", "Budget: the whole install"),
                            ("team", "Budget: a team"),
                            ("person", "Budget: a person"),
                            ("key", "Budget: a key"),
                            ("org", "Budget: an organization (with a percent)"),
                            ("customer", "Budget: a customer (with a percent)"),
                            ("tag", "Budget: a tag (with a percent)"),
                            ("model", "Budget: a model (with a percent)")
                        ],
                        &v("scope")
                    ),
                    input(
                        "name",
                        "Budget: name",
                        &v("name"),
                        "",
                        "The team, person, key prefix, organization, customer, tag or model. Empty: each one. Inside an organization, acme/payments."
                    ),
                    input(
                        "percent",
                        "Budget: percent of the policy's budget",
                        &v("percent"),
                        r#" type="number" min="1" max="1000""#,
                        "Fires when spend reaches this percent of each budget the policy sets for the scope, in its own period (calendar or sliding). Period and amount are then the policy's."
                    ),
                    select(
                        "period",
                        "Budget period",
                        &[("month", "Budget: this month"), ("day", "Budget: today")],
                        &v("period")
                    ),
                    input(
                        "usd",
                        "Amount in US dollars",
                        &v("usd"),
                        "",
                        "Budget: the amount. Unusual spend: the least a day's spend must be (default 5)."
                    ),
                    input(
                        "count",
                        "Count",
                        &v("count"),
                        "",
                        "Rate limits, refusals, provider errors, slow requests, guardrail blocks: how many in the window (default 1)."
                    ),
                    input(
                        "minutes",
                        "Window in minutes",
                        &v("minutes"),
                        "",
                        "Default 5, at most 1440."
                    ),
                    input(
                        "by",
                        "Group by",
                        &v("by"),
                        "",
                        "all, person, team or key (rate limits, refusals, guardrail blocks)."
                    ),
                    input(
                        "codes",
                        "Refusal codes",
                        &v("codes"),
                        "",
                        "Refusals only: comma-separated codes, such as budget_exceeded,key_budget_exceeded."
                    ),
                    input(
                        "provider",
                        "Provider",
                        &v("provider"),
                        "",
                        "Provider errors and slow requests: only this provider. Empty: each."
                    ),
                    [
                        input(
                            "ms",
                            "Slow above, in ms",
                            &v("ms"),
                            "",
                            "Slow requests: from the decision to the answer's end."
                        ),
                        input(
                            "hours",
                            "Working hours",
                            &v("hours"),
                            "",
                            "After hours: 08-19, or 08-19+0200 for an offset from UTC. Weekends are after hours."
                        ),
                        input(
                            "factor",
                            "Times the usual",
                            &v("factor"),
                            "",
                            "Unusual spend: how many times the person's daily average of the last 14 days (default 3)."
                        ),
                        input(
                            "at",
                            "Digest time",
                            &v("at"),
                            "",
                            "Daily digest: 09:00, or 09:00+0200 for an offset from UTC (default 09:00 UTC)."
                        ),
                        input(
                            "region",
                            "Region",
                            &v("region"),
                            "",
                            "Region outage: the region: label of alias deployments, such as eu. Empty: each region."
                        )
                    ]
                    .concat(),
                    if v("forecast") == "on" {
                        " checked"
                    } else {
                        ""
                    },
                    html::button("Save rule", "", "submit", "")
                ),
            ),
        );
    }

    // Recent alerts.
    let mut list = String::new();
    for row in &recent {
        let id: i64 = row.try_get(0).map_err(db_error)?;
        let text = |i| row.try_get::<_, String>(i).map_err(db_error);
        let evidence: Vec<Value> = serde_json::from_str(&text(5)?).unwrap_or_default();
        let links: Vec<String> = evidence
            .iter()
            .filter_map(|e| e["id"].as_str())
            .map(|d| {
                format!(
                    r#"<a class="t-mono-sm" href="/console/audit?q={0}">{0}</a>"#,
                    esc(d)
                )
            })
            .collect();
        let facts = html::facts(&[
            ("Rule", esc(&text(1)?)),
            ("Subject", esc(&text(3)?)),
            ("Fired", esc(&text(6)?)),
            (
                "Records",
                if links.is_empty() {
                    "none".into()
                } else {
                    links.join(" ")
                },
            ),
            ("Delivery", esc(&text(7)?)),
        ]);
        list += &format!(
            r#"<div id="alert-{id}">{}</div>"#,
            html::row(&format!("{id}. {}", esc(&text(4)?)), &facts, "", false)
        );
    }
    if list.is_empty() {
        list = r#"<p class="t-body g-muted">No alert has fired.</p>"#.into();
    }
    out += &section(
        "Recent alerts",
        &format!(r#"<section class="g-list">{list}</section>"#),
    );
    Ok(out)
}

async fn act(
    State(console): State<Console>,
    Ext(alerts): Ext<Alerts>,
    headers: HeaderMap,
    uri: Uri,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign().into_response();
    }
    let Some(admin) = console.signed_in(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    let (notice, error, once) = match change(&console, &alerts, &admin, &form).await {
        Ok((notice, once)) => (notice, false, once),
        Err(err) => (err, true, String::new()),
    };
    show(&console, &alerts, &admin, &uri, &notice, error, &once, None).await
}

/// Does one change, recorded first. `Ok` is the notice and anything shown once; `Err` the message to show.
async fn change(
    console: &Console,
    alerts: &Alerts,
    admin: &Admin,
    form: &Form,
) -> Result<(String, String), String> {
    let engine = &alerts.engine;
    let action: &'static str = match form.get("action") {
        "channel_save" => "alert_channel_saved",
        "channel_test" => "alert_channel_tested",
        "channel_remove" => "alert_channel_removed",
        "rule_save" => "alert_rule_saved",
        "rule_enable" => "alert_rule_enabled",
        "rule_disable" => "alert_rule_disabled",
        "rule_remove" => "alert_rule_removed",
        _ => return Err("Unknown action. Use the buttons on this page.".into()),
    };
    let refuse = |code: &'static str, details: Value, message: String| async move {
        let _ = console
            .audit(Some(admin), action, details, Some(code))
            .await;
        Err::<(String, String), String>(message)
    };
    if role_of(admin) == Role::Viewer {
        return refuse(
            "read_only",
            json!({}),
            "Your role is viewer. An owner or admin can make this change.".into(),
        )
        .await;
    }
    let record = |details: Value| async move {
        console
            .audit(Some(admin), action, details, None)
            .await
            .map_err(str::to_string)
    };
    let id: i64 = form.get("id").trim().parse().unwrap_or(-1);
    let (_, channels) = engine.load().await?;
    match action {
        "alert_channel_saved" => {
            let Some(kind) = ChannelKind::parse(form.get("kind")) else {
                return Err("Choose a channel kind from the list.".into());
            };
            let name: String = form.get("name").trim().chars().take(100).collect();
            if name.is_empty() {
                return Err("Enter a name for the channel.".into());
            }
            let url = form.get("url").trim().to_string();
            let mut secret = form.get("secret").trim().to_string();
            let options: serde_json::Map<String, Value> = ["username", "from", "to"]
                .into_iter()
                .filter(|k| kind == ChannelKind::Email && !form.get(k).trim().is_empty())
                .map(|k| (k.to_string(), Value::from(form.get(k).trim())))
                .collect();
            let (stored_url, shown) = match kind {
                ChannelKind::Slack | ChannelKind::Teams => {
                    if !channels::url_allowed(kind, &url) {
                        return refuse(
                            "invalid_url",
                            json!({ "kind": kind.word() }),
                            "The webhook URL must use https://.".into(),
                        )
                        .await;
                    }
                    secret = url;
                    (String::new(), String::new())
                }
                ChannelKind::PagerDuty => {
                    if secret.is_empty() {
                        return Err(
                            "Enter the PagerDuty integration's routing key in Secret.".into()
                        );
                    }
                    (url.clone(), url)
                }
                ChannelKind::Email => {
                    if !channels::url_allowed(kind, &url) {
                        return refuse(
                            "invalid_url",
                            json!({ "kind": kind.word() }),
                            "The SMTP server URL is smtps://host:465 or smtp://host:587.".into(),
                        )
                        .await;
                    }
                    if form.get("from").trim().is_empty() || form.get("to").trim().is_empty() {
                        return Err("Enter the From address and at least one To address.".into());
                    }
                    (url.clone(), url)
                }
                ChannelKind::Webhook => {
                    if !channels::url_allowed(kind, &url) {
                        return refuse(
                            "invalid_url",
                            json!({ "kind": kind.word() }),
                            "The webhook URL must use https:// (plain http only to this machine)."
                                .into(),
                        )
                        .await;
                    }
                    secret = format!("whsec_{}", {
                        use base64::Engine;
                        let hex = random_hex(24)?;
                        base64::engine::general_purpose::STANDARD.encode(hex.as_bytes())
                    });
                    (url.clone(), url)
                }
            };
            let Some(key) = engine.key.as_ref() else {
                return Err("Channel credentials are kept encrypted in the database, and ENTERPLACE_EXPORT_KEY is not set. Set it on every replica to the same 64 hex characters (openssl rand -hex 32) and restart.".into());
            };
            let sealed = if secret.is_empty() {
                String::new()
            } else {
                seal_secret(key, &secret)?
            };
            // The webhook URLs of Slack and Teams are credentials: the record names the kind and channel only.
            record(json!({ "kind": kind.word(), "name": name, "url": shown })).await?;
            let client = engine.db.client().await?;
            let row = client
                .query_one(
                    "INSERT INTO enterprise_alert_channels (kind, name, url, secret, options, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                    &[&kind.word(), &name, &stored_url, &sealed, &Value::Object(options).to_string(), &admin.name],
                )
                .await
                .map_err(db_error)?;
            let new: i64 = row.try_get(0).map_err(db_error)?;
            let once = if kind == ChannelKind::Webhook {
                section(
                    "Signing secret",
                    &format!(
                        r#"<p class="t-body" style="margin: 0">Verify each POST the Standard Webhooks way: <span class="t-mono-sm">webhook-signature</span> is <span class="t-mono-sm">v1,</span> and the base64 HMAC-SHA256 of <span class="t-mono-sm">webhook-id.webhook-timestamp.body</span> under the base64-decoded part of this secret after <span class="t-mono-sm">whsec_</span>. It is shown once.</p><span class="g-command g-command--value"><span class="g-command__text t-mono" id="signing-secret">{}</span></span>"#,
                        esc(&secret)
                    ),
                )
            } else {
                String::new()
            };
            Ok((
                format!("Saved channel {new}. Add it to a rule to send alerts there."),
                once,
            ))
        }
        "alert_channel_tested" => {
            let channel = channels
                .iter()
                .find(|c| c.id == id)
                .ok_or("There is no such channel.")?
                .clone();
            record(json!({ "channel": id })).await?;
            let alert = Alert {
                id: 0,
                rule: "Test alert".into(),
                kind: "test",
                severity: Severity::Warning,
                key: "test".into(),
                summary: format!(
                    "A test alert from Enterplace to {}, sent by {}.",
                    channel.name, admin.name
                ),
                time: audit::timestamp(),
                evidence: Vec::new(),
                console: engine.console.clone(),
            };
            let sinks = engine.sinks.clone();
            let ch = channel.clone();
            let result =
                tokio::task::spawn_blocking(move || channels::deliver(&sinks, &ch, &alert))
                    .await
                    .unwrap_or_else(|err| Err(format!("the sender stopped: {err}")));
            engine.outcome(id, &result).await?;
            match result {
                Ok(()) => Ok(("The test alert was delivered.".into(), String::new())),
                Err(err) => Err(format!("The test alert failed: {err}")),
            }
        }
        "alert_channel_removed" => {
            record(json!({ "channel": id })).await?;
            let client = engine.db.client().await?;
            client
                .execute(
                    "DELETE FROM enterprise_alert_channels WHERE id = $1",
                    &[&id],
                )
                .await
                .map_err(db_error)?;
            Ok((format!("Removed channel {id}."), String::new()))
        }
        "alert_rule_saved" => {
            let Some(kind) = RuleKind::parse(form.get("kind")) else {
                return Err("Choose a rule kind from the list.".into());
            };
            let name: String = form.get("name_rule").trim().chars().take(100).collect();
            if name.is_empty() {
                return Err("Enter a name for the rule.".into());
            }
            let params = match Rule::check(kind, form) {
                Ok(params) => params,
                Err(err) => {
                    return refuse("invalid_rule", json!({ "kind": kind.word() }), err).await;
                }
            };
            let wanted: Vec<i64> = form
                .get("channels")
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(|c| {
                    c.parse()
                        .map_err(|_| format!("\"{c}\" is not a channel number."))
                })
                .collect::<Result<_, _>>()?;
            if let Some(missing) = wanted
                .iter()
                .find(|w| !channels.iter().any(|c| c.id == **w))
            {
                return Err(format!("There is no channel {missing}."));
            }
            let cooldown: i32 = form.get("cooldown").trim().parse().unwrap_or(60);
            let max_per_hour: i32 = form.get("max_per_hour").trim().parse().unwrap_or(10);
            if !(0..=10_080).contains(&cooldown) || !(1..=1000).contains(&max_per_hour) {
                return Err(
                    "The quiet period is 0 to 10080 minutes and at most per hour 1 to 1000.".into(),
                );
            }
            let channel_list = wanted
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            record(json!({
                "rule": if id > 0 { Value::from(id) } else { Value::Null },
                "name": name, "kind": kind.word(), "params": params,
                "channels": wanted, "cooldown_minutes": cooldown, "max_per_hour": max_per_hour,
            }))
            .await?;
            let client = engine.db.client().await?;
            if id > 0 {
                let changed = client
                    .execute(
                        "UPDATE enterprise_alert_rules SET name = $2, kind = $3, params = $4, channels = $5, cooldown_minutes = $6, \
                         max_per_hour = $7, updated_by = $8, updated_at = now() WHERE id = $1",
                        &[&id, &name, &kind.word(), &params.to_string(), &channel_list, &cooldown, &max_per_hour, &admin.name],
                    )
                    .await
                    .map_err(db_error)?;
                if changed == 0 {
                    return Err("There is no such rule.".into());
                }
                return Ok((format!("Saved rule {id}."), String::new()));
            }
            let row = client
                .query_one(
                    "INSERT INTO enterprise_alert_rules (name, kind, params, channels, cooldown_minutes, max_per_hour, updated_by) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
                    &[&name, &kind.word(), &params.to_string(), &channel_list, &cooldown, &max_per_hour, &admin.name],
                )
                .await
                .map_err(db_error)?;
            let new: i64 = row.try_get(0).map_err(db_error)?;
            Ok((
                format!("Added rule {new}. It applies to records written from now on."),
                String::new(),
            ))
        }
        _ => {
            record(json!({ "rule": id })).await?;
            let client = engine.db.client().await?;
            let changed = if action == "alert_rule_removed" {
                client.execute("DELETE FROM enterprise_alert_rules WHERE id = $1", &[&id]).await
            } else {
                client
                    .execute(
                        "UPDATE enterprise_alert_rules SET enabled = $2, updated_by = $3, updated_at = now() WHERE id = $1",
                        &[&id, &(action == "alert_rule_enabled"), &admin.name],
                    )
                    .await
            }
            .map_err(db_error)?;
            if changed == 0 {
                return Err("There is no such rule.".into());
            }
            Ok((
                match action {
                    "alert_rule_removed" => {
                        format!("Removed rule {id}. Its past alerts stay listed.")
                    }
                    "alert_rule_enabled" => format!("Rule {id} is on."),
                    _ => format!("Rule {id} is off."),
                },
                String::new(),
            ))
        }
    }
}

/// Whether a record of this kind can add to spend.
fn spends(event: &str) -> bool {
    matches!(event, "usage" | "watch")
}

/// What a record adds to spend: what a forwarded request was charged, or the cost Claude Code estimated for a
/// request it reported itself (a `watch` record). Rules by amount and unusual spend count both; a share of a policy
/// budget counts only the first, as the policy does.
fn charged(event: &str, record: &Value) -> f64 {
    match event {
        "usage" => record["charged_usd"].as_f64().unwrap_or(0.0),
        "watch" if record["kind"] == "api_request" => record["cost_usd"].as_f64().unwrap_or(0.0),
        _ => 0.0,
    }
}
