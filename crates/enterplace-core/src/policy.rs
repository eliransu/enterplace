//! The decision every request must pass: who is asking, and may they use this model.
//!
//! This is the in-memory shape the hot path reads, so a decision never waits on a file or a store.
//! `config` builds it from the policy and keys files.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::{guard::Guardrail, id::sha256, usage::PriceOverrides};

/// Who a key belongs to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub team: String,
    /// May use the admin API to issue and revoke keys.
    pub admin: bool,
    /// First 8 hex characters of the key's SHA-256: names the key in records, and its budget in the ledger.
    // ponytail: two keys sharing 8 hex characters would share a key budget; revoking by prefix refuses them too.
    pub key: String,
    /// UTC date or time from which the key is refused, written so it compares with record timestamps as text.
    pub expires: Option<String>,
    /// Most this key may spend, on top of its rule's budget.
    pub budget: Option<Budget>,
    /// The models this key may use, within its rule's. `None` leaves the rule's list as it is.
    pub models: Option<Vec<String>>,
    /// Most tokens this key may use per minute, on top of its rule's limit.
    pub tpm: Option<u32>,
    /// The organization the key belongs to. Empty for an install with one: scopes then keep their names of before
    /// organizations, so spend counted before them still counts.
    pub org: String,
    /// The end customer every request with this key is for, set by an admin. A header cannot change it.
    pub customer: Option<String>,
    /// Tags every request with this key carries, set by an admin, on top of the ones a rule lets the caller send.
    pub tags: Vec<String>,
    /// Most requests this key may have in flight at once.
    pub parallel: Option<u32>,
    /// The console role the key signs in with, from the policy's `roles:`. `admin: true` is the role `admin`.
    pub role: Option<String>,
    /// The rest of the key's settings: rpm, metadata, routes, source addresses, rotation.
    pub options: KeyOptions,
    /// Set when the caller signed in with a JWT from a trusted issuer instead of an Enterplace key.
    pub jwt: Option<JwtIdentity>,
}

/// The issuer and subject of a verified JWT, for the record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JwtIdentity {
    pub issuer: String,
    pub subject: String,
}

/// A key's settings beyond budget, models, tpm and the hierarchy's fields (org, customer, tags, parallel, role),
/// kept together in one store column. The default sets nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyOptions {
    /// Most requests this key may send per minute, on top of its rule's rpm.
    pub rpm: Option<u32>,
    /// The admin's own notes on the key (owner, ticket, cost center). Shown and recorded, never decided on.
    pub metadata: BTreeMap<String, String>,
    /// Path prefixes this key may call, such as /v1/chat/completions. Empty allows every route.
    pub routes: Vec<String>,
    /// Source addresses this key may be used from. Empty allows any.
    pub from: Vec<Cidr>,
    /// Set by a rotation: the hash prefix of the key that replaces this one. Every use is recorded as such.
    pub replaced_by: Option<String>,
    /// MCP tools this key may use, within its rule's `tools:` (`<server>.<tool>`, `<server>.*`, `!` to deny). Empty
    /// leaves the rule's list as it is: the list only narrows, never widens.
    pub mcp_tools: Vec<String>,
    /// Guardrails this key adds to its rule's, by the name the policy's `guardrails:` defines each under. They
    /// only add: a key never runs fewer guardrails than its rule.
    pub guardrails: Vec<String>,
    /// The client certificate this key is bound to, by its subject common name or a subject alternative name: the
    /// key is refused on a connection that did not present it (`tls: { client_ca_file }`).
    pub cert: Option<String>,
}

impl KeyOptions {
    pub fn is_empty(&self) -> bool {
        *self == KeyOptions::default()
    }

    /// Whether this key may call `path`. A prefix matches whole path segments.
    pub fn reaches(&self, path: &str) -> bool {
        self.routes.is_empty()
            || self
                .routes
                .iter()
                .any(|prefix| segment_prefix(path, prefix))
    }
}

/// Whether `prefix` starts `path` on a segment boundary: `/v1/chat` reaches `/v1/chat/completions`, not `/v1/chatx`.
pub fn segment_prefix(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix.trim_end_matches('/'))
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// An address range such as `10.0.0.0/8` or `2001:db8::/32`. A bare address is a range of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    bits: u8,
}

impl Cidr {
    /// Whether `ip` is in the range. An IPv4 address mapped into IPv6 (`::ffff:10.0.0.1`) counts as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.bits)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.bits))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::str::FromStr for Cidr {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let wrong = || {
            format!(
                "\"{text}\" is not an address range. Write one such as 10.0.0.0/8, 203.0.113.7 or 2001:db8::/32"
            )
        };
        let (addr, bits) = match text.trim().split_once('/') {
            Some((addr, bits)) => (addr, Some(bits)),
            None => (text.trim(), None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| wrong())?;
        let most = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            None => most,
            Some(bits) => bits
                .parse::<u8>()
                .ok()
                .filter(|b| *b <= most)
                .ok_or_else(wrong)?,
        };
        Ok(Cidr { addr, bits })
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

/// An identity provider whose JWTs Enterplace accepts in place of an Enterplace key on the model routes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwtTrust {
    /// `iss` must equal this.
    pub issuer: String,
    /// `aud` must be or contain this.
    pub audience: String,
    /// Where the issuer publishes its signing keys.
    pub jwks_url: String,
    /// The claim that names the person, `sub` unless set.
    pub person_claim: String,
    /// The claim that names the team, or `None` when every caller of this issuer has `team`.
    pub team_claim: Option<String>,
    pub team: Option<String>,
    /// The claim whose values give a caller of the admin API the first role whose `sso_values` hold one. `None`
    /// keeps this issuer's tokens off the admin API.
    pub role_claim: Option<String>,
}

impl Principal {
    /// `name` inside the key's organization, as counters and records name it: `acme/payments`, or `payments` alone
    /// in an install without organizations.
    pub fn within(&self, name: &str) -> String {
        within(&self.org, name)
    }

    /// The counter of the key's team.
    pub fn team_scope(&self) -> String {
        format!("team:{}", self.within(&self.team))
    }

    /// The counter of the key's person.
    pub fn person_scope(&self) -> String {
        format!("person:{}", self.within(&self.name))
    }

    /// Whether the key has expired at `now`, a record timestamp such as `2026-11-13T09:14:02.120Z`.
    pub fn expired(&self, now: &str) -> bool {
        self.expires
            .as_deref()
            .is_some_and(|at| expiry_passed(at, now))
    }
}

/// Whether an expiry (`2026-12-31` or `2026-12-31T18:00:00Z`) has passed at `now`, a record timestamp.
pub fn expiry_passed(at: &str, now: &str) -> bool {
    // A time is compared to the second: the record's milliseconds would sort `.` before the `Z` of `expires`.
    match at.strip_suffix('Z') {
        Some(at) => now.get(..19).is_none_or(|now| now >= at),
        None => now >= at,
    }
}

/// `name` inside organization `org`, or `name` alone outside any.
pub fn within(org: &str, name: &str) -> String {
    if org.is_empty() {
        name.to_string()
    } else {
        format!("{org}/{name}")
    }
}

/// Who a rule applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Who {
    Team(String),
    Name(String),
    /// Every key whose entry carries this tag. A tag the caller sends in a header never picks a rule.
    Tag(String),
    Any,
}

/// The models a rule allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Models {
    Any,
    Only(Vec<String>),
}

/// The calendar unit a budget period counts in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Unit {
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl Unit {
    fn name(self) -> &'static str {
        match self {
            Unit::Minute => "minute",
            Unit::Hour => "hour",
            Unit::Day => "day",
            Unit::Week => "week",
            Unit::Month => "month",
            Unit::Year => "year",
        }
    }

    fn short(self) -> &'static str {
        match self {
            Unit::Minute => "min",
            Unit::Hour => "h",
            Unit::Day => "d",
            Unit::Week => "w",
            Unit::Month => "mo",
            Unit::Year => "y",
        }
    }

    /// Roughly how many minutes one unit lasts, to refuse a period longer than a year.
    fn minutes(self) -> u64 {
        match self {
            Unit::Minute => 1,
            Unit::Hour => 60,
            Unit::Day => 1440,
            Unit::Week => 7 * 1440,
            Unit::Month => 31 * 1440,
            Unit::Year => 366 * 1440,
        }
    }
}

/// How often a budget starts again from zero: every `every` units, aligned to the calendar of `tz` (UTC when
/// `None`). Windows are counted from 1970-01-01 00:00 in that zone, so `per: day` starts at each local midnight,
/// `per: 3mo` at each quarter and `per: 6h` at 00:00, 06:00, 12:00 and 18:00.
///
/// A sliding period (`per: { sliding: 24h }`) never starts again: it counts what was spent in the `every` units
/// before now. It is kept in slots of 1/1,440 of the window (a minute for 24 hours), and a cost counts until its
/// slot is wholly older than the window, so never less than the window and at most a slot more.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Period {
    pub every: u32,
    pub unit: Unit,
    /// An IANA zone name such as `America/New_York`, interned: there are a few hundred and each is kept once.
    pub tz: Option<&'static str>,
    pub sliding: bool,
}

// The names of before periods had a unit and a zone, so every caller written against them still reads.
#[allow(non_upper_case_globals)]
impl Period {
    pub const Day: Period = Period {
        every: 1,
        unit: Unit::Day,
        tz: None,
        sliding: false,
    };
    pub const Month: Period = Period {
        every: 1,
        unit: Unit::Month,
        tz: None,
        sliding: false,
    };
    pub const Hour: Period = Period {
        every: 1,
        unit: Unit::Hour,
        tz: None,
        sliding: false,
    };
    /// What a session's counters are kept under: a session has no calendar, so its counter lasts as long as any
    /// counter may.
    // ponytail: a session still running at 00:00 UTC on 1 January starts its counters again. A period of its own
    // when a session outlives a year.
    pub const Session: Period = Period {
        every: 1,
        unit: Unit::Year,
        tz: None,
        sliding: false,
    };
}

/// Zone names already checked, each leaked once so a `Period` stays `Copy`. Bounded by the zone database.
fn intern_tz(name: &str) -> &'static str {
    static NAMES: std::sync::Mutex<Vec<&'static str>> = std::sync::Mutex::new(Vec::new());
    let mut names = match NAMES.lock() {
        Ok(names) => names,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(known) = names.iter().find(|n| **n == name) {
        return known;
    }
    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    names.push(leaked);
    leaked
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The civil date of a day counted from 1970-01-01.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

/// `2026-11-14T13:59` for a count of minutes since the epoch, UTC.
fn minute_label(minutes: i64) -> String {
    let (y, m, d) = civil_from_days(minutes.div_euclid(1440));
    let (h, mi) = (minutes.rem_euclid(1440) / 60, minutes.rem_euclid(60));
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}")
}

/// Seconds since the epoch of a record timestamp, `2026-11-13T09:14:02.120Z`. None for another shape.
pub fn unix_seconds(time: &str) -> Option<i64> {
    let num = |r: std::ops::Range<usize>| time.get(r)?.parse::<i64>().ok();
    let days = days_from_civil(num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (
        num(11..13).unwrap_or(0),
        num(14..16).unwrap_or(0),
        num(17..19).unwrap_or(0),
    );
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

impl Period {
    /// Reads `per` (`day`, `week`, `month`, `year`, `hour`, `minute`, or a count of units such as `6h`, `15min`,
    /// `7d`, `2w`, `3mo`) and `tz` (an IANA name, or none for UTC). The message names the fix. `sliding 24h` (or
    /// `sliding:24h`, as [`Period::word`] writes it) is a sliding window of minutes, hours, days or weeks.
    pub fn parse(per: &str, tz: Option<&str>) -> Result<Period, String> {
        if let Some(length) = per.strip_prefix("sliding") {
            let length = length.trim_start_matches([':', ' ']);
            let fixed = || {
                format!(
                    "per is \"{per}\". A sliding window is a fixed length of minutes, hours, days or weeks: write per: {{ sliding: 24h }}, {{ sliding: 30d }} or {{ sliding: 90min }}. Months and years have no fixed length; for those use a calendar period such as per: month."
                )
            };
            let period = Period::parse(length, None).map_err(|_| fixed())?;
            if matches!(period.unit, Unit::Month | Unit::Year) {
                return Err(fixed());
            }
            if tz.is_some_and(|tz| tz != "UTC") {
                return Err(format!(
                    "per is \"{per}\" with a tz. A sliding window counts back from now and has no calendar, so a time zone changes nothing: remove tz."
                ));
            }
            return Ok(Period {
                sliding: true,
                ..period
            });
        }
        let unit_of = |word: &str| match word {
            "minute" | "min" => Some(Unit::Minute),
            "hour" | "h" => Some(Unit::Hour),
            "day" | "d" => Some(Unit::Day),
            "week" | "w" => Some(Unit::Week),
            "month" | "mo" => Some(Unit::Month),
            "year" | "y" => Some(Unit::Year),
            _ => None,
        };
        let digits = per.bytes().take_while(u8::is_ascii_digit).count();
        let (count, word) = per.split_at(digits);
        let every = if count.is_empty() {
            Some(1)
        } else {
            count.parse::<u32>().ok().filter(|n| *n >= 1)
        };
        let shape = || {
            format!(
                "per is \"{per}\". A budget starts again each minute, hour, day, week, month or year, or every so many of them: write per: day, per: month, or a count such as per: 6h, 15min, 7d, 2w or 3mo."
            )
        };
        let (Some(every), Some(unit)) = (every, unit_of(word)) else {
            return Err(shape());
        };
        if u64::from(every) * unit.minutes() > Unit::Year.minutes() {
            return Err(format!(
                "per is \"{per}\", longer than a year. A budget starts again at least once a year: write per: year or a shorter period."
            ));
        }
        let tz = match tz {
            None | Some("UTC") => None,
            Some(name) => match jiff::tz::TimeZone::get(name) {
                Ok(_) => Some(intern_tz(name)),
                Err(_) => {
                    return Err(format!(
                        "tz is \"{name}\", which is not a time zone Enterplace knows. Write an IANA name such as America/New_York, Europe/Berlin or Asia/Jerusalem, or leave tz out for UTC."
                    ));
                }
            },
        };
        Ok(Period {
            every,
            unit,
            tz,
            sliding: false,
        })
    }

    /// The name counters keep the period under. `day` and `month` in UTC keep the names of before.
    pub fn word(self) -> String {
        if self.sliding {
            return format!("sliding:{}{}", self.every, self.unit.short());
        }
        let base = if self.every == 1 {
            self.unit.name().to_string()
        } else {
            format!("{}{}", self.every, self.unit.short())
        };
        match self.tz {
            None => base,
            Some(tz) => format!("{base}@{tz}"),
        }
    }

    /// Reads back what [`Period::word`] wrote. None for a word no version of Enterplace writes.
    pub fn from_word(word: &str) -> Option<Period> {
        let (per, tz) = match word.split_once('@') {
            Some((per, tz)) => (per, Some(tz)),
            None => (word, None),
        };
        Period::parse(per, tz).ok()
    }

    /// The period as a person reads it after "this": `day`, `6 hours`, `month (America/New_York)`.
    pub fn describe(self) -> String {
        let base = if self.every == 1 {
            self.unit.name().to_string()
        } else {
            format!("{} {}s", self.every, self.unit.name())
        };
        if self.sliding {
            return format!("{base}, sliding");
        }
        match self.tz {
            None => base,
            Some(tz) => format!("{base} ({tz})"),
        }
    }

    /// Seconds to add to a UTC time to read the clock in the period's zone at that instant.
    fn offset(self, unix: i64) -> i64 {
        let Some(name) = self.tz else {
            return 0;
        };
        match (
            jiff::tz::TimeZone::get(name),
            jiff::Timestamp::from_second(unix),
        ) {
            (Ok(tz), Ok(at)) => i64::from(tz.to_offset(at).seconds()),
            // The name was checked when the policy loaded: the bundled database cannot lose it.
            _ => 0,
        }
    }

    /// The window `time` (a record timestamp) falls in, named by when it starts on the zone's clock: `2026-11`,
    /// `2026-11-13`, `2026-11-13T09`, `2026-11-13T09:15`, `2026`. Names of one period sort in time order.
    pub fn label(self, time: &str) -> String {
        if self.sliding {
            let slot = self.slot_minutes();
            let start = (unix_seconds(time).unwrap_or(0).div_euclid(60)).div_euclid(slot) * slot;
            return minute_label(start);
        }
        // The common case, and the hot path's: one day or one month in UTC is the start of the timestamp itself.
        if self.tz.is_none() && self.every == 1 {
            match self.unit {
                Unit::Day => return time.get(..10).unwrap_or(time).to_string(),
                Unit::Month => return time.get(..7).unwrap_or(time).to_string(),
                _ => {}
            }
        }
        let unix = unix_seconds(time).unwrap_or(0);
        let local = unix + self.offset(unix);
        let every = i64::from(self.every);
        let days = local.div_euclid(86_400);
        let minutes = local.div_euclid(60);
        match self.unit {
            Unit::Minute | Unit::Hour => {
                let size = if self.unit == Unit::Hour { 60 } else { 1 } * every;
                let start = minutes.div_euclid(size) * size;
                let (y, m, d) = civil_from_days(start.div_euclid(1440));
                let (h, mi) = (start.rem_euclid(1440) / 60, start.rem_euclid(60));
                if self.unit == Unit::Hour {
                    format!("{y:04}-{m:02}-{d:02}T{h:02}")
                } else {
                    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}")
                }
            }
            Unit::Day | Unit::Week => {
                // Weeks start on Monday: 1969-12-29 was one.
                let (size, from) = if self.unit == Unit::Week {
                    (7 * every, -3)
                } else {
                    (every, 0)
                };
                let start = (days - from).div_euclid(size) * size + from;
                let (y, m, d) = civil_from_days(start);
                format!("{y:04}-{m:02}-{d:02}")
            }
            Unit::Month | Unit::Year => {
                let (y, m, _) = civil_from_days(days);
                let months = if self.unit == Unit::Year { 12 } else { 1 } * every;
                let start = ((y - 1970) * 12 + m - 1).div_euclid(months) * months;
                if self.unit == Unit::Year {
                    format!("{:04}", 1970 + start.div_euclid(12))
                } else {
                    format!(
                        "{:04}-{:02}",
                        1970 + start.div_euclid(12),
                        start.rem_euclid(12) + 1
                    )
                }
            }
        }
    }

    /// The window the instant `unix` (seconds since the epoch) falls in, as UTC seconds: when it started and when
    /// it resets. What a forecast measures a budget's spend and pace over.
    pub fn window(self, unix: i64) -> (i64, i64) {
        if self.sliding {
            return (unix - self.minutes() * 60, unix);
        }
        let time = crate::audit::rfc3339(
            std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(u64::try_from(unix).unwrap_or(0)),
        );
        let label = self.label(&time);
        let clock = |text: &str| {
            let num = |r: std::ops::Range<usize>, default: i64| {
                text.get(r)
                    .and_then(|t| t.parse::<i64>().ok())
                    .unwrap_or(default)
            };
            days_from_civil(num(0..4, 1970), num(5..7, 1), num(8..10, 1)) * 86_400
                + num(11..13, 0) * 3600
                + num(14..16, 0) * 60
        };
        (
            self.utc(clock(&label)),
            self.utc(clock(&self.resets(&label))),
        )
    }

    /// The UTC instant a time on the zone's clock names. The offset is the one in force there; at a clock change it
    /// is taken from the instant just before.
    fn utc(self, local: i64) -> i64 {
        local - self.offset(local - self.offset(local))
    }

    /// The period's length in minutes (a month as 31 days, a year as 366).
    pub fn minutes(self) -> i64 {
        i64::from(self.every) * self.unit.minutes() as i64
    }

    /// A sliding window's slot: 1/1,440 of it, rounded up to whole minutes.
    fn slot_minutes(self) -> i64 {
        (self.minutes() + 1439).div_euclid(1440).max(1)
    }

    /// The first slot a sliding window ending in slot `label` counts: the one the instant a window before falls in.
    /// Every slot from it to `label` counts, both included, so a cost counts for at least the whole window.
    pub fn window_start_label(self, label: &str) -> String {
        let start = unix_seconds(label).unwrap_or(0).div_euclid(60) - self.minutes();
        let slot = self.slot_minutes();
        minute_label(start.div_euclid(slot) * slot)
    }

    /// When the window named `label` ends, on the zone's clock: `2026-12-01 00:00 UTC`. A sliding window does not
    /// end: what it says instead.
    pub fn resets(self, label: &str) -> String {
        if self.sliding {
            return format!(
                "no fixed time: each cost stops counting {} after it was made",
                self.describe().trim_end_matches(", sliding")
            );
        }
        let num = |r: std::ops::Range<usize>| label.get(r).and_then(|t| t.parse::<i64>().ok());
        let every = i64::from(self.every);
        let (y, m) = (num(0..4).unwrap_or(1970), num(5..7).unwrap_or(1));
        let start_days = days_from_civil(y, m, num(8..10).unwrap_or(1));
        let (days, minute) = match self.unit {
            Unit::Year => (days_from_civil(y + every, 1, 1), 0),
            Unit::Month => {
                let next = (y * 12 + m - 1) + every;
                (
                    days_from_civil(next.div_euclid(12), next.rem_euclid(12) + 1, 1),
                    0,
                )
            }
            Unit::Week => (start_days + 7 * every, 0),
            Unit::Day => (start_days + every, 0),
            Unit::Hour | Unit::Minute => {
                let size = if self.unit == Unit::Hour { 60 } else { 1 } * every;
                let start =
                    start_days * 1440 + num(11..13).unwrap_or(0) * 60 + num(14..16).unwrap_or(0);
                let end = start + size;
                (end.div_euclid(1440), end.rem_euclid(1440))
            }
        };
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02} {:02}:{:02} {}",
            minute / 60,
            minute % 60,
            self.tz.unwrap_or("UTC")
        )
    }
}

/// Most a rule's callers may spend in a period, in US dollars.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Budget {
    pub usd: f64,
    pub per: Period,
}

// The loader refuses a budget that is not a finite number, so equality is total.
impl Eq for Budget {}

/// A budget of a rule: counted for every model it reaches, or for the listed ones only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cap {
    pub budget: Budget,
    /// Empty counts every model. Otherwise only requests for these (by the name sent, an alias, or the model it
    /// is sent to) count, in a counter of their own.
    pub models: Vec<String>,
    /// The access profile it came from, when the rule took it from one.
    pub from: Option<String>,
    /// Until this UTC date or time the budget only records what it would refuse (`would_refuse`).
    pub shadow_until: Option<String>,
}

impl Cap {
    /// Whether a request for `sent`, sent to `model`, counts against this budget.
    pub fn counts(&self, sent: &str, model: &str) -> bool {
        self.models.is_empty() || self.models.iter().any(|m| m == sent || m == model)
    }
}

/// What a rule limits besides the models. The default limits nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// Counted per team for a team rule, and per person for a name rule or an `any` rule. Several may apply at
    /// once: a daily and a monthly one, or one for an expensive model only.
    pub budgets: Vec<Cap>,
    /// Most requests in flight at once, counted where the budget is.
    pub parallel: Option<u32>,
    /// The access profile each of rpm, tpm and parallel came from, when the rule took it from one.
    pub inherited: Vec<(&'static str, String)>,
    /// Requests per minute, per person.
    pub rpm: Option<u32>,
    /// Requests per calendar hour and per calendar day (UTC), per person.
    pub rph: Option<u32>,
    pub rpd: Option<u32>,
    /// `budget: { usd, per: session }`: the most one session may spend.
    pub session_budget: Option<Budget>,
    /// `rate: { session_requests }`: the most requests one session may send.
    pub session_requests: Option<u32>,
    /// `require.headers`: headers every request must carry, lower case.
    pub require_headers: Vec<String>,
    /// `require.body`: body fields every request must carry, as dotted paths (`metadata.ticket`).
    pub require_body: Vec<String>,
    /// Tokens per minute (prompt and answer), counted where the budget is: per team for a team rule, per person
    /// otherwise.
    pub tpm: Option<u32>,
    /// How long an answer is served again for the same request, in seconds.
    pub cache_ttl_seconds: Option<u64>,
    /// Whose requests share cached answers: one person's (the default) or one team's. Never wider.
    pub cache_scope: CacheScope,
    /// Serve a cached answer to a request that means the same, not only one identical byte for byte.
    pub semantic: Option<Semantic>,
    /// Mark the stable prefix of a messages request with cache breakpoints when the caller placed none.
    pub prompt_cache: bool,
    /// Hold a streamed answer whole so the answer guardrails check it before the caller sees any of it.
    pub buffer_stream: bool,
    /// Tell the caller what its tightest budget has left, in `x-enterplace-budget-remaining-usd` and
    /// `x-enterplace-budget-reset` on each answer.
    pub budget_headers: bool,
    /// Check a streamed answer every this many characters, letting through only what was checked.
    pub check_stream_every: Option<u32>,
    /// Whether a caller may send their own provider key in `x-enterplace-provider-key`.
    pub caller_provider_key: CallerKey,
    /// Most tokens (prompt and answer) per calendar day (UTC), counted where the budget is. Subscription traffic is
    /// not billed per call, so tokens are what a company limits it by.
    pub tpd: Option<u32>,
    /// `budget_basis: api_equivalent`: dollar budgets count subscription passthrough traffic at its estimated API
    /// price. Without it they do not count it: the subscription, not the request, is what is paid for.
    pub budget_api_equivalent: bool,
    /// Source addresses the rule's callers may send from. Empty allows any.
    pub from: Vec<Cidr>,
    /// Data residency: the regions an alias deployment must be labelled with. A request with no deployment in one
    /// is refused, never sent elsewhere. `None` sets no residency.
    pub regions: Option<Vec<String>>,
    /// Keep the redacted request and answer of each request this rule allows (`capture:`).
    pub capture: Option<Capture>,
    /// Days a file uploaded through Enterplace (a batch input, a fine-tuning set) is kept before it is deleted at the
    /// provider. None keeps the provider's default.
    pub file_retention_days: Option<u32>,
    /// The most lines one batch (a batch file or a message batch) may hold under this rule.
    pub batch_max_lines: Option<u32>,
    /// The most batches a person under this rule may have open (not yet ended) at once.
    pub batch_max_open: Option<u32>,
    /// The memory sizes (`1g`, `4g`, `16g`, `64g`) of the code interpreter containers the rule's callers may create.
    /// Empty allows none.
    pub containers: Vec<String>,
}

/// Whose requests share a rule's cached answers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CacheScope {
    #[default]
    Person,
    /// A person without a team keeps a scope of their own: an empty team is not a team.
    Team,
}

impl CacheScope {
    pub fn word(self) -> &'static str {
        match self {
            CacheScope::Person => "person",
            CacheScope::Team => "team",
        }
    }
}

/// The semantic cache of a rule: requests are compared by the embeddings of their text, made by `model` through
/// Enterplace's own embeddings route, and an answer is served again above `threshold` (cosine similarity).
#[derive(Clone, Debug, PartialEq)]
pub struct Semantic {
    pub model: String,
    pub threshold: f64,
}

// The loader refuses a threshold that is not a finite number, so equality is total.
impl Eq for Semantic {}

impl Limits {
    /// The first budget that counts every model: what a page with room for one shows.
    pub fn budget(&self) -> Option<Budget> {
        self.budgets
            .iter()
            .find(|c| c.models.is_empty())
            .map(|c| c.budget)
    }
}

/// What a rule's `capture:` keeps, for how long, and for whom.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capture {
    pub days: u32,
    /// A name, `team:<team>` or `role:<console role>`.
    pub viewers: Vec<String>,
}

/// What a rule does with a provider key the caller sends in `x-enterplace-provider-key`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CallerKey {
    /// The request is refused: never forwarded with the caller's key and never with Enterplace's in its place.
    #[default]
    Refused,
    /// The caller's key is sent in place of Enterplace's. Its spend is recorded as caller-paid and not counted against
    /// budgets, which limit what the organization pays: rate and token limits still hold.
    Allowed,
    /// As `Allowed`, and its spend counts against budgets as any other.
    AllowedBudgeted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    /// Line of the rule in the policy file, 0 when the policy was not read from a file.
    pub line: usize,
    pub who: Who,
    pub models: Models,
    /// Run in this order on every request the rule allows, before it is recorded and sent.
    pub guardrails: Vec<Guardrail>,
    pub limits: Limits,
    /// Native provider paths the rule may reach through `/passthrough/<provider>/...`. Empty reaches none.
    pub passthrough: Vec<Passthrough>,
    /// MCP tools the rule allows, as `<server>.<tool>`, `<server>.*` or `*`. Empty allows none.
    pub tools: Vec<String>,
    /// `tool_action: strip`: a function tool `tools:` does not allow is taken out of the request or answer, not refused.
    pub tool_strip: bool,
    /// MCP prompts, resources and tools that need an admin's approval.
    pub mcp: crate::mcp::McpRule,
    /// The organization whose callers the rule applies to. `None` applies to callers of every organization.
    pub org: Option<String>,
    /// The access profiles the rule includes, in order, already merged into its models, guardrails and limits.
    pub profiles: Vec<String>,
    /// Tags a caller may send in `x-enterplace-tags`. `*` allows any. An unlisted tag is refused by name.
    pub tags: Vec<String>,
    /// End customers a caller may name in `x-enterplace-customer`. `*` allows any. Empty allows none.
    pub customers: Vec<String>,
    /// The applications its callers run as. One alone is every request's; of several, or with `*`, the caller names
    /// its own in `x-enterplace-application`. Sent to events plugins with its stated purpose.
    pub applications: Vec<crate::events::Application>,
    /// What the rule set over a profile it includes, for the explanation: `rate.tpm 100000 of profile "standard"`.
    pub overrides: Vec<String>,
    /// Until this UTC date or time what the rule would refuse (its models, rate, tpm, parallel, regions and budgets)
    /// is recorded as `would_refuse` and forwarded.
    pub shadow_until: Option<String>,
}

/// One provider and the path prefixes of its own API a rule may reach as sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Passthrough {
    pub provider: String,
    pub paths: Vec<String>,
}

impl Rule {
    /// Whether the rule lets a request reach `path` at `provider`. A prefix matches whole path segments, so
    /// `/v1/batches` reaches `/v1/batches/b1` and not `/v1/batchesX`.
    pub fn reaches(&self, provider: &str, path: &str) -> bool {
        self.passthrough
            .iter()
            .filter(|p| p.provider == provider)
            .any(|p| {
                p.paths.iter().any(|prefix| {
                    path.strip_prefix(prefix.as_str())
                        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
                })
            })
    }

    fn applies_to(&self, principal: &Principal) -> bool {
        self.org.as_ref().is_none_or(|org| *org == principal.org)
            && match &self.who {
                Who::Any => true,
                Who::Team(team) => *team == principal.team,
                Who::Name(name) => *name == principal.name,
                Who::Tag(tag) => principal.tags.contains(tag),
            }
    }

    /// Who the rule names, as a person reads it.
    pub fn names(&self) -> String {
        let who = match &self.who {
            Who::Any => "every caller".to_string(),
            Who::Team(team) => format!("team \"{team}\""),
            Who::Name(name) => format!("\"{name}\""),
            Who::Tag(tag) => format!("keys tagged \"{tag}\""),
        };
        match &self.org {
            Some(org) => format!("{who} of organization \"{org}\""),
            None => who,
        }
    }

    /// The rule as an explanation names it: `rule "payments-team" (line 12)`.
    pub fn label(&self) -> String {
        if self.line > 0 {
            format!("rule \"{}\" (line {})", self.name, self.line)
        } else {
            format!("rule \"{}\"", self.name)
        }
    }

    pub fn allows(&self, model: &str) -> bool {
        match &self.models {
            Models::Any => true,
            // `gpt-*` lets a rule allow a provider's new models without an edit.
            Models::Only(models) => models
                .iter()
                .any(|allowed| crate::config::model_matches(allowed, model)),
        }
    }
}

impl Rule {
    /// Whether a caller under this rule may send `tag` in `x-enterplace-tags`.
    pub fn accepts_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == "*" || t == tag)
    }

    /// The application of a request under this rule, from what the caller names in `x-enterplace-application` and
    /// states in `x-enterplace-application-intent`. A name the rule lists takes the policy's intent over the caller's;
    /// `*` takes any name with the caller's intent; one listed application needs no header. `Err` names an
    /// application the rule does not list.
    pub fn application(
        &self,
        named: Option<&str>,
        intent: Option<&str>,
    ) -> Result<Option<crate::events::Application>, String> {
        let Some(named) = named else {
            return Ok(match self.applications.as_slice() {
                [only] if only.name != "*" => Some(only.clone()),
                _ => None,
            });
        };
        if let Some(listed) = self.applications.iter().find(|a| a.name == named) {
            return Ok(Some(crate::events::Application {
                name: listed.name.clone(),
                intent: listed.intent.clone().or_else(|| intent.map(str::to_string)),
            }));
        }
        if self.applications.iter().any(|a| a.name == "*") {
            return Ok(Some(crate::events::Application {
                name: named.to_string(),
                intent: intent.map(str::to_string),
            }));
        }
        Err(named.to_string())
    }

    /// Whether a caller under this rule may name `customer` in `x-enterplace-customer`.
    pub fn accepts_customer(&self, customer: &str) -> bool {
        self.customers.iter().any(|c| c == "*" || c == customer)
    }
}

/// What a `limits:` entry is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScopeKind {
    /// Everything the install sends, together.
    Global,
    Org,
    Team,
    Person,
    Key,
    /// An end customer of the company's product, named by a key or a header.
    Customer,
    Tag,
    Model,
    /// A named group of models from `model_groups:`.
    ModelGroup,
}

impl ScopeKind {
    pub fn word(self) -> &'static str {
        match self {
            ScopeKind::Global => "global",
            ScopeKind::Org => "org",
            ScopeKind::Team => "team",
            ScopeKind::Person => "person",
            ScopeKind::Key => "key",
            ScopeKind::Customer => "customer",
            ScopeKind::Tag => "tag",
            ScopeKind::Model => "model",
            ScopeKind::ModelGroup => "model_group",
        }
    }
}

/// One entry of the policy's `limits:` list: the limits of one scope, or of each scope of a kind (`*`), within one
/// organization or all of them. A request counts against every kind at once; within a kind, each limit comes from
/// the most specific entry that sets it, and the entries it overrides are named in the explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeLimit {
    pub kind: ScopeKind,
    /// The team, person, key prefix, customer, tag, model or organization, or `*` for each one. Empty for global.
    pub name: String,
    /// Confines an entry of another kind to one organization.
    pub org: Option<String>,
    pub line: usize,
    pub budgets: Vec<Budget>,
    pub rpm: Option<u32>,
    /// Requests per calendar hour and per calendar day (UTC).
    pub rph: Option<u32>,
    pub rpd: Option<u32>,
    pub tpm: Option<u32>,
    /// Tokens per calendar day (UTC).
    pub tpd: Option<u32>,
    pub parallel: Option<u32>,
    /// Until this UTC date or time the entry's limits only record what they would refuse (`would_refuse`).
    pub shadow_until: Option<String>,
}

impl ScopeLimit {
    /// The entry as an explanation names it: `limits { team: *, org: acme } (line 40)`.
    pub fn label(&self) -> String {
        let what = match (self.kind, &self.org) {
            (ScopeKind::Global, _) => "global: true".to_string(),
            (kind, Some(org)) => format!("{}: {}, org: {org}", kind.word(), self.name),
            (kind, None) => format!("{}: {}", kind.word(), self.name),
        };
        if self.line > 0 {
            format!("limits {{ {what} }} (line {})", self.line)
        } else {
            format!("limits {{ {what} }}")
        }
    }
}

/// One limit that applies to a request, where it came from and what it overrode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    Budget(Budget),
    Rpm(u32),
    Tpm(u32),
    Parallel(u32),
    /// Most requests in a period: an hour (`rph`), a day (`rpd`) or a session (`session_requests`).
    Requests(u32, Period),
    /// Most tokens (prompt and answer) per calendar day (`tpd`).
    Tpd(u32),
}

impl Limit {
    pub fn word(&self) -> &'static str {
        match self {
            Limit::Budget(_) => "budget",
            Limit::Rpm(_) => "rpm",
            Limit::Tpm(_) => "tpm",
            Limit::Tpd(_) => "tpd",
            Limit::Parallel(_) => "parallel",
            Limit::Requests(_, per) if *per == Period::Hour => "rph",
            Limit::Requests(_, per) if *per == Period::Day => "rpd",
            Limit::Requests(..) => "session_requests",
        }
    }
}

/// What a role's holders may grant when they issue a key, and what a key from `enterplace login` may hold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyBounds {
    /// The longest a key may work, in days. A key issued without `expires` gets this many.
    pub max_days: Option<u32>,
    /// The most a key may spend: its budget may not spend faster. A key issued without a budget gets this one.
    pub max_budget: Option<Budget>,
    /// The models a key may be given (patterns as in a rule's `models:`). Empty bounds none. A key issued without
    /// `models` gets this list.
    pub models: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The kind of scope: `rule`, `key`, or a [`ScopeKind`] word.
    pub of: &'static str,
    /// The counter it is kept in: `team:payments`, `customer:acme/globex`, `global`.
    pub scope: String,
    /// The scope as a refusal names it: `team "payments"`, `customer "globex"`.
    pub whose: String,
    pub limit: Limit,
    /// Where it is written: `rule "payments-team" (line 12)`, `limits { customer: * } (line 40)`.
    pub source: String,
    /// The entries of the same kind that set this limit too, less specific, and so did not apply.
    pub overrides: Vec<String>,
    /// Set when the limit records what it would refuse and refuses nothing: `observe` for the policy's mode,
    /// `shadow_until` for its own shadow period.
    pub shadow: Option<&'static str>,
}

/// What of a request picks the limits it counts against, besides its key and rule.
#[derive(Clone, Copy, Debug, Default)]
pub struct Context<'a> {
    /// The model name the caller sent, an alias's included.
    pub sent: &'a str,
    /// The model it is sent to: the alias's deployment, or `sent`.
    pub model: &'a str,
    pub customer: Option<&'a str>,
    pub tags: &'a [String],
}

/// A permission a console role may grant. The admin API checks the same ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Permission {
    /// See keys and who holds them.
    SeeKeys,
    IssueKeys,
    RevokeKeys,
    /// Turn kill switches on and off.
    Kill,
    /// Add, rotate and remove provider credentials.
    Credentials,
    /// Change the policy.
    EditPolicy,
    /// See spend, budgets and the explanation of a caller's limits.
    SeeSpend,
    /// See the audit log's records.
    SeeRecords,
    /// See captured request and answer bodies.
    SeeBodies,
}

impl Permission {
    pub const ALL: [Permission; 9] = [
        Permission::SeeKeys,
        Permission::IssueKeys,
        Permission::RevokeKeys,
        Permission::Kill,
        Permission::Credentials,
        Permission::EditPolicy,
        Permission::SeeSpend,
        Permission::SeeRecords,
        Permission::SeeBodies,
    ];

    pub fn word(self) -> &'static str {
        match self {
            Permission::SeeKeys => "see_keys",
            Permission::IssueKeys => "issue_keys",
            Permission::RevokeKeys => "revoke_keys",
            Permission::Kill => "kill",
            Permission::Credentials => "credentials",
            Permission::EditPolicy => "edit_policy",
            Permission::SeeSpend => "see_spend",
            Permission::SeeRecords => "see_records",
            Permission::SeeBodies => "see_bodies",
        }
    }

    pub fn from_word(word: &str) -> Option<Permission> {
        Permission::ALL.into_iter().find(|p| p.word() == word)
    }
}

/// A console role: what its holders may do, and within which organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
    /// Confines its holders to one organization's keys, records and spend.
    pub org: Option<String>,
    /// Confines its holders to these teams' keys, records and spend. Empty: every team.
    pub teams: Vec<String>,
    /// Confines its holders to these end customers' keys, records and spend. Empty: every customer.
    pub customers: Vec<String>,
    /// Values of the identity provider's role claim that sign a person in with this role.
    pub sso_values: Vec<String>,
    pub line: usize,
}

impl Role {
    pub fn may(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Whether its holders are kept to part of the install: an organization, teams or customers.
    pub fn confined(&self) -> bool {
        self.org.is_some() || !self.teams.is_empty() || !self.customers.is_empty()
    }

    /// Whether a key of this organization, team and end customer is within the role's reach.
    pub fn covers(&self, org: &str, team: &str, customer: Option<&str>) -> bool {
        self.org.as_ref().is_none_or(|o| o == org)
            && (self.teams.is_empty() || self.teams.iter().any(|t| t == team))
            && (self.customers.is_empty()
                || customer.is_some_and(|c| self.customers.iter().any(|x| x == c)))
    }
}

/// A team as the policy's `teams:` names it: who owns it, who is in it, and the identity provider groups that put a
/// person in it when they sign in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Team {
    pub name: String,
    /// Lower case email of the person answerable for it.
    pub owner: Option<String>,
    /// Lower case emails.
    pub members: Vec<String>,
    /// Values of the identity provider's role claim (or SAML role attribute) that put a person in this team.
    pub sso_values: Vec<String>,
    /// The admin's own notes, as a key's `metadata`.
    pub metadata: BTreeMap<String, String>,
    pub line: usize,
}

/// The team a person signing in belongs to: the first that lists their email, else the first whose `sso_values`
/// holds one of the identity provider's values for them.
pub fn team_of<'a>(teams: &'a [Team], email: &str, values: &[&str]) -> Option<&'a Team> {
    teams
        .iter()
        .find(|t| t.members.iter().any(|m| m == email))
        .or_else(|| {
            teams
                .iter()
                .find(|t| t.sso_values.iter().any(|s| values.contains(&s.as_str())))
        })
}

/// The roles every install has: `admin` may do everything, `read_only` may look at keys, spend and records.
pub fn builtin_role(name: &str) -> Option<Role> {
    let permissions = match name {
        "admin" => Permission::ALL.to_vec(),
        "read_only" => vec![
            Permission::SeeKeys,
            Permission::SeeSpend,
            Permission::SeeRecords,
        ],
        _ => return None,
    };
    Some(Role {
        name: name.to_string(),
        permissions,
        org: None,
        teams: Vec::new(),
        customers: Vec::new(),
        sso_values: Vec::new(),
        line: 0,
    })
}

/// The outcome of checking one request from a known caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision<'a> {
    Allow(&'a Rule),
    /// No rule names this caller. Anything not explicitly allowed is refused.
    NoRule,
    /// The first rule that names this caller does not allow this model.
    ModelNotAllowed(&'a Rule),
    /// The rule allows this model and the caller's key, which lists its own models, does not.
    KeyModelNotAllowed(&'a Rule),
}

/// Keys and rules.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    // Keyed by the SHA-256 of the key: the key itself is never held, and a lookup by hash
    // does not compare secret bytes one at a time.
    keys: HashMap<[u8; 32], Principal>,
    rules: Vec<Rule>,
    /// Prices the policy file sets, over the built-in ones.
    prices: PriceOverrides,
    /// Virtual MCP servers, served at `/mcp/<name>`.
    bundles: Vec<crate::mcp::Bundle>,
    /// The `limits:` list, in file order.
    limits: Vec<ScopeLimit>,
    /// The roles the policy defines beside the built-in ones.
    roles: Vec<Role>,
    /// The organizations `orgs:` lists.
    orgs: Vec<String>,
    /// The `teams:` list.
    teams: Vec<Team>,
    /// Identity providers whose JWTs stand in for an Enterplace key.
    jwt: Vec<JwtTrust>,
    /// Proxies whose `X-Forwarded-For` names the client. A request from anywhere else is taken by its own address.
    trusted_proxies: Vec<Cidr>,
    /// `identity_headers:`: the headers an authenticating proxy names the caller in.
    identity_headers: Option<IdentityHeaders>,
    /// `cors:`: the browser origins that may call the gateway's routes. None, the default, answers no origin.
    cors: Option<Cors>,
    mode: Mode,
    /// Every guardrail the policy's `guardrails:` defines, for the ones a key adds by name.
    guardrail_defs: Vec<Guardrail>,
    /// `model_groups:`: each group's name and the models (or patterns) in it.
    model_groups: Vec<(String, Vec<String>)>,
    /// `key_bounds:` by role name; the empty name is the one for every role without its own, and for `enterplace login`.
    key_bounds: Vec<(String, KeyBounds)>,
}

/// `identity_headers:` in the policy: the request headers (lower case) in which a proxy that authenticates people
/// (oauth2-proxy, an ingress with OIDC, Cloudflare Access behind a tunnel) names the caller. They are read only on
/// a connection from `trusted_proxies`; anyone else can write a header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityHeaders {
    /// The header that holds the person: their email or user name.
    pub user: String,
    /// The header that holds their groups, separated by commas, mapped by `sso_values` to roles and teams.
    pub groups: Option<String>,
    /// The team of a person whose groups put them in none.
    pub team: Option<String>,
}

/// `cors:` in the policy: pages served from these origins may call Enterplace from the browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cors {
    /// Lowercase `scheme://host[:port]`, or `*` for any origin.
    pub allowed_origins: Vec<String>,
}

impl Cors {
    /// What `Access-Control-Allow-Origin` says to a request from `origin`: the origin itself when it is listed,
    /// `*` when any origin is, nothing otherwise.
    pub fn allow<'a>(&self, origin: &'a str) -> Option<&'a str> {
        if self.allowed_origins.iter().any(|o| o == "*") {
            return Some("*");
        }
        self.allowed_origins
            .iter()
            .any(|o| o.eq_ignore_ascii_case(origin))
            .then_some(origin)
    }
}

/// Whether the policy refuses what it decides against (`enforce`, the default) or forwards it and records it as
/// `would_refuse` (`observe`). Observing never opens the gateway: a missing, bad or revoked key, an unknown model and
/// a kill switch are refused in both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Enforce,
    Observe,
}

/// Whether a shadow period that ends at `until` (a UTC date or time) is still running, read from the clock.
pub fn shadowing(until: Option<&str>) -> bool {
    until.is_some_and(|until| {
        !expiry_passed(until, &crate::audit::rfc3339(std::time::SystemTime::now()))
    })
}

/// Why a decision against a request is recorded and not enforced, if it is: `observe` or `shadow_until`.
fn shadow_by(observe: bool, until: Option<&str>) -> Option<&'static str> {
    if observe {
        Some("observe")
    } else if shadowing(until) {
        Some("shadow_until")
    } else {
        None
    }
}

/// The rule a caller no rule names is forwarded under in observe mode: every model, no limits.
pub static OBSERVED: std::sync::LazyLock<Rule> = std::sync::LazyLock::new(|| Rule {
    name: "(observe mode: no rule names this caller)".into(),
    line: 0,
    who: Who::Any,
    models: Models::Any,
    guardrails: Vec::new(),
    limits: Limits::default(),
    passthrough: Vec::new(),
    tools: Vec::new(),
    tool_strip: false,
    mcp: crate::mcp::McpRule::default(),
    org: None,
    profiles: Vec::new(),
    tags: Vec::new(),
    customers: Vec::new(),
    applications: Vec::new(),
    overrides: Vec::new(),
    shadow_until: None,
});

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Why a decision against a request is recorded as `would_refuse` and forwarded rather than refused: `observe`
    /// in observe mode, `shadow_until` while the feature's own shadow period runs. `None` enforces it.
    pub fn observing(&self, shadow_until: Option<&str>) -> Option<&'static str> {
        shadow_by(self.mode == Mode::Observe, shadow_until)
    }

    pub fn from_parts(keys: HashMap<[u8; 32], Principal>, rules: Vec<Rule>) -> Self {
        Self {
            keys,
            rules,
            ..Self::default()
        }
    }

    pub fn with_guardrail_defs(mut self, defs: Vec<Guardrail>) -> Self {
        self.guardrail_defs = defs;
        self
    }

    /// The guardrails a request of `who` under `rule` runs: the rule's, then each the key adds that the rule does
    /// not already run. Borrowed when the key adds none, so the common request clones nothing.
    pub fn guardrails_for<'a>(
        &self,
        who: &Principal,
        rule: &'a Rule,
    ) -> std::borrow::Cow<'a, [Guardrail]> {
        let added: Vec<Guardrail> = who
            .options
            .guardrails
            .iter()
            .filter(|name| !rule.guardrails.iter().any(|g| g.name == **name))
            .filter_map(|name| self.guardrail_defs.iter().find(|g| g.name == *name))
            .cloned()
            .collect();
        if added.is_empty() {
            return std::borrow::Cow::Borrowed(&rule.guardrails);
        }
        let mut all = rule.guardrails.clone();
        all.extend(added);
        std::borrow::Cow::Owned(all)
    }

    /// Whether the policy defines a guardrail of this name.
    pub fn defines_guardrail(&self, name: &str) -> bool {
        self.guardrail_defs.iter().any(|g| g.name == name)
    }

    pub fn with_model_groups(mut self, groups: Vec<(String, Vec<String>)>) -> Self {
        self.model_groups = groups;
        self
    }

    pub fn model_groups(&self) -> &[(String, Vec<String>)] {
        &self.model_groups
    }

    pub fn with_key_bounds(mut self, bounds: Vec<(String, KeyBounds)>) -> Self {
        self.key_bounds = bounds;
        self
    }

    /// What a holder of `role` may grant: the role's own bounds, else the policy's. `None` bounds nothing.
    pub fn key_bounds(&self, role: Option<&str>) -> Option<&KeyBounds> {
        let of = |name: &str| {
            self.key_bounds
                .iter()
                .find(|(r, _)| r == name)
                .map(|(_, b)| b)
        };
        role.and_then(of).or_else(|| of(""))
    }

    /// The limits a rule sets on one session, for a request in `session`: its budget and its request count.
    pub fn session_limits(&self, rule: &Rule, session: &str) -> Vec<Applied> {
        let shadow = shadow_by(self.mode == Mode::Observe, rule.shadow_until.as_deref());
        let limits = [
            rule.limits.session_budget.map(Limit::Budget),
            rule.limits
                .session_requests
                .map(|n| Limit::Requests(n, Period::Session)),
        ];
        limits
            .into_iter()
            .flatten()
            .map(|limit| Applied {
                of: "session",
                scope: format!("session:{session}"),
                whose: format!("session \"{session}\""),
                limit,
                source: rule.label(),
                overrides: Vec::new(),
                shadow,
            })
            .collect()
    }

    /// Sets the `limits:` list, for the loader and for embedders that build a policy in code.
    pub fn with_scope_limits(mut self, limits: Vec<ScopeLimit>) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_orgs(mut self, orgs: Vec<String>) -> Self {
        self.orgs = orgs;
        self
    }

    pub fn orgs(&self) -> &[String] {
        &self.orgs
    }

    pub fn with_teams(mut self, teams: Vec<Team>) -> Self {
        self.teams = teams;
        self
    }

    /// The `teams:` list. Teams named only by keys are not in it.
    pub fn teams(&self) -> &[Team] {
        &self.teams
    }

    pub fn with_roles(mut self, roles: Vec<Role>) -> Self {
        self.roles = roles;
        self
    }

    pub fn scope_limits(&self) -> &[ScopeLimit] {
        &self.limits
    }

    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    /// A role by name: one the policy defines, else a built-in one.
    pub fn role(&self, name: &str) -> Option<Role> {
        self.roles
            .iter()
            .find(|r| r.name == name)
            .cloned()
            .or_else(|| builtin_role(name))
    }

    /// The role a key signs in to the console and the admin API with: its `role:`, else `admin` for an admin key.
    /// A key whose org is set is confined to it, whatever its role says.
    pub fn role_of(&self, who: &Principal) -> Option<Role> {
        let mut role = match (&who.role, who.admin) {
            (Some(name), _) => self.role(name)?,
            (None, true) => builtin_role("admin")?,
            (None, false) => return None,
        };
        if !who.org.is_empty() {
            role.org = Some(who.org.clone());
        }
        Some(role)
    }

    pub fn with_mcp_bundles(mut self, bundles: Vec<crate::mcp::Bundle>) -> Self {
        self.bundles = bundles;
        self
    }

    /// The virtual MCP server served at `/mcp/<name>`, if the policy names one.
    pub fn mcp_bundle(&self, name: &str) -> Option<&crate::mcp::Bundle> {
        self.bundles.iter().find(|b| b.name == name)
    }

    pub fn with_jwt(mut self, jwt: Vec<JwtTrust>) -> Self {
        self.jwt = jwt;
        self
    }

    pub fn jwt(&self) -> &[JwtTrust] {
        &self.jwt
    }

    pub fn with_trusted_proxies(mut self, proxies: Vec<Cidr>) -> Self {
        self.trusted_proxies = proxies;
        self
    }

    pub fn with_identity_headers(mut self, headers: Option<IdentityHeaders>) -> Self {
        self.identity_headers = headers;
        self
    }

    pub fn identity_headers(&self) -> Option<&IdentityHeaders> {
        self.identity_headers.as_ref()
    }

    /// Whether `peer`, the address a connection came from, is one of `trusted_proxies`.
    pub fn trusted_proxy(&self, peer: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|c| c.contains(peer))
    }

    pub fn with_cors(mut self, cors: Option<Cors>) -> Self {
        self.cors = cors;
        self
    }

    pub fn cors(&self) -> Option<&Cors> {
        self.cors.as_ref()
    }

    /// The client's address: the connection's, or, from a trusted proxy, the last address in `X-Forwarded-For`
    /// that is not a trusted proxy itself. Anyone else can write that header, so it is not read for them.
    pub fn client_ip(&self, peer: IpAddr, forwarded_for: &[&str]) -> IpAddr {
        let trusted = |ip: IpAddr| self.trusted_proxies.iter().any(|c| c.contains(ip));
        if !trusted(peer) {
            return peer;
        }
        let mut client = peer;
        for hop in forwarded_for.iter().flat_map(|v| v.split(',')).rev() {
            let Ok(ip) = hop.trim().parse::<IpAddr>() else {
                // A hop that is not an address cannot be checked: stop at the last one that could.
                break;
            };
            client = ip;
            if !trusted(ip) {
                break;
            }
        }
        client
    }

    pub fn with_prices(mut self, prices: PriceOverrides) -> Self {
        self.prices = prices;
        self
    }

    pub fn prices(&self) -> &PriceOverrides {
        &self.prices
    }

    pub fn with_key(mut self, key: &str, name: impl Into<String>, team: impl Into<String>) -> Self {
        self.keys.insert(
            sha256(key.as_bytes()),
            Principal {
                name: name.into(),
                team: team.into(),
                admin: false,
                key: crate::id::sha256_hex(key.as_bytes())[..8].to_string(),
                ..Principal::default()
            },
        );
        self
    }

    /// Narrows the models of a key added before, for tests and embedders that build a policy in code.
    pub fn with_key_models(mut self, key: &str, models: &[&str]) -> Self {
        if let Some(who) = self.keys.get_mut(&sha256(key.as_bytes())) {
            who.models = Some(models.iter().map(|m| m.to_string()).collect());
        }
        self
    }

    pub fn with_rule(mut self, name: impl Into<String>, who: Who, models: Models) -> Self {
        self.rules.push(Rule {
            name: name.into(),
            line: 0,
            who,
            models,
            guardrails: Vec::new(),
            limits: Limits::default(),
            passthrough: Vec::new(),
            tools: Vec::new(),
            tool_strip: false,
            mcp: crate::mcp::McpRule::default(),
            org: None,
            profiles: Vec::new(),
            tags: Vec::new(),
            customers: Vec::new(),
            applications: Vec::new(),
            overrides: Vec::new(),
            shadow_until: None,
        });
        self
    }

    /// Changes the rule added last, for tests and embedders that build a policy in code.
    pub fn with_rule_change(mut self, change: impl FnOnce(&mut Rule)) -> Self {
        if let Some(rule) = self.rules.last_mut() {
            change(rule);
        }
        self
    }

    /// Changes the key added before, for tests and embedders that build a policy in code.
    pub fn with_key_change(mut self, key: &str, change: impl FnOnce(&mut Principal)) -> Self {
        if let Some(who) = self.keys.get_mut(&sha256(key.as_bytes())) {
            change(who);
        }
        self
    }

    /// Every rule runs these guardrails, for tests and benchmarks that build a policy in code.
    pub fn with_guardrails(mut self, guards: &[Guardrail]) -> Self {
        for rule in &mut self.rules {
            rule.guardrails = guards.to_vec();
        }
        self
    }

    /// Sets the limits of the rule added last, for tests and embedders that build a policy in code.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        if let Some(rule) = self.rules.last_mut() {
            rule.limits = limits;
        }
        self
    }

    /// A rule that lets one team use these models.
    pub fn with_models(
        self,
        team: impl Into<String>,
        models: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let team = team.into();
        let models = Models::Only(models.into_iter().map(Into::into).collect());
        self.with_rule(format!("{team}-team"), Who::Team(team), models)
    }

    pub fn keys(&self) -> usize {
        self.keys.len()
    }

    pub fn rules(&self) -> usize {
        self.rules.len()
    }

    /// The rules in file order, for showing them.
    pub fn rule_list(&self) -> &[Rule] {
        &self.rules
    }

    /// Every key's hash and who it belongs to, in no particular order.
    pub fn entries(&self) -> impl Iterator<Item = (&[u8; 32], &Principal)> {
        self.keys.iter()
    }

    /// Who this key was issued to, if anyone.
    pub fn identify(&self, key: &str) -> Option<&Principal> {
        self.keys.get(&sha256(key.as_bytes()))
    }

    /// Decides one request. Rules are read in file order and the first one that names the caller decides.
    /// The rule that decides for this caller: the first one that names them.
    pub fn rule_for(&self, principal: &Principal) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.applies_to(principal))
    }

    pub fn decide(&self, principal: &Principal, model: &str) -> Decision<'_> {
        match self.rules.iter().find(|rule| rule.applies_to(principal)) {
            None => Decision::NoRule,
            Some(rule) if !rule.allows(model) => Decision::ModelNotAllowed(rule),
            // A key's list narrows its rule: it never reaches a model the rule does not allow.
            Some(rule)
                if principal
                    .models
                    .as_ref()
                    .is_some_and(|m| !m.iter().any(|k| k == model)) =>
            {
                Decision::KeyModelNotAllowed(rule)
            }
            Some(rule) => Decision::Allow(rule),
        }
    }
}

/// Each limit one kind of scope sets for a request: per limit, the most specific entry that sets it.
/// `entries` are (rank, source, entry), lower rank more specific; file order breaks a tie.
fn resolve(
    of: &'static str,
    scope: &str,
    whose: &str,
    mut entries: Vec<(u8, String, &ScopeLimit)>,
    observe: bool,
    out: &mut Vec<Applied>,
) {
    if entries.is_empty() {
        return;
    }
    entries.sort_by_key(|(rank, _, _)| *rank);
    let mut fields: Vec<(Limit, &String)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let shadow_of = |source: &String| {
        let until = entries
            .iter()
            .find(|(_, s, _)| s == source)
            .and_then(|(_, _, e)| e.shadow_until.as_deref());
        shadow_by(observe, until)
    };
    for (_, source, entry) in &entries {
        for budget in &entry.budgets {
            fields.push((Limit::Budget(*budget), source));
        }
        for (limit, value) in [
            (Limit::Rpm as fn(u32) -> Limit, entry.rpm),
            (Limit::Tpm, entry.tpm),
            (Limit::Tpd, entry.tpd),
            (Limit::Parallel, entry.parallel),
        ] {
            if let Some(value) = value {
                fields.push((limit(value), source));
            }
        }
        for (per, value) in [(Period::Hour, entry.rph), (Period::Day, entry.rpd)] {
            if let Some(value) = value {
                fields.push((Limit::Requests(value, per), source));
            }
        }
    }
    // A field is a limit's kind, and for a budget its period: a daily budget does not override a monthly one.
    let field = |limit: &Limit| match limit {
        Limit::Budget(b) => format!("budget {}", b.per.word()),
        other => other.word().to_string(),
    };
    for (limit, source) in &fields {
        let name = field(limit);
        if seen.contains(&name) {
            continue;
        }
        seen.push(name.clone());
        let overrides = fields
            .iter()
            .filter(|(other, from)| field(other) == name && *from != *source)
            .map(|(_, from)| (*from).clone())
            .collect();
        out.push(Applied {
            of,
            scope: scope.to_string(),
            whose: whose.to_string(),
            limit: *limit,
            source: (*source).clone(),
            overrides,
            shadow: shadow_of(source),
        });
    }
}

impl Policy {
    /// Every limit a request from `who`, decided by `rule`, counts against: its rule's, its key's, and those of the
    /// `limits:` list for the global total, its organization, team, person, customer, each tag and its model.
    /// Allocates nothing for a policy with none.
    pub fn applied(&self, who: &Principal, rule: &Rule, ctx: Context<'_>) -> Vec<Applied> {
        let mut out = Vec::new();
        // The hot path of a policy with no limits at all: nothing to name, so nothing is formatted.
        let l = &rule.limits;
        if self.limits.is_empty()
            && l.budgets.is_empty()
            && l.rpm.is_none()
            && l.rph.is_none()
            && l.rpd.is_none()
            && l.tpm.is_none()
            && l.tpd.is_none()
            && l.parallel.is_none()
            && who.budget.is_none()
            && who.tpm.is_none()
            && who.parallel.is_none()
            && who.options.rpm.is_none()
        {
            return out;
        }
        let (base, whose) = match &rule.who {
            Who::Team(_) => (
                who.team_scope(),
                format!("team \"{}\"", who.within(&who.team)),
            ),
            _ => (who.person_scope(), format!("\"{}\"", who.within(&who.name))),
        };
        let observe = self.mode == Mode::Observe;
        let rule_shadow = shadow_by(observe, rule.shadow_until.as_deref());
        let under = rule.label();
        let from = |profile: Option<&String>| match profile {
            Some(profile) => format!("profile \"{profile}\" via {under}"),
            None => under.clone(),
        };
        for cap in &rule.limits.budgets {
            if !cap.counts(ctx.sent, ctx.model) {
                continue;
            }
            let scope = if cap.models.is_empty() {
                base.clone()
            } else {
                format!("{base} models:{}", cap.models.join(","))
            };
            out.push(Applied {
                of: "rule",
                scope,
                whose: whose.clone(),
                limit: Limit::Budget(cap.budget),
                source: from(cap.from.as_ref()),
                overrides: Vec::new(),
                shadow: rule_shadow.or_else(|| shadow_by(false, cap.shadow_until.as_deref())),
            });
        }
        let inherited = |field: &str| {
            rule.limits
                .inherited
                .iter()
                .find(|(f, _)| *f == field)
                .map(|(_, p)| p)
        };
        let person_whose = format!("\"{}\"", who.within(&who.name));
        for (limit, scope, whose, field) in [
            (
                rule.limits.rpm.map(Limit::Rpm),
                who.person_scope(),
                &person_whose,
                "rpm",
            ),
            (
                rule.limits.rph.map(|n| Limit::Requests(n, Period::Hour)),
                who.person_scope(),
                &person_whose,
                "rph",
            ),
            (
                rule.limits.rpd.map(|n| Limit::Requests(n, Period::Day)),
                who.person_scope(),
                &person_whose,
                "rpd",
            ),
            (rule.limits.tpm.map(Limit::Tpm), base.clone(), &whose, "tpm"),
            (rule.limits.tpd.map(Limit::Tpd), base.clone(), &whose, "tpd"),
            (
                rule.limits.parallel.map(Limit::Parallel),
                base.clone(),
                &whose,
                "parallel",
            ),
        ] {
            if let Some(limit) = limit {
                out.push(Applied {
                    of: "rule",
                    scope,
                    whose: whose.clone(),
                    limit,
                    source: from(inherited(field)),
                    overrides: Vec::new(),
                    shadow: rule_shadow,
                });
            }
        }
        // The key's own limits, from its entry in the keys file, are the most specific of the key kind.
        let own = ScopeLimit {
            kind: ScopeKind::Key,
            name: who.key.clone(),
            org: None,
            line: 0,
            budgets: who.budget.into_iter().collect(),
            rpm: who.options.rpm,
            rph: None,
            rpd: None,
            tpm: who.tpm,
            tpd: None,
            parallel: who.parallel,
            shadow_until: None,
        };
        let key_whose = format!("the key {} of \"{}\"", who.key, who.name);
        let mut keyed = Vec::new();
        if !own.budgets.is_empty()
            || own.rpm.is_some()
            || own.tpm.is_some()
            || own.parallel.is_some()
        {
            keyed.push((0, format!("key {} (keys file)", who.key), &own));
        }
        if self.limits.is_empty() {
            resolve(
                "key",
                &format!("key:{}", who.key),
                &key_whose,
                keyed,
                observe,
                &mut out,
            );
            return out;
        }
        // Rank within a kind: this name in this org, every name in this org, this name anywhere, every name anywhere.
        let rank = |entry: &ScopeLimit, name: &str| -> Option<u8> {
            let in_org = match &entry.org {
                None => false,
                Some(org) if *org == who.org => true,
                Some(_) => return None,
            };
            let exact = if entry.name == name {
                true
            } else if entry.name == "*" {
                false
            } else {
                return None;
            };
            Some(match (in_org, exact) {
                (true, true) => 1,
                (true, false) => 2,
                (false, true) => 3,
                (false, false) => 4,
            })
        };
        let of_kind = |kind: ScopeKind, names: &[&str]| -> Vec<(u8, String, &ScopeLimit)> {
            self.limits
                .iter()
                .filter(|e| e.kind == kind)
                .filter_map(|e| {
                    names
                        .iter()
                        .filter_map(|n| rank(e, n))
                        .min()
                        .map(|r| (r, e.label(), e))
                })
                .collect()
        };
        keyed.extend(of_kind(ScopeKind::Key, &[&who.key]));
        resolve(
            "key",
            &format!("key:{}", who.key),
            &key_whose,
            keyed,
            observe,
            &mut out,
        );
        let global: Vec<_> = self
            .limits
            .iter()
            .filter(|e| e.kind == ScopeKind::Global)
            .map(|e| (0, e.label(), e))
            .collect();
        resolve(
            "global",
            "global",
            "the whole install",
            global,
            observe,
            &mut out,
        );
        if !who.org.is_empty() {
            // An org entry's own name is its org: `{ org: acme }` alone, or `{ org: "*" }` for each.
            let orgs: Vec<_> = self
                .limits
                .iter()
                .filter(|e| e.kind == ScopeKind::Org)
                .filter_map(|e| match e.name.as_str() {
                    n if n == who.org => Some((0, e.label(), e)),
                    "*" => Some((1, e.label(), e)),
                    _ => None,
                })
                .collect();
            let whose = format!("organization \"{}\"", who.org);
            resolve(
                "org",
                &format!("org:{}", who.org),
                &whose,
                orgs,
                observe,
                &mut out,
            );
        }
        let team_whose = format!("team \"{}\"", who.within(&who.team));
        resolve(
            "team",
            &who.team_scope(),
            &team_whose,
            of_kind(ScopeKind::Team, &[&who.team]),
            observe,
            &mut out,
        );
        resolve(
            "person",
            &who.person_scope(),
            &person_whose,
            of_kind(ScopeKind::Person, &[&who.name]),
            observe,
            &mut out,
        );
        if let Some(customer) = ctx.customer {
            let scope = format!("customer:{}", who.within(customer));
            let whose = format!("customer \"{}\"", who.within(customer));
            resolve(
                "customer",
                &scope,
                &whose,
                of_kind(ScopeKind::Customer, &[customer]),
                observe,
                &mut out,
            );
        }
        for tag in ctx.tags {
            let scope = format!("tag:{}", who.within(tag));
            let whose = format!("tag \"{}\"", who.within(tag));
            resolve(
                "tag",
                &scope,
                &whose,
                of_kind(ScopeKind::Tag, &[tag]),
                observe,
                &mut out,
            );
        }
        // A model entry counts by the name it lists: the alias sent, or the model it is sent to.
        let mut models: Vec<&str> = vec![ctx.sent];
        if ctx.model != ctx.sent && !ctx.model.is_empty() {
            models.push(ctx.model);
        }
        for name in models {
            let entries: Vec<_> = of_kind(ScopeKind::Model, &[name])
                .into_iter()
                // `*` counts each model once, under the name sent.
                .filter(|(_, _, e)| e.name == name || (e.name == "*" && name == ctx.sent))
                .collect();
            let scope = format!("model:{}", who.within(name));
            let whose = format!("model \"{name}\"");
            resolve("model", &scope, &whose, entries, observe, &mut out);
        }
        // A group counts every model in it together, whichever of them the request names or is sent to.
        for (group, members) in &self.model_groups {
            let holds = |model: &str| {
                !model.is_empty()
                    && members
                        .iter()
                        .any(|m| crate::config::model_matches(m, model))
            };
            if !holds(ctx.sent) && !holds(ctx.model) {
                continue;
            }
            let scope = format!("model_group:{}", who.within(group));
            let whose = format!("model group \"{group}\"");
            resolve(
                "model_group",
                &scope,
                &whose,
                of_kind(ScopeKind::ModelGroup, &[group]),
                observe,
                &mut out,
            );
        }
        out
    }

    /// Why a request from `who` for `ctx.sent` would be allowed or refused, and every limit that would apply with
    /// where it is written and what it overrides. The admin API adds what each budget has spent.
    pub fn explain(&self, who: &Principal, ctx: Context<'_>) -> serde_json::Value {
        use serde_json::json;
        let mut skipped = Vec::new();
        for rule in &self.rules {
            if rule.applies_to(who) {
                break;
            }
            let why = match &rule.org {
                Some(org) if *org != who.org => format!("is for organization \"{org}\""),
                _ => format!("names {}", rule.names()),
            };
            skipped.push(json!({ "rule": rule.name, "line": rule.line, "why": why }));
        }
        let decision = self.decide(who, ctx.sent);
        let (verdict, rule) = match decision {
            Decision::Allow(rule) => ("allow", Some(rule)),
            Decision::NoRule => ("no_rule", None),
            Decision::ModelNotAllowed(rule) => ("model_not_allowed", Some(rule)),
            Decision::KeyModelNotAllowed(rule) => ("key_model_not_allowed", Some(rule)),
        };
        let mut problems = Vec::new();
        if let (Some(rule), Some(customer)) = (rule, ctx.customer) {
            if who.customer.as_deref().is_some_and(|c| c != customer) {
                problems.push(format!(
                    "the key is for customer \"{}\", and a header cannot name another",
                    who.customer.as_deref().unwrap_or_default()
                ));
            } else if who.customer.is_none() && !rule.accepts_customer(customer) {
                problems.push(format!(
                    "{} does not let a caller name customer \"{customer}\"",
                    rule.label()
                ));
            }
        }
        if let Some(rule) = rule {
            for tag in ctx.tags.iter().filter(|t| !who.tags.contains(t)) {
                if !rule.accepts_tag(tag) {
                    problems.push(format!(
                        "{} does not let a caller send tag \"{tag}\"",
                        rule.label()
                    ));
                }
            }
        }
        let limits: Vec<serde_json::Value> = rule
            .map(|rule| {
                let mut applied = self.applied(who, rule, ctx);
                // Each session has its own counters: shown once, for any session.
                applied.extend(self.session_limits(rule, "*"));
                applied
            })
            .unwrap_or_default()
            .iter()
            .map(applied_json)
            .collect();
        json!({
            "caller": {
                "name": who.name,
                "team": who.team,
                "org": (!who.org.is_empty()).then_some(&who.org),
                "key": who.key,
                "customer": ctx.customer,
                "tags": ctx.tags,
            },
            "model": ctx.sent,
            "verdict": if problems.is_empty() { verdict } else { "refused" },
            "problems": problems,
            "skipped": skipped,
            "rule": rule.map(|r| json!({
                "name": r.name,
                "line": r.line,
                "org": r.org,
                "profiles": r.profiles,
                "overrides": r.overrides,
            })),
            "limits": limits,
        })
    }
}

/// One applied limit as the explanation and refusal records show it.
pub fn applied_json(a: &Applied) -> serde_json::Value {
    let mut v = serde_json::json!({
        "of": a.of,
        "scope": a.scope,
        "limit": a.limit.word(),
        "source": a.source,
        "overrides": a.overrides,
    });
    if let Some(fields) = v.as_object_mut() {
        // Only when set, so explanations of enforced limits keep their shape.
        if let Some(by) = a.shadow {
            fields.insert("shadow".into(), by.into());
        }
        match a.limit {
            Limit::Budget(b) => {
                fields.insert("usd".into(), b.usd.into());
                let per = if a.of == "session" {
                    "session".to_string()
                } else {
                    b.per.word()
                };
                fields.insert("per".into(), per.into());
            }
            Limit::Rpm(n)
            | Limit::Tpm(n)
            | Limit::Tpd(n)
            | Limit::Parallel(n)
            | Limit::Requests(n, _) => {
                fields.insert("value".into(), n.into());
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::new()
            .with_key("key-maya", "maya.cohen", "payments")
            .with_key("key-omer", "omer.katz", "payments")
            .with_key("key-dana", "dana.levi", "interns")
            .with_rule(
                "maya-only",
                Who::Name("maya.cohen".into()),
                Models::Only(vec!["model-a".into()]),
            )
            .with_rule("payments-team", Who::Team("payments".into()), Models::Any)
    }

    fn decide<'a>(policy: &'a Policy, key: &str, model: &str) -> Option<Decision<'a>> {
        policy.identify(key).map(|who| policy.decide(who, model))
    }

    #[test]
    fn an_unknown_key_identifies_nobody() {
        assert_eq!(policy().identify("key-nobody"), None);
        assert_eq!(Policy::new().identify("anything"), None);
    }

    #[test]
    fn the_first_rule_that_names_the_caller_decides() {
        let policy = policy();
        assert!(matches!(
            decide(&policy, "key-maya", "model-a"),
            Some(Decision::Allow(rule)) if rule.name == "maya-only"
        ));
        // The team rule below would allow this, but the rule above it names maya first.
        assert!(matches!(
            decide(&policy, "key-maya", "model-b"),
            Some(Decision::ModelNotAllowed(rule)) if rule.name == "maya-only"
        ));
    }

    #[test]
    fn a_wildcard_allows_any_model_and_an_empty_list_allows_none() {
        let policy = policy();
        assert!(matches!(
            decide(&policy, "key-omer", "anything-at-all"),
            Some(Decision::Allow(_))
        ));
        let closed = Policy::new().with_key("k", "p", "t").with_rule(
            "everyone-else",
            Who::Any,
            Models::Only(vec![]),
        );
        assert!(matches!(
            decide(&closed, "k", "model-a"),
            Some(Decision::ModelNotAllowed(_))
        ));
    }

    #[test]
    fn a_key_expires_when_its_day_or_second_starts() {
        let mut who = policy().identify("key-maya").cloned().unwrap_or_default();
        assert!(!who.expired("2026-12-31T09:00:00.000Z"));
        who.expires = Some("2026-12-31".into());
        assert!(!who.expired("2026-12-30T23:59:59.999Z"));
        assert!(who.expired("2026-12-31T00:00:00.000Z"));
        who.expires = Some("2026-12-31T18:00:00Z".into());
        assert!(!who.expired("2026-12-31T17:59:59.999Z"));
        assert!(who.expired("2026-12-31T18:00:00.000Z"));
        assert!(who.expired("2027-01-01T00:00:00.000Z"));
    }

    #[test]
    fn a_key_model_list_narrows_its_rule_and_never_widens_it() {
        let mut policy = policy();
        let narrowed = Policy::new()
            .with_key("key-omer", "omer.katz", "payments")
            .with_rule(
                "payments-team",
                Who::Team("payments".into()),
                Models::Only(vec!["a".into(), "b".into()]),
            );
        policy = Policy {
            rules: narrowed.rules,
            ..policy
        };
        let Some(mut omer) = policy.identify("key-omer").cloned() else {
            panic!("omer is in the policy");
        };
        omer.models = Some(vec!["a".into(), "c".into()]);
        assert!(matches!(policy.decide(&omer, "a"), Decision::Allow(_)));
        assert!(matches!(
            policy.decide(&omer, "b"),
            Decision::KeyModelNotAllowed(_)
        ));
        // "c" is on the key and not on the rule: the rule still decides.
        assert!(matches!(
            policy.decide(&omer, "c"),
            Decision::ModelNotAllowed(_)
        ));
    }

    #[test]
    fn an_address_range_holds_what_it_says_and_nothing_else() -> Result<(), String> {
        let ip = |s: &str| s.parse::<IpAddr>().map_err(|e| e.to_string());
        let ten: Cidr = "10.0.0.0/8".parse()?;
        assert!(ten.contains(ip("10.200.3.4")?));
        assert!(!ten.contains(ip("11.0.0.1")?));
        assert!(
            ten.contains(ip("::ffff:10.1.2.3")?),
            "a mapped IPv4 address is IPv4"
        );
        let one: Cidr = "203.0.113.7".parse()?;
        assert!(one.contains(ip("203.0.113.7")?) && !one.contains(ip("203.0.113.8")?));
        assert_eq!(one.to_string(), "203.0.113.7/32");
        let any: Cidr = "0.0.0.0/0".parse()?;
        assert!(any.contains(ip("8.8.8.8")?) && !any.contains(ip("::1")?));
        let v6: Cidr = "2001:db8::/32".parse()?;
        assert!(v6.contains(ip("2001:db8:1::1")?) && !v6.contains(ip("2001:db9::1")?));
        for bad in ["10.0.0.0/33", "nope", "10.0.0/8", "::/129", ""] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
        Ok(())
    }

    #[test]
    fn forwarded_for_is_read_only_from_a_trusted_proxy() -> Result<(), String> {
        let ip = |s: &str| s.parse::<IpAddr>().map_err(|e| e.to_string());
        let policy = Policy::new().with_trusted_proxies(vec!["10.0.0.0/8".parse()?]);
        // From the load balancer: the last address it did not add is the client's.
        assert_eq!(
            policy.client_ip(ip("10.0.0.5")?, &["198.51.100.9, 10.0.0.7"]),
            ip("198.51.100.9")?
        );
        // A client cannot claim another address by writing the header itself: the proxy appends what it saw.
        assert_eq!(
            policy.client_ip(ip("10.0.0.5")?, &["1.2.3.4, 198.51.100.9"]),
            ip("198.51.100.9")?
        );
        // From anywhere else the header is ignored.
        assert_eq!(
            policy.client_ip(ip("198.51.100.9")?, &["10.1.1.1"]),
            ip("198.51.100.9")?
        );
        assert_eq!(
            Policy::new().client_ip(ip("10.0.0.5")?, &["1.2.3.4"]),
            ip("10.0.0.5")?
        );
        Ok(())
    }

    #[test]
    fn a_key_route_list_matches_whole_segments() {
        let options = KeyOptions {
            routes: vec!["/v1/chat".into(), "/v1/messages/".into()],
            ..KeyOptions::default()
        };
        assert!(options.reaches("/v1/chat/completions"));
        assert!(options.reaches("/v1/messages"));
        assert!(!options.reaches("/v1/chatx"));
        assert!(!options.reaches("/v1/embeddings"));
        assert!(KeyOptions::default().reaches("/anything"));
    }

    #[test]
    fn a_caller_no_rule_names_gets_nothing() {
        assert_eq!(
            decide(&policy(), "key-dana", "model-a"),
            Some(Decision::NoRule)
        );
    }

    #[test]
    fn periods_align_to_the_calendar_of_their_zone() -> Result<(), String> {
        let utc = |per: &str| Period::parse(per, None);
        let ny = |per: &str| Period::parse(per, Some("America/New_York"));
        let t = "2026-12-01T04:30:00.000Z";
        assert_eq!(utc("month")?.label(t), "2026-12");
        // Still 30 November, 23:30, in New York: the November window.
        assert_eq!(ny("month")?.label(t), "2026-11");
        assert_eq!(ny("month")?.label("2026-12-01T05:30:00.000Z"), "2026-12");
        assert_eq!(
            ny("month")?.resets("2026-11"),
            "2026-12-01 00:00 America/New_York"
        );
        // Daylight saving: midnight in New York is 05:00 UTC in winter and 04:00 UTC in summer.
        assert_eq!(ny("day")?.label("2026-07-01T03:59:00Z"), "2026-06-30");
        assert_eq!(ny("day")?.label("2026-07-01T04:00:00Z"), "2026-07-01");
        assert_eq!(utc("week")?.label("2026-11-14T10:00:00Z"), "2026-11-09");
        assert_eq!(utc("week")?.resets("2026-11-09"), "2026-11-16 00:00 UTC");
        assert_eq!(utc("6h")?.label("2026-11-14T13:59:00Z"), "2026-11-14T12");
        assert_eq!(utc("6h")?.resets("2026-11-14T12"), "2026-11-14 18:00 UTC");
        assert_eq!(
            utc("15min")?.label("2026-11-14T13:59:00Z"),
            "2026-11-14T13:45"
        );
        assert_eq!(
            utc("15min")?.resets("2026-11-14T23:45"),
            "2026-11-15 00:00 UTC"
        );
        assert_eq!(utc("3mo")?.label("2026-11-14T13:59:00Z"), "2026-10");
        assert_eq!(utc("3mo")?.resets("2026-10"), "2027-01-01 00:00 UTC");
        assert_eq!(utc("year")?.label("2026-11-14T13:59:00Z"), "2026");
        assert_eq!(utc("30d")?.resets("2026-10-29"), "2026-11-28 00:00 UTC");
        assert_eq!(utc("day")?.word(), "day");
        assert_eq!(ny("month")?.word(), "month@America/New_York");
        assert_eq!(
            Period::from_word("6h@Europe/Berlin"),
            Period::parse("6h", Some("Europe/Berlin")).ok()
        );
        assert_eq!(Period::from_word("month"), Some(Period::Month));
        for bad in ["fortnight", "0d", "13mo", "2y", "d6"] {
            assert!(utc(bad).is_err(), "{bad}");
        }
        assert!(Period::parse("day", Some("Mars/Olympus")).is_err());
        Ok(())
    }

    #[test]
    fn a_sliding_window_counts_back_from_now_in_slots_and_has_no_calendar() -> Result<(), String> {
        let at = |time: &str| unix_seconds(time).ok_or(format!("no time in {time}"));
        let day = Period::parse("sliding 24h", None)?;
        assert!(day.sliding);
        assert_eq!(day.word(), "sliding:24h");
        assert_eq!(Period::from_word("sliding:24h"), Some(day));
        assert_eq!(Period::parse("sliding: 1d", None)?.word(), "sliding:1d");
        assert_eq!(day.describe(), "24 hours, sliding");
        // A 24 hour window counts in minute slots: a cost leaves it within a minute of turning 24 hours old.
        assert_eq!(day.label("2026-11-14T13:59:42.120Z"), "2026-11-14T13:59");
        assert_eq!(
            day.window_start_label("2026-11-14T13:59"),
            "2026-11-13T13:59"
        );
        assert_eq!(
            day.window(at("2026-11-14T13:59:42Z")?),
            (at("2026-11-13T13:59:42Z")?, at("2026-11-14T13:59:42Z")?)
        );
        // A week counts in slots of 7 minutes, 1,440 of them, aligned to the epoch.
        let week = Period::parse("sliding 7d", None)?;
        assert_eq!(week.label("2026-11-14T13:59:42Z"), "2026-11-14T13:57");
        assert_eq!(
            week.window_start_label("2026-11-14T13:57"),
            "2026-11-07T13:57"
        );
        // No calendar: months and years have no fixed length, and a zone means nothing.
        for bad in [
            "sliding month",
            "sliding 3mo",
            "sliding y",
            "sliding",
            "sliding 0h",
            "sliding 2y",
        ] {
            assert!(Period::parse(bad, None).is_err(), "{bad}");
        }
        let zoned = Period::parse("sliding 24h", Some("Europe/Berlin"));
        assert!(zoned.is_err_and(|e| e.contains("tz")));
        // The calendar day it is not: the two never share a counter.
        assert_ne!(day.word(), Period::Day.word());
        Ok(())
    }

    #[test]
    fn a_window_is_the_period_the_instant_falls_in_in_utc_seconds() -> Result<(), String> {
        let at = |time: &str| unix_seconds(time).ok_or(format!("no time in {time}"));
        let now = at("2026-11-12T15:30:00Z")?; // a Thursday
        let window = |per: &str, tz: Option<&str>| Period::parse(per, tz).map(|p| p.window(now));
        assert_eq!(
            window("month", None)?,
            (at("2026-11-01T00:00:00Z")?, at("2026-12-01T00:00:00Z")?)
        );
        assert_eq!(
            window("week", None)?,
            (at("2026-11-09T00:00:00Z")?, at("2026-11-16T00:00:00Z")?),
            "weeks start on Monday"
        );
        assert_eq!(
            window("6h", None)?,
            (at("2026-11-12T12:00:00Z")?, at("2026-11-12T18:00:00Z")?)
        );
        // New York is UTC-5 in November: its day began at 05:00 UTC.
        assert_eq!(
            window("day", Some("America/New_York"))?,
            (at("2026-11-12T05:00:00Z")?, at("2026-11-13T05:00:00Z")?)
        );
        // A month in a zone that changed its clocks during it: Berlin's November began at UTC+1 and its October at
        // UTC+2 (summer time ended on 2026-10-25).
        assert_eq!(
            Period::parse("month", Some("Europe/Berlin"))?.window(at("2026-10-30T12:00:00Z")?),
            (at("2026-09-30T22:00:00Z")?, at("2026-10-31T23:00:00Z")?)
        );
        Ok(())
    }

    fn scope(kind: ScopeKind, name: &str, org: Option<&str>, line: usize) -> ScopeLimit {
        ScopeLimit {
            kind,
            name: name.into(),
            org: org.map(Into::into),
            line,
            budgets: Vec::new(),
            rpm: None,
            rph: None,
            rpd: None,
            tpm: None,
            tpd: None,
            parallel: None,
            shadow_until: None,
        }
    }

    fn day(usd: f64) -> Budget {
        Budget {
            usd,
            per: Period::Day,
        }
    }

    #[test]
    fn each_limit_comes_from_the_most_specific_entry_and_names_what_it_overrides() {
        let mut every = scope(ScopeKind::Person, "*", None, 10);
        every.budgets = vec![
            day(5.0),
            Budget {
                usd: 50.0,
                per: Period::Month,
            },
        ];
        let mut in_acme = scope(ScopeKind::Person, "*", Some("acme"), 11);
        in_acme.budgets = vec![day(8.0)];
        let mut maya = scope(ScopeKind::Person, "maya", Some("acme"), 12);
        maya.budgets = vec![day(30.0)];
        maya.parallel = Some(2);
        let mut customers = scope(ScopeKind::Customer, "*", None, 13);
        customers.rpm = Some(30);
        let mut global = scope(ScopeKind::Global, "", None, 14);
        global.parallel = Some(500);
        let mut other_org = scope(ScopeKind::Team, "*", Some("globex"), 15);
        other_org.tpm = Some(1);
        let mut key_default = scope(ScopeKind::Key, "*", None, 16);
        key_default.budgets = vec![day(1.0)];
        key_default.parallel = Some(9);
        let policy = Policy::new()
            .with_key("k", "maya", "payments")
            .with_key_change("k", |p| {
                p.org = "acme".into();
                p.budget = Some(day(3.0));
            })
            .with_rule("pay", Who::Team("payments".into()), Models::Any)
            .with_scope_limits(vec![
                every,
                in_acme,
                maya,
                customers,
                global,
                other_org,
                key_default,
            ]);
        let Some(who) = policy.identify("k") else {
            panic!("the key is in the policy");
        };
        let Some(rule) = policy.rule_for(who) else {
            panic!("the rule names the key");
        };
        let tags = vec!["search".to_string()];
        let applied = policy.applied(
            who,
            rule,
            Context {
                sent: "gpt-4o",
                model: "gpt-4o",
                customer: Some("globex-shop"),
                tags: &tags,
            },
        );
        let find = |of: &str, limit: &str| {
            applied
                .iter()
                .filter(|a| a.of == of && a.limit.word() == limit)
                .collect::<Vec<_>>()
        };
        let person = find("person", "budget");
        assert_eq!(person.len(), 2, "{applied:?}");
        // The daily budget is maya's own; the monthly one is inherited from every person.
        assert_eq!(person[0].limit, Limit::Budget(day(30.0)));
        assert_eq!(person[0].scope, "person:acme/maya");
        assert_eq!(
            person[0].overrides,
            vec![
                "limits { person: *, org: acme } (line 11)".to_string(),
                "limits { person: * } (line 10)".to_string(),
            ]
        );
        assert_eq!(person[1].source, "limits { person: * } (line 10)");
        assert!(person[1].overrides.is_empty());
        // The key's own budget beats the default for every key, which still gives it parallel.
        let key = find("key", "budget");
        assert_eq!(key[0].limit, Limit::Budget(day(3.0)));
        assert_eq!(key[0].source, format!("key {} (keys file)", who.key));
        assert_eq!(find("key", "parallel")[0].limit, Limit::Parallel(9));
        assert_eq!(
            find("customer", "rpm")[0].scope,
            "customer:acme/globex-shop"
        );
        assert_eq!(find("global", "parallel")[0].scope, "global");
        // Another organization's entry never applies.
        assert!(find("team", "tpm").is_empty());
        let explained = policy.explain(
            who,
            Context {
                sent: "gpt-4o",
                model: "gpt-4o",
                customer: Some("globex-shop"),
                tags: &tags,
            },
        );
        assert_eq!(explained["verdict"], "refused");
        assert_eq!(explained["rule"]["name"], "pay");
        assert!(
            explained["problems"][0]
                .as_str()
                .is_some_and(|p| p.contains("does not let a caller name customer \"globex-shop\""))
        );
        assert!(explained["limits"].as_array().is_some_and(|l| {
            l.iter()
                .any(|x| x["scope"] == "person:acme/maya" && x["usd"] == 30.0)
        }));
    }

    // Found by a real Claude Code session: `rate: { tpd: 2000 }` alone on a rule let every request through, because
    // the no-limits fast path did not look at tpd.
    #[test]
    fn a_rule_whose_only_limit_is_tokens_per_day_applies_it() {
        let policy = Policy::new()
            .with_key("k", "maya", "payments")
            .with_rule("everyone", Who::Any, Models::Any)
            .with_rule_change(|r| r.limits.tpd = Some(2000));
        let Some(who) = policy.identify("k") else {
            panic!("the key is in the policy");
        };
        let Some(rule) = policy.rule_for(who) else {
            panic!("the rule names the key");
        };
        let applied = policy.applied(
            who,
            rule,
            Context {
                sent: "claude-haiku-4-5",
                model: "claude-haiku-4-5",
                customer: None,
                tags: &[],
            },
        );
        assert!(
            applied.iter().any(|a| a.limit == Limit::Tpd(2000)),
            "{applied:?}"
        );
    }

    #[test]
    fn a_rule_for_an_org_or_a_tag_names_only_its_callers() {
        let policy = Policy::new()
            .with_key("a", "maya", "payments")
            .with_key_change("a", |p| p.org = "acme".into())
            .with_key("g", "omer", "payments")
            .with_key_change("g", |p| {
                p.org = "globex".into();
                p.tags = vec!["ci".into()];
            })
            .with_rule("acme-payments", Who::Team("payments".into()), Models::Any)
            .with_rule_change(|r| r.org = Some("acme".into()))
            .with_rule("ci", Who::Tag("ci".into()), Models::Only(vec!["m".into()]));
        let decide = |key: &str, model: &str| {
            policy
                .identify(key)
                .map(|who| matches!(policy.decide(who, model), Decision::Allow(_)))
        };
        assert_eq!(decide("a", "anything"), Some(true));
        assert_eq!(decide("g", "anything"), Some(false));
        assert_eq!(decide("g", "m"), Some(true));
        let Some(omer) = policy.identify("g") else {
            panic!("omer is in the policy");
        };
        let explained = policy.explain(
            omer,
            Context {
                sent: "m",
                model: "m",
                ..Context::default()
            },
        );
        assert_eq!(
            explained["skipped"][0]["why"],
            "is for organization \"acme\""
        );
        assert_eq!(explained["verdict"], "allow");
    }

    #[test]
    fn roles_grant_permissions_and_an_org_key_is_confined() {
        let finance = Role {
            name: "finance".into(),
            permissions: vec![Permission::SeeSpend],
            org: None,
            teams: Vec::new(),
            customers: Vec::new(),
            sso_values: Vec::new(),
            line: 3,
        };
        let policy = Policy::new()
            .with_key("a", "admin", "ops")
            .with_key_change("a", |p| p.admin = true)
            .with_key("f", "fin", "money")
            .with_key_change("f", |p| {
                p.role = Some("finance".into());
                p.org = "acme".into();
            })
            .with_key("n", "nobody", "x")
            .with_roles(vec![finance]);
        let role = |k: &str| policy.identify(k).and_then(|who| policy.role_of(who));
        assert!(
            role("a").is_some_and(|r| Permission::ALL.iter().all(|p| r.may(*p)) && r.org.is_none())
        );
        assert!(role("f").is_some_and(|r| r.may(Permission::SeeSpend)
            && !r.may(Permission::IssueKeys)
            && r.org.as_deref() == Some("acme")));
        assert!(role("n").is_none());
        assert!(builtin_role("read_only").is_some_and(|r| !r.may(Permission::SeeBodies)));
    }
}
