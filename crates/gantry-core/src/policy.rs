//! The decision every request must pass: who is asking, and may they use this model.
//!
//! This is the in-memory shape the hot path reads, so a decision never waits on a file or a store.
//! `config` builds it from the policy and keys files.

use std::collections::HashMap;

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
}

impl Principal {
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

/// Who a rule applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Who {
    Team(String),
    Name(String),
    Any,
}

/// The models a rule allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Models {
    Any,
    Only(Vec<String>),
}

/// How often a budget starts again from zero, at midnight UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Period {
    Day,
    Month,
}

impl Period {
    pub fn word(self) -> &'static str {
        match self {
            Period::Day => "day",
            Period::Month => "month",
        }
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

/// What a rule limits besides the models. The default limits nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    /// Counted per team for a team rule, and per person for a name rule or an `any` rule.
    pub budget: Option<Budget>,
    /// Requests per minute, per person.
    pub rpm: Option<u32>,
    /// Tokens per minute (prompt and answer), counted where the budget is: per team for a team rule, per person
    /// otherwise.
    pub tpm: Option<u32>,
    /// How long an answer is served again for the same request, in seconds.
    pub cache_ttl_seconds: Option<u64>,
    /// Hold a streamed answer whole so the answer guardrails check it before the caller sees any of it.
    pub buffer_stream: bool,
    /// Check a streamed answer every this many characters, letting through only what was checked.
    pub check_stream_every: Option<u32>,
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
        match &self.who {
            Who::Any => true,
            Who::Team(team) => *team == principal.team,
            Who::Name(name) => *name == principal.name,
        }
    }

    pub fn allows(&self, model: &str) -> bool {
        match &self.models {
            Models::Any => true,
            Models::Only(models) => models.iter().any(|allowed| allowed == model),
        }
    }
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
}

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_parts(keys: HashMap<[u8; 32], Principal>, rules: Vec<Rule>) -> Self {
        Self {
            keys,
            rules,
            prices: PriceOverrides::new(),
        }
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
        });
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
    fn a_caller_no_rule_names_gets_nothing() {
        assert_eq!(
            decide(&policy(), "key-dana", "model-a"),
            Some(Decision::NoRule)
        );
    }
}
