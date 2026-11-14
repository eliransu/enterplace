//! The Gitleaks default rule set as a secrets detector pack (`type: secrets`, `pack: gitleaks`).
//!
//! The rules are Gitleaks' own (MIT license, Copyright (c) 2019 Zachary Rice), imported (literal braces escaped) by
//! scripts/gitleaks_import.py into data/gitleaks-rules.json; see data/GITLEAKS-LICENSE. Each rule is read as Gitleaks
//! reads it: its keywords first (a text without one is not searched), then its regex, then its secret group, its
//! entropy floor, and the allowlists (the rule's and the global one: regexes and stopwords). Path allowlists do not
//! apply, since a prompt has no file path.

use std::{ops::Range, sync::OnceLock};

// Bytes, ASCII classes: the workspace builds regex without its Unicode tables, and Gitleaks' rules are ASCII.
use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;

const RULES: &str = include_str!("../data/gitleaks-rules.json");

#[derive(Deserialize)]
struct File {
    global: ListFile,
    rules: Vec<RuleFile>,
}

#[derive(Deserialize)]
struct ListFile {
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    and_path: bool,
}

#[derive(Deserialize)]
struct RuleFile {
    id: String,
    regex: String,
    secret_group: usize,
    entropy: Option<f64>,
    keywords: Vec<String>,
    allowlists: Vec<ListFile>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Secret,
    Match,
    Line,
}

struct List {
    regexes: Vec<Regex>,
    stopwords: Vec<String>,
    target: Target,
}

struct Rule {
    id: String,
    re: Regex,
    secret_group: usize,
    entropy: Option<f64>,
    keywords: Vec<String>,
    allow: Vec<List>,
}

/// The compiled pack: its rules and the global allowlist.
struct Pack {
    rules: Vec<Rule>,
    global: List,
}

fn compile(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .unicode(false)
        .size_limit(32 << 20)
        .dfa_size_limit(8 << 20)
        .build()
        .map_err(|err| format!("a Gitleaks rule did not compile: {err:?}. This is a bug in Gantry; report it."))
}

fn list(file: &ListFile) -> Result<List, String> {
    Ok(List {
        regexes: file.regexes.iter().map(|r| compile(r)).collect::<Result<_, _>>()?,
        stopwords: file.stopwords.clone(),
        target: match file.target.as_deref() {
            Some("match") => Target::Match,
            Some("line") => Target::Line,
            _ => Target::Secret,
        },
    })
}

fn pack() -> Result<&'static Pack, String> {
    static PACK: OnceLock<Result<Pack, String>> = OnceLock::new();
    PACK.get_or_init(|| {
        let file: File = serde_json::from_str(RULES)
            .map_err(|err| format!("the Gitleaks rule file did not load: {err}. This is a bug in Gantry; report it."))?;
        let mut rules = Vec::new();
        for r in &file.rules {
            rules.push(Rule {
                id: r.id.clone(),
                re: compile(&r.regex).map_err(|e| format!("rule {}: {e}", r.id))?,
                secret_group: r.secret_group,
                entropy: r.entropy,
                keywords: r.keywords.clone(),
                // An allowlist that also needs a path match can never hold on a prompt.
                allow: r
                    .allowlists
                    .iter()
                    .filter(|a| !a.and_path)
                    .map(list)
                    .collect::<Result<_, _>>()?,
            });
        }
        Ok(Pack {
            rules,
            global: list(&file.global)?,
        })
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// How many rules the pack holds, for the docs and the tests.
pub fn rule_count() -> Result<usize, String> {
    Ok(pack()?.rules.len())
}

/// Shannon entropy in bits per character, as Gitleaks measures a secret.
fn entropy(text: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    for c in text.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = text.chars().count() as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

impl List {
    fn allows(&self, secret: &[u8], matched: &[u8], line: &[u8]) -> bool {
        let target = match self.target {
            Target::Secret => secret,
            Target::Match => matched,
            Target::Line => line,
        };
        let lower = String::from_utf8_lossy(secret).to_lowercase();
        self.regexes.iter().any(|r| r.is_match(target))
            || self.stopwords.iter().any(|w| lower.contains(w.as_str()))
    }
}

/// Every rule that matches `text`: (rule id, byte range of the secret, on character boundaries).
pub fn scan(text: &str) -> Result<Vec<(&'static str, Range<usize>)>, String> {
    let pack = pack()?;
    let lower = text.to_lowercase();
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for rule in &pack.rules {
        if !rule.keywords.is_empty() && !rule.keywords.iter().any(|k| lower.contains(k.as_str())) {
            continue;
        }
        for caps in rule.re.captures_iter(bytes) {
            let Some(whole) = caps.get(0) else { continue };
            // The secret group, or else the first group that matched, or else the whole match: as Gitleaks takes it.
            let secret = if rule.secret_group > 0 {
                caps.get(rule.secret_group)
            } else {
                caps.iter().skip(1).flatten().find(|m| !m.as_bytes().is_empty())
            }
            .unwrap_or(whole);
            if rule
                .entropy
                .is_some_and(|floor| entropy(&String::from_utf8_lossy(secret.as_bytes())) < floor)
            {
                continue;
            }
            let start = bytes[..whole.start()]
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |i| i + 1);
            let end = bytes[whole.end()..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(bytes.len(), |i| whole.end() + i);
            let allowed = std::iter::once(&pack.global)
                .chain(&rule.allow)
                .any(|l| l.allows(secret.as_bytes(), whole.as_bytes(), &bytes[start..end]));
            if allowed {
                continue;
            }
            // A byte class may stop inside a character: the span grows to whole characters, so masking is valid.
            let (mut from, mut to) = (secret.start(), secret.end());
            while !text.is_char_boundary(from) {
                from -= 1;
            }
            while !text.is_char_boundary(to) {
                to += 1;
            }
            out.push((rule.id.as_str(), from..to));
        }
    }
    // One secret, one finding: where spans overlap a named rule wins over generic-api-key, then the longer span.
    out.sort_by_key(|(id, span)| (*id == "generic-api-key", std::cmp::Reverse(span.len())));
    let mut kept: Vec<(&'static str, Range<usize>)> = Vec::new();
    for (id, span) in out {
        if !kept.iter().any(|(_, k)| k.start < span.end && span.start < k.end) {
            kept.push((id, span));
        }
    }
    kept.sort_by_key(|(_, span)| span.start);
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_compiles_and_known_secrets_are_found() -> Result<(), String> {
        assert!(rule_count()? > 200);
        // Gitleaks' own documented example shapes, made up here.
        let aws = scan("key AKIAZ4SM2TBQYXGXWB7Q in config")?;
        assert_eq!(aws.first().map(|f| f.0), Some("aws-access-token"), "{aws:?}");
        let gh = scan("token ghp_R4nd0mT0k3nV4lu3Abcdefghij0123456789xy")?;
        assert!(gh.iter().any(|f| f.0 == "github-pat"), "{gh:?}");
        // Allowlisted placeholders and low entropy text are not findings.
        assert!(scan("password = ${PASSWORD}")?.is_empty());
        assert!(scan("hello, how are you today?")?.is_empty());
        Ok(())
    }
}
