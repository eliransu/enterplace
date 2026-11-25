//! `enterplace demo-seed <empty folder> --fake-records`, not listed in the help: a folder with a policy, a keys file and
//! five weeks of made-up usage records (teams, people, coding agents, apps, models, refusals, unnamed and subscription
//! requests) in a real audit chain, so the console's multi-day charts can be looked at and screenshotted without
//! backdating real traffic. It never touches an install: it writes only into a folder that is new or empty, and only
//! with the flag that says the records are fake.

use std::path::Path;

use enterplace_core::{
    audit::{self, AuditLog, Entry},
    id::sha256_hex,
};
use serde_json::{Map, Value, json};

/// How many days back the records go.
const DAYS: u64 = 35;

const POLICY: &str = "\
# Made by `enterplace demo-seed`: the records in enterplace-audit.jsonl are fake. Nothing here reaches a provider.
version: 1
providers:
  - name: openai
    kind: openai
    url: http://127.0.0.1:9
    allow_private: true
    models: [gpt-4o, gpt-4o-mini]
  - name: anthropic
    kind: anthropic
    url: http://127.0.0.1:9
    allow_private: true
    auth: passthrough
    models: [claude-sonnet-4-5, claude-haiku-4-5]
prices:
  gpt-4o: { input: 2.5, output: 10 }
  gpt-4o-mini: { input: 0.15, output: 0.6 }
  claude-sonnet-4-5: { input: 3, output: 15 }
  claude-haiku-4-5: { input: 1, output: 5 }
rules:
  - name: payments-team
    principals: { team: payments }
    models: [\"*\"]
    budget: { usd: 400, per: month }
  - name: everyone
    principals: { any: true }
    models: [\"*\"]
limits:
  - { person: \"*\", budget: { usd: 60, per: month } }
  - { team: search, budget: { usd: 250, per: month } }
audit: { path: enterplace-audit.jsonl }
";

/// Who sends what: name, team, the user agent of their tool, and the models they use, cheapest first.
const SENDERS: [(&str, &str, &str, &[&str]); 9] = [
    (
        "maya.cohen",
        "payments",
        "claude-cli/2.0.14 (external, cli)",
        &["claude-haiku-4-5", "claude-sonnet-4-5"],
    ),
    (
        "dana.levi",
        "search",
        "codex_cli_rs/0.46.0 (Mac OS 26.0; arm64)",
        &["gpt-4o-mini", "gpt-4o"],
    ),
    (
        "lee.k",
        "platform",
        "cursor/1.7.2",
        &["gpt-4o-mini", "claude-sonnet-4-5"],
    ),
    (
        "omer.tal",
        "payments",
        "GeminiCLI/0.9.0 (darwin; arm64)",
        &["gpt-4o-mini", "gpt-4o"],
    ),
    (
        "noa.bar",
        "platform",
        "claude-cli/2.0.14 (external, cli)",
        &["claude-haiku-4-5", "claude-sonnet-4-5"],
    ),
    (
        "ari.ben",
        "search",
        "Cline/3.35.0",
        &["claude-haiku-4-5", "gpt-4o"],
    ),
    // Apps, each on its own service key.
    (
        "invoice-bot",
        "payments",
        "OpenAI/Python 1.54.3",
        &["gpt-4o-mini", "gpt-4o"],
    ),
    (
        "search-indexer",
        "search",
        "python-requests/2.32.3",
        &["gpt-4o-mini", "gpt-4o-mini"],
    ),
    // A coding agent without a person token: unnamed, the problem the console says how to fix.
    (
        "unknown",
        "unknown",
        "claude-cli/2.0.14 (external, cli)",
        &["claude-haiku-4-5", "claude-sonnet-4-5"],
    ),
];

/// A small deterministic generator, so two seeds of the same day draw the same charts.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn price(model: &str) -> (f64, f64) {
    match model {
        "gpt-4o" => (2.5, 10.0),
        "gpt-4o-mini" => (0.15, 0.6),
        "claude-sonnet-4-5" => (3.0, 15.0),
        _ => (1.0, 5.0),
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// Writes the folder and returns the admin key, which the console signs in with.
pub(crate) fn seed(folder: &Path) -> Result<String, String> {
    if folder.exists() {
        let mut entries = std::fs::read_dir(folder).map_err(|err| {
            format!(
                "{} cannot be read: {err}. Name a new or empty folder.",
                folder.display()
            )
        })?;
        if entries.next().is_some() {
            return Err(format!(
                "{} is not empty. demo-seed writes fake records, so it only writes into a new or empty folder, never next to a real install. Name a new folder.",
                folder.display()
            ));
        }
    }
    std::fs::create_dir_all(folder)
        .map_err(|err| format!("{} cannot be made: {err}.", folder.display()))?;
    let written = |name: &str, err: std::io::Error| {
        format!("{} cannot be written: {err}.", folder.join(name).display())
    };
    std::fs::write(folder.join("enterplace.policy.yaml"), POLICY)
        .map_err(|err| written("enterplace.policy.yaml", err))?;
    let admin = format!("enterplace_{}", enterplace_core::id::random_hex(32));
    let mut keys = format!(
        "keys:\n  - name: demo.admin\n    team: platform\n    sha256: {}\n    admin: true\n",
        sha256_hex(admin.as_bytes())
    );
    // Each sender's key is made up: only its hash is kept, and its prefix is what the records name.
    let prefix = |name: &str| sha256_hex(format!("demo key of {name}").as_bytes());
    for (name, team, _, _) in SENDERS.iter().filter(|s| s.0 != "unknown") {
        keys.push_str(&format!(
            "  - name: {name}\n    team: {team}\n    sha256: {}\n",
            prefix(name)
        ));
        if name.contains('-') {
            keys.push_str("    metadata: { kind: workload }\n");
        }
        if *name == "invoice-bot" {
            keys.push_str("    budget: { usd: 120, per: month }\n");
        }
    }
    std::fs::write(folder.join("enterplace.keys.yaml"), keys)
        .map_err(|err| written("enterplace.keys.yaml", err))?;

    let path = folder.join("enterplace-audit.jsonl");
    let log = AuditLog::open(&path)?;
    let now = enterplace_core::insights::now_secs();
    let mut draw = Draw(0x9E37_79B9_7F4A_7C15 ^ (now / 86_400));
    let mut n = 0u64;
    let write = |record: &Map<String, Value>| {
        log.append_record(record)
            .map_err(|err| written("enterplace-audit.jsonl", err))
    };
    for back in (0..DAYS).rev() {
        let day = (now / 86_400).saturating_sub(back) * 86_400;
        // Fewer requests at the weekend (1970-01-01 was a Thursday: day 2 and 3 of the week are Saturday and Sunday).
        let weekend = matches!((day / 86_400) % 7, 2 | 3);
        // A slow ramp: the team adopted coding agents over the month.
        let ramp = 4 + (DAYS - back) / 4;
        let mut times: Vec<(u64, usize)> = Vec::new();
        for (i, (name, _, _, _)) in SENDERS.iter().enumerate() {
            let busy = if name.contains('-') { 6 } else { ramp };
            let count = if weekend {
                busy / 4
            } else {
                busy + draw.below(busy)
            };
            for _ in 0..count {
                // Working hours, UTC, with a little spread.
                let at = day + 7 * 3600 + draw.below(11 * 3600);
                if at <= now {
                    times.push((at, i));
                }
            }
        }
        times.sort_unstable();
        for (at, i) in times {
            let (name, team, agent, models) = SENDERS[i];
            n += 1;
            let id = format!("01DEMO{n:020}");
            let time = audit::rfc3339(std::time::UNIX_EPOCH + std::time::Duration::from_secs(at));
            let model = models[usize::from(draw.below(4) == 0)];
            let provider = if model.starts_with("claude") {
                "anthropic"
            } else {
                "openai"
            };
            let key = (name != "unknown").then(|| prefix(name)[..8].to_string());
            let roll = draw.below(100);
            // About 3 in 100 refused: payments by its budget on its busiest days, others by a model not allowed.
            let refused = roll < 3;
            let code = match (refused, team) {
                (false, _) => None,
                (true, "payments") => Some("budget_exceeded"),
                (true, _) => Some("model_not_allowed"),
            };
            let rule = if team == "payments" {
                "payments-team"
            } else {
                "everyone"
            };
            let mut decision = audit::record(&Entry {
                id: &id,
                person: Some(name),
                team: Some(team),
                user_agent: Some(agent),
                key: key.as_deref(),
                method: "POST",
                path: if provider == "anthropic" {
                    "/v1/messages"
                } else {
                    "/v1/chat/completions"
                },
                model: Some(model),
                allowed: !refused,
                code,
                rule: Some(rule),
                provider: if refused { "" } else { provider },
                ..Entry::default()
            });
            decision.insert("time".into(), time.clone().into());
            // Two in five Claude Code requests use the developer's own subscription login.
            let subscription = agent.starts_with("claude-cli") && name != "unknown" && roll % 5 < 2;
            if subscription {
                decision.insert("auth".into(), "passthrough".into());
            }
            if code == Some("budget_exceeded") {
                decision.insert(
                    "applied".into(),
                    json!({ "of": "rule", "scope": "team:payments", "limit": "budget", "source": "rule \"payments-team\" (line 21)", "usd": 400.0, "per": "month" }),
                );
            }
            write(&decision)?;
            if refused {
                continue;
            }
            let input = 1_500 + draw.below(if name.contains('-') { 3_000 } else { 60_000 });
            let output = 150 + draw.below(4_000);
            let (in_price, out_price) = price(model);
            let cost = (input as f64 * in_price + output as f64 * out_price) / 1_000_000.0;
            let status = if draw.below(100) < 2 { 529 } else { 200 };
            let mut usage = object(json!({
                "event": "usage", "id": id, "time": time, "person": name, "team": team, "key": key,
                "provider": provider, "model": model, "status": status, "input_tokens": input,
                "output_tokens": output, "cost_usd": if status == 200 { cost } else { 0.0 }, "charged_usd": if status == 200 { cost } else { 0.0 },
                "latency_ms": 400 + draw.below(if status == 200 { 9_000 } else { 300 }),
            }));
            if subscription {
                usage.insert("auth".into(), "passthrough".into());
                usage.insert("cost_basis".into(), "api_equivalent_estimate".into());
                usage.insert("caller_paid".into(), true.into());
                usage.insert("budget".into(), "not_counted".into());
            }
            write(&usage)?;
        }
    }
    log.flush();
    Ok(admin)
}
