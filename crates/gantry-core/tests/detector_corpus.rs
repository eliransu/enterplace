//! Precision and recall of the built-in detectors on the labelled corpus, and a check that the table published in
//! the guardrails page is exactly what was measured, so the docs cannot claim numbers the code does not reach.
//!
//! After a detector change: `GANTRY_WRITE_DETECTOR_TABLE=1 cargo test -p gantry-core --test detector_corpus`
//! rewrites the table, and the diff shows what moved.

use std::{collections::BTreeMap, error::Error, fs, path::PathBuf};

use gantry_core::guard::{TextPart, scan};
use serde_json::Value;

type TestResult = Result<(), Box<dyn Error>>;

const CORPUS: &str = "gantry-detectors-v2";
const START: &str = "{/* detector-corpus-table:start */}";
const END: &str = "{/* detector-corpus-table:end */}";

/// Every kind, in the order the docs list them, with its detector.
const KINDS: [(&str, &str); 24] = [
    ("private_key", "secrets"),
    ("aws_access_key", "secrets"),
    ("github_token", "secrets"),
    ("slack_token", "secrets"),
    ("gantry_key", "secrets"),
    ("jwt", "secrets"),
    ("gcp_service_account_key", "secrets"),
    ("gcp_api_key", "secrets"),
    ("azure_connection_string", "secrets"),
    ("stripe_key", "secrets"),
    ("twilio_api_key", "secrets"),
    ("sendgrid_key", "secrets"),
    ("openai_project_key", "secrets"),
    ("anthropic_key", "secrets"),
    ("api_key", "secrets"),
    ("database_url", "secrets"),
    ("email_address", "pii"),
    ("phone_number", "pii"),
    ("credit_card", "pii"),
    ("iban", "pii"),
    ("israeli_id", "pii"),
    ("us_ssn", "pii"),
    ("medical_record_number", "pii"),
    ("date_of_birth", "pii"),
];

/// The lowest precision and recall (in percent) each kind may score on this corpus: the v1 measurement for the v1
/// kinds, and the v2 measurement for the kinds v2 added, each rounded down to the next whole percent. A change that
/// loses ground fails here even if the docs table is rewritten with it.
const FLOORS: [(&str, f64, f64); 24] = [
    ("private_key", 100.0, 100.0),
    ("aws_access_key", 100.0, 100.0),
    ("github_token", 100.0, 100.0),
    ("slack_token", 97.0, 100.0),
    ("gantry_key", 100.0, 100.0),
    ("jwt", 100.0, 100.0),
    ("gcp_service_account_key", 100.0, 100.0),
    ("gcp_api_key", 100.0, 100.0),
    ("azure_connection_string", 100.0, 100.0),
    ("stripe_key", 100.0, 100.0),
    ("twilio_api_key", 100.0, 100.0),
    ("sendgrid_key", 100.0, 100.0),
    ("openai_project_key", 100.0, 100.0),
    ("anthropic_key", 100.0, 100.0),
    ("api_key", 95.0, 100.0),
    ("database_url", 100.0, 100.0),
    ("email_address", 86.0, 100.0),
    ("phone_number", 80.0, 90.0),
    ("credit_card", 94.0, 100.0),
    ("iban", 100.0, 95.0),
    ("israeli_id", 92.0, 95.0),
    ("us_ssn", 78.0, 92.0),
    ("medical_record_number", 97.0, 95.0),
    ("date_of_birth", 97.0, 90.0),
];

#[derive(Default)]
struct Score {
    positives: usize,
    negatives: usize,
    true_pos: usize,
    false_pos: usize,
    false_neg: usize,
}

impl Score {
    fn precision(&self) -> f64 {
        match self.true_pos + self.false_pos {
            0 => 100.0,
            found => 100.0 * self.true_pos as f64 / found as f64,
        }
    }

    fn recall(&self) -> f64 {
        match self.positives {
            0 => 100.0,
            n => 100.0 * self.true_pos as f64 / n as f64,
        }
    }
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn measure() -> Result<BTreeMap<&'static str, Score>, Box<dyn Error>> {
    let path = root().join(format!("tests/corpus/{CORPUS}.jsonl"));
    let corpus = fs::read_to_string(&path)?;
    let mut scores: BTreeMap<&str, Score> =
        KINDS.iter().map(|(k, _)| (*k, Score::default())).collect();
    let mut misses = Vec::new();
    for line in corpus
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let row: Value = serde_json::from_str(line)?;
        let id = &row["id"];
        let target = row["target"]
            .as_str()
            .ok_or("a corpus line has no target")?;
        let text = row["text"].as_str().ok_or("a corpus line has no text")?;
        let mut expected: BTreeMap<&str, usize> = BTreeMap::new();
        for kind in row["expect"]
            .as_array()
            .ok_or("a corpus line has no expect list")?
        {
            let kind = kind.as_str().ok_or("expect holds a non-string")?;
            let known = KINDS
                .iter()
                .find(|(k, _)| *k == kind)
                .ok_or(format!("line {id}: unknown kind {kind}"))?;
            *expected.entry(known.0).or_default() += 1;
        }
        let parts = [TextPart {
            path: "/corpus".into(),
            role: "user".into(),
            text: text.into(),
        }];
        let mut found: BTreeMap<String, usize> = BTreeMap::new();
        for finding in scan(&parts)? {
            *found.entry(finding.kind.to_string()).or_default() += 1;
        }
        for (kind, score) in scores.iter_mut() {
            let want = expected.get(kind).copied().unwrap_or(0);
            let got = found.get(*kind).copied().unwrap_or(0);
            let hit = want.min(got);
            score.positives += want;
            score.negatives += usize::from(target == *kind && want == 0);
            score.true_pos += hit;
            score.false_pos += got - hit;
            score.false_neg += want - hit;
            if want != got {
                misses.push(format!("line {id}: {kind} expected {want}, found {got}"));
            }
        }
        if let Some(kind) = found.keys().find(|k| !scores.contains_key(k.as_str())) {
            return Err(format!(
                "the detectors report kind {kind}, which this test does not know. Add it to KINDS."
            )
            .into());
        }
    }
    // Printed on failure, and with --nocapture, so a moved number can be traced to its lines.
    eprintln!("{}", misses.join("\n"));
    Ok(scores)
}

fn table(scores: &BTreeMap<&str, Score>) -> String {
    let mut out = format!(
        "Measured on the `{CORPUS}` corpus.\n\n| Kind | Type | Positives | Negatives | Precision | Recall |\n|---|---|---|---|---|---|\n"
    );
    for (kind, detector) in KINDS {
        if let Some(s) = scores.get(kind) {
            out.push_str(&format!(
                "| `{kind}` | `{detector}` | {} | {} | {:.1}% | {:.1}% |\n",
                s.positives,
                s.negatives,
                s.precision(),
                s.recall()
            ));
        }
    }
    out
}

#[test]
fn detectors_reach_their_floors_on_the_corpus() -> TestResult {
    let scores = measure()?;
    let mut below = Vec::new();
    for (kind, precision, recall) in FLOORS {
        let s = scores.get(kind).ok_or(format!("no score for {kind}"))?;
        if s.positives < 40 || s.negatives < 40 {
            below.push(format!(
                "{kind}: the corpus has {} positives and {} negatives, fewer than 40",
                s.positives, s.negatives
            ));
        }
        if s.precision() < precision || s.recall() < recall {
            below.push(format!(
                "{kind}: precision {:.1}% (floor {precision}%), recall {:.1}% (floor {recall}%)",
                s.precision(),
                s.recall()
            ));
        }
    }
    assert!(below.is_empty(), "{}", below.join("\n"));
    Ok(())
}

#[test]
fn published_table_matches_the_measurement() -> TestResult {
    let docs = root().join("../../docs/src/content/docs/governance/guardrails.mdx");
    let page = fs::read_to_string(&docs)?;
    let (head, rest) = page
        .split_once(START)
        .ok_or(format!("{} has no {START} marker", docs.display()))?;
    let (published, tail) = rest
        .split_once(END)
        .ok_or(format!("{} has no {END} marker", docs.display()))?;
    let measured = table(&measure()?);
    if std::env::var_os("GANTRY_WRITE_DETECTOR_TABLE").is_some() {
        fs::write(&docs, format!("{head}{START}\n\n{measured}\n{END}{tail}"))?;
        return Ok(());
    }
    assert_eq!(
        published.trim(),
        measured.trim(),
        "the detector table in guardrails.mdx is not what the corpus measures. Rerun with GANTRY_WRITE_DETECTOR_TABLE=1 to rewrite it, and check the diff."
    );
    Ok(())
}
