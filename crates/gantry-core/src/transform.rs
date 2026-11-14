//! Transforms: a service (a `type: transform` guardrail) or an embedding binary rewriting the whole request before
//! it is checked and sent, or the whole answer before it is checked and returned. Every change is recorded as a diff
//! summary: which JSON paths were added, removed or changed, never their values.
//!
//! Order on a request: transforms (the binary's, then each `transform` guardrail in the rule's order), then the
//! rule's function tool check, then its other guardrails. On an answer the same: transforms, tool check, guardrails.
//! So every check reads what is really sent or returned. The contract is in docs/governance/transforms.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The most changes a record lists: past it the summary says how many more there were.
const MAX_CHANGES: usize = 32;

/// Which body a transform rewrites.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Request,
    Answer,
}

/// What Gantry sends a transform service.
#[derive(Clone, Debug, Serialize)]
pub struct TransformRequest<'a> {
    pub decision_id: &'a str,
    pub person: &'a str,
    pub team: &'a str,
    pub route: &'a str,
    pub side: Side,
    pub body: &'a Value,
}

/// What a transform service answers: the body to use.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformAnswer {
    pub body: Value,
}

/// One change: `add`, `remove` or `change`, at a JSON pointer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Change {
    pub op: &'static str,
    pub path: String,
}

/// What one transform did to one body, for the record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub transform: String,
    pub side: Side,
    /// `changed`, `unchanged`, or `skipped` when a fail_open service did not answer.
    pub outcome: &'static str,
    pub changes: Vec<Change>,
    /// Changes past the ones listed.
    #[serde(skip_serializing_if = "is_zero")]
    pub more: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn walk(before: &Value, after: &Value, at: &str, out: &mut Vec<Change>) {
    match (before, after) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in a {
                let path = format!("{at}/{}", escape(k));
                match b.get(k) {
                    Some(w) => walk(v, w, &path, out),
                    None => out.push(Change { op: "remove", path }),
                }
            }
            for k in b.keys().filter(|k| !a.contains_key(*k)) {
                out.push(Change {
                    op: "add",
                    path: format!("{at}/{}", escape(k)),
                });
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            for i in 0..a.len().max(b.len()) {
                let path = format!("{at}/{i}");
                match (a.get(i), b.get(i)) {
                    (Some(v), Some(w)) => walk(v, w, &path, out),
                    (Some(_), None) => out.push(Change { op: "remove", path }),
                    (None, Some(_)) => out.push(Change { op: "add", path }),
                    (None, None) => {}
                }
            }
        }
        (a, b) if a != b => out.push(Change {
            op: "change",
            path: if at.is_empty() { "/".into() } else { at.into() },
        }),
        _ => {}
    }
}

/// The changes from `before` to `after`, by path, no values.
pub fn summary(transform: &str, side: Side, before: &Value, after: &Value) -> Summary {
    let mut changes = Vec::new();
    walk(before, after, "", &mut changes);
    let more = changes.len().saturating_sub(MAX_CHANGES);
    changes.truncate(MAX_CHANGES);
    Summary {
        transform: transform.to_string(),
        side,
        outcome: if changes.is_empty() {
            "unchanged"
        } else {
            "changed"
        },
        changes,
        more,
    }
}

/// Whether a rewritten request is one Gantry can still send as decided: an object, with the model and stream it was
/// routed and metered by. `Err` says what the transform changed.
pub fn request_ok(before: &Value, after: &Value) -> Result<(), String> {
    if !after.is_object() {
        return Err("the transform's body is not a JSON object".into());
    }
    for field in ["model", "stream"] {
        if before.get(field) != after.get(field) {
            return Err(format!(
                "the transform changed \"{field}\", which the request was already routed and metered by; a transform may not change it"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_summary_names_paths_and_never_values() {
        let before = json!({"model": "m", "messages": [{"role": "user", "content": "secret text"}], "temperature": 1});
        let after = json!({"model": "m", "messages": [{"role": "system", "content": "house style"}, {"role": "user", "content": "secret text"}], "user": "x"});
        let s = summary("style", Side::Request, &before, &after);
        assert_eq!(s.outcome, "changed");
        let text = serde_json::to_string(&s).unwrap_or_default();
        assert!(
            !text.contains("secret text") && !text.contains("house style"),
            "{text}"
        );
        assert!(s.changes.contains(&Change {
            op: "remove",
            path: "/temperature".into()
        }));
        assert!(s.changes.contains(&Change {
            op: "add",
            path: "/user".into()
        }));
        assert!(s.changes.contains(&Change {
            op: "add",
            path: "/messages/1".into()
        }));
        assert_eq!(
            summary("t", Side::Answer, &before, &before).outcome,
            "unchanged"
        );
    }

    #[test]
    fn a_request_transform_may_not_change_the_model_or_stream() {
        let before = json!({"model": "m", "stream": true});
        assert!(request_ok(&before, &json!({"model": "m", "stream": true, "x": 1})).is_ok());
        assert!(request_ok(&before, &json!({"model": "other", "stream": true})).is_err());
        assert!(request_ok(&before, &json!({"model": "m"})).is_err());
        assert!(request_ok(&before, &json!([1])).is_err());
    }
}
