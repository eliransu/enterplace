//! What a gateway admin does in the console to fix a refusal, with the values filled in: the steps, the console link
//! that opens the dialog that fixes it, and the refusal's docs section. Sent with every refusal an admin can fix, so
//! the caller (or its coding agent) can hand the admin the exact steps instead of changing the app around it.

use axum::http::{HeaderMap, Uri, header};
use serde_json::{Value, json};

const DOCS: &str = "https://docs.enterplace.dev/reference/refusal-codes/";

/// What the refusal was about, as far as the gateway knows it when it refuses.
#[derive(Default)]
pub(crate) struct Facts<'a> {
    /// This gateway as the caller reached it: `https://gw.example.com`.
    pub base: &'a str,
    pub model: &'a str,
    pub caller: &'a str,
    pub team: &'a str,
    pub rule: &'a str,
    /// An MCP server and the tool asked of it.
    pub server: &'a str,
    pub tool: &'a str,
    /// The refusal's own message and the fields its record gains (`applied`, `key_models`).
    pub message: &'a str,
    pub record: Option<&'a Value>,
}

/// This Enterplace as the caller reached it: the scheme (TLS here, or a proxy that says so) and the Host header.
pub(crate) fn origin(headers: &HeaderMap, uri: &Uri, tls: bool) -> String {
    let https = tls
        || uri.scheme_str() == Some("https")
        || headers
            .get("x-forwarded-proto")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"https"));
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        // Only what a host may hold: the origin goes into links and pages.
        .filter(|h| {
            !h.is_empty()
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        })
        .unwrap_or("localhost");
    format!("{}://{host}", if https { "https" } else { "http" })
}

/// A query value as a URL carries it.
fn enc(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The fix for `code`, or `None` when the caller fixes it itself or no console change does.
pub(crate) fn fix(code: &str, f: &Facts<'_>) -> Option<Value> {
    let app = format!("{}/console/app/#/", f.base);
    let model = f.model;
    let applied = f.record.and_then(|r| r.get("applied"));
    let apply =
        "Press Save, then Apply on the change it shows. Every gateway follows within 2 seconds.";
    let (route, mut steps): (String, Vec<String>) = match code {
        "unknown_model" if !model.is_empty() => {
            let served_as_is = if model.contains('/') {
                " (OpenRouter serves vendor/model names like this one as they are)"
            } else {
                ""
            };
            (
                format!("providers?model={}", enc(model)),
                {
                    let mut steps = vec![format!("Pick a provider that serves \"{model}\"{served_as_is}, paste its key, and press Add provider. Every gateway follows within 2 seconds.")];
                    // An alias is named as a provider is, so a vendor/model name cannot be one.
                    if enterplace_core::config::valid_name(model) {
                        steps.push(format!("Or, to send \"{model}\" to a model this gateway already serves, open {app}policy?add=alias&name={} instead, write that model as provider/model under Sends to, press Add alias, then Apply on the change it shows.", enc(model)));
                    }
                    steps
                },
            )
        }
        "wrong_route" | "login_needed" if !model.is_empty() => (
            format!("providers?model={}", enc(model)),
            vec![format!(
                "Pick a provider that serves \"{model}\" with its own key (Anthropic for a Claude model, OpenAI for a GPT model, or OpenRouter for either), paste its key, and press Add provider. The provider serving it now {}, so this call cannot use it. Every gateway follows within 2 seconds.",
                if code == "login_needed" {
                    "takes only each person's own Claude or ChatGPT login"
                } else {
                    "does not take this route"
                }
            )],
        ),
        "model_not_allowed" if f.record.is_some_and(|r| r["key_models"] == true) => (
            format!("people?q={}", enc(f.caller)),
            vec![format!(
                "Press Edit on the key of \"{}\", add \"{model}\" to its Models, and press Save.",
                f.caller
            )],
        ),
        "model_not_allowed" if !f.rule.is_empty() && !model.is_empty() => (
            format!("policy?rule={}&model={}", enc(f.rule), enc(model)),
            vec![
                format!("Rule \"{}\" opens with \"{model}\" added to its Models.", f.rule),
                apply.into(),
            ],
        ),
        "no_rule" if !f.team.is_empty() => (
            format!("policy?add=rule&team={}", enc(f.team)),
            vec![
                format!("Add a rule opens for team \"{}\". List the models it may use under Models (* for every one) and press Add rule.", f.team),
                "Press Apply on the change it shows. Every gateway follows within 2 seconds.".into(),
            ],
        ),
        "awaiting_approval" | "caller_blocked" if !f.caller.is_empty() => (
            format!("apps/new?allow={}", enc(f.caller)),
            vec![format!(
                "Access requests opens and asks to allow \"{}\". Press Allow. Every gateway follows within 2 seconds.",
                f.caller
            )],
        ),
        "passthrough_not_allowed" if !f.rule.is_empty() => (
            format!("policy?rule={}", enc(f.rule)),
            vec![
                format!("Rule \"{}\" opens. Under Provider APIs reached as sent, add the provider and path the refusal names, as provider: /path.", f.rule),
                apply.into(),
            ],
        ),
        "tool_not_allowed" | "mcp_access_denied" if !f.server.is_empty() => (
            format!("mcp?access={}&team={}", enc(f.server), enc(f.team)),
            vec![format!(
                "Access for MCP server \"{}\" opens with team \"{}\" filled in. Tick \"{}\" (or leave every tool unticked to grant them all), press Grant, then Apply on the change it shows. Every gateway follows within 2 seconds.",
                f.server, f.team, f.tool
            )],
        ),
        "budget_exceeded" | "rate_limited" | "parallel_limited" => {
            let of = applied.and_then(|a| a["of"].as_str()).unwrap_or("");
            let scope = applied.and_then(|a| a["scope"].as_str()).unwrap_or("");
            let route = match of {
                "team" if !scope.is_empty() => format!("policy?add=limit&team={}", enc(scope)),
                _ if !f.rule.is_empty() && of == "rule" => format!("policy?rule={}", enc(f.rule)),
                _ => "policy?at=limits".into(),
            };
            let which = if scope.is_empty() {
                "the limit the refusal names".to_string()
            } else {
                format!("the limit of {of} \"{scope}\"")
            };
            (
                route,
                vec![
                    format!("Raise {which}, or wait for it to start again as the refusal says."),
                    apply.into(),
                ],
            )
        }
        "key_budget_exceeded" if !f.caller.is_empty() => (
            format!("people?q={}", enc(f.caller)),
            vec![format!(
                "Press Edit on the key of \"{}\", raise its Budget, and press Save.",
                f.caller
            )],
        ),
        // A guardrail whose own service could not check the request: not a finding about the text.
        "guardrail_blocked" if f.message.contains("fail_closed") => (
            "guardrails".into(),
            vec![
                "Find the guardrail the refusal names, press Test to see whether its service answers, and fix the service it calls, or press Edit and let requests through while it is down.".into(),
                apply.into(),
            ],
        ),
        _ => return None,
    };
    let console = format!("{app}{route}");
    steps.insert(0, format!("Open {console}"));
    steps.push("Then retry the same call, unchanged.".into());
    Some(json!({ "steps": steps, "console": console, "docs": format!("{DOCS}#{code}") }))
}

/// The steps as one paragraph for the end of a refusal's message, which is all most clients show.
pub(crate) fn sentence(fix: &Value) -> String {
    let steps: Vec<String> = fix["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .enumerate()
        .map(|(i, s)| format!("{}. {}", i + 1, s.trim_end_matches('.')))
        .collect();
    format!(
        "Fix on the gateway (an Enterplace admin does this in the console): {}. Docs: {}",
        steps.join(". "),
        fix["docs"].as_str().unwrap_or(DOCS)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_encoded_and_a_caller_side_refusal_has_none() {
        let f = Facts {
            base: "https://gw",
            model: "a/b c",
            ..Facts::default()
        };
        let fix = fix("unknown_model", &f);
        assert_eq!(
            fix.as_ref().map(|v| v["console"].clone()),
            Some(Value::from(
                "https://gw/console/app/#/providers?model=a%2Fb%20c"
            ))
        );
        assert!(super::fix("no_key", &f).is_none());
        assert!(super::fix("unknown_model", &Facts::default()).is_none());
    }
}
