//! Function tools: the tools a request declares for the model to call (OpenAI `tools` and `functions`, Anthropic
//! `tools`, Gemini `functionDeclarations`), and the calls a model makes to them in its answer.
//!
//! A rule's `tools:` list names them as `function.<name>` (or `function.*`), next to its MCP tools. An entry written
//! `!function.<name>` denies one. A rule whose list has no `function.` entry leaves function tools alone, so a
//! policy written for MCP tools changes nothing for them. A tool the list does not allow is refused with
//! `tool_not_allowed`, or, with `tool_action: strip`, taken out of the request (or the answer) and the rest sent.
//! Either way the record names each tool and what was done, never the tool's arguments.

use serde_json::Value;

use crate::guard::AuditEntry;

/// The namespace of function tools in a `tools:` list, and so a name no MCP server may take.
pub const NAMESPACE: &str = "function";
/// The refusal code, shared with MCP tools.
pub const NOT_ALLOWED: &str = "tool_not_allowed";
/// The detector the record names.
const DETECTOR: &str = "function_tools";

/// For a `tools:` entry (without its `!`): `None` when it is not a function tool entry, else whether its name is
/// one Enterplace accepts.
pub fn entry_name(entry: &str) -> Option<Result<(), String>> {
    let name = entry.strip_prefix("function.")?;
    let ok = name == "*"
        || ((1..=64).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)));
    Some(if ok {
        Ok(())
    } else {
        Err("a function tool is named function.<name>, the name 1 to 64 letters, digits, dots, dashes or underscores, or function.* for every one".into())
    })
}

/// Whether the list says anything about function tools.
pub fn checked(patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|p| p.trim_start_matches('!').starts_with("function."))
}

/// Whether the list allows the function tool `name`. With no allow entry for function tools (`function.<name>`,
/// `function.*` or `*`) every one is allowed but those denied.
pub fn allowed(patterns: &[String], name: &str) -> bool {
    let full = format!("{NAMESPACE}.{name}");
    let matches = |p: &str| crate::mcp::pattern_matches(p, &full);
    let denied = patterns
        .iter()
        .filter_map(|p| p.strip_prefix('!'))
        .any(&matches);
    let allow: Vec<&String> = patterns
        .iter()
        .filter(|p| *p == "*" || p.starts_with("function."))
        .collect();
    !denied && (allow.is_empty() || allow.iter().any(|p| matches(p)))
}

/// What the check did to one body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// The tools refused, in order, when the body is refused.
    pub refused: Vec<String>,
    /// Whether tools were stripped from the body.
    pub changed: bool,
    pub audit: Vec<AuditEntry>,
}

/// A tool name as a record's kind: the same short run of safe characters a finding's kind is.
fn kind(name: &str) -> String {
    let out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if out.is_empty() {
        "unnamed".into()
    } else {
        out
    }
}

/// Where each declaration or call sits: the array it is in (a JSON pointer), its index there, and its name.
type Found = Vec<(String, usize, String)>;

fn names_in(list: &Value, at: &str, name: impl Fn(&Value) -> Option<&str>, out: &mut Found) {
    for (i, item) in list.as_array().into_iter().flatten().enumerate() {
        if let Some(n) = name(item) {
            out.push((at.to_string(), i, n.to_string()));
        }
    }
}

/// The function tools a request declares.
fn declared(body: &Value) -> Found {
    let mut out = Vec::new();
    for (i, tool) in body["tools"].as_array().into_iter().flatten().enumerate() {
        let gemini = ["functionDeclarations", "function_declarations"]
            .into_iter()
            .find(|k| tool[*k].is_array());
        if let Some(key) = gemini {
            names_in(
                &tool[key],
                &format!("/tools/{i}/{key}"),
                |d| d["name"].as_str(),
                &mut out,
            );
        } else if let Some(name) = tool["function"]["name"]
            .as_str()
            .or_else(|| tool["name"].as_str())
        {
            // OpenAI chat nests the name under `function`; Responses and Anthropic keep it at the top.
            out.push(("/tools".into(), i, name.to_string()));
        }
    }
    names_in(
        &body["functions"],
        "/functions",
        |f| f["name"].as_str(),
        &mut out,
    );
    out
}

/// The tool calls in a whole answer.
fn calls(answer: &Value) -> Found {
    let mut out = Vec::new();
    for (i, choice) in answer["choices"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        names_in(
            &choice["message"]["tool_calls"],
            &format!("/choices/{i}/message/tool_calls"),
            |c| c["function"]["name"].as_str(),
            &mut out,
        );
    }
    if answer["type"] == "message" {
        names_in(
            &answer["content"],
            "/content",
            |b| {
                matches!(b["type"].as_str(), Some("tool_use" | "server_tool_use"))
                    .then(|| b["name"].as_str())
                    .flatten()
            },
            &mut out,
        );
    }
    names_in(
        &answer["output"],
        "/output",
        |o| {
            (o["type"] == "function_call")
                .then(|| o["name"].as_str())
                .flatten()
        },
        &mut out,
    );
    for (i, candidate) in answer["candidates"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        names_in(
            &candidate["content"]["parts"],
            &format!("/candidates/{i}/content/parts"),
            |p| p["functionCall"]["name"].as_str(),
            &mut out,
        );
    }
    out
}

/// The tool a request forces the model to call, if it names one.
fn forced(body: &Value) -> Vec<&str> {
    let mut out: Vec<&str> = [
        &body["tool_choice"]["function"]["name"],
        &body["tool_choice"]["name"],
        &body["function_call"]["name"],
    ]
    .into_iter()
    .filter_map(Value::as_str)
    .collect();
    out.extend(
        body.pointer("/toolConfig/functionCallingConfig/allowedFunctionNames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str),
    );
    out
}

fn check(
    body: &mut Value,
    found: Found,
    patterns: &[String],
    strip: bool,
    request: bool,
) -> Verdict {
    let mut verdict = Verdict::default();
    if !checked(patterns) {
        return verdict;
    }
    let bad: Vec<(String, usize, String)> = found
        .into_iter()
        .filter(|(_, _, name)| !allowed(patterns, name))
        .collect();
    if bad.is_empty() {
        return verdict;
    }
    let mut names: Vec<String> = bad.iter().map(|(_, _, n)| n.clone()).collect();
    names.dedup();
    // Forcing a stripped tool would only fail at the provider: refused here, with the reason named.
    let forces_stripped = request && forced(body).iter().any(|f| names.iter().any(|n| n == f));
    let action = if strip && !forces_stripped {
        "strip"
    } else {
        "block"
    };
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for (_, _, name) in &bad {
        *counts.entry(kind(name)).or_default() += 1;
    }
    verdict.audit = counts
        .into_iter()
        .map(|(kind, count)| AuditEntry {
            guardrail: "tools".into(),
            detector: DETECTOR.into(),
            kind,
            action,
            count,
        })
        .collect();
    if action == "block" {
        verdict.refused = names;
        return verdict;
    }
    // Removed from the end of each array, so the indexes still to remove hold.
    for (at, i, _) in bad.iter().rev() {
        if let Some(Value::Array(list)) = body.pointer_mut(at) {
            if *i < list.len() {
                list.remove(*i);
            }
        }
    }
    tidy(body, request);
    verdict.changed = true;
    verdict
}

/// After stripping: an emptied list goes, with what only makes sense beside it, so the provider gets a body it takes.
fn tidy(body: &mut Value, request: bool) {
    let Some(map) = body.as_object_mut() else {
        return;
    };
    if request {
        if let Some(Value::Array(tools)) = map.get_mut("tools") {
            tools.retain(|t| {
                ["functionDeclarations", "function_declarations"]
                    .iter()
                    .all(|k| t[*k].as_array().is_none_or(|d| !d.is_empty()))
            });
        }
        if map
            .get("tools")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            map.remove("tools");
            map.remove("tool_choice");
            map.remove("parallel_tool_calls");
            map.remove("toolConfig");
        }
        if map
            .get("functions")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            map.remove("functions");
            map.remove("function_call");
        }
        return;
    }
    // An answer whose every call was taken out ends as a plain one.
    for choice in map
        .get_mut("choices")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        let message = &mut choice["message"];
        if message["tool_calls"].as_array().is_some_and(Vec::is_empty) {
            if let Some(m) = message.as_object_mut() {
                m.remove("tool_calls");
            }
            if choice["finish_reason"] == "tool_calls" {
                choice["finish_reason"] = "stop".into();
            }
        }
    }
    if map.get("stop_reason").and_then(Value::as_str) == Some("tool_use")
        && !map
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|b| b["type"] == "tool_use")
    {
        map.insert("stop_reason".into(), "end_turn".into());
    }
}

/// Checks the function tools a request declares against a rule's `tools:` list.
pub fn request(body: &mut Value, patterns: &[String], strip: bool) -> Verdict {
    let found = declared(body);
    check(body, found, patterns, strip, true)
}

/// Checks the tool calls in a whole answer against a rule's `tools:` list.
pub fn answer(body: &mut Value, patterns: &[String], strip: bool) -> Verdict {
    let found = calls(body);
    check(body, found, patterns, strip, false)
}

/// The refusal message for a request (or an answer) holding tools the rule does not allow.
pub fn refusal(rule: &str, refused: &[String], patterns: &[String], answer: bool) -> String {
    let allowed: Vec<&String> = patterns
        .iter()
        .filter(|p| p.starts_with("function.") || *p == "*")
        .collect();
    let allows = if allowed.is_empty() {
        "It allows every function tool not denied.".to_string()
    } else {
        format!(
            "It allows: {}.",
            allowed
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let quoted: Vec<String> = refused.iter().map(|n| format!("\"{}\"", kind(n))).collect();
    if answer {
        format!(
            "Refused: the model's answer calls function tool {} that rule \"{rule}\" does not allow, so it was withheld. {allows} The answer was produced and is counted in usage. Declare only allowed tools, or ask a Enterplace admin to add function.<name> to the rule's tools.",
            quoted.join(", ")
        )
    } else {
        format!(
            "Refused: rule \"{rule}\" does not allow function tool {}. {allows} Remove it from the request, or ask a Enterplace admin to add function.<name> to the rule's tools.",
            quoted.join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_list_without_function_entries_leaves_function_tools_alone() {
        let mut body = json!({"tools": [{"type": "function", "function": {"name": "run_shell"}}]});
        let before = body.clone();
        let v = request(&mut body, &list(&["github.*"]), false);
        assert_eq!(v, Verdict::default());
        assert_eq!(body, before);
        let v = request(&mut body, &list(&["*"]), false);
        assert!(v.refused.is_empty());
    }

    #[test]
    fn allow_and_deny_entries_decide_each_declared_tool_in_every_format() {
        let allow = list(&["github.*", "function.get_weather", "function.search"]);
        let deny = list(&["*", "!function.run_shell"]);
        let bodies = [
            json!({"tools": [{"type": "function", "function": {"name": "get_weather"}}, {"type": "function", "function": {"name": "run_shell"}}]}),
            json!({"functions": [{"name": "get_weather"}, {"name": "run_shell"}]}),
            json!({"tools": [{"type": "function", "name": "get_weather"}, {"type": "function", "name": "run_shell"}]}),
            json!({"tools": [{"name": "get_weather", "input_schema": {}}, {"name": "run_shell", "input_schema": {}}]}),
            json!({"tools": [{"functionDeclarations": [{"name": "get_weather"}, {"name": "run_shell"}]}]}),
        ];
        for body in bodies {
            for patterns in [&allow, &deny] {
                let mut b = body.clone();
                let v = request(&mut b, patterns, false);
                assert_eq!(v.refused, vec!["run_shell".to_string()], "{body}");
                assert_eq!(v.audit[0].action, "block");
                assert_eq!(v.audit[0].kind, "run_shell");
                assert_eq!(b, body, "a refused body is not changed");
            }
        }
    }

    #[test]
    fn strip_takes_refused_tools_out_and_tidies_what_is_left() {
        let patterns = list(&["function.get_weather"]);
        let mut body = json!({
            "tools": [{"type": "function", "function": {"name": "get_weather"}}, {"type": "function", "function": {"name": "run_shell"}}],
            "tool_choice": "auto"
        });
        let v = request(&mut body, &patterns, true);
        assert!(v.refused.is_empty() && v.changed);
        assert_eq!(v.audit[0].action, "strip");
        assert_eq!(body["tools"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["tool_choice"], "auto");

        let mut only_bad =
            json!({"tools": [{"functionDeclarations": [{"name": "run_shell"}]}], "toolConfig": {}});
        request(&mut only_bad, &patterns, true);
        assert_eq!(only_bad, json!({}));

        // Forcing a stripped tool would fail at the provider: refused instead.
        let mut forced = json!({
            "tools": [{"type": "function", "function": {"name": "run_shell"}}],
            "tool_choice": {"type": "function", "function": {"name": "run_shell"}}
        });
        let v = request(&mut forced, &patterns, true);
        assert_eq!(v.refused, vec!["run_shell".to_string()]);
        assert_eq!(v.audit[0].action, "block");
    }

    #[test]
    fn tool_calls_in_answers_are_refused_or_stripped_in_every_format() {
        let patterns = list(&["function.get_weather"]);
        let answers = [
            json!({"choices": [{"message": {"role": "assistant", "content": null, "tool_calls": [{"id": "1", "type": "function", "function": {"name": "run_shell", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}]}),
            json!({"type": "message", "content": [{"type": "text", "text": "ok"}, {"type": "tool_use", "id": "t", "name": "run_shell", "input": {}}], "stop_reason": "tool_use"}),
            json!({"output": [{"type": "function_call", "name": "run_shell", "arguments": "{}"}]}),
            json!({"candidates": [{"content": {"parts": [{"functionCall": {"name": "run_shell", "args": {}}}]}}]}),
        ];
        for a in answers {
            let mut blocked = a.clone();
            assert_eq!(
                answer(&mut blocked, &patterns, false).refused,
                vec!["run_shell".to_string()]
            );
            let mut stripped = a.clone();
            let v = answer(&mut stripped, &patterns, true);
            assert!(v.changed, "{a}");
            assert!(calls(&stripped).is_empty(), "{stripped}");
        }
        let mut chat = answers_first();
        answer(&mut chat, &patterns, true);
        assert_eq!(chat["choices"][0]["finish_reason"], "stop");
        assert!(chat["choices"][0]["message"].get("tool_calls").is_none());
    }

    fn answers_first() -> Value {
        json!({"choices": [{"message": {"role": "assistant", "content": null, "tool_calls": [{"id": "1", "type": "function", "function": {"name": "run_shell", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}]})
    }

    #[test]
    fn entry_names_are_checked() {
        assert_eq!(entry_name("github.x"), None);
        assert_eq!(entry_name("function.*"), Some(Ok(())));
        assert!(matches!(entry_name("function.a b"), Some(Err(_))));
    }
}
