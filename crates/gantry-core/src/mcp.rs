//! The MCP servers a policy names, and which of their tools a rule allows.
//!
//! Gantry shows every tool to a caller as `<server>.<tool>`. A server name holds no dot, so the first dot of a name
//! always splits it the same way, whatever the tool's own name holds.

use std::{collections::BTreeMap, path::Path};

use serde::Deserialize;

use crate::config::{base_url, is_private, line_of_key, list_lines};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerFile {
    name: String,
    url: String,
    #[serde(default)]
    headers_env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    allow_private: bool,
}

/// An upstream MCP server, as checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server {
    pub name: String,
    /// The server's MCP endpoint, for example `https://mcp.example.com/mcp`, without a trailing slash.
    pub url: String,
    /// (header name, environment variable). Only the variable's name is in the policy; its value is read at start.
    pub headers_env: Vec<(String, String)>,
    pub allow_private: bool,
}

/// Headers a credential may not use: Gantry sets these itself, or they belong to the connection or the session.
const RESERVED: &[&str] = &[
    "host",
    "content-type",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
];

/// A server name: letters, digits, dashes and underscores. No dot, so `<server>.<tool>` splits one way only.
fn server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether a rule's `tools:` list allows the tool a caller sees as `name` (`<server>.<tool>`).
/// `*` allows every tool, `<server>.*` every tool of one server, and anything else names one tool exactly.
pub fn tool_allowed(patterns: &[String], name: &str) -> bool {
    patterns.iter().any(|pattern| {
        pattern == "*"
            || pattern == name
            || pattern
                .strip_suffix(".*")
                .zip(name.split_once('.'))
                .is_some_and(|(server, (of, _))| server == of)
    })
}

/// Checks the `mcp:` list, each problem with its line.
pub(crate) fn servers(
    file: &Path,
    text: &str,
    list: &[ServerFile],
    errors: &mut Vec<String>,
) -> Vec<Server> {
    let lines = list_lines(text, "mcp");
    let mut out = Vec::new();
    for (i, entry) in list.iter().enumerate() {
        let line = lines.get(i).copied().unwrap_or(0);
        let until = lines.get(i + 1).copied().unwrap_or(usize::MAX);
        let at = |key: &str| format!("{}:{}", file.display(), line_of_key(text, key, line, until));
        if !server_name(&entry.name) {
            errors.push(format!(
                "{}: an MCP server name uses letters, digits, dashes and underscores only, at most 64 characters, and no dot: callers see its tools as <server>.<tool>.",
                at("name")
            ));
        }
        if list[..i].iter().any(|other| other.name == entry.name) {
            errors.push(format!(
                "{}: two MCP servers are named \"{}\". Each needs its own name, because tools are named and allowed by it.",
                at("name"),
                entry.name
            ));
        }
        let url = match base_url(&entry.url) {
            Ok(url) => url,
            Err(problem) => {
                errors.push(format!(
                    "{}: {}",
                    at("url"),
                    problem.replace("provider url", "MCP server url")
                ));
                continue;
            }
        };
        if is_private(&url) && !entry.allow_private {
            errors.push(format!(
                "{}: the MCP server url points at this machine or a private network. If that is intended, add `allow_private: true` to the server.",
                at("url")
            ));
        }
        let mut headers_env = Vec::new();
        for (header, variable) in entry.headers_env.iter().flatten() {
            let token = !header.is_empty()
                && header
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !token || RESERVED.contains(&header.to_ascii_lowercase().as_str()) {
                errors.push(format!(
                    "{}: headers_env names header \"{header}\", which a credential cannot use. Name a header such as Authorization or X-Api-Key.",
                    at("headers_env")
                ));
                continue;
            }
            let env_name = !variable.is_empty()
                && !variable.starts_with(|c: char| c.is_ascii_digit())
                && variable
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_');
            if !env_name {
                errors.push(format!(
                    "{}: headers_env gives header {header} the value \"{variable}\", which is not the name of an environment variable. Write the variable's name, for example {header}: GITHUB_MCP_TOKEN, and keep the value itself out of this file.",
                    at("headers_env")
                ));
                continue;
            }
            headers_env.push((header.clone(), variable.clone()));
        }
        out.push(Server {
            name: entry.name.clone(),
            url,
            headers_env,
            allow_private: entry.allow_private,
        });
    }
    out
}

/// Checks one rule's `tools:` list against the servers. `at` is where the list is written.
pub(crate) fn check_tools(
    at: &str,
    tools: &[String],
    list: &[ServerFile],
    errors: &mut Vec<String>,
) {
    if tools.iter().any(|t| t == "*") && tools.len() > 1 {
        errors.push(format!(
            "{at}: \"*\" already allows every MCP tool. List it alone, or list the tools by name."
        ));
    }
    let names: Vec<&str> = list.iter().map(|s| s.name.as_str()).collect();
    for tool in tools.iter().filter(|t| *t != "*") {
        let Some((server, name)) = tool.split_once('.').filter(|(_, n)| !n.is_empty()) else {
            errors.push(format!(
                "{at}: tool \"{tool}\" names no server. Write <server>.<tool>, for example github.create_issue, or <server>.* for every tool of one server."
            ));
            continue;
        };
        if !names.contains(&server) {
            let defined = if names.is_empty() {
                "No MCP server is defined: add it under mcp.".to_string()
            } else {
                format!("The MCP servers are: {}.", names.join(", "))
            };
            errors.push(format!(
                "{at}: tool \"{tool}\" is on MCP server \"{server}\", which is not defined under mcp. {defined}"
            ));
        } else if name.contains('*') && name != "*" {
            errors.push(format!(
                "{at}: tool \"{tool}\" holds a \"*\" inside its name. Name one tool exactly, or write {server}.* for every tool of the server."
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tool_allowed;

    #[test]
    fn a_pattern_allows_one_tool_a_server_or_everything() {
        let rule = vec!["github.create_issue".to_string(), "docs.*".to_string()];
        assert!(tool_allowed(&rule, "github.create_issue"));
        assert!(tool_allowed(&rule, "docs.search"));
        assert!(tool_allowed(&rule, "docs.a.b"));
        assert!(!tool_allowed(&rule, "github.delete_repo"));
        // `docs.*` is the server docs, not every server whose name starts with docs.
        assert!(!tool_allowed(&rule, "docsx.search"));
        assert!(!tool_allowed(&[], "docs.search"));
        assert!(tool_allowed(&["*".to_string()], "any.thing"));
    }
}
