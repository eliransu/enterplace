//! What people may do in their coding agents: skip permission checks (Claude Code's `bypassPermissions` mode,
//! `--dangerously-skip-permissions`), run in auto mode, and drive a web browser (Claude in Chrome and other browser
//! MCP servers). `coding_agents:` at the top of the policy sets each for the organization; the same block on a rule
//! overrides it for that rule's callers.
//!
//! Two places enforce it. The device agent writes Claude Code's managed settings from it (enterprise). The gateway
//! sees the tools each request offers the model, so it refuses (or strips) browser tools; a request carries no
//! reliable sign of the permission mode, so bypass and auto mode are enforced on the device alone.

use serde_json::{Map, Value, json};

/// The refusal code of a request offering browser tools the rule blocks.
pub const BROWSER_NOT_ALLOWED: &str = "browser_not_allowed";

/// How the record names the browser check.
pub const BROWSER_LABELS: crate::fntools::Labels = ("coding_agents", "browser");

/// MCP servers whose tools drive a web browser, by the name a coding agent gives them: Claude Code names a tool
/// `mcp__<server>__<tool>`. `claude-in-chrome` is Claude Code's own (`--chrome`); the rest are the common browser
/// servers under their documented names.
// ponytail: matched by server name; a browser server installed under another name is not seen at the gateway.
pub const BROWSER_SERVERS: &[&str] = &[
    "claude-in-chrome",
    "playwright",
    "puppeteer",
    "chrome-devtools",
    "browserbase",
    "browsermcp",
];

/// One control: not said (left as it is), allowed, or blocked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Control {
    #[default]
    Unset,
    Allow,
    Block,
}

impl Control {
    pub fn word(self) -> Option<&'static str> {
        match self {
            Self::Unset => None,
            Self::Allow => Some("allow"),
            Self::Block => Some("block"),
        }
    }

    fn parse(word: Option<&str>) -> Result<Self, String> {
        match word {
            None => Ok(Self::Unset),
            Some("allow") => Ok(Self::Allow),
            Some("block") => Ok(Self::Block),
            Some(other) => Err(other.to_string()),
        }
    }
}

/// The three controls. The names are the policy's keys, the device profile's and the console's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodingAgents {
    pub bypass_permissions: Control,
    pub auto_mode: Control,
    pub browser: Control,
}

/// The keys `coding_agents:` takes.
pub const KEYS: [&str; 3] = ["bypass_permissions", "auto_mode", "browser"];

impl CodingAgents {
    /// Each control this one sets, else the one under it: a rule's over the policy's.
    pub fn over(self, under: Self) -> Self {
        let pick = |a: Control, b: Control| if a == Control::Unset { b } else { a };
        Self {
            bypass_permissions: pick(self.bypass_permissions, under.bypass_permissions),
            auto_mode: pick(self.auto_mode, under.auto_mode),
            browser: pick(self.browser, under.browser),
        }
    }

    fn fields(self) -> [(&'static str, Control); 3] {
        [
            (KEYS[0], self.bypass_permissions),
            (KEYS[1], self.auto_mode),
            (KEYS[2], self.browser),
        ]
    }

    /// As the device profile and the console send it: only the controls set.
    pub fn to_json(self) -> Value {
        let map: Map<String, Value> = self
            .fields()
            .into_iter()
            .filter_map(|(k, c)| c.word().map(|w| (k.to_string(), json!(w))))
            .collect();
        Value::Object(map)
    }

    /// From a profile's or the policy's `coding_agents` object. `Err` names the key and the word it does not take.
    pub fn from_json(value: &Value) -> Result<Self, String> {
        let mut out = Self::default();
        let Some(map) = value.as_object() else {
            return if value.is_null() {
                Ok(out)
            } else {
                Err("coding_agents is a map: bypass_permissions, auto_mode and browser, each allow or block".into())
            };
        };
        for (key, word) in map {
            let control = Control::parse(word.as_str())
                .ok()
                .filter(|_| word.is_string())
                .ok_or_else(|| {
                    format!("coding_agents.{key} is {word}. Write allow or block, or leave it out to leave it as it is")
                })?;
            match key.as_str() {
                "bypass_permissions" => out.bypass_permissions = control,
                "auto_mode" => out.auto_mode = control,
                "browser" => out.browser = control,
                other => {
                    return Err(format!(
                        "coding_agents has no setting \"{other}\". It takes bypass_permissions, auto_mode and browser, each allow or block"
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// Whether `tool` (as a request declares it) is a browser server's tool.
pub fn is_browser_tool(tool: &str) -> bool {
    tool.strip_prefix("mcp__")
        .and_then(|rest| rest.split_once("__"))
        .is_some_and(|(server, _)| BROWSER_SERVERS.contains(&server))
}

/// The refusal message: the tools, the rule, and the fixes on both sides.
pub fn browser_refusal(rule: &str, tools: &[String]) -> String {
    format!(
        "Refused: rule \"{rule}\" does not allow coding agents to use a browser, and this request offers browser tool {}. In Claude Code turn Chrome off (/chrome, or start without --chrome) or remove the browser MCP server, then send again. An Enterplace admin can allow it with coding_agents: {{ browser: allow }} on the rule or the policy.",
        tools
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_tools_are_known_by_server_name() {
        assert!(is_browser_tool("mcp__claude-in-chrome__navigate"));
        assert!(is_browser_tool("mcp__playwright__browser_click"));
        assert!(!is_browser_tool("mcp__docs__open_in_chrome"));
        assert!(!is_browser_tool("claude-in-chrome"));
        assert!(!is_browser_tool("WebFetch"));
    }

    #[test]
    fn a_rule_overrides_only_what_it_sets_and_json_round_trips() -> Result<(), String> {
        let org = CodingAgents::from_json(&json!({"browser": "block", "auto_mode": "block"}))?;
        let rule = CodingAgents::from_json(&json!({"browser": "allow"}))?;
        let both = rule.over(org);
        assert_eq!(both.browser, Control::Allow);
        assert_eq!(both.auto_mode, Control::Block);
        assert_eq!(both.bypass_permissions, Control::Unset);
        assert_eq!(
            both.to_json(),
            json!({"auto_mode": "block", "browser": "allow"})
        );
        assert_eq!(CodingAgents::from_json(&both.to_json())?, both);
        let bad = CodingAgents::from_json(&json!({"browser": "deny"})).err();
        assert!(bad.is_some_and(|e| e.contains("allow or block")));
        let bad = CodingAgents::from_json(&json!({"chrome": "block"})).err();
        assert!(bad.is_some_and(|e| e.contains("\"chrome\"")));
        Ok(())
    }
}
