//! The MCP servers a policy names, and which of their tools, prompts and resources a rule allows.
//!
//! Enterplace shows every tool to a caller as `<server>.<tool>`. A server name holds no dot, so the first dot of a name
//! always splits it the same way, whatever the tool's own name holds. Prompts are named the same way, and a
//! resource is allowed as `<server>.<uri>`.

use std::{collections::BTreeMap, path::Path};

use serde::Deserialize;

use crate::config::{base_url, is_private, line_of_key, list_lines};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerFile {
    name: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    call_price_usd: Option<f64>,
    #[serde(default)]
    tool_prices: Option<BTreeMap<String, f64>>,
    #[serde(default)]
    token_url: Option<String>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    headers_env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    allow_private: bool,
    #[serde(default)]
    user_auth: Option<String>,
    #[serde(default)]
    user_headers: Option<Vec<String>>,
    #[serde(default)]
    oauth_client_id: Option<String>,
    #[serde(default)]
    oauth_client_secret_env: Option<String>,
    #[serde(default)]
    oauth_scopes: Vec<String>,
    #[serde(default)]
    tool_changes: Option<String>,
    #[serde(default)]
    disabled_tools: Vec<String>,
}

/// How each person signs in to an upstream server themselves, so a call runs with their own credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserAuth {
    /// Each person gives their own value for these headers, for example their own `Authorization` token.
    Headers(Vec<String>),
    /// Each person signs in at the server's OAuth authorization server once; Enterplace keeps and refreshes the token.
    OAuth {
        /// Registered with the authorization server by hand. `None` registers Enterplace dynamically (RFC 7591).
        client_id: Option<String>,
        /// The environment variable that holds the client secret of a confidential client.
        client_secret_env: Option<String>,
        scopes: Vec<String>,
    },
    /// Enterplace trades the token the caller holds for one the server takes, at the identity provider's token
    /// endpoint, on every person's behalf: RFC 8693 token exchange, or the on-behalf-of flow.
    Exchange {
        /// `true` sends the on-behalf-of form (`grant_type=jwt-bearer`, `requested_token_use=on_behalf_of`).
        on_behalf_of: bool,
        token_url: String,
        client_id: String,
        client_secret_env: Option<String>,
        scopes: Vec<String>,
        audience: Option<String>,
        resource: Option<String>,
    },
}

/// How Enterplace reaches an upstream server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    /// MCP's Streamable HTTP: one POST per message.
    #[default]
    Http,
    /// The older HTTP+SSE transport (MCP 2024-11-05): a GET that stays open for answers, and a POST per message
    /// to the endpoint the server names on it.
    Sse,
    /// A process the gateway starts, spoken to on its standard input and output.
    Stdio {
        command: String,
        args: Vec<String>,
        /// (the child's variable, the gateway's variable its value is read from).
        env: Vec<(String, String)>,
    },
}

impl Transport {
    pub fn word(&self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::Sse => "sse",
            Transport::Stdio { .. } => "stdio",
        }
    }
}

/// The environment variable that lists the commands a gateway may start as stdio MCP servers, comma separated,
/// each an absolute path. It is read from the gateway's environment only, never from the policy: whoever can
/// change the policy cannot choose what the gateway runs.
pub const STDIO_ALLOW_ENV: &str = "ENTERPLACE_MCP_STDIO_ALLOW";

/// What Enterplace does when a server changes a tool's description or schema after it was first seen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ToolChanges {
    /// Record the change and serve the new tool.
    #[default]
    Record,
    /// Record the change and hide the tool, refusing calls to it, until an admin approves it.
    Block,
}

/// An upstream MCP server, as checked.
#[derive(Clone, Debug, PartialEq)]
pub struct Server {
    pub name: String,
    /// The server's MCP endpoint, for example `https://mcp.example.com/mcp`, without a trailing slash. Empty for
    /// a stdio server.
    pub url: String,
    pub transport: Transport,
    /// What one call of any tool of this server costs, in US dollars, unless `tool_prices` names the tool.
    pub call_price_usd: Option<f64>,
    /// (tool, US dollars per call), by the server's own tool names.
    pub tool_prices: Vec<(String, f64)>,
    /// (header name, environment variable). Only the variable's name is in the policy; its value is read at start.
    pub headers_env: Vec<(String, String)>,
    pub allow_private: bool,
    /// `None`: every call uses the server's shared credential from `headers_env`.
    pub user_auth: Option<UserAuth>,
    pub tool_changes: ToolChanges,
    /// Tools switched off in the console's tool catalog, by the server's own names: listed to no one and refused to
    /// everyone, whatever a rule allows.
    pub disabled_tools: Vec<String>,
}

impl Server {
    /// Whether the tool (the server's own name for it) is switched off.
    pub fn tool_disabled(&self, tool: &str) -> bool {
        self.disabled_tools.iter().any(|t| t == tool)
    }
}

/// What a rule allows of the MCP gateway besides tools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpRule {
    /// Prompts, as `<server>.<prompt>`, `<server>.*` or `*`. Empty allows none.
    pub prompts: Vec<String>,
    /// Resources, as `<server>.<uri>`, `<server>.*` or `*`. Empty allows none.
    pub resources: Vec<String>,
    /// Tools whose calls wait for an admin's approval in the console, in the patterns of `tools`.
    pub approve: Vec<String>,
    /// How long a call waits for that approval before it is refused.
    pub approval_timeout_seconds: u64,
    /// The MCP client applications that may use the gateway under this rule. Empty lets every client.
    pub clients: Vec<String>,
    /// Never from the policy: lists a request adds (the key's `mcp_tools`, the `x-enterplace-mcp-tools` header), each of
    /// which must also allow a tool. They only narrow what `tools` allows.
    pub narrow: Vec<Vec<String>>,
}

pub const DEFAULT_APPROVAL_TIMEOUT: u64 = 300;

impl Default for McpRule {
    fn default() -> Self {
        Self {
            prompts: Vec::new(),
            resources: Vec::new(),
            approve: Vec::new(),
            approval_timeout_seconds: DEFAULT_APPROVAL_TIMEOUT,
            clients: Vec::new(),
            narrow: Vec::new(),
        }
    }
}

/// Whether a rule's `mcp_clients:` list lets a client connect. `name` is what the client called itself at
/// `initialize` (`clientInfo.name`), `user_agent` its `user-agent` header and `oauth_client` the OAuth client it
/// signed in through. An entry matches a name, or the product of a user agent (the part before the first `/` or
/// space), without regard to case, and ends in `*` to match a prefix; `oauth:<client id>` matches the OAuth client
/// exactly. An empty list lets every client.
pub fn client_allowed(
    patterns: &[String],
    name: Option<&str>,
    user_agent: Option<&str>,
    oauth_client: Option<&str>,
) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let product = user_agent.map(|ua| {
        ua.split(|c: char| c == '/' || c.is_whitespace())
            .next()
            .unwrap_or(ua)
    });
    patterns.iter().any(|pattern| {
        if let Some(id) = pattern.strip_prefix("oauth:") {
            return oauth_client == Some(id);
        }
        let pattern = pattern.to_ascii_lowercase();
        [name, product].into_iter().flatten().any(|given| {
            let given = given.to_ascii_lowercase();
            match pattern.strip_suffix('*') {
                Some(prefix) => given.starts_with(prefix),
                None => given == pattern,
            }
        })
    })
}

/// A virtual MCP server: chosen tools of several servers, served at `/mcp/<name>`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleFile {
    name: String,
    tools: Vec<String>,
    #[serde(default)]
    teams: Vec<String>,
}

/// A virtual MCP server, as checked. A caller still sees only what their rule allows of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub name: String,
    pub tools: Vec<String>,
    /// The teams that may connect to it. Empty lets every team.
    pub teams: Vec<String>,
}

/// Headers a credential may not use: Enterplace sets these itself, or they belong to the connection or the session.
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

/// A tool as its server names it: not empty, no `*`, no white space. A dot is allowed: servers use them.
fn own_tool_name(tool: &str) -> bool {
    !tool.is_empty()
        && tool.len() <= 128
        && !tool.contains('*')
        && !tool.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Whether a rule's `tools:` list allows the tool a caller sees as `name` (`<server>.<tool>`).
/// `*` allows every tool, `<server>.*` every tool of one server, and anything else names one tool exactly.
/// An entry written `!<pattern>` denies what it matches, whatever else allows it.
pub fn tool_allowed(patterns: &[String], name: &str) -> bool {
    let denied = patterns
        .iter()
        .filter_map(|p| p.strip_prefix('!'))
        .any(|p| pattern_matches(p, name));
    !denied
        && patterns
            .iter()
            .filter(|p| !p.starts_with('!'))
            .any(|p| pattern_matches(p, name))
}

/// Whether `entry` is a well formed MCP tool pattern for a list that narrows (a key's `mcp_tools`, the
/// `x-enterplace-mcp-tools` header): `*`, `<server>.*`, `<server>.<tool>`, each optionally `!` to deny.
pub fn narrowing_entry(entry: &str) -> bool {
    let bare = entry.strip_prefix('!').unwrap_or(entry);
    bare == "*"
        || bare.split_once('.').is_some_and(|(server, tool)| {
            server_name(server)
                && !tool.is_empty()
                && tool.len() <= 128
                && (tool == "*" || !tool.contains('*'))
                && !tool
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == ',')
        })
}

/// One `tools:` entry against one name: `*`, `<server>.*`, or the name exactly.
pub fn pattern_matches(pattern: &str, name: &str) -> bool {
    pattern == "*"
        || pattern == name
        || pattern
            .strip_suffix(".*")
            .zip(name.split_once('.'))
            .is_some_and(|(server, (of, _))| server == of)
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
        if entry.name == crate::fntools::NAMESPACE {
            errors.push(format!(
                "{}: an MCP server cannot be named \"{}\": `tools:` entries written function.<name> name the function tools a request declares. Rename the server.",
                at("name"),
                entry.name
            ));
        }
        if list[..i].iter().any(|other| other.name == entry.name) {
            errors.push(format!(
                "{}: two MCP servers are named \"{}\". Each needs its own name, because tools are named and allowed by it.",
                at("name"),
                entry.name
            ));
        }
        if entry.name == "sessions" {
            errors.push(format!(
                "{}: an MCP server cannot be named \"sessions\": /admin/mcp/sessions lists the MCP sessions. Rename the server.",
                at("name")
            ));
        }
        let (url, transport) = match transport(entry, &at, errors) {
            Some(found) => found,
            None => continue,
        };
        let mut tool_prices = Vec::new();
        for (what, price) in entry
            .call_price_usd
            .iter()
            .map(|p| ("call_price_usd".to_string(), *p))
            .chain(
                entry
                    .tool_prices
                    .iter()
                    .flatten()
                    .map(|(tool, p)| (format!("tool_prices: {tool}"), *p)),
            )
        {
            if !(price.is_finite() && (0.0..=1000.0).contains(&price)) {
                errors.push(format!(
                    "{}: {what} is {price}. Write what one call costs in US dollars, from 0 to 1000, for example 0.002.",
                    at(what.split(':').next().unwrap_or("tool_prices"))
                ));
            }
        }
        for (tool, price) in entry.tool_prices.iter().flatten() {
            if tool.is_empty() || tool.contains('*') {
                errors.push(format!(
                    "{}: tool_prices names \"{tool}\". Name each tool as the server names it, for example create_issue, and set call_price_usd for every other tool of the server.",
                    at("tool_prices")
                ));
            }
            tool_prices.push((tool.clone(), *price));
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
        let user_auth = user_auth(entry, &headers_env, &at("user_auth"), errors);
        let tool_changes = match entry.tool_changes.as_deref() {
            None | Some("record") => ToolChanges::Record,
            Some("block") => ToolChanges::Block,
            Some(other) => {
                errors.push(format!(
                    "{}: tool_changes is \"{other}\". Write record (record a changed tool and serve it) or block (hide it until an admin approves it).",
                    at("tool_changes")
                ));
                ToolChanges::Record
            }
        };
        if matches!(transport, Transport::Stdio { .. })
            && (user_auth.is_some() || !headers_env.is_empty())
        {
            errors.push(format!(
                "{}: a stdio MCP server takes no HTTP headers, so headers_env and user_auth do not apply to it. Pass its credential in env, as <the process's variable>: <the gateway's variable>.",
                at("transport")
            ));
        }
        for tool in &entry.disabled_tools {
            if !own_tool_name(tool) {
                errors.push(format!(
                    "{}: disabled_tools names \"{tool}\". Name each tool to switch off as the server lists it, for example delete_repo, with no server name and no *.",
                    at("disabled_tools")
                ));
            }
        }
        out.push(Server {
            name: entry.name.clone(),
            url,
            transport,
            call_price_usd: entry.call_price_usd,
            tool_prices,
            headers_env,
            allow_private: entry.allow_private,
            user_auth,
            tool_changes,
            disabled_tools: entry.disabled_tools.clone(),
        });
    }
    out
}

/// A server's address and how it is reached: `url` with `transport: http` (the default) or `sse`, or `command`
/// with `transport: stdio`.
fn transport(
    entry: &ServerFile,
    at: &dyn Fn(&str) -> String,
    errors: &mut Vec<String>,
) -> Option<(String, Transport)> {
    let word = entry
        .transport
        .as_deref()
        .unwrap_or(if entry.command.is_some() {
            "stdio"
        } else {
            "http"
        });
    if word == "stdio" {
        if entry.url.is_some() {
            errors.push(format!(
                "{}: a stdio MCP server is a process the gateway starts, so it has no url. Remove url, or remove command and transport to reach the server over HTTP.",
                at("url")
            ));
        }
        let Some(command) = entry.command.clone().filter(|c| Path::new(c).is_absolute()) else {
            errors.push(format!(
                "{}: a stdio MCP server needs command, the absolute path of the program to start, for example /usr/local/bin/mcp-server-git. The gateway starts it only when its own environment lists that path in {STDIO_ALLOW_ENV}.",
                at("command")
            ));
            return None;
        };
        let mut env = Vec::new();
        for (child, variable) in entry.env.iter().flatten() {
            let name = |v: &str| {
                !v.is_empty()
                    && !v.starts_with(|c: char| c.is_ascii_digit())
                    && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            };
            if !name(child) || !name(variable) {
                errors.push(format!(
                    "{}: env gives the process {child} from \"{variable}\". Write <the process's variable>: <the gateway's variable>, both names of environment variables, and keep the value itself out of this file.",
                    at("env")
                ));
                continue;
            }
            env.push((child.clone(), variable.clone()));
        }
        return Some((
            String::new(),
            Transport::Stdio {
                command,
                args: entry.args.clone(),
                env,
            },
        ));
    }
    if entry.command.is_some() || !entry.args.is_empty() || entry.env.is_some() {
        errors.push(format!(
            "{}: command, args and env belong to a stdio MCP server. Add `transport: stdio`, or remove them.",
            at("command")
        ));
    }
    let kind = match word {
        "http" => Transport::Http,
        "sse" => Transport::Sse,
        other => {
            errors.push(format!(
                "{}: transport is \"{other}\". Write http (Streamable HTTP, the default), sse (the older HTTP+SSE transport) or stdio (a process the gateway starts).",
                at("transport")
            ));
            Transport::Http
        }
    };
    let Some(given) = &entry.url else {
        errors.push(format!(
            "{}: MCP server \"{}\" has no url. Add the server's MCP endpoint, for example url: https://mcp.example.com/mcp.",
            at("name"),
            entry.name
        ));
        return None;
    };
    let url = match base_url(given) {
        Ok(url) => url,
        Err(problem) => {
            errors.push(format!(
                "{}: {}",
                at("url"),
                problem.replace("provider url", "MCP server url")
            ));
            return None;
        }
    };
    if is_private(&url) && !entry.allow_private {
        errors.push(format!(
            "{}: the MCP server url points at this machine or a private network. If that is intended, add `allow_private: true` to the server.",
            at("url")
        ));
    }
    Some((url, kind))
}

/// A server's `user_auth`, checked against its other fields.
fn user_auth(
    entry: &ServerFile,
    shared: &[(String, String)],
    at: &str,
    errors: &mut Vec<String>,
) -> Option<UserAuth> {
    let oauth_fields = entry.oauth_client_id.is_some()
        || entry.oauth_client_secret_env.is_some()
        || !entry.oauth_scopes.is_empty();
    let auth = match entry.user_auth.as_deref() {
        None => None,
        Some("headers") => {
            let headers = entry
                .user_headers
                .clone()
                .unwrap_or_else(|| vec!["Authorization".to_string()]);
            for header in &headers {
                let token = !header.is_empty()
                    && header
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
                if !token || RESERVED.contains(&header.to_ascii_lowercase().as_str()) {
                    errors.push(format!(
                        "{at}: user_headers names header \"{header}\", which a credential cannot use. Name a header such as Authorization or X-Api-Key."
                    ));
                }
            }
            Some(UserAuth::Headers(headers))
        }
        Some("oauth") => {
            if let Some(variable) = &entry.oauth_client_secret_env
                && (variable.is_empty()
                    || !variable
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            {
                errors.push(format!(
                    "{at}: oauth_client_secret_env is \"{variable}\", which is not the name of an environment variable. Write the variable's name and keep the secret itself out of this file."
                ));
            }
            if entry.oauth_client_secret_env.is_some() && entry.oauth_client_id.is_none() {
                errors.push(format!(
                    "{at}: oauth_client_secret_env is set without oauth_client_id. Add the client ID the secret belongs to, or remove both to let Enterplace register itself."
                ));
            }
            Some(UserAuth::OAuth {
                client_id: entry.oauth_client_id.clone(),
                client_secret_env: entry.oauth_client_secret_env.clone(),
                scopes: entry.oauth_scopes.clone(),
            })
        }
        Some(word @ ("token_exchange" | "on_behalf_of")) => {
            let token_url = entry.token_url.clone().unwrap_or_default();
            match base_url(&token_url) {
                Ok(_) if entry.oauth_client_id.is_some() => {}
                _ => errors.push(format!(
                    "{at}: user_auth: {word} needs token_url, the identity provider's token endpoint (an https URL), and oauth_client_id, the client Enterplace is registered as there."
                )),
            }
            if let Some(variable) = &entry.oauth_client_secret_env
                && (variable.is_empty()
                    || !variable
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            {
                errors.push(format!(
                    "{at}: oauth_client_secret_env is \"{variable}\", which is not the name of an environment variable. Write the variable's name and keep the secret itself out of this file."
                ));
            }
            Some(UserAuth::Exchange {
                on_behalf_of: word == "on_behalf_of",
                token_url,
                client_id: entry.oauth_client_id.clone().unwrap_or_default(),
                client_secret_env: entry.oauth_client_secret_env.clone(),
                scopes: entry.oauth_scopes.clone(),
                audience: entry.audience.clone(),
                resource: entry.resource.clone(),
            })
        }
        Some(other) => {
            errors.push(format!(
                "{at}: user_auth is \"{other}\". Write headers (each person gives their own header values), oauth (each person signs in at the server once), token_exchange (Enterplace trades the caller's token for the server's, RFC 8693) or on_behalf_of."
            ));
            None
        }
    };
    let exchange = matches!(auth, Some(UserAuth::Exchange { .. }));
    if (entry.token_url.is_some() || entry.audience.is_some() || entry.resource.is_some())
        && !exchange
    {
        errors.push(format!(
            "{at}: token_url, audience or resource is set and user_auth is not token_exchange or on_behalf_of. Add one of them as user_auth, or remove the fields."
        ));
    }
    if entry.user_headers.is_some() && !matches!(auth, Some(UserAuth::Headers(_))) {
        errors.push(format!(
            "{at}: user_headers is set and user_auth is not headers. Add `user_auth: headers`, or remove user_headers."
        ));
    }
    if oauth_fields && !matches!(auth, Some(UserAuth::OAuth { .. })) && !exchange {
        errors.push(format!(
            "{at}: oauth_client_id, oauth_client_secret_env or oauth_scopes is set and user_auth is not oauth. Add `user_auth: oauth`, or remove them."
        ));
    }
    // A header sent from both places would carry the shared credential and the person's at once.
    let personal: Vec<String> = match &auth {
        Some(UserAuth::Headers(headers)) => {
            headers.iter().map(|h| h.to_ascii_lowercase()).collect()
        }
        Some(UserAuth::OAuth { .. } | UserAuth::Exchange { .. }) => {
            vec!["authorization".to_string()]
        }
        None => Vec::new(),
    };
    for (header, _) in shared {
        if personal.contains(&header.to_ascii_lowercase()) {
            errors.push(format!(
                "{at}: header {header} is in headers_env and is also each person's own under user_auth. Remove it from headers_env: with user_auth every call carries the caller's own."
            ));
        }
    }
    auth
}

/// Checks one rule's `tools:` list against the servers. `at` is where the list is written.
pub(crate) fn check_tools(
    at: &str,
    tools: &[String],
    list: &[ServerFile],
    errors: &mut Vec<String>,
) {
    // function.<name> entries are the function tools a request declares, not MCP tools: checked on their own.
    let mut mcp = Vec::new();
    for tool in tools {
        let bare = tool.strip_prefix('!').unwrap_or(tool);
        match crate::fntools::entry_name(bare) {
            Some(Ok(())) => {}
            Some(Err(why)) => errors.push(format!("{at}: \"{tool}\": {why}")),
            None => mcp.push(bare.to_string()),
        }
    }
    // A deny entry next to "*" is how "everything but" is written, so only allow entries count against "*".
    let allow = tools.iter().filter(|t| !t.starts_with('!')).count();
    if tools.iter().any(|t| t == "*") && allow > 1 {
        errors.push(format!(
            "{at}: \"*\" already allows every MCP tool and function tool. List it alone, or list them by name (deny entries written !<name> may stand next to it)."
        ));
    }
    let mcp: Vec<String> = mcp.into_iter().filter(|t| t != "*").collect();
    check_names(at, "tool", &mcp, list, errors);
}

/// Checks a list of `<server>.<name>` patterns (tools, prompts or resources) against the servers.
fn check_names(
    at: &str,
    noun: &str,
    tools: &[String],
    list: &[ServerFile],
    errors: &mut Vec<String>,
) {
    if tools.iter().any(|t| t == "*") && tools.len() > 1 {
        errors.push(format!(
            "{at}: \"*\" already allows every MCP {noun}. List it alone, or list them by name."
        ));
    }
    let names: Vec<&str> = list.iter().map(|s| s.name.as_str()).collect();
    for tool in tools.iter().filter(|t| *t != "*") {
        let Some((server, name)) = tool.split_once('.').filter(|(_, n)| !n.is_empty()) else {
            errors.push(format!(
                "{at}: {noun} \"{tool}\" names no server. Write <server>.<{noun}>, for example github.create_issue, or <server>.* for every {noun} of one server."
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
                "{at}: {noun} \"{tool}\" is on MCP server \"{server}\", which is not defined under mcp. {defined}"
            ));
        } else if name.contains('*') && name != "*" {
            errors.push(format!(
                "{at}: {noun} \"{tool}\" holds a \"*\" inside its name. Name one exactly, or write {server}.* for every {noun} of the server."
            ));
        }
    }
}

/// What a rule file says of MCP besides `tools`, as `config` reads it.
pub(crate) struct RuleFields<'a> {
    pub prompts: &'a [String],
    pub resources: &'a [String],
    pub approve_tools: &'a [String],
    pub approval_timeout_seconds: Option<i64>,
    pub mcp_clients: &'a [String],
}

/// Checks a rule's prompts, resources and approvals. `at` gives where each key is written.
pub(crate) fn rule(
    at: &dyn Fn(&str) -> String,
    fields: &RuleFields<'_>,
    list: &[ServerFile],
    errors: &mut Vec<String>,
) -> McpRule {
    check_names(&at("prompts"), "prompt", fields.prompts, list, errors);
    check_names(&at("resources"), "resource", fields.resources, list, errors);
    check_names(
        &at("approve_tools"),
        "tool",
        fields.approve_tools,
        list,
        errors,
    );
    let approval_timeout_seconds = match fields.approval_timeout_seconds {
        None => DEFAULT_APPROVAL_TIMEOUT,
        Some(seconds) if (10..=3600).contains(&seconds) => seconds.unsigned_abs(),
        Some(seconds) => {
            errors.push(format!(
                "{}: approval_timeout_seconds is {seconds}. Write a number of seconds from 10 to 3600; a call waits that long for an admin before it is refused.",
                at("approval_timeout_seconds")
            ));
            DEFAULT_APPROVAL_TIMEOUT
        }
    };
    for client in fields.mcp_clients {
        let bare = client.strip_prefix("oauth:").unwrap_or(client);
        let inner = bare.strip_suffix('*').unwrap_or(bare);
        if inner.is_empty()
            || inner.len() > 200
            || inner.contains('*')
            || (client.starts_with("oauth:") && bare.ends_with('*'))
        {
            errors.push(format!(
                "{}: \"{client}\" is not an MCP client. Write the name a client gives itself (for example claude-code), a prefix ending in * (cursor*), or oauth:<client id> for the OAuth client it signs in through.",
                at("mcp_clients")
            ));
        }
    }
    McpRule {
        clients: fields.mcp_clients.to_vec(),
        prompts: fields.prompts.to_vec(),
        resources: fields.resources.to_vec(),
        approve: fields.approve_tools.to_vec(),
        approval_timeout_seconds,
        narrow: Vec::new(),
    }
}

/// Checks the `mcp_bundles:` list, each problem with its line.
pub(crate) fn bundles(
    file: &Path,
    text: &str,
    list: &[BundleFile],
    servers: &[ServerFile],
    errors: &mut Vec<String>,
) -> Vec<Bundle> {
    let lines = list_lines(text, "mcp_bundles");
    let mut out = Vec::new();
    for (i, entry) in list.iter().enumerate() {
        let line = lines.get(i).copied().unwrap_or(0);
        let until = lines.get(i + 1).copied().unwrap_or(usize::MAX);
        let at = |key: &str| format!("{}:{}", file.display(), line_of_key(text, key, line, until));
        if !server_name(&entry.name) {
            errors.push(format!(
                "{}: an MCP bundle name uses letters, digits, dashes and underscores only, at most 64 characters: it is served at /mcp/<name>.",
                at("name")
            ));
        }
        if list[..i].iter().any(|other| other.name == entry.name) {
            errors.push(format!(
                "{}: two MCP bundles are named \"{}\". Each needs its own name, because each is served at /mcp/<name>.",
                at("name"),
                entry.name
            ));
        }
        if entry.tools.is_empty() {
            errors.push(format!(
                "{}: MCP bundle \"{}\" lists no tools. List the tools it serves, as <server>.<tool> or <server>.*.",
                at("tools"),
                entry.name
            ));
        }
        check_names(&at("tools"), "tool", &entry.tools, servers, errors);
        out.push(Bundle {
            name: entry.name.clone(),
            tools: entry.tools.clone(),
            teams: entry.teams.clone(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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

#[cfg(test)]
mod checks {
    use super::*;

    fn server(fields: &str) -> Result<(Vec<Server>, Vec<String>), String> {
        let text = format!("mcp:\n  - name: gh\n    url: https://mcp.example.com/mcp\n{fields}");
        #[derive(Deserialize)]
        struct File {
            mcp: Vec<ServerFile>,
        }
        let file: File = serde_saphyr::from_str(&text).map_err(|e| e.to_string())?;
        let mut errors = Vec::new();
        let servers = servers(Path::new("p.yaml"), &text, &file.mcp, &mut errors);
        Ok((servers, errors))
    }

    #[test]
    fn user_auth_and_tool_changes_load_and_their_mistakes_are_named() -> Result<(), String> {
        let (servers, errors) =
            server("    user_auth: oauth\n    oauth_scopes: [repo]\n    tool_changes: block\n")?;
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(servers[0].tool_changes, ToolChanges::Block);
        assert!(
            matches!(&servers[0].user_auth, Some(UserAuth::OAuth { scopes, client_id: None, .. }) if scopes == &["repo"])
        );
        let (servers, _) = server("    user_auth: headers\n")?;
        assert_eq!(
            servers[0].user_auth,
            Some(UserAuth::Headers(vec!["Authorization".into()]))
        );
        let (_, errors) =
            server("    user_auth: headers\n    headers_env: { Authorization: GH }\n")?;
        assert!(
            errors
                .iter()
                .any(|e| e.contains("Remove it from headers_env")),
            "{errors:?}"
        );
        let (_, errors) = server("    user_auth: magic\n    tool_changes: maybe\n")?;
        assert!(
            errors.iter().any(|e| e.contains("user_auth is \"magic\"")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("tool_changes is \"maybe\"")),
            "{errors:?}"
        );
        let (_, errors) = server("    oauth_scopes: [repo]\n")?;
        assert!(
            errors.iter().any(|e| e.contains("user_auth is not oauth")),
            "{errors:?}"
        );
        Ok(())
    }
}
