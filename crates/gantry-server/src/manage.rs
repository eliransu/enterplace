//! Every route of the admin API in one table, the dispatcher that sends a call to the module that serves it, the
//! OpenAPI 3.1 document built from the table (`GET /admin/openapi.json`), and the routes that manage the policy a
//! part at a time: providers, models and prices, rules, guardrails, MCP servers, aliases, budgets and teams, and
//! usage summed by any dimension (`GET /admin/usage`).
//!
//! The table is the one list of what the admin API serves: a path it does not hold is refused with `unknown_route`
//! before any module sees it, and the document is made from it, so the two cannot drift. A policy change made here is
//! a new policy version exactly as `PUT /admin/policy` makes one: checked as `gantry check` checks a file, recorded
//! in the audit chain first, live on every gateway within 2 seconds or waiting for a second admin.
//!
//! An embedding binary adds its own routes through [`AdminApi`] (Gantry Enterprise: alert rules). The dispatcher
//! checks the caller, the permission and writes the admin record for them as for its own.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use gantry_core::{
    config, id,
    insights::{self, Query, Stats},
    policy::{Permission, Role},
    store::Pending,
    versions,
};
use serde_json::{Map, Value, json};

use crate::{
    AppState, ClientAddr, DECISION, Refusal,
    admin::{self, Call, blocking, json_response, reach, record, refused},
    caller_key, policy_api, read_body, teams_api,
};

/// Which module serves a route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Module {
    /// `admin.rs`: keys, kill switches, credentials, explain, guardrail backtest.
    Keys,
    /// `policy_api.rs`: the whole policy and its versions.
    Policy,
    /// This module.
    Manage,
    /// `teams_api.rs`: the policy's `teams:` and the teams keys name.
    Teams,
}

/// One route of the admin API.
#[derive(Clone, Copy, Debug)]
pub struct AdminRoute {
    pub method: &'static str,
    /// Below the gateway's root, with `{name}` for one path segment, as axum writes it.
    pub path: &'static str,
    /// The `action` of its admin record.
    pub action: &'static str,
    /// What the caller's role needs. `None`: any role (the route checks more itself, as `revoke_own_key` does).
    pub permission: Option<Permission>,
    pub summary: &'static str,
}

const fn r(
    method: &'static str,
    path: &'static str,
    action: &'static str,
    permission: Option<Permission>,
    summary: &'static str,
) -> AdminRoute {
    AdminRoute {
        method,
        path,
        action,
        permission,
        summary,
    }
}

use Permission::{
    Credentials, EditPolicy, IssueKeys, Kill, RevokeKeys, SeeKeys, SeeRecords, SeeSpend,
};

/// Every route of the open source admin API, with the module that serves it.
pub(crate) const ROUTES: &[(Module, AdminRoute)] = &[
    (
        Module::Manage,
        r(
            "GET",
            "/admin/openapi.json",
            "openapi",
            None,
            "This document. Needs no key.",
        ),
    ),
    (
        Module::Keys,
        r(
            "GET",
            "/admin/explain",
            "explain",
            Some(SeeSpend),
            "Why a request would be allowed or refused, and every limit with its spend",
        ),
    ),
    (
        Module::Keys,
        r(
            "GET",
            "/admin/keys",
            "list_keys",
            Some(SeeKeys),
            "Lists the keys in use",
        ),
    ),
    (
        Module::Keys,
        r(
            "POST",
            "/admin/keys",
            "issue_key",
            Some(IssueKeys),
            "Issues a key",
        ),
    ),
    (
        Module::Keys,
        r(
            "DELETE",
            "/admin/keys/self",
            "revoke_own_key",
            None,
            "Revokes the key that sends the request",
        ),
    ),
    (
        Module::Keys,
        r(
            "GET",
            "/admin/keys/{prefix}",
            "key_info",
            Some(SeeKeys),
            "A key's settings and spend",
        ),
    ),
    (
        Module::Keys,
        r(
            "PATCH",
            "/admin/keys/{prefix}",
            "update_key",
            Some(IssueKeys),
            "Changes a key's settings",
        ),
    ),
    (
        Module::Keys,
        r(
            "DELETE",
            "/admin/keys/{prefix}",
            "revoke_key",
            Some(RevokeKeys),
            "Revokes a key by its hash prefix",
        ),
    ),
    (
        Module::Keys,
        r(
            "POST",
            "/admin/keys/{prefix}/rotate",
            "rotate_key",
            Some(IssueKeys),
            "Makes a new key and ends the old one after a grace",
        ),
    ),
    (
        Module::Keys,
        r(
            "GET",
            "/admin/kills",
            "list_kills",
            Some(Kill),
            "Lists the kill switches that are on",
        ),
    ),
    (
        Module::Keys,
        r(
            "POST",
            "/admin/kills",
            "set_kill",
            Some(Kill),
            "Turns a kill switch on",
        ),
    ),
    (
        Module::Keys,
        r(
            "DELETE",
            "/admin/kills",
            "clear_kill",
            Some(Kill),
            "Turns a kill switch off",
        ),
    ),
    (
        Module::Keys,
        r(
            "GET",
            "/admin/credentials",
            "list_credentials",
            Some(Credentials),
            "Lists provider credentials, never their values",
        ),
    ),
    (
        Module::Keys,
        r(
            "POST",
            "/admin/credentials",
            "add_credential",
            Some(Credentials),
            "Adds a provider credential (write-only)",
        ),
    ),
    (
        Module::Keys,
        r(
            "PUT",
            "/admin/credentials/{name}",
            "rotate_credential",
            Some(Credentials),
            "Gives a credential a new value (write-only)",
        ),
    ),
    (
        Module::Keys,
        r(
            "DELETE",
            "/admin/credentials/{name}",
            "remove_credential",
            Some(Credentials),
            "Removes a credential",
        ),
    ),
    (
        Module::Keys,
        r(
            "POST",
            "/admin/guardrails/test",
            "test_guardrail",
            Some(EditPolicy),
            "Backtests a guardrail over a corpus",
        ),
    ),
    (
        Module::Policy,
        r(
            "GET",
            "/admin/policy",
            "get_policy",
            Some(EditPolicy),
            "The live policy as YAML, its version in ETag",
        ),
    ),
    (
        Module::Policy,
        r(
            "PUT",
            "/admin/policy",
            "propose_policy",
            Some(EditPolicy),
            "Saves a new policy version",
        ),
    ),
    (
        Module::Policy,
        r(
            "GET",
            "/admin/policy/versions",
            "list_policy_versions",
            Some(EditPolicy),
            "Lists the policy versions",
        ),
    ),
    (
        Module::Policy,
        r(
            "GET",
            "/admin/policy/versions/{n}",
            "show_policy_version",
            Some(EditPolicy),
            "One policy version with its diff",
        ),
    ),
    (
        Module::Policy,
        r(
            "POST",
            "/admin/policy/versions/{n}/approve",
            "approve_policy",
            Some(EditPolicy),
            "Approves a pending version",
        ),
    ),
    (
        Module::Policy,
        r(
            "POST",
            "/admin/policy/versions/{n}/reject",
            "reject_policy",
            Some(EditPolicy),
            "Rejects a pending version",
        ),
    ),
    (
        Module::Policy,
        r(
            "POST",
            "/admin/policy/versions/{n}/rollback",
            "rollback_policy",
            Some(EditPolicy),
            "Makes an earlier version live again",
        ),
    ),
    (
        Module::Policy,
        r(
            "POST",
            "/admin/policy/dry-run",
            "dry_run_policy",
            Some(EditPolicy),
            "The recent requests a draft decides differently",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/usage",
            "usage",
            Some(SeeSpend),
            "Spend, tokens and requests grouped by a dimension, day or hour, as JSON or CSV",
        ),
    ),
    (
        Module::Teams,
        r(
            "GET",
            "/admin/teams",
            "list_teams",
            Some(SeeKeys),
            "The teams, from teams: and from keys, with their keys",
        ),
    ),
    (
        Module::Teams,
        r(
            "POST",
            "/admin/teams",
            "create_team",
            Some(EditPolicy),
            "Adds a team to teams:, as a new policy version",
        ),
    ),
    (
        Module::Teams,
        r(
            "GET",
            "/admin/teams/{name}",
            "show_team",
            Some(SeeKeys),
            "One team",
        ),
    ),
    (
        Module::Teams,
        r(
            "PUT",
            "/admin/teams/{name}",
            "update_team",
            Some(EditPolicy),
            "Replaces a team's owner, members, groups and metadata, as a new policy version",
        ),
    ),
    (
        Module::Teams,
        r(
            "DELETE",
            "/admin/teams/{name}",
            "delete_team",
            Some(EditPolicy),
            "Takes a team out of teams:, as a new policy version",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/models",
            "list_models",
            None,
            "The models served, by provider, with prices and aliases",
        ),
    ),
    (
        Module::Manage,
        r(
            "POST",
            "/admin/models",
            "add_model",
            Some(EditPolicy),
            "Adds a model to a provider, with a price and aliases",
        ),
    ),
    (
        Module::Manage,
        r(
            "PUT",
            "/admin/models/{model}/price",
            "price_model",
            Some(EditPolicy),
            "Sets a model's price",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/budgets",
            "list_budgets",
            None,
            "The policy's limits: budgets, rates and parallel limits by scope",
        ),
    ),
    (
        Module::Manage,
        r(
            "PUT",
            "/admin/budgets",
            "put_budgets",
            Some(EditPolicy),
            "Replaces the policy's limits",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/providers",
            "list_providers",
            None,
            "The policy's providers",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/deployments",
            "list_deployments",
            None,
            "Each alias deployment's state, probe, limits, load, latency and error rate, and each provider's key pool, as every gateway on the store sees them",
        ),
    ),
    (
        Module::Manage,
        r(
            "POST",
            "/admin/providers/{name}/test",
            "test_provider",
            Some(EditPolicy),
            "Tests the connection to a provider with its model list, which bills nothing; the outcome is in the answer and the admin record",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/providers/{name}",
            "show_provider",
            None,
            "One provider",
        ),
    ),
    (
        Module::Manage,
        r(
            "PUT",
            "/admin/providers/{name}",
            "put_provider",
            Some(EditPolicy),
            "Adds or replaces a provider",
        ),
    ),
    (
        Module::Manage,
        r(
            "DELETE",
            "/admin/providers/{name}",
            "remove_provider",
            Some(EditPolicy),
            "Removes a provider",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/rules",
            "list_rules",
            None,
            "The policy's rules",
        ),
    ),
    (
        Module::Manage,
        r("GET", "/admin/rules/{name}", "show_rule", None, "One rule"),
    ),
    (
        Module::Manage,
        r(
            "PUT",
            "/admin/rules/{name}",
            "put_rule",
            Some(EditPolicy),
            "Adds or replaces a rule",
        ),
    ),
    (
        Module::Manage,
        r(
            "DELETE",
            "/admin/rules/{name}",
            "remove_rule",
            Some(EditPolicy),
            "Removes a rule",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/guardrails",
            "list_guardrails",
            None,
            "The policy's guardrails",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/guardrails/{name}",
            "show_guardrail",
            None,
            "One guardrail",
        ),
    ),
    (
        Module::Manage,
        r(
            "PUT",
            "/admin/guardrails/{name}",
            "put_guardrail",
            Some(EditPolicy),
            "Adds or replaces a guardrail",
        ),
    ),
    (
        Module::Manage,
        r(
            "DELETE",
            "/admin/guardrails/{name}",
            "remove_guardrail",
            Some(EditPolicy),
            "Removes a guardrail",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/mcp",
            "list_mcp_servers",
            None,
            "The policy's MCP servers",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/mcp/{name}",
            "show_mcp_server",
            None,
            "One MCP server",
        ),
    ),
    (
        Module::Manage,
        r(
            "PUT",
            "/admin/mcp/{name}",
            "put_mcp_server",
            Some(EditPolicy),
            "Adds or replaces an MCP server",
        ),
    ),
    (
        Module::Manage,
        r(
            "DELETE",
            "/admin/mcp/{name}",
            "remove_mcp_server",
            Some(EditPolicy),
            "Removes an MCP server",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/replicas",
            "list_replicas",
            Some(SeeRecords),
            "Every gateway on the store, with its version, schema and whether its heartbeat is recent",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/budget/raises",
            "budget_raises",
            Some(SeeSpend),
            "Budget raises, the ones waiting for a decision first",
        ),
    ),
    (
        Module::Manage,
        r(
            "POST",
            "/admin/budget/raises",
            "add_budget_raise",
            Some(IssueKeys),
            "Raises the budgets of a scope by an amount until a time",
        ),
    ),
    (
        Module::Manage,
        r(
            "POST",
            "/admin/budget/raises/{id}/approve",
            "approve_budget_raise",
            Some(IssueKeys),
            "Approves a raise a person asked for, for an amount and a window",
        ),
    ),
    (
        Module::Manage,
        r(
            "POST",
            "/admin/budget/raises/{id}/reject",
            "reject_budget_raise",
            Some(IssueKeys),
            "Rejects a raise a person asked for",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/aliases",
            "list_aliases",
            None,
            "The policy's aliases: model names served from deployments",
        ),
    ),
    (
        Module::Manage,
        r(
            "GET",
            "/admin/aliases/{name}",
            "show_alias",
            None,
            "One alias",
        ),
    ),
    (
        Module::Manage,
        r(
            "PUT",
            "/admin/aliases/{name}",
            "put_alias",
            Some(EditPolicy),
            "Adds or replaces an alias",
        ),
    ),
    (
        Module::Manage,
        r(
            "DELETE",
            "/admin/aliases/{name}",
            "remove_alias",
            Some(EditPolicy),
            "Removes an alias",
        ),
    ),
];

/// The path segments a template's `{name}` parts matched, when `path` fits `template`.
pub(crate) fn fits(template: &str, path: &str) -> Option<Vec<String>> {
    let (t, p): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
    if t.len() != p.len() {
        return None;
    }
    let mut params = Vec::new();
    for (t, p) in t.iter().zip(&p) {
        if t.starts_with('{') {
            if p.is_empty() {
                return None;
            }
            params.push(p.to_string());
        } else if t != p {
            return None;
        }
    }
    Some(params)
}

/// The route a method and path ask for. A literal segment wins over `{name}`, as the table lists literals first.
pub(crate) fn find(method: &Method, path: &str) -> Option<(Module, AdminRoute, Vec<String>)> {
    ROUTES.iter().find_map(|(module, route)| {
        (route.method == method.as_str())
            .then(|| fits(route.path, path))
            .flatten()
            .map(|params| (*module, *route, params))
    })
}

/// What an embedding binary adds to the admin API. The gateway checks the caller's key and role, the route's
/// permission, and writes the admin record before calling it, and again when the call fails.
pub trait AdminApi: Send + Sync {
    /// The routes it serves, under `/admin`. They must not be routes of the table.
    fn routes(&self) -> Vec<AdminRoute>;
    /// Does the call. An answer with a status of 400 or more is a refusal: its body is
    /// `{"error": {"code": "...", "message": "..."}}`, and the code goes in the record.
    fn call(&self, call: AdminCall) -> Pending<(StatusCode, Value)>;
}

/// One call to an [`AdminApi`] route, once the caller may make it.
#[derive(Debug, Clone)]
pub struct AdminCall {
    pub action: &'static str,
    /// The values of the route's `{name}` segments, in order.
    pub params: Vec<String>,
    pub query: String,
    /// The JSON body, `null` when there is none.
    pub body: Value,
    /// The name of the caller's key.
    pub by: String,
}

/// `/admin` and everything below it.
pub(crate) async fn dispatch(state: State<AppState>, request: Request) -> Response {
    let (method, path) = (request.method().clone(), request.uri().path().to_string());
    if let Some(api) = state.admin_api.clone() {
        let routes = api.routes();
        if let Some((route, params)) = routes.iter().find_map(|route| {
            (route.method == method.as_str())
                .then(|| fits(route.path, &path))
                .flatten()
                .map(|p| (*route, p))
        }) {
            return answer(&state, request, Planned::Extension(api, route, params)).await;
        }
    }
    let module = find(&method, &path).map(|(module, ..)| module).or_else(|| {
        // A known path with another method goes to the module that serves the path, which names its routes.
        ROUTES
            .iter()
            .find(|(_, route)| fits(route.path, &path).is_some())
            .map(|(module, _)| *module)
    });
    match module {
        Some(Module::Policy) => policy_api::handle(state, request).await,
        Some(Module::Manage) => handle(state, request).await,
        Some(Module::Keys) => admin::handle(state, request).await,
        Some(Module::Teams) => teams_api::handle(state, request).await,
        None if path.starts_with("/admin/policy") => policy_api::handle(state, request).await,
        // No route has this path: refused here, as the keys module would take any GET for a list of keys.
        None => answer(&state, request, Planned::Unknown).await,
    }
}

async fn handle(state: State<AppState>, request: Request) -> Response {
    let path = request.uri().path().to_string();
    let Some((_, route, params)) = find(request.method(), &path) else {
        return answer(&state, request, Planned::Unknown).await;
    };
    if route.action == "openapi" {
        return json_response(StatusCode::OK, &openapi(&state));
    }
    answer(&state, request, Planned::Own(route, params)).await
}

enum Planned {
    Own(AdminRoute, Vec<String>),
    Extension(Arc<dyn AdminApi>, AdminRoute, Vec<String>),
    Unknown,
}

async fn answer(state: &AppState, request: Request, planned: Planned) -> Response {
    let decision = id::decision_id();
    let mut response = match run(state, request, planned, &decision).await {
        Ok(response) => response,
        Err(refusal) => refusal.respond(&decision, false),
    };
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(DECISION, value);
    }
    response
}

/// What a call does once it is allowed.
enum Plan {
    Read(Value),
    /// A CSV file and the name a browser saves it under.
    Csv(String, &'static str),
    Change {
        text: String,
        base: Option<i64>,
        note: String,
        by: String,
    },
    Extension(Arc<dyn AdminApi>, AdminCall),
    /// A budget raise to keep: added, approved or rejected.
    Raise(Box<gantry_core::store::Raise>),
}

async fn run(
    state: &AppState,
    request: Request,
    planned: Planned,
    decision: &str,
) -> Result<Response, Refusal> {
    let version = state.version();
    let client = request
        .extensions()
        .get::<ClientAddr>()
        .map(|addr| addr.0.ip().to_string());
    let mut call = Call::default();
    let outcome = allow(state, request, planned, &mut call).await;
    record(
        state,
        decision,
        &version,
        &call,
        client.as_deref(),
        outcome.as_ref().err().map(|r| r.code),
        None,
    )
    .await?;
    let plan = outcome?;
    let done = act(state, plan).await;
    let failed = match &done {
        Err(refusal) => Some((refusal.code.to_string(), refusal.message.clone())),
        // An extension's refusal is recorded with its own code.
        Ok((_, Some(refusal))) => Some(refusal.clone()),
        Ok(_) => None,
    };
    if let Some((code, message)) = failed {
        record(
            state,
            decision,
            &version,
            &call,
            client.as_deref(),
            Some(&code),
            Some(&message),
        )
        .await?;
    }
    done.map(|(response, _)| response)
}

/// The policy section a path names, as the policy file names it.
fn section_of(path: &str) -> &'static str {
    match path.split('/').nth(2).unwrap_or_default() {
        "providers" => "providers",
        "rules" => "rules",
        "guardrails" => "guardrails",
        "mcp" => "mcp",
        "aliases" => "aliases",
        "budgets" => "limits",
        "models" => "models",
        _ => "",
    }
}

fn bad(message: impl Into<String>) -> Refusal {
    refused(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        format!("Refused: {}", message.into()),
    )
}

/// Who calls and whether they may, then what they ask for. Nothing is changed here.
async fn allow(
    state: &AppState,
    request: Request,
    planned: Planned,
    call: &mut Call,
) -> Result<Plan, Refusal> {
    let (parts, body) = request.into_parts();
    let (route, params, api) = match planned {
        Planned::Own(route, params) => (Some(route), params, None),
        Planned::Extension(api, route, params) => (Some(route), params, Some(api)),
        Planned::Unknown => (None, Vec::new(), None),
    };
    call.action = route.map(|r| r.action);
    let version = state.version();
    let Some(policy) = &version.policy else {
        return Err(refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            "Refused: this Gantry serves no keys file, so it has no admin API.",
        ));
    };
    let key = caller_key(&parts.headers)?;
    let Some(person) = policy.identify(key) else {
        call.key = Some(id::sha256_hex(key.as_bytes())[..8].to_string());
        return Err(refused(
            StatusCode::UNAUTHORIZED,
            "unknown_key",
            "Refused: Gantry does not know this key. It was never issued or it has been removed. Ask a Gantry admin.",
        ));
    };
    call.person = Some(person.clone());
    call.key = Some(person.key.clone());
    let Some(role) = policy.role_of(person) else {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "not_admin",
            format!(
                "Refused: the admin API is for keys marked `admin: true` or given a role: in the keys file, and the key of \"{}\" is neither. Ask a Gantry admin.",
                person.name
            ),
        ));
    };
    let Some(route) = route else {
        return Err(refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            "Refused: the admin API has no such route. GET /admin/openapi.json lists every route, its method and the permission it needs.",
        ));
    };
    if let Some(permission) = route.permission {
        if !role.may(permission) {
            return Err(refused(
                StatusCode::FORBIDDEN,
                "not_permitted",
                format!(
                    "Refused: role \"{}\" of \"{}\" does not have the {} permission, which {} needs. Ask a Gantry admin to add it to the role under roles: in the policy, or to give you another role.",
                    role.name,
                    person.name,
                    permission.word(),
                    route.action
                ),
            ));
        }
        // The policy governs the whole install: changing it is for a role not kept to part of it.
        if permission == EditPolicy && role.confined() {
            return Err(refused(
                StatusCode::FORBIDDEN,
                "not_permitted",
                format!(
                    "Refused: {} changes the policy of the whole install, and role \"{}\" is kept to {}. Ask an admin of the whole install.",
                    route.action,
                    role.name,
                    reach(&role)
                ),
            ));
        }
    }
    let by = person.name.clone();
    let query = parts.uri.query().unwrap_or_default().to_string();
    let has_body = matches!(parts.method, Method::POST | Method::PUT | Method::PATCH);
    let sent: Value = if has_body {
        let (bytes, _held) = read_body(Some(&by), state, &parts.headers, body).await?;
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|err| bad(format!("send a JSON body ({err}).")))?
        }
    } else {
        Value::Null
    };
    if let Some(api) = api {
        call.target = Some(json!({ "params": params, "body": sent }));
        return Ok(Plan::Extension(
            api,
            AdminCall {
                action: route.action,
                params,
                query,
                body: sent,
                by,
            },
        ));
    }
    match route.action {
        "list_replicas" => {
            // Without a store this gateway is the only one: it is listed alone, healthy since it answers.
            let replicas = match &state.spend.store {
                Some(store) => store.replicas().await.map_err(|err| {
                    refused(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "store_unavailable",
                        format!("Refused: the store could not be read ({err}). Check that its Postgres is reachable and try again."),
                    )
                })?,
                None => Vec::new(),
            };
            return Ok(Plan::Read(
                json!({ "store": state.spend.store.is_some(), "replicas": replicas }),
            ));
        }
        "budget_raises" => return Ok(Plan::Read(crate::govern::listed(&state.raises, &role))),
        action @ ("add_budget_raise" | "approve_budget_raise" | "reject_budget_raise") => {
            let id = params.first().map_or("", String::as_str);
            let raise = crate::govern::decided(&state.raises, &role, action, id, &sent, &by)?;
            call.target = serde_json::to_value(&raise).ok();
            return Ok(Plan::Raise(Box::new(raise)));
        }
        _ => {}
    }
    let reloader = state.reloader.clone().ok_or_else(|| {
        refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            "Refused: this Gantry serves no policy file, so it has no admin API.",
        )
    })?;
    let policy_path = reloader.policy_path().to_path_buf();
    let text = {
        let path = policy_path.clone();
        blocking(move || config::policy_text(&path))
            .await?
            .map_err(|err| {
                refused(
                    StatusCode::CONFLICT,
                    "policy_file",
                    format!("Refused: {err}"),
                )
            })?
    };
    let section = section_of(parts.uri.path());
    let read = |name: &str| versions::section(&text, name).map_err(bad);
    let name = params.first().cloned().unwrap_or_default();
    match route.action {
        "usage" => {
            let form = gantry_console::Form::parse(&query);
            call.target = Some(json!({ "query": query }));
            if form.get("format") == "focus" {
                return focus(&reloader.audit_path(), &form, &role).await;
            }
            let wants_csv = form.get("format") == "csv"
                || parts
                    .headers
                    .get(header::ACCEPT)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|a| a.contains("text/csv"));
            usage(&reloader.audit_path(), &form, &role, wants_csv).await
        }
        "list_models" => {
            let mut models = Vec::new();
            let prices = read("prices")?;
            for provider in &version.providers {
                for model in &provider.models {
                    models.push(json!({ "model": model, "provider": provider.name, "price": prices.get(model) }));
                }
            }
            Ok(Plan::Read(
                json!({ "models": models, "aliases": read("aliases")?.as_array().cloned().unwrap_or_default() }),
            ))
        }
        "list_deployments" => Ok(Plan::Read(crate::health::deployments(state, &version))),
        "test_provider" => {
            let Some(index) = version.providers.iter().position(|p| p.name == name) else {
                call.target = Some(json!({ "provider": name }));
                return Err(refused(
                    StatusCode::NOT_FOUND,
                    "no_such_entry",
                    format!(
                        "Refused: the policy has no provider named \"{name}\". GET /admin/providers lists them."
                    ),
                ));
            };
            // Run before the admin record is written, so the one record holds the outcome. The test reads a model
            // list and changes nothing, so nothing is done that the record could fail to cover.
            let result = crate::health::test_provider(state, &version, index).await;
            call.target = Some(result.clone());
            Ok(Plan::Read(result))
        }
        "list_budgets" => Ok(Plan::Read(
            json!({ "limits": read("limits")?.as_array().cloned().unwrap_or_default() }),
        )),
        action if action.starts_with("list_") => Ok(Plan::Read(
            json!({ section: read(section)?.as_array().cloned().unwrap_or_default() }),
        )),
        action if action.starts_with("show_") => {
            call.target = Some(json!({ "section": section, "name": name }));
            let found = read(section)?
                .as_array()
                .and_then(|list| {
                    list.iter()
                        .find(|e| e.get("name").and_then(Value::as_str) == Some(name.as_str()))
                        .cloned()
                })
                .ok_or_else(|| {
                    refused(
                        StatusCode::NOT_FOUND,
                        "no_such_entry",
                        format!("Refused: the policy has no entry named \"{name}\" under {section}. GET /admin/{} lists them.", parts.uri.path().split('/').nth(2).unwrap_or_default()),
                    )
                })?;
            Ok(Plan::Read(found))
        }
        action => {
            call.target = Some(json!({ "section": section, "name": name, "entry": sent }));
            let live = gantry_core::store::policy_store(&policy_path)
                .and_then(|s| s.live_policy())
                .ok_or_else(|| {
                    refused(
                        StatusCode::CONFLICT,
                        "policy_in_file",
                        format!("Refused: {}", versions::read_only_message(&policy_path)),
                    )
                })?;
            let base = match if_match(&parts.headers) {
                Some(Some(n)) => Some(n),
                Some(None) => {
                    return Err(bad(
                        "If-Match is a policy version number, as the ETag of GET /admin/policy gives it, for example If-Match: \"3\". Leave it out to change the live version.",
                    ));
                }
                None => Some(live.id),
            };
            let number = |field: &str| {
                sent[field]
                    .as_f64()
                    .filter(|n| n.is_finite() && *n >= 0.0)
                    .ok_or_else(|| bad(format!("{field} is US dollars per million tokens, 0 or more, for example {{\"input\": 0.15, \"output\": 0.60}}.")))
            };
            let edited = match action {
                "put_budgets" => match &sent {
                    Value::Array(list) if list.is_empty() => {
                        versions::set_section(&live.text, "limits", None)
                    }
                    Value::Array(_) => {
                        versions::set_section(&live.text, "limits", Some(sent.clone()))
                    }
                    _ => {
                        return Err(bad(
                            "send the limits as a JSON list, as limits: holds them in the policy, for example [{\"team\": \"payments\", \"budget\": {\"usd\": 500, \"per\": \"month\"}}].",
                        ));
                    }
                },
                "add_model" => {
                    let text = |f: &str| sent[f].as_str().unwrap_or_default().trim().to_string();
                    let model = text("model");
                    if !config::valid_name(&model) {
                        return Err(bad(
                            "send {\"provider\": \"openai\", \"model\": \"gpt-4o-mini\", \"input\": 0.15, \"output\": 0.60, \"aliases\": [\"fast\"]}; a model name uses letters, digits, '.', '-', '_' and '@'.",
                        ));
                    }
                    let price = match (sent.get("input"), sent.get("output")) {
                        (None, None) => None,
                        _ => Some((number("input")?, number("output")?)),
                    };
                    let aliases: Vec<String> = sent["aliases"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|a| a.as_str().map(str::to_string))
                        .collect();
                    if let Some(wrong) = aliases.iter().find(|a| !config::valid_name(a)) {
                        return Err(bad(format!(
                            "the alias \"{wrong}\" uses a character a model name cannot. Use letters, digits, '.', '-', '_' and '@'."
                        )));
                    }
                    versions::add_model(&live.text, &text("provider"), &model, price, &aliases)
                }
                "price_model" => {
                    versions::set_price(&live.text, &name, (number("input")?, number("output")?))
                }
                a if a.starts_with("remove_") => {
                    versions::set_item(&live.text, section, &name, None).map_err(|e| {
                        if e.contains("has no entry") {
                            format!(
                                "{e} GET /admin/{} lists them.",
                                parts.uri.path().split('/').nth(2).unwrap_or_default()
                            )
                        } else {
                            e
                        }
                    })
                }
                _ => {
                    if !sent.is_object() {
                        return Err(bad(format!(
                            "send the entry as a JSON object, with the fields an entry of {section}: has in the policy file."
                        )));
                    }
                    versions::set_item(&live.text, section, &name, Some(sent.clone()))
                }
            };
            let text = edited.map_err(|e| {
                if e.contains("has no entry") {
                    refused(
                        StatusCode::NOT_FOUND,
                        "no_such_entry",
                        format!("Refused: {e}"),
                    )
                } else {
                    bad(e)
                }
            })?;
            let note = format!("{action} {name} through the admin API").replace("  ", " ");
            Ok(Plan::Change {
                text,
                base,
                note: note.trim().to_string(),
                by,
            })
        }
    }
}

/// `If-Match`: absent (`None`), a number, or something else (`Some(None)`).
fn if_match(headers: &HeaderMap) -> Option<Option<i64>> {
    let value = headers.get(header::IF_MATCH)?.to_str().ok()?;
    Some(
        value
            .trim()
            .trim_start_matches("W/")
            .trim_matches('"')
            .parse()
            .ok(),
    )
}

/// A group's numbers as the usage API answers them.
fn stats_json(stats: &Stats) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("requests".into(), stats.requests.into());
    out.insert("refused".into(), stats.refused.into());
    out.insert("errors".into(), stats.errors.into());
    out.insert("input_tokens".into(), stats.input_tokens.into());
    out.insert("output_tokens".into(), stats.output_tokens.into());
    out.insert(
        "total_tokens".into(),
        (stats.input_tokens + stats.output_tokens).into(),
    );
    out.insert("spend_usd".into(), stats.cost_usd.into());
    out.insert("latency_p50_ms".into(), stats.percentile(50.0).into());
    out.insert("latency_p95_ms".into(), stats.percentile(95.0).into());
    out
}

/// What the usage columns are, in CSV order after the group.
const USAGE_COLUMNS: [&str; 9] = [
    "requests",
    "refused",
    "errors",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "spend_usd",
    "latency_p50_ms",
    "latency_p95_ms",
];

/// A CSV field, quoted, and kept from reading as a formula in a spreadsheet.
pub(crate) fn csv_field(text: &str) -> String {
    let text = if text.starts_with(['=', '+', '-', '@']) {
        format!("'{text}")
    } else {
        text.to_string()
    };
    format!("\"{}\"", text.replace('"', "\"\""))
}

/// Keeps a query within what a confined role reaches: its organization, teams and customers. A filter outside them is
/// refused, not quietly dropped, so a caller never mistakes an empty answer for no usage.
fn confine(query: &mut Query, role: &Role) -> Result<(), Refusal> {
    let org: Vec<String> = role.org.iter().cloned().collect();
    for (dimension, reach_of) in [
        ("org", &org),
        ("team", &role.teams),
        ("customer", &role.customers),
    ] {
        if reach_of.is_empty() {
            continue;
        }
        if let Some((_, value)) = query
            .labels
            .iter()
            .find(|(d, v)| d == dimension && !reach_of.contains(v))
        {
            return Err(refused(
                StatusCode::FORBIDDEN,
                "not_permitted",
                format!(
                    "Refused: role \"{}\" is kept to {}, so it sees usage within it only, and {dimension} \"{value}\" is not. Leave {dimension} out, or ask an admin of the whole install.",
                    role.name,
                    reach(role)
                ),
            ));
        }
        query.within.push((dimension.to_string(), reach_of.clone()));
    }
    Ok(())
}

/// `GET /admin/usage`: the requests the query matches, summed by one dimension, day or hour. Summed in SQL by the
/// store's request index when the gateway has one; else folded from this gateway's audit chain.
async fn usage(
    audit: &std::path::Path,
    form: &gantry_console::Form,
    role: &Role,
    csv: bool,
) -> Result<Plan, Refusal> {
    let mut query = Query::parse(&|name| form.get(name).to_string()).map_err(bad)?;
    confine(&mut query, role)?;
    let group = match form.get("group_by").trim() {
        "" => "day",
        g => g,
    };
    let names: Vec<&str> = insights::dimensions().map(|d| d.name).collect();
    let time = matches!(group, "day" | "hour");
    if !time && !names.contains(&group) {
        return Err(bad(format!(
            "group_by is \"{group}\". Group by day, hour or one of {}.",
            names.join(", ")
        )));
    }
    query.limit = insights::MAX_ROWS;
    let hourly = group == "hour";
    let dimension = if time { "team" } else { group }.to_string();
    let counted_by;
    let summed = match insights::attached(audit).index {
        Some(index) => {
            counted_by = "store";
            index.analytics(&query, hourly, &dimension).await
        }
        None => {
            counted_by = "this gateway";
            let (path, q, d) = (audit.to_path_buf(), query.clone(), dimension.clone());
            blocking(move || {
                insights::fold_chain(&path).map(|rows| {
                    let rows: Vec<_> = rows.into_iter().filter(|r| q.matches(r)).collect();
                    insights::analytics(&rows, hourly, &d)
                })
            })
            .await?
        }
    }
    .map_err(|err| {
        refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            format!("Refused: {err}"),
        )
    })?;
    let groups = if time { summed.series } else { summed.ranking };
    if csv {
        let mut out = format!("{group},{}\n", USAGE_COLUMNS.join(","));
        for (value, stats) in &groups {
            let row = stats_json(stats);
            let cells: Vec<String> = USAGE_COLUMNS
                .iter()
                .map(|c| match &row[*c] {
                    Value::Null => String::new(),
                    v => v.to_string(),
                })
                .collect();
            out.push_str(&format!("{},{}\n", csv_field(value), cells.join(",")));
        }
        return Ok(Plan::Csv(out, "gantry-usage.csv"));
    }
    let rows: Vec<Value> = groups
        .iter()
        .map(|(value, stats)| {
            let mut row = Map::new();
            row.insert(group.to_string(), value.clone().into());
            row.extend(stats_json(stats));
            Value::Object(row)
        })
        .collect();
    Ok(Plan::Read(json!({
        "group_by": group,
        "from": query.from,
        "to": query.to,
        "filters": query.pairs().into_iter().filter(|(k, _)| k != "from" && k != "to").map(|(k, v)| (k, Value::from(v))).collect::<Map<String, Value>>(),
        "counted_by": counted_by,
        "totals": stats_json(&summed.totals),
        "groups": rows,
    })))
}

/// `GET /admin/usage?format=focus`: the requests the query matches as a FOCUS 1.2 cost and usage file, one line per
/// UTC day, organization, team, provider and model (`focus.rs` has the column mapping). `group_by` does not apply.
async fn focus(
    audit: &std::path::Path,
    form: &gantry_console::Form,
    role: &Role,
) -> Result<Plan, Refusal> {
    let mut query = Query::parse(&|name| form.get(name).to_string()).map_err(bad)?;
    confine(&mut query, role)?;
    query.limit = insights::MAX_ROWS;
    let lines = match insights::attached(audit).index {
        Some(index) => index.cost_lines(&query).await,
        None => {
            let path = audit.to_path_buf();
            blocking(move || {
                insights::fold_chain(&path).map(|rows| {
                    let rows: Vec<_> = rows.into_iter().filter(|r| query.matches(r)).collect();
                    insights::cost_lines(&rows)
                })
            })
            .await?
        }
    }
    .map_err(|err| {
        refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            format!("Refused: {err}"),
        )
    })?;
    Ok(Plan::Csv(crate::focus::csv(&lines), "gantry-focus.csv"))
}

type Done = (Response, Option<(String, String)>);

async fn act(state: &AppState, plan: Plan) -> Result<Done, Refusal> {
    match plan {
        Plan::Read(body) => Ok((json_response(StatusCode::OK, &body), None)),
        Plan::Csv(text, name) => Ok((
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{name}\""),
                    ),
                ],
                text,
            )
                .into_response(),
            None,
        )),
        Plan::Change {
            text,
            base,
            note,
            by,
        } => {
            let reloader = state.reloader.clone().ok_or_else(|| {
                refused(
                    StatusCode::NOT_FOUND,
                    "unknown_route",
                    "Refused: this Gantry serves no policy file, so it has no admin API.",
                )
            })?;
            let (policy_path, keys_path) = (
                reloader.policy_path().to_path_buf(),
                reloader.keys_path().to_path_buf(),
            );
            let done = blocking(move || {
                versions::propose(&policy_path, &keys_path, &text, base, &note, &by)
            })
            .await?;
            Ok((
                policy_api::changed(state, done, StatusCode::CREATED).await?,
                None,
            ))
        }
        Plan::Raise(raise) => {
            let (raises, kept) = (state.raises.clone(), raise.clone());
            blocking(move || raises.put(&kept)).await?.map_err(|err| {
                refused(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "store_unavailable",
                    format!("Refused: {err}"),
                )
            })?;
            let status = if raise.requested_at == raise.decided_at.clone().unwrap_or_default() {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            Ok((
                json_response(status, &serde_json::to_value(&raise).unwrap_or_default()),
                None,
            ))
        }
        Plan::Extension(api, call) => {
            let (status, body) = api.call(call).await.map_err(|err| {
                refused(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "admin_api_failed",
                    format!("Refused: {err}"),
                )
            })?;
            let refusal = (status.as_u16() >= 400).then(|| {
                (
                    body["error"]["code"]
                        .as_str()
                        .unwrap_or("refused")
                        .to_string(),
                    body["error"]["message"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                )
            });
            Ok((json_response(status, &body), refusal))
        }
    }
}

/// The OpenAPI 3.1 document of every admin route this gateway serves: the table and an embedding binary's routes.
pub(crate) fn openapi(state: &AppState) -> Value {
    let mut routes: Vec<AdminRoute> = ROUTES.iter().map(|(_, r)| *r).collect();
    if let Some(api) = &state.admin_api {
        routes.extend(api.routes());
    }
    document(&routes)
}

pub(crate) fn document(routes: &[AdminRoute]) -> Value {
    let mut paths = Map::new();
    for route in routes {
        let parameters: Vec<Value> = route
            .path
            .split('/')
            .filter_map(|s| s.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
            .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } }))
            .collect();
        let mut operation = json!({
            "operationId": route.action,
            "summary": route.summary,
            "x-gantry-action": route.action,
            "x-gantry-permission": route.permission.map(Permission::word),
            "parameters": parameters,
            "responses": {
                "200": { "description": "Done", "content": { "application/json": { "schema": { "type": "object" } } } },
                "default": { "description": "Refused", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } } }
            }
        });
        if route.action == "openapi" {
            operation["security"] = json!([]);
        }
        if matches!(route.method, "POST" | "PUT" | "PATCH") {
            operation["requestBody"] =
                json!({ "content": { "application/json": { "schema": {} } } });
        }
        let entry = paths
            .entry(route.path.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(entry) = entry {
            entry.insert(route.method.to_ascii_lowercase(), operation);
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Gantry admin API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Every call needs an admin key, or a key whose role has the route's permission (x-gantry-permission), as Authorization: Bearer gantry_... Every call is an admin record in the audit log. See https://gantry-docs.eliran.me/reference/admin-api/."
        },
        "security": [{ "bearer": [] }],
        "components": {
            "securitySchemes": { "bearer": { "type": "http", "scheme": "bearer" } },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": { "error": { "type": "object", "properties": {
                        "message": { "type": "string" }, "type": { "type": "string" }, "code": { "type": "string" }
                    } } }
                }
            }
        },
        "paths": paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_segments_win_and_params_take_one_segment() {
        let found = find(&Method::DELETE, "/admin/keys/self").map(|(_, r, _)| r.action);
        assert_eq!(found, Some("revoke_own_key"));
        let found = find(&Method::DELETE, "/admin/keys/1a2b3c4d");
        assert_eq!(
            found.map(|(_, r, p)| (r.action, p)),
            Some(("revoke_key", vec!["1a2b3c4d".to_string()]))
        );
        assert!(find(&Method::GET, "/admin/keys/a/b").is_none());
        assert!(find(&Method::GET, "/admin/rules/").is_none());
    }

    #[test]
    fn every_route_is_once_in_the_document() {
        let doc = document(&ROUTES.iter().map(|(_, r)| *r).collect::<Vec<_>>());
        let mut seen = std::collections::BTreeSet::new();
        for (_, route) in ROUTES {
            assert!(
                seen.insert((route.method, route.path)),
                "{} {} twice",
                route.method,
                route.path
            );
            assert_eq!(
                doc["paths"][route.path][route.method.to_ascii_lowercase()]["operationId"],
                route.action
            );
        }
        let operations: usize = doc["paths"]
            .as_object()
            .map(|p| p.values().filter_map(Value::as_object).map(Map::len).sum())
            .unwrap_or_default();
        assert_eq!(operations, ROUTES.len());
    }

    fn role(org: Option<&str>, teams: &[&str], customers: &[&str]) -> Role {
        Role {
            name: "kept".into(),
            permissions: vec![SeeSpend],
            org: org.map(str::to_string),
            teams: teams.iter().map(|t| (*t).to_string()).collect(),
            customers: customers.iter().map(|c| (*c).to_string()).collect(),
            sso_values: Vec::new(),
            line: 1,
        }
    }

    /// A chain of three answered requests: payments for customer acme-corp, payments for globex-inc, and search.
    fn chain() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("gantry-manage-{}", id::random_hex(6)));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("audit.jsonl");
        let log = gantry_core::audit::AuditLog::open(&path)?;
        for (decision, team, customer) in [
            ("D1", "payments", "acme-corp"),
            ("D2", "payments", "globex-inc"),
            ("D3", "search", "acme-corp"),
        ] {
            let mut request = gantry_core::audit::record(&gantry_core::audit::Entry {
                id: decision,
                person: Some("maya.cohen"),
                team: Some(team),
                key: Some("5d1e4a07"),
                method: "POST",
                path: "/v1/chat/completions",
                model: Some("m"),
                allowed: true,
                provider: "mock",
                ..Default::default()
            });
            request.insert("customer".into(), customer.into());
            log.append_record(&request)?;
            let usage = json!({"event": "usage", "id": decision, "provider": "mock", "model": "m", "status": 200,
                "input_tokens": 10, "output_tokens": 5, "charged_usd": 1.0, "customer": customer});
            log.append_record(usage.as_object().ok_or("not an object")?)?;
        }
        log.flush();
        Ok(path)
    }

    async fn summed(
        path: &std::path::Path,
        query: &str,
        role: &Role,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        match usage(path, &gantry_console::Form::parse(query), role, false).await {
            Ok(Plan::Read(value)) => Ok(value),
            Ok(_) => Err("not a JSON answer".into()),
            Err(refusal) => Err(format!("{}: {}", refusal.code, refusal.message).into()),
        }
    }

    #[tokio::test]
    async fn usage_stays_within_the_teams_and_customers_a_role_is_kept_to()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = chain()?;
        let everyone = role(None, &[], &[]);
        assert_eq!(
            summed(&path, "group_by=team", &everyone).await?["totals"]["requests"],
            3
        );

        let payments = role(None, &["payments"], &[]);
        let seen = summed(&path, "group_by=team", &payments).await?;
        assert_eq!(seen["totals"]["requests"], 2, "{seen}");
        assert!(
            seen["groups"]
                .as_array()
                .is_some_and(|g| g.iter().all(|r| r["team"] == "payments")),
            "{seen}"
        );
        let refused = summed(&path, "team=search", &payments).await;
        let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            message.starts_with("not_permitted") && message.contains("team payments"),
            "{message}"
        );

        let acme = role(None, &[], &["acme-corp"]);
        let seen = summed(&path, "group_by=team", &acme).await?;
        assert_eq!(seen["totals"]["requests"], 2, "{seen}");
        let refused = summed(&path, "customer=globex-inc", &acme).await;
        assert!(refused.is_err(), "another customer's usage is refused");

        // Kept to both: only what lies in each.
        let both = role(None, &["payments"], &["acme-corp"]);
        assert_eq!(summed(&path, "", &both).await?["totals"]["requests"], 1);
        Ok(())
    }

    #[test]
    fn a_role_kept_to_teams_or_customers_is_confined_and_says_to_what() {
        assert!(role(None, &["payments"], &[]).confined());
        assert!(role(None, &[], &["acme-corp"]).confined());
        assert!(!role(None, &[], &[]).confined());
        assert_eq!(
            reach(&role(Some("acme"), &["payments", "web"], &["acme-corp"])),
            "organization \"acme\" and teams payments, web and customer acme-corp"
        );
    }

    /// A route the router serves itself, beside the catch-all, would never reach this table: the OpenAPI document
    /// would miss it and its calls would skip the checks here. A branch that adds one (`/admin/teams` handlers, say)
    /// fails this until the route is a row of `ROUTES` instead.
    #[test]
    fn every_admin_route_the_router_serves_goes_through_the_table() {
        let source = include_str!("lib.rs");
        let mut served = Vec::new();
        for piece in source.split(".route(\"").skip(1) {
            let path = piece.split('"').next().unwrap_or_default();
            if path == "/admin" || path.starts_with("/admin/") {
                served.push(path);
            }
        }
        assert_eq!(
            served,
            ["/admin", "/admin/{*rest}"],
            "add these to ROUTES (the method, action, permission and summary) and drop them from the router; dispatch sends every /admin path through the table"
        );
        assert!(ROUTES.iter().all(|(_, r)| r.path.starts_with("/admin")));
    }

    #[test]
    fn csv_fields_are_quoted_and_never_formulas() {
        assert_eq!(csv_field("payments"), "\"payments\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("=cmd()"), "\"'=cmd()\"");
    }
}
