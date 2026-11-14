//! The admin API for keys: issue, list and revoke keys while Gantry runs, without editing the keys file by hand.
//!
//! Only a key whose entry says `admin: true` may call it, wherever Gantry listens, so it is never open. Every call
//! is recorded before anything is done, as a request is. The keys file stays the one source of truth: a key is
//! added by appending its entry, removed by a replace that only happens while the file is as it was read, and the
//! reload that follows is the same one a hand edit gets.

use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use gantry_core::store::{self, Store};
use gantry_core::{
    audit,
    config::{self, valid_name},
    id, keyfile, kill,
    policy::{Permission, Policy, Principal, Role},
};
use serde_json::{Map, Value, json};
use std::sync::Arc;

use crate::{
    AppState, ClientAddr, DECISION, Refusal, Reload, Snapshot, Trigger, caller_key, read_body,
};

const ROUTES: &str = "GET /admin/explain?key=<prefix>&model=<model>[&customer=<name>][&tags=<a,b>], GET /admin/keys, POST /admin/keys, GET, PATCH and DELETE /admin/keys/<first 8 hex characters of the hash>, POST /admin/keys/<prefix>/rotate, DELETE /admin/keys/self, GET, POST and DELETE /admin/kills, GET and POST /admin/credentials, PUT and DELETE /admin/credentials/<name>, and POST /admin/guardrails/test";

/// Why there is no credential to add or list on a gateway without a store.
const NEED_STORE: &str = "Refused: provider credentials are kept in the store, sealed with a master key, and this gateway's policy has no store: section. Keep provider keys in environment variables with key_env (or in files with key_file), or add `store: { postgres_url_env: DATABASE_URL }` to the policy and set GANTRY_MASTER_KEY.";

/// What an admin call asks for, once it is allowed.
enum Plan {
    /// The keys, of one organization when the caller's role is confined to one.
    List(Role),
    /// Why a request would be allowed or refused, and every limit it would count against with what it has spent.
    Explain(Box<Value>),
    Issue {
        name: String,
        team: String,
        key: String,
        attributes: keyfile::Attributes,
    },
    Revoke {
        prefix: String,
    },
    Info(config::KeyEntry),
    Update {
        prefix: String,
        changes: Vec<(String, Value)>,
    },
    Rotate {
        old: config::KeyEntry,
        key: String,
        /// When the old key stops working, as `expires` takes it.
        until: String,
    },
    Kills,
    Kill(kill::Kill),
    Unkill {
        scope: String,
        value: String,
    },
    Credentials(Arc<dyn Store>),
    AddCredential {
        store: Arc<dyn Store>,
        name: String,
        provider: String,
        value: String,
        by: String,
    },
    RotateCredential {
        store: Arc<dyn Store>,
        name: String,
        value: String,
        by: String,
    },
    RemoveCredential {
        store: Arc<dyn Store>,
        name: String,
    },
    /// A finished backtest: nothing is changed, so it is run while the call is checked.
    Backtest(Value),
}

/// `POST /admin/guardrails/test`: a guardrail by name (one a rule of the policy in use runs) or a definition not in
/// the policy yet, and the examples to run it over.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TestGuardrail {
    guardrail: Value,
    #[serde(default)]
    corpus: Vec<Value>,
    #[serde(default)]
    since: Option<String>,
}

/// A credential to add, or the new value of one.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NewCredential {
    #[serde(default)]
    name: String,
    #[serde(default)]
    provider: String,
    value: String,
}

/// A kill switch to set (`reason` required) or clear.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Switch {
    scope: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    reason: String,
    /// Sets the switch even when it matches no key, team or served model.
    #[serde(default)]
    force: bool,
}

/// Why a switch would stop nothing, with the names it may have meant. UX12-1: `gantry login` names keys by email,
/// so `--person maya.cohen` looks right, is reported on, and stops nothing.
fn matches_nothing(
    version: &Snapshot,
    policy: &Policy,
    scope: &str,
    value: &str,
) -> Option<String> {
    let close = |names: Vec<String>, what: &str| {
        let mut near: Vec<String> = names
            .iter()
            .filter(|n| n.contains(value) || value.contains(n.split('@').next().unwrap_or(n)))
            .cloned()
            .collect();
        near.sort();
        near.dedup();
        near.truncate(5);
        let hint = if near.is_empty() {
            String::new()
        } else {
            format!(" {what} like it: {}.", near.join(", "))
        };
        Some(hint)
    };
    let hint = match scope {
        "person" | "team" => {
            let names: Vec<String> = policy
                .entries()
                .map(|(_, who)| {
                    if scope == "person" {
                        who.name.clone()
                    } else {
                        who.team.clone()
                    }
                })
                .collect();
            if names.iter().any(|n| n == value) {
                return None;
            }
            close(
                names,
                if scope == "person" {
                    "Keys named"
                } else {
                    "Teams"
                },
            )?
        }
        "key_prefix" => {
            if policy
                .entries()
                .any(|(hash, _)| id::hex(hash).starts_with(value))
            {
                return None;
            }
            String::new()
        }
        "model" => {
            let names: Vec<String> = version
                .providers
                .iter()
                .flat_map(|p| p.models.iter().cloned())
                .chain(version.aliases.iter().map(|a| a.name.clone()))
                .chain(
                    version
                        .aliases
                        .iter()
                        .flat_map(|a| a.deployments.iter().map(|d| d.model.clone())),
                )
                .collect();
            if names.iter().any(|n| n == value) {
                return None;
            }
            close(names, "Models")?
        }
        _ => return None,
    };
    let what = if scope == "key_prefix" { "key" } else { scope };
    Some(format!(
        "Refused: no {what} \"{value}\" is served or holds a key here, so this switch would stop nothing.{hint} Name one that exists, or send \"force\": true (gantry kill --force) to set it anyway."
    ))
}

/// What is known about a call, for its record.
#[derive(Default)]
pub(crate) struct Call {
    pub(crate) action: Option<&'static str>,
    pub(crate) person: Option<Principal>,
    pub(crate) key: Option<String>,
    pub(crate) target: Option<Value>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NewKey {
    name: String,
    team: String,
    /// `2026-12-31` or `2026-12-31T18:00:00Z`, UTC.
    #[serde(default)]
    expires: Option<String>,
    #[serde(default)]
    budget: Option<NewBudget>,
    /// The models this key may use, within its rule's.
    #[serde(default)]
    models: Option<Vec<String>>,
    #[serde(default)]
    tpm: Option<u32>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    customer: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    parallel: Option<u32>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    rpm: Option<Value>,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(default)]
    routes: Option<Value>,
    #[serde(default)]
    from: Option<Value>,
}

/// The key fields `PATCH /admin/keys/<prefix>` changes. Name, team, org, role and admin are not among them: a new
/// name or organization is a new key, and rights are given only when a key is issued.
const UPDATABLE: &str =
    "expires, budget, models, tpm, rpm, parallel, customer, tags, metadata, routes and from";

/// Sets one field of `entry` from its JSON value, or says what is wrong with it. `null` clears the field.
fn apply(
    entry: &mut config::KeyEntry,
    field: &str,
    value: &Value,
    served: &[&String],
) -> Result<(), String> {
    let number = |most: u64| -> Result<Option<u32>, String> {
        match value {
            Value::Null => Ok(None),
            v => v
                .as_u64()
                .filter(|n| (1..=most).contains(n))
                .and_then(|n| u32::try_from(n).ok())
                .map(Some)
                .ok_or_else(|| {
                    format!("{field} is a whole number from 1 to {most}, or null to remove it")
                }),
        }
    };
    let list = || -> Result<Vec<String>, String> {
        match value {
            Value::Null => Ok(Vec::new()),
            Value::Array(items) => items
                .iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| format!("{field} is a list of strings, or null to remove it")),
            _ => Err(format!(
                "{field} is a list of strings, or null to remove it"
            )),
        }
    };
    match field {
        "expires" => {
            entry.expires = match value {
                Value::Null => None,
                Value::String(at) => {
                    config::issuable_expiry(at)?;
                    Some(at.clone())
                }
                _ => return Err(
                    "expires is a UTC date or time such as \"2026-12-31\", or null to remove it"
                        .into(),
                ),
            }
        }
        "budget" => {
            entry.budget = match value {
                Value::Null => None,
                v => {
                    let usd = v["usd"].as_f64().filter(|u| u.is_finite() && *u > 0.0);
                    let per = v["per"]
                        .as_str()
                        .map(|per| gantry_core::policy::Period::parse(per, v["tz"].as_str()))
                        .transpose()?;
                    match (usd, per) {
                        (Some(usd), Some(per)) => Some(gantry_core::policy::Budget { usd, per }),
                        _ => return Err("budget takes US dollars above 0 and a period, for example {\"usd\": 20, \"per\": \"month\"} or {\"usd\": 5, \"per\": \"week\", \"tz\": \"Europe/Berlin\"}, or null to remove it".into()),
                    }
                }
            }
        }
        "models" => {
            entry.models = match value {
                Value::Null => None,
                _ => {
                    let models = list()?;
                    if models.is_empty() {
                        return Err("models lists at least one model the key may use, or is null to leave its rule's list".into());
                    }
                    if let Some(unknown) = models.iter().find(|m| *m != "*" && !served.contains(m))
                    {
                        return Err(format!(
                            "model \"{unknown}\" is not served here, so the key could never use it. List models or aliases of the policy, as GET /v1/models lists them"
                        ));
                    }
                    Some(models)
                }
            }
        }
        "tpm" => entry.tpm = number(1_000_000_000)?,
        "rpm" => entry.options.rpm = number(1_000_000)?,
        "parallel" => entry.parallel = number(100_000)?,
        "tags" => {
            let tags = list()?;
            if tags.len() > config::MAX_TAGS || tags.iter().any(|t| !valid_name(t)) {
                return Err(format!(
                    "tags lists at most {} names in letters, digits, '.', '-', '_' and '@', or is null to remove them",
                    config::MAX_TAGS
                ));
            }
            entry.tags = tags;
        }
        "customer" => {
            entry.customer = match value {
                Value::Null => None,
                Value::String(c) if valid_name(c) => Some(c.clone()),
                _ => return Err("customer is the end customer every request with the key is for, in letters, digits, '.', '-', '_' and '@', or null to remove it".into()),
            }
        }
        "routes" => entry.options.routes = list()?,
        "from" => entry.options.from = config::cidrs(&list()?)?,
        "metadata" => {
            entry.options.metadata = match value {
                Value::Null => Default::default(),
                Value::Object(map) => map
                    .iter()
                    .map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                    .collect::<Option<_>>()
                    .ok_or("metadata is an object of names to text values, or null to remove it")?,
                _ => {
                    return Err(
                        "metadata is an object of names to text values, or null to remove it"
                            .into(),
                    );
                }
            }
        }
        other => {
            return Err(format!(
                "\"{other}\" is not a key field the admin API changes. It changes {UPDATABLE}"
            ));
        }
    }
    config::key_options_problem(&entry.options).map_or(Ok(()), Err)
}

/// A key's settings as the admin API shows them. Never the key.
fn key_json(entry: &config::KeyEntry) -> Value {
    let o = &entry.options;
    json!({
        "name": entry.name,
        "team": entry.team,
        "sha256_prefix": &entry.sha256[..8],
        "admin": entry.admin,
        "expires": entry.expires,
        "budget": entry.budget.map(|b| json!({ "usd": b.usd, "per": b.per.word() })),
        "models": entry.models,
        "tpm": entry.tpm,
        "org": (!entry.org.is_empty()).then_some(&entry.org),
        "customer": entry.customer,
        "tags": entry.tags,
        "parallel": entry.parallel,
        "role": entry.role,
        "rpm": o.rpm,
        "metadata": o.metadata,
        "routes": o.routes,
        "from": o.from.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "replaced_by": o.replaced_by,
    })
}

/// How long the old key keeps working after a rotation: `48h`, `30m`, `7d`, `90s` or `0`. At most 90 days.
fn grace(text: &str) -> Result<std::time::Duration, String> {
    let wrong = || {
        format!(
            "grace is \"{text}\". Write how long the old key keeps working, such as 48h, 30m or 7d (at most 90d), or 0 to end it now"
        )
    };
    let text = text.trim();
    if text == "0" {
        return Ok(std::time::Duration::ZERO);
    }
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let n: u64 = number.parse().map_err(|_| wrong())?;
    let seconds = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        "d" => n.saturating_mul(86_400),
        _ => return Err(wrong()),
    };
    if seconds > 90 * 86_400 {
        return Err(wrong());
    }
    Ok(std::time::Duration::from_secs(seconds))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NewBudget {
    usd: f64,
    per: String,
    #[serde(default)]
    tz: Option<String>,
}

/// The permission each admin action needs.
fn needs(action: &str) -> Permission {
    match action {
        "list_keys" => Permission::SeeKeys,
        "issue_key" => Permission::IssueKeys,
        "revoke_key" => Permission::RevokeKeys,
        "list_kills" | "set_kill" | "clear_kill" => Permission::Kill,
        "explain" => Permission::SeeSpend,
        "key_info" => Permission::SeeKeys,
        "update_key" | "rotate_key" => Permission::IssueKeys,
        // A backtest tries a guardrail before it goes into the policy: the policy author's job, not the credential keeper's.
        "test_guardrail" => Permission::EditPolicy,
        _ => Permission::Credentials,
    }
}

/// A query parameter, percent-decoded for the characters names hold.
fn query_param(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| {
            v.replace("%2C", ",")
                .replace("%2c", ",")
                .replace("%40", "@")
                .replace('+', " ")
        })
}

pub(crate) async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let decision = id::decision_id();
    let mut response = match admin(&state, request, &decision).await {
        Ok(response) => response,
        Err(refusal) => refusal.respond(&decision, false),
    };
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(DECISION, value);
    }
    response
}

pub(crate) fn refused(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Refusal {
    Refusal::new(status, code, message)
}

async fn admin(state: &AppState, request: Request, decision: &str) -> Result<Response, Refusal> {
    let version = state.version();
    let client = request
        .extensions()
        .get::<ClientAddr>()
        .map(|addr| addr.0.ip().to_string());
    let mut call = Call::default();
    let outcome = allow(state, &version, request, &mut call).await;
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
    let done = act(state, &version, plan).await;
    if let Err(refusal) = &done {
        // The call was recorded as allowed before it was tried. This says it did not happen.
        record(
            state,
            decision,
            &version,
            &call,
            client.as_deref(),
            Some(refusal.code),
            Some(&refusal.message),
        )
        .await?;
    }
    done
}

/// Who is calling, whether they may, and what they ask for. Nothing is changed here.
async fn allow(
    state: &AppState,
    version: &Snapshot,
    request: Request,
    call: &mut Call,
) -> Result<Plan, Refusal> {
    let (parts, body) = request.into_parts();
    let prefix = parts
        .uri
        .path()
        .strip_prefix("/admin/keys/")
        .map(str::to_string);
    let kills = parts.uri.path() == "/admin/kills";
    let backtest = parts.uri.path() == "/admin/guardrails/test";
    let explain = parts.uri.path() == "/admin/explain";
    let credential = parts
        .uri
        .path()
        .strip_prefix("/admin/credentials")
        .map(|rest| rest.trim_start_matches('/').to_string());
    call.action = match (&parts.method, credential.as_deref()) {
        (&Method::GET, Some("")) => Some("list_credentials"),
        (&Method::POST, Some("")) => Some("add_credential"),
        (&Method::PUT, Some(name)) if !name.is_empty() => Some("rotate_credential"),
        (&Method::DELETE, Some(name)) if !name.is_empty() => Some("remove_credential"),
        (_, Some(_)) => None,
        _ => call.action,
    };
    call.action = match (&parts.method, prefix.as_deref(), kills) {
        _ if credential.is_some() => call.action,
        (&Method::POST, None, false) if backtest => Some("test_guardrail"),
        _ if backtest => None,
        (&Method::GET, None, false) if explain => Some("explain"),
        _ if explain => None,
        (&Method::GET, None, false) => Some("list_keys"),
        (&Method::POST, None, false) => Some("issue_key"),
        (&Method::DELETE, Some("self"), _) => Some("revoke_own_key"),
        (&Method::POST, Some(p), _) if p.ends_with("/rotate") => Some("rotate_key"),
        (_, Some(p), _) if p.contains('/') => None,
        (&Method::DELETE, Some(_), _) => Some("revoke_key"),
        (&Method::GET, Some(_), _) => Some("key_info"),
        (&Method::PATCH, Some(_), _) => Some("update_key"),
        (&Method::GET, None, true) => Some("list_kills"),
        (&Method::POST, None, true) => Some("set_kill"),
        (&Method::DELETE, None, true) => Some("clear_kill"),
        _ => None,
    };
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
    // Every admin record names the caller's key by its hash prefix, as request records do.
    call.key = Some(person.key.clone());
    // `gantry logout` revokes the key it sends, whoever's it is: no one needs to be an admin to give up their own key.
    if call.action == Some("revoke_own_key") {
        let hash = id::sha256_hex(key.as_bytes());
        call.target =
            Some(json!({ "name": person.name, "team": person.team, "sha256_prefix": &hash[..8] }));
        return Ok(Plan::Revoke { prefix: hash });
    }
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
    let not_here = || {
        refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            format!("Refused: the admin API serves {ROUTES}. Check the method and the path."),
        )
    };
    let action = call.action.ok_or_else(not_here)?;
    if !role.may(needs(action)) {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "not_permitted",
            format!(
                "Refused: role \"{}\" of \"{}\" does not have the {} permission, which {action} needs. Ask a Gantry admin to add it to the role under roles: in the policy, or to give you another role.",
                role.name,
                person.name,
                needs(action).word()
            ),
        ));
    }
    // Kill switches, provider credentials and teams act on the whole install: a role kept to part of it has none.
    if role.confined() && matches!(needs(action), Permission::Kill | Permission::Credentials) {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "not_permitted",
            format!(
                "Refused: {action} acts on the whole install, and role \"{}\" is kept to {}. Ask an admin of the whole install.",
                role.name,
                reach(&role)
            ),
        ));
    }
    match action {
        "explain" => {
            let query = parts.uri.query().unwrap_or_default();
            let (Some(key), Some(model)) = (query_param(query, "key"), query_param(query, "model"))
            else {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Refused: name the caller and the model, for example GET /admin/explain?key=1a2b3c4d&model=gpt-4o, and optionally &customer=<name> and &tags=<a,b>.",
                ));
            };
            let key = key.to_ascii_lowercase();
            let who = policy
                .entries()
                .map(|(_, p)| p)
                .filter(|p| key.len() >= 8 && p.key.starts_with(&key[..8]) || p.name == key)
                .find(|p| role.covers(&p.org, &p.team, p.customer.as_deref()))
                .ok_or_else(|| {
                    refused(
                        StatusCode::NOT_FOUND,
                        "no_such_key",
                        format!("Refused: no key you may see has the hash prefix or name \"{key}\". GET /admin/keys lists them."),
                    )
                })?;
            call.target = Some(json!({ "explain": { "key": who.key, "model": model } }));
            let customer = query_param(query, "customer").or_else(|| who.customer.clone());
            let mut tags = who.tags.clone();
            for tag in query_param(query, "tags").unwrap_or_default().split(',') {
                let tag = tag.trim();
                if !tag.is_empty() && !tags.iter().any(|t| t == tag) {
                    tags.push(tag.to_string());
                }
            }
            let deployed = version
                .aliases
                .iter()
                .find(|a| a.name == model)
                .and_then(|a| a.deployments.first())
                .map_or(model.clone(), |d| d.model.clone());
            let ctx = gantry_core::policy::Context {
                sent: &model,
                model: &deployed,
                customer: customer.as_deref(),
                tags: &tags,
            };
            let mut explained = policy.explain(who, ctx);
            // What each budget has spent and holds in its period now.
            if let Some(limits) = explained["limits"].as_array_mut() {
                for limit in limits {
                    let per = limit["per"]
                        .as_str()
                        .and_then(gantry_core::policy::Period::from_word);
                    if let (Some(per), Some(scope)) = (per, limit["scope"].as_str()) {
                        if let Some((spent, reserved)) = state.spend.spent_now(scope, per).await {
                            limit["spent_usd"] = spent.into();
                            limit["reserved_usd"] = reserved.into();
                            limit["resets"] = per.resets(&per.label(&audit::timestamp())).into();
                        }
                    }
                }
            }
            Ok(Plan::Explain(Box::new(explained)))
        }
        action @ ("list_credentials" | "add_credential" | "rotate_credential"
        | "remove_credential") => {
            let keys_path = state
                .reloader
                .as_ref()
                .map(|r| r.keys_path().to_path_buf())
                .unwrap_or_default();
            let store = store::attached(&keys_path).ok_or_else(|| {
                refused(StatusCode::NOT_FOUND, "credentials_need_store", NEED_STORE)
            })?;
            if let Err(off) = store.credentials() {
                return Err(refused(
                    StatusCode::CONFLICT,
                    "no_master_key",
                    format!("Refused: {off}"),
                ));
            }
            let name = credential.unwrap_or_default();
            let by = person.name.clone();
            if action == "list_credentials" {
                return Ok(Plan::Credentials(store));
            }
            if action == "remove_credential" {
                call.target = Some(json!({ "name": name }));
                let in_use = state
                    .reloader
                    .as_ref()
                    .map(|r| r.credentials_in_use())
                    .unwrap_or_default();
                if let Some((provider, _)) = in_use.iter().find(|(_, c)| *c == name) {
                    return Err(refused(
                        StatusCode::CONFLICT,
                        "credential_in_use",
                        format!(
                            "Refused: provider \"{provider}\" in the policy in use takes its key from credential \"{name}\", so removing it would leave the provider without a key at the next start. Point the provider at another credential or key_env first, or rotate this one with PUT /admin/credentials/{name}."
                        ),
                    ));
                }
                return Ok(Plan::RemoveCredential { store, name });
            }
            let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
            let shape = if action == "add_credential" {
                "{\"name\": \"openai-prod\", \"provider\": \"openai\", \"value\": \"<the provider key>\"}"
            } else {
                "{\"value\": \"<the new provider key>\"}"
            };
            // The parser's own error could quote the value: it is never repeated.
            let new: NewCredential = serde_json::from_slice(&bytes).map_err(|_| {
                refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("Refused: send a JSON object such as {shape}."),
                )
            })?;
            if let Some(problem) = store::credential_value_problem(&new.value) {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("Refused: {problem}"),
                ));
            }
            let fingerprint = store::fingerprint(new.value.trim());
            if action == "rotate_credential" {
                call.target = Some(json!({ "name": name, "fingerprint": fingerprint }));
                return Ok(Plan::RotateCredential {
                    store,
                    name,
                    value: new.value,
                    by,
                });
            }
            call.target = Some(
                json!({ "name": new.name, "provider": new.provider, "fingerprint": fingerprint }),
            );
            if !valid_name(&new.name) || !valid_name(&new.provider) {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!(
                        "Refused: a credential's name and provider use letters, digits, dots, dashes, underscores and @ only, at most 100 characters. Send {shape}."
                    ),
                ));
            }
            Ok(Plan::AddCredential {
                store,
                name: new.name,
                provider: new.provider,
                value: new.value,
                by,
            })
        }
        "list_keys" => Ok(Plan::List(role.clone())),
        "list_kills" => Ok(Plan::Kills),
        "test_guardrail" => {
            let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
            let bad = |message: String| {
                refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("Refused: {message}"),
                )
            };
            let ask: TestGuardrail = serde_json::from_slice(&bytes).map_err(|err| {
                bad(format!("{err}. Send {{\"guardrail\": \"<name>\" or a definition, \"corpus\": [{{\"text\": \"...\", \"expect\": true}}]}}."))
            })?;
            let guard = match &ask.guardrail {
                Value::String(name) => {
                    call.target = Some(json!({ "guardrail": name }));
                    policy
                        .rule_list()
                        .iter()
                        .flat_map(|rule| &rule.guardrails)
                        .find(|g| &g.name == name)
                        .cloned()
                        .ok_or_else(|| {
                            refused(
                                StatusCode::NOT_FOUND,
                                "unknown_guardrail",
                                format!("Refused: no rule of the policy in use runs a guardrail named \"{name}\". Name one that does, or send its definition as an object to test it before it goes live."),
                            )
                        })?
                }
                definition @ Value::Object(_) => {
                    let def: gantry_core::guard::GuardrailFile =
                        serde_json::from_value(definition.clone()).map_err(|err| {
                            bad(format!("the guardrail definition does not read: {err}."))
                        })?;
                    call.target = Some(json!({ "guardrail": def.name, "definition": true }));
                    gantry_core::guard::guardrails(&[def])
                        .map_err(|errors| bad(errors.join(" ")))?
                        .pop()
                        .ok_or_else(|| bad("the definition holds no guardrail.".into()))?
                }
                _ => return Err(bad("guardrail is a name or a definition object.".into())),
            };
            if let Some(since) = &ask.since {
                gantry_core::guard::since_seconds(since).map_err(bad)?;
                if ask.corpus.is_empty() {
                    return Err(refused(
                        StatusCode::CONFLICT,
                        "capture_unavailable",
                        format!("Refused: {}", gantry_core::guard::NO_CAPTURE),
                    ));
                }
            }
            if ask.corpus.is_empty() {
                return Err(bad(
                    "corpus is empty. Send the examples to run the guardrail over.".into(),
                ));
            }
            let samples = ask
                .corpus
                .iter()
                .enumerate()
                .map(|(i, row)| {
                    gantry_core::guard::sample(row, i + 1)
                        .map_err(|why| format!("corpus item {}: {why}", i + 1))
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(bad)?;
            let report = gantry_core::guard::backtest(&guard, &samples).map_err(bad)?;
            let report = serde_json::to_value(report).map_err(|err| {
                refused(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    format!("Refused: {err}"),
                )
            })?;
            Ok(Plan::Backtest(report))
        }
        action @ ("set_kill" | "clear_kill") => {
            let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
            let switch: Switch = serde_json::from_slice(&bytes).map_err(|err| {
                refused(StatusCode::BAD_REQUEST, "invalid_request", format!("Refused: send a JSON object with \"scope\" (person, team, key_prefix, model or all), \"value\" and, to set a switch, \"reason\" ({err})."))
            })?;
            // Clearing needs no reason, so a placeholder passes the check of scope and value.
            let reason = if action == "set_kill" {
                switch.reason.as_str()
            } else {
                "-"
            };
            let value = kill::checked(&switch.scope, &switch.value, reason).map_err(|err| {
                refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("Refused: {err}"),
                )
            })?;
            let mut target = json!({ "scope": switch.scope, "value": value });
            if action == "set_kill" {
                target["reason"] = switch.reason.trim().into();
            }
            call.target = Some(target);
            if action == "set_kill"
                && !switch.force
                && let Some(problem) = matches_nothing(version, policy, &switch.scope, &value)
            {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "kill_matches_nothing",
                    problem,
                ));
            }
            if action == "clear_kill" {
                return Ok(Plan::Unkill {
                    scope: switch.scope,
                    value,
                });
            }
            Ok(Plan::Kill(kill::Kill {
                scope: switch.scope,
                value,
                reason: switch.reason.trim().to_string(),
                by: person.name.clone(),
                at: audit::timestamp(),
            }))
        }
        "issue_key" => {
            let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
            let mut new: NewKey = serde_json::from_slice(&bytes).map_err(|err| {
                refused(StatusCode::BAD_REQUEST, "invalid_request", format!("Refused: send a JSON object with \"name\" and \"team\", and optionally \"expires\", \"budget\", \"models\", \"tpm\", \"org\", \"customer\", \"tags\", \"parallel\", \"role\", \"rpm\", \"metadata\", \"routes\" and \"from\" ({err})."))
            })?;
            let mut extra = config::KeyEntry::default();
            for (field, value) in [
                ("rpm", &new.rpm),
                ("metadata", &new.metadata),
                ("routes", &new.routes),
                ("from", &new.from),
            ] {
                if let Some(value) = value {
                    apply(&mut extra, field, value, &[]).map_err(|problem| {
                        refused(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            format!("Refused: {problem}."),
                        )
                    })?;
                }
            }
            if !valid_name(&new.name) || !valid_name(&new.team) {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Refused: a name and a team use letters, digits, dots, dashes, underscores and @ only, at most 100 characters, for example maya.cohen and payments.",
                ));
            }
            if let Some(Err(problem)) = new.expires.as_deref().map(config::issuable_expiry) {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("Refused: {problem}."),
                ));
            }
            let budget = match &new.budget {
                None => None,
                Some(b) => {
                    let per = gantry_core::policy::Period::parse(&b.per, b.tz.as_deref());
                    match per {
                        Ok(per) if b.usd.is_finite() && b.usd > 0.0 => {
                            Some(gantry_core::policy::Budget { usd: b.usd, per })
                        }
                        Err(problem) => {
                            return Err(refused(
                                StatusCode::BAD_REQUEST,
                                "invalid_request",
                                format!("Refused: {problem}"),
                            ));
                        }
                        _ => {
                            return Err(refused(
                                StatusCode::BAD_REQUEST,
                                "invalid_request",
                                "Refused: budget takes US dollars above 0 and a period, for example {\"usd\": 20, \"per\": \"month\"}.",
                            ));
                        }
                    }
                }
            };
            // A role kept to one organization issues keys in it only.
            let org = match (&role.org, new.org.clone()) {
                (Some(own), Some(asked)) if *own != asked => {
                    return Err(refused(
                        StatusCode::FORBIDDEN,
                        "not_permitted",
                        format!(
                            "Refused: role \"{}\" issues keys in organization \"{own}\" only, and this key asks for \"{asked}\". Leave org out, or ask an admin of the whole install.",
                            role.name
                        ),
                    ));
                }
                (Some(own), _) => own.clone(),
                (None, asked) => asked.unwrap_or_default(),
            };
            // A role kept to teams or customers issues keys in them only; one kept to a single customer issues
            // its keys for that customer.
            if let ([only], None) = (role.customers.as_slice(), &new.customer) {
                new.customer = Some(only.clone());
            }
            if !role.covers(&org, &new.team, new.customer.as_deref()) {
                return Err(refused(
                    StatusCode::FORBIDDEN,
                    "not_permitted",
                    format!(
                        "Refused: role \"{}\" is kept to {}, and this key is for team \"{}\"{}. Issue it within your reach, or ask an admin of the whole install.",
                        role.name,
                        reach(&role),
                        new.team,
                        new.customer
                            .as_deref()
                            .map(|c| format!(" and customer \"{c}\""))
                            .unwrap_or_default()
                    ),
                ));
            }
            // A key may not be given more than its issuer holds: a role with a permission the issuer lacks, or one
            // not kept to the issuer's organization.
            if let Some(name) = &new.role {
                let granted: Option<Role> = policy.role(name);
                let Some(granted) = granted else {
                    return Err(refused(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        format!(
                            "Refused: role \"{name}\" is not defined under roles in the policy, and is not a built-in role (admin, read_only)."
                        ),
                    ));
                };
                let within = |mine: &[String], theirs: &[String]| {
                    mine.is_empty()
                        || (!theirs.is_empty() && theirs.iter().all(|t| mine.contains(t)))
                };
                let wider = granted.permissions.iter().any(|p| !role.may(*p))
                    || (role.org.is_some() && org.is_empty())
                    || !within(&role.teams, &granted.teams)
                    || !within(&role.customers, &granted.customers);
                if wider {
                    return Err(refused(
                        StatusCode::FORBIDDEN,
                        "not_permitted",
                        format!(
                            "Refused: role \"{name}\" grants more than your role \"{}\" holds, so you may not give it to a key. Ask an admin of the whole install.",
                            role.name
                        ),
                    ));
                }
            }
            if !org.is_empty() && !policy.orgs().contains(&org) {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!(
                        "Refused: organization \"{org}\" is not listed under orgs in the policy. Add it there first, or check the spelling."
                    ),
                ));
            }
            if let Some(models) = &new.models {
                let served: Vec<&String> = version
                    .providers
                    .iter()
                    .flat_map(|p| p.models.iter())
                    .chain(version.aliases.iter().map(|a| &a.name))
                    .collect();
                if let Some(unknown) = models.iter().find(|m| *m != "*" && !served.contains(m)) {
                    return Err(refused(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        format!(
                            "Refused: model \"{unknown}\" is not served here, so the key could never use it. List models or aliases of the policy, as GET /v1/models lists them."
                        ),
                    ));
                }
            }
            if new.models.as_ref().is_some_and(Vec::is_empty)
                || new.tpm.is_some_and(|t| !(1..=1_000_000_000).contains(&t))
            {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Refused: models lists at least one model the key may use, and tpm is the tokens it may use per minute, 1 to 1000000000, for example {\"models\": [\"gpt-4o-mini\"], \"tpm\": 200000}.",
                ));
            }
            let key = id::new_key().map_err(|err| {
                refused(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no_randomness",
                    format!("Refused: {err}. Try again."),
                )
            })?;
            call.target = Some(
                json!({ "name": new.name, "team": new.team, "sha256_prefix": &id::sha256_hex(key.as_bytes())[..8] }),
            );
            Ok(Plan::Issue {
                name: new.name,
                team: new.team,
                key,
                attributes: keyfile::Attributes {
                    admin: false,
                    expires: new.expires,
                    budget,
                    models: new.models,
                    tpm: new.tpm,
                    org,
                    customer: new.customer,
                    tags: new.tags,
                    parallel: new.parallel,
                    role: new.role,
                    options: extra.options,
                },
            })
        }
        action @ ("key_info" | "update_key" | "rotate_key") => {
            let raw = prefix.unwrap_or_default();
            let prefix = raw.trim_end_matches("/rotate").to_ascii_lowercase();
            let found = one_key(state, &prefix)?;
            // A role kept to part of the install sees and changes the keys within it only.
            if !role.covers(&found.org, &found.team, found.customer.as_deref()) {
                return Err(refused(
                    StatusCode::FORBIDDEN,
                    "not_permitted",
                    format!(
                        "Refused: the key {} is not within {}, which role \"{}\" is kept to.",
                        &found.sha256[..8],
                        reach(&role),
                        role.name
                    ),
                ));
            }
            let named = json!({ "name": found.name, "team": found.team, "sha256_prefix": &found.sha256[..8] });
            call.target = Some(named.clone());
            if action == "key_info" {
                return Ok(Plan::Info(found));
            }
            let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
            let sent: Value = if bytes.is_empty() {
                json!({})
            } else {
                serde_json::from_slice(&bytes).map_err(|_| {
                    refused(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "Refused: send a JSON object.",
                    )
                })?
            };
            let Value::Object(sent) = sent else {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Refused: send a JSON object.",
                ));
            };
            if action == "rotate_key" {
                // The new key carries the old one's rights, and its issuer sees it: only someone who holds those
                // rights may rotate it, as only they may issue it.
                let granted = match (&found.role, found.admin) {
                    (Some(name), _) => policy.role(name),
                    (None, true) => gantry_core::policy::builtin_role("admin"),
                    (None, false) => None,
                };
                if granted.is_some_and(|g| g.permissions.iter().any(|p| !role.may(*p))) {
                    return Err(refused(
                        StatusCode::FORBIDDEN,
                        "not_permitted",
                        format!(
                            "Refused: the key {} holds rights your role \"{}\" does not, so you may not rotate it. Ask an admin of the whole install.",
                            &found.sha256[..8],
                            role.name
                        ),
                    ));
                }
                if let Some(other) = sent.keys().find(|k| *k != "grace") {
                    return Err(refused(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        format!(
                            "Refused: a rotation takes only \"grace\", such as {{\"grace\": \"48h\"}}, not \"{other}\"."
                        ),
                    ));
                }
                if found.options.replaced_by.is_some() {
                    return Err(refused(
                        StatusCode::CONFLICT,
                        "already_rotated",
                        format!(
                            "Refused: the key {} was already rotated and replaced by {}. Rotate the new key instead, or revoke this one.",
                            &found.sha256[..8],
                            found.options.replaced_by.as_deref().unwrap_or_default()
                        ),
                    ));
                }
                let wait = grace(sent.get("grace").and_then(Value::as_str).unwrap_or("24h"))
                    .map_err(|problem| {
                        refused(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            format!("Refused: {problem}."),
                        )
                    })?;
                let key = id::new_key().map_err(|err| {
                    refused(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "no_randomness",
                        format!("Refused: {err}. Try again."),
                    )
                })?;
                let at = audit::rfc3339(std::time::SystemTime::now() + wait);
                // An expiry already earlier than the grace stays: a rotation never lengthens a key's life.
                let until = match &found.expires {
                    Some(old) if gantry_core::policy::expiry_passed(old, &at) => old.clone(),
                    _ => format!("{}Z", &at[..19]),
                };
                let mut target = named;
                target["replaced_by"] = id::sha256_hex(key.as_bytes())[..8].into();
                target["old_key_until"] = until.clone().into();
                call.target = Some(target);
                return Ok(Plan::Rotate {
                    old: found,
                    key,
                    until,
                });
            }
            let served: Vec<&String> = version
                .providers
                .iter()
                .flat_map(|p| p.models.iter())
                .chain(version.aliases.iter().map(|a| &a.name))
                .collect();
            if sent.is_empty() {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!(
                        "Refused: send the fields to change, such as {{\"rpm\": 60, \"tags\": [\"batch\"]}}. The admin API changes {UPDATABLE}; null removes one."
                    ),
                ));
            }
            let mut after = found.clone();
            for (field, value) in &sent {
                apply(&mut after, field, value, &served).map_err(|problem| {
                    refused(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        format!("Refused: {problem}. Nothing was changed."),
                    )
                })?;
            }
            if !role.covers(&after.org, &after.team, after.customer.as_deref()) {
                return Err(refused(
                    StatusCode::FORBIDDEN,
                    "not_permitted",
                    format!(
                        "Refused: the change would take the key {} out of {}, which role \"{}\" is kept to. Nothing was changed.",
                        &found.sha256[..8],
                        reach(&role),
                        role.name
                    ),
                ));
            }
            // The record says what each field was and what it becomes.
            let (was, now) = (key_json(&found), key_json(&after));
            let changes: Map<String, Value> = sent
                .keys()
                .map(|field| {
                    (
                        field.clone(),
                        json!({ "from": was[field.as_str()], "to": now[field.as_str()] }),
                    )
                })
                .collect();
            let mut target = named;
            target["changes"] = changes.into();
            call.target = Some(target);
            Ok(Plan::Update {
                prefix,
                changes: sent.into_iter().collect(),
            })
        }
        _ => {
            let prefix = prefix.unwrap_or_default().to_ascii_lowercase();
            if prefix.len() < 8
                || prefix.len() > 64
                || !prefix.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(refused(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Refused: name the key by the first 8 hex characters of its hash, as GET /admin/keys lists it.",
                ));
            }
            let keys_path = state
                .reloader
                .as_ref()
                .map(|r| r.keys_path().to_path_buf())
                .unwrap_or_default();
            // Looked up in the file, which may hold an entry the version in use does not have yet.
            let entries = config::read_keys(&keys_path)
                .map_err(|err| {
                    refused(StatusCode::CONFLICT, "keys_file", format!("Refused: {err}"))
                })?
                .map(|text| config::key_entries(&keys_path, &text).unwrap_or_default())
                .unwrap_or_default();
            let matching: Vec<_> = entries
                .iter()
                .filter(|e| e.sha256.starts_with(&prefix))
                .collect();
            match matching.as_slice() {
                [] => Err(refused(
                    StatusCode::NOT_FOUND,
                    "no_such_key",
                    format!(
                        "Refused: no key in the keys file has a hash that starts with {prefix}. GET /admin/keys lists them."
                    ),
                )),
                [found] if !role.covers(&found.org, &found.team, found.customer.as_deref()) => {
                    Err(refused(
                        StatusCode::FORBIDDEN,
                        "not_permitted",
                        format!(
                            "Refused: the key {prefix} is not within {}, which role \"{}\" is kept to.",
                            reach(&role),
                            role.name
                        ),
                    ))
                }
                [found] => {
                    call.target = Some(
                        json!({ "name": found.name, "team": found.team, "sha256_prefix": &found.sha256[..8] }),
                    );
                    Ok(Plan::Revoke { prefix })
                }
                _ => Err(refused(
                    StatusCode::BAD_REQUEST,
                    "ambiguous_key",
                    format!(
                        "Refused: more than one key hash starts with {prefix}. Send more of the hash."
                    ),
                )),
            }
        }
    }
}

/// The one key whose hash starts with `prefix`, from the keys file or the store, which may hold an entry the version
/// in use does not have yet.
fn one_key(state: &AppState, prefix: &str) -> Result<config::KeyEntry, Refusal> {
    if prefix.len() < 8 || prefix.len() > 64 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Refused: name the key by the first 8 hex characters of its hash, as GET /admin/keys lists it.",
        ));
    }
    let keys_path = state
        .reloader
        .as_ref()
        .map(|r| r.keys_path().to_path_buf())
        .unwrap_or_default();
    let entries = config::read_keys(&keys_path)
        .map_err(|err| refused(StatusCode::CONFLICT, "keys_file", format!("Refused: {err}")))?
        .map(|text| config::key_entries(&keys_path, &text).unwrap_or_default())
        .unwrap_or_default();
    let matching: Vec<_> = entries
        .into_iter()
        .filter(|e| e.sha256.starts_with(prefix))
        .collect();
    match <[config::KeyEntry; 1]>::try_from(matching) {
        Ok([found]) => Ok(found),
        Err(none) if none.is_empty() => Err(refused(
            StatusCode::NOT_FOUND,
            "no_such_key",
            format!(
                "Refused: no key has a hash that starts with {prefix}. GET /admin/keys lists them."
            ),
        )),
        Err(_) => Err(refused(
            StatusCode::BAD_REQUEST,
            "ambiguous_key",
            format!("Refused: more than one key hash starts with {prefix}. Send more of the hash."),
        )),
    }
}

/// Writes the record of an admin call and waits for it. A call that cannot be recorded does not happen.
pub(crate) async fn record(
    state: &AppState,
    decision: &str,
    version: &Snapshot,
    call: &Call,
    client: Option<&str>,
    code: Option<&str>,
    error: Option<&str>,
) -> Result<(), Refusal> {
    let Some(audit) = &state.audit else {
        return Ok(());
    };
    let verdict = match (code, error) {
        (None, _) => "allow",
        (Some(_), None) => "refused",
        (Some(_), Some(_)) => "failed",
    };
    let mut record = Map::new();
    record.insert("event".into(), "admin".into());
    record.insert("id".into(), decision.into());
    record.insert("time".into(), audit::timestamp().into());
    record.insert(
        "person".into(),
        call.person
            .as_ref()
            .map_or("unknown", |p| p.name.as_str())
            .into(),
    );
    record.insert(
        "team".into(),
        call.person.as_ref().map(|p| p.team.clone()).into(),
    );
    record.insert("client".into(), client.into());
    record.insert("key".into(), call.key.clone().into());
    record.insert("action".into(), call.action.into());
    record.insert("target".into(), call.target.clone().unwrap_or(Value::Null));
    record.insert("verdict".into(), verdict.into());
    record.insert("code".into(), code.into());
    if let Some(error) = error {
        record.insert("error".into(), error.into());
    }
    record.insert("policy_sha256".into(), version.policy_sha256.clone().into());
    record.insert("keys_sha256".into(), version.keys_sha256.clone().into());
    let (tell, written) = tokio::sync::oneshot::channel();
    audit.log.append_record_then(&record, move |result| {
        let _ = tell.send(result);
    });
    if matches!(written.await, Ok(Ok(()))) {
        return Ok(());
    }
    eprintln!("gantry: the audit log could not be written, so admin call {decision} was refused");
    Err(refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
        "Refused: Gantry could not write this call to its audit log, and it does not act on what it cannot record. Tell your Gantry admin.",
    ))
}

pub(crate) fn json_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

pub(crate) async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Refusal> {
    tokio::task::spawn_blocking(work).await.map_err(|_| {
        refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Refused: the change stopped before it finished. Check the keys file and try again.",
        )
    })
}

/// Puts the change in effect at once, so the answer can say whether it is.
async fn reload(state: &AppState) -> Result<Value, Refusal> {
    let Some(reloader) = state.reloader.clone() else {
        return Ok(json!({ "in_effect": false }));
    };
    Ok(
        match blocking(move || reloader.check(Trigger::FileChange)).await? {
            Reload::Loaded | Reload::Unchanged => json!({ "in_effect": true }),
            Reload::Rejected(problems) => json!({
                "in_effect": false,
                "problems": problems,
                "message": "The keys file changed, but the files on disk do not pass the check, so Gantry keeps the version it has. Fix the problems listed and the change applies within 2 seconds.",
            }),
        },
    )
}

async fn act(state: &AppState, version: &Snapshot, plan: Plan) -> Result<Response, Refusal> {
    let switches = state.kills.clone();
    let switches = || {
        switches.clone().ok_or_else(|| {
            refused(
                StatusCode::NOT_FOUND,
                "unknown_route",
                "Refused: this Gantry serves no keys file, so it has no kill switches.",
            )
        })
    };
    let kills_error = |err: String| {
        refused(
            StatusCode::CONFLICT,
            "kills_file",
            format!("Refused: {err}"),
        )
    };
    let keys_path = state
        .reloader
        .as_ref()
        .map(|r| r.keys_path().to_path_buf())
        .unwrap_or_default();
    let file_error =
        |err: String| refused(StatusCode::CONFLICT, "keys_file", format!("Refused: {err}"));
    let store_error = |err: String| {
        refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            format!("Refused: {err}"),
        )
    };
    let no_such = |name: &str| {
        refused(
            StatusCode::NOT_FOUND,
            "no_such_credential",
            format!(
                "Refused: there is no credential named \"{name}\". GET /admin/credentials lists them."
            ),
        )
    };
    match plan {
        Plan::Credentials(store) => {
            let list = store.credentials().map_err(store_error)?;
            Ok(json_response(
                StatusCode::OK,
                &json!({ "credentials": *list }),
            ))
        }
        Plan::AddCredential {
            store,
            name,
            provider,
            value,
            by,
        } => {
            let n = name.clone();
            match blocking(move || store.add_credential(&n, &provider, &value, &by))
                .await?
                .map_err(store_error)?
            {
                Some(added) => Ok(json_response(
                    StatusCode::CREATED,
                    &json!({
                        "credential": added,
                        "message": "The value is sealed in the store and never shown again. A provider names it with credential: in the policy.",
                    }),
                )),
                None => Err(refused(
                    StatusCode::CONFLICT,
                    "credential_exists",
                    format!(
                        "Refused: a credential named \"{name}\" is already in the store. Rotate it with PUT /admin/credentials/{name}, or choose another name."
                    ),
                )),
            }
        }
        Plan::RotateCredential {
            store,
            name,
            value,
            by,
        } => {
            let n = name.clone();
            match blocking(move || store.rotate_credential(&n, &value, &by))
                .await?
                .map_err(store_error)?
            {
                Some(rotated) => Ok(json_response(
                    StatusCode::OK,
                    &json!({
                        "credential": rotated,
                        "message": "Every gateway on this store sends the new value within 2 seconds. Requests already sent finish with the old one.",
                    }),
                )),
                None => Err(no_such(&name)),
            }
        }
        Plan::RemoveCredential { store, name } => {
            let n = name.clone();
            match blocking(move || store.remove_credential(&n))
                .await?
                .map_err(store_error)?
            {
                Some(removed) => Ok(json_response(
                    StatusCode::OK,
                    &json!({ "removed": removed }),
                )),
                None => Err(no_such(&name)),
            }
        }
        Plan::Explain(explained) => Ok(json_response(StatusCode::OK, &explained)),
        Plan::List(role) => {
            let mut keys: Vec<Value> = version
                .policy
                .iter()
                .flat_map(|policy| policy.entries())
                .filter(|(_, who)| role.covers(&who.org, &who.team, who.customer.as_deref()))
                .map(|(hash, who)| {
                    json!({
                        "name": who.name,
                        "team": who.team,
                        "sha256_prefix": id::hex(&hash[..4]),
                        "admin": who.admin,
                        "expires": who.expires,
                        "budget": who.budget.map(|b| json!({ "usd": b.usd, "per": b.per.word() })),
                        "models": who.models,
                        "tpm": who.tpm,
                        "org": (!who.org.is_empty()).then_some(&who.org),
                        "customer": who.customer,
                        "tags": who.tags,
                        "parallel": who.parallel,
                        "role": who.role,
                        "rpm": who.options.rpm,
                        "metadata": who.options.metadata,
                        "routes": who.options.routes,
                        "from": who.options.from.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "replaced_by": who.options.replaced_by,
                    })
                })
                .collect();
            keys.sort_by_key(|k| (k["name"].to_string(), k["sha256_prefix"].to_string()));
            Ok(json_response(StatusCode::OK, &json!({ "keys": keys })))
        }
        Plan::Issue {
            name,
            team,
            key,
            attributes,
        } => {
            let (n, t, k) = (name.clone(), team.clone(), key.clone());
            let rotated = blocking(move || keyfile::add_with(&n, &t, &k, &attributes, &keys_path))
                .await?
                .map_err(file_error)?;
            let status = reload(state).await?;
            Ok(json_response(
                StatusCode::CREATED,
                &json!({
                    "key": key,
                    "name": name,
                    "team": team,
                    "sha256_prefix": &id::sha256_hex(key.as_bytes())[..8],
                    "rotated": rotated,
                    "status": status,
                    "message": "This key is shown once and is not stored anywhere. Only its hash is in the keys file.",
                }),
            ))
        }
        Plan::Backtest(report) => Ok(json_response(StatusCode::OK, &report)),
        Plan::Info(entry) => {
            let scope = format!("key:{}", &entry.sha256[..8]);
            let (rows, source) = match &state.spend.store {
                Some(store) => (store.spend(scope).await.map_err(store_error)?, "store"),
                None => (state.spend.usage(&scope), "this gateway"),
            };
            let spend: Vec<Value> = rows
                .into_iter()
                .map(|(per, period, spent, reserved)| {
                    json!({ "per": per, "period": period, "spent_usd": spent, "reserved_usd": reserved })
                })
                .collect();
            Ok(json_response(
                StatusCode::OK,
                &json!({ "key": key_json(&entry), "spend": spend, "spend_counted_by": source }),
            ))
        }
        Plan::Update { prefix, changes } => {
            let served: Vec<String> = version
                .providers
                .iter()
                .flat_map(|p| p.models.iter().cloned())
                .chain(version.aliases.iter().map(|a| a.name.clone()))
                .collect();
            let changed = blocking(move || {
                let served: Vec<&String> = served.iter().collect();
                keyfile::update(&keys_path, &prefix, &|entry| {
                    for (field, value) in &changes {
                        // Checked before the call was recorded; a field that fails now changes nothing.
                        let _ = apply(entry, field, value, &served);
                    }
                })
            })
            .await?
            .map_err(file_error)?;
            let Some((_, after)) = changed else {
                return Err(refused(
                    StatusCode::NOT_FOUND,
                    "no_such_key",
                    "Refused: the key was removed by someone else meanwhile.",
                ));
            };
            let status = reload(state).await?;
            Ok(json_response(
                StatusCode::OK,
                &json!({ "key": key_json(&after), "status": status }),
            ))
        }
        Plan::Rotate { old, key, until } => {
            let attributes = keyfile::Attributes {
                admin: old.admin,
                expires: old.expires.clone(),
                budget: old.budget,
                models: old.models.clone(),
                tpm: old.tpm,
                org: old.org.clone(),
                customer: old.customer.clone(),
                tags: old.tags.clone(),
                parallel: old.parallel,
                role: old.role.clone(),
                options: gantry_core::policy::KeyOptions {
                    replaced_by: None,
                    ..old.options.clone()
                },
            };
            let new_prefix = id::sha256_hex(key.as_bytes())[..8].to_string();
            let (o, k, p, u, np) = (
                old.clone(),
                key.clone(),
                keys_path.clone(),
                until.clone(),
                new_prefix.clone(),
            );
            blocking(move || {
                keyfile::add_with(&o.name, &o.team, &k, &attributes, &p)?;
                let ended = keyfile::update(&p, &o.sha256, &|entry| {
                    entry.expires = Some(u.clone());
                    entry.options.replaced_by = Some(np.clone());
                });
                match ended {
                    Ok(Some(_)) => Ok(()),
                    // The new key was never shown: it is taken out again, so nobody holds a key the record does not explain.
                    other => {
                        let _ = keyfile::revoke(&p, &id::sha256_hex(k.as_bytes()));
                        Err(match other {
                            Err(err) => err,
                            _ => "the old key was removed by someone else meanwhile. No new key was made.".into(),
                        })
                    }
                }
            })
            .await?
            .map_err(file_error)?;
            let status = reload(state).await?;
            Ok(json_response(
                StatusCode::CREATED,
                &json!({
                    "key": key,
                    "name": old.name,
                    "team": old.team,
                    "sha256_prefix": new_prefix,
                    "replaces": &old.sha256[..8],
                    "old_key_until": until,
                    "status": status,
                    "message": "This key is shown once and is not stored anywhere. The old key keeps working until old_key_until, and every request made with it until then is recorded with key_rotated.",
                }),
            ))
        }
        Plan::Kills => {
            let kills = switches()?.current().map_err(kills_error)?;
            Ok(json_response(StatusCode::OK, &json!({ "kills": *kills })))
        }
        Plan::Kill(kill) => {
            let s = switches()?;
            let k = kill.clone();
            let replaced = blocking(move || s.set(k)).await?.map_err(kills_error)?;
            Ok(json_response(
                StatusCode::CREATED,
                &json!({ "kill": kill, "replaced": replaced, "in_effect": true }),
            ))
        }
        Plan::Unkill { scope, value } => {
            let s = switches()?;
            let (sc, v) = (scope.clone(), value.clone());
            match blocking(move || s.clear(&sc, &v))
                .await?
                .map_err(kills_error)?
            {
                Some(cleared) => Ok(json_response(
                    StatusCode::OK,
                    &json!({ "cleared": cleared, "in_effect": true }),
                )),
                None => Err(refused(
                    StatusCode::NOT_FOUND,
                    "no_such_switch",
                    format!(
                        "Refused: no kill switch is on for {scope} {value}. GET /admin/kills lists the ones that are."
                    ),
                )),
            }
        }
        Plan::Revoke { prefix } => {
            let gone = blocking(move || keyfile::revoke(&keys_path, &prefix))
                .await?
                .map_err(file_error)?;
            let Some(gone) = gone else {
                return Err(refused(
                    StatusCode::NOT_FOUND,
                    "no_such_key",
                    "Refused: the key was removed from the keys file by someone else meanwhile.",
                ));
            };
            let status = reload(state).await?;
            Ok(json_response(
                StatusCode::OK,
                &json!({
                    "revoked": { "name": gone.name, "team": gone.team, "sha256_prefix": &gone.sha256[..8] },
                    "status": status,
                }),
            ))
        }
    }
}

/// What a confined role is kept to, for messages: "organization \"acme\", teams payments, web".
fn reach(role: &Role) -> String {
    let mut parts = Vec::new();
    if let Some(org) = &role.org {
        parts.push(format!("organization \"{org}\""));
    }
    if !role.teams.is_empty() {
        parts.push(format!(
            "team{} {}",
            if role.teams.len() == 1 { "" } else { "s" },
            role.teams.join(", ")
        ));
    }
    if !role.customers.is_empty() {
        parts.push(format!(
            "customer{} {}",
            if role.customers.len() == 1 { "" } else { "s" },
            role.customers.join(", ")
        ));
    }
    if parts.is_empty() {
        "the whole install".into()
    } else {
        parts.join(" and ")
    }
}
