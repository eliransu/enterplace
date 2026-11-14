//! The admin API for the policy: read it, and, when it is kept in the store (`store.policy_from: store`), save a new
//! version, approve or reject one, roll back to an earlier one, and replay recent requests against a draft.
//!
//! A version is checked exactly as `gantry check` checks a file, and goes live on every gateway on the database
//! within 2 seconds. Every call is recorded before anything is done, as the keys API records its calls.
//!
//! - `GET /admin/policy`: the live policy as YAML, with its version in `ETag` (export).
//! - `PUT /admin/policy` with `If-Match: <version>` (or `none` for the first) and a YAML body: a new version
//!   (import). `X-Gantry-Note` says why.
//! - `GET /admin/policy/versions`, `GET /admin/policy/versions/<n>`: the history, and one version with its diff.
//! - `POST /admin/policy/versions/<n>/approve`, `.../reject`, `.../rollback`.
//! - `POST /admin/policy/dry-run?hours=24` with a YAML body: the recent requests the draft decides differently.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use gantry_core::{
    config, id,
    store::PolicyVersion,
    versions::{self, Refused},
};
use serde_json::{Value, json};

use crate::{
    AppState, ClientAddr, DECISION, Refusal, Trigger,
    admin::{Call, blocking, json_response, record, refused},
    caller_key, read_body,
};

const ROUTES: &str = "GET and PUT /admin/policy, GET /admin/policy/versions, GET /admin/policy/versions/<n>, POST /admin/policy/versions/<n>/approve, /reject or /rollback, and POST /admin/policy/dry-run?hours=<1 to 720>";

/// What a call asks for, once it is allowed.
enum Plan {
    Get,
    List,
    Show(i64),
    Propose {
        text: String,
        base: Option<i64>,
        note: String,
    },
    Decide {
        id: i64,
        approve: bool,
    },
    Rollback(i64),
    DryRun {
        text: String,
        hours: u64,
    },
}

pub(crate) async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let decision = id::decision_id();
    let mut response = match run(&state, request, &decision).await {
        Ok(response) => response,
        Err(refusal) => refusal.respond(&decision, false),
    };
    if let Ok(value) = HeaderValue::from_str(&decision) {
        response.headers_mut().insert(DECISION, value);
    }
    response
}

async fn run(state: &AppState, request: Request, decision: &str) -> Result<Response, Refusal> {
    let version = state.version();
    let client = request
        .extensions()
        .get::<ClientAddr>()
        .map(|addr| addr.0.ip().to_string());
    let mut call = Call::default();
    let outcome = allow(state, request, &mut call).await;
    let code = outcome.as_ref().err().map(|r| r.code);
    record(
        state,
        decision,
        &version,
        &call,
        client.as_deref(),
        code,
        None,
    )
    .await?;
    let plan = outcome?;
    let by = call
        .person
        .as_ref()
        .map(|p| p.name.clone())
        .unwrap_or_default();
    let done = act(state, plan, &by).await;
    if let Err(refusal) = &done {
        // Recorded as allowed before it was tried: this says it did not happen, and why.
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
async fn allow(state: &AppState, request: Request, call: &mut Call) -> Result<Plan, Refusal> {
    let (parts, body) = request.into_parts();
    let rest = parts
        .uri
        .path()
        .strip_prefix("/admin/policy")
        .unwrap_or_default()
        .trim_matches('/')
        .to_string();
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let number = |s: &str| s.parse::<i64>().ok();
    call.action = match (&parts.method, segments.as_slice()) {
        (&Method::GET, []) => Some("get_policy"),
        (&Method::PUT, []) => Some("propose_policy"),
        (&Method::GET, ["versions"]) => Some("list_policy_versions"),
        (&Method::GET, ["versions", n]) if number(n).is_some() => Some("show_policy_version"),
        (&Method::POST, ["versions", n, "approve"]) if number(n).is_some() => {
            Some("approve_policy")
        }
        (&Method::POST, ["versions", n, "reject"]) if number(n).is_some() => Some("reject_policy"),
        (&Method::POST, ["versions", n, "rollback"]) if number(n).is_some() => {
            Some("rollback_policy")
        }
        (&Method::POST, ["dry-run"]) => Some("dry_run_policy"),
        _ => None,
    };
    let version = state.version();
    let Some(policy) = &version.policy else {
        return Err(refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            "Refused: this Gantry serves no policy file, so it has no admin API.",
        ));
    };
    let key = caller_key(&parts.headers)?;
    let person = &crate::admin::caller(state, policy, key, call).await?;
    // The policy governs every organization: its API needs edit_policy, from a role not kept to one of them.
    match policy.role_of(person) {
        Some(role) if role.may(gantry_core::policy::Permission::EditPolicy) && !role.confined() => {
        }
        Some(role) => {
            return Err(refused(
                StatusCode::FORBIDDEN,
                "not_permitted",
                format!(
                    "Refused: the policy API needs the edit_policy permission in a role that is not kept to an organization, teams or customers, and role \"{}\" of \"{}\" is not such a role. Ask a Gantry admin.",
                    role.name, person.name
                ),
            ));
        }
        None => {
            return Err(refused(
                StatusCode::FORBIDDEN,
                "not_admin",
                format!(
                    "Refused: the admin API is for keys marked `admin: true` or given a role: in the keys file, and the key of \"{}\" is neither. Ask a Gantry admin.",
                    person.name
                ),
            ));
        }
    }
    let Some(action) = call.action else {
        return Err(refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            format!("Refused: the policy API serves {ROUTES}. Check the method and the path."),
        ));
    };
    let n = segments.get(1).and_then(|s| number(s)).unwrap_or_default();
    call.target = (n > 0).then(|| json!({ "version": n }));
    let text = |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec()).map_err(|_| {
            refused(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Refused: send the policy as UTF-8 YAML text, for example with `curl --data-binary @gantry.policy.yaml`.",
            )
        })
    };
    Ok(match action {
        "get_policy" => Plan::Get,
        "list_policy_versions" => Plan::List,
        "show_policy_version" => Plan::Show(n),
        "approve_policy" => Plan::Decide {
            id: n,
            approve: true,
        },
        "reject_policy" => Plan::Decide {
            id: n,
            approve: false,
        },
        "rollback_policy" => Plan::Rollback(n),
        "dry_run_policy" => {
            let hours = parts
                .uri
                .query()
                .unwrap_or_default()
                .split('&')
                .find_map(|pair| pair.strip_prefix("hours="))
                .map_or(Ok(24), str::parse::<u64>);
            let hours = match hours {
                Ok(h @ 1..=720) => h,
                _ => {
                    return Err(refused(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "Refused: hours is how far back to replay, 1 to 720, for example ?hours=24.",
                    ));
                }
            };
            let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
            let text = text(&bytes)?;
            call.target =
                Some(json!({ "hours": hours, "sha256": id::sha256_hex(text.as_bytes()) }));
            Plan::DryRun { text, hours }
        }
        _ => {
            let base = if_match(&parts.headers)?;
            let note = parts
                .headers
                .get("x-gantry-note")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .chars()
                .take(500)
                .collect::<String>();
            let (bytes, _held) = read_body(Some(&person.name), state, &parts.headers, body).await?;
            let text = text(&bytes)?;
            // The draft is in the record whole: the policy holds no secrets, and the chain keeps every change,
            // including one that waits for approval or is refused.
            call.target = Some(
                json!({ "base": base, "note": note, "sha256": id::sha256_hex(text.as_bytes()), "policy": text }),
            );
            Plan::Propose { text, base, note }
        }
    })
}

/// The version a draft started from, from `If-Match`: a number, or `none` before the first version.
fn if_match(headers: &HeaderMap) -> Result<Option<i64>, Refusal> {
    let missing = || {
        refused(
            StatusCode::PRECONDITION_REQUIRED,
            "if_match_required",
            "Refused: send If-Match with the version you started from, as the ETag of GET /admin/policy gives it (for example If-Match: \"3\"), so a change saved meanwhile is not overwritten.",
        )
    };
    let value = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(missing)?
        .trim()
        .trim_start_matches("W/")
        .trim_matches('"');
    if value == "none" {
        return Ok(None);
    }
    value.parse().map(Some).map_err(|_| missing())
}

pub(crate) fn refusal(err: &Refused) -> Refusal {
    let (status, code) = match err {
        Refused::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid_policy"),
        Refused::ReadOnly(_) => (StatusCode::CONFLICT, "policy_in_file"),
        Refused::Forbidden(_) => (StatusCode::FORBIDDEN, "own_version"),
        Refused::Conflict(_) => (StatusCode::CONFLICT, "version_conflict"),
        Refused::Unknown(_) => (StatusCode::NOT_FOUND, "no_such_version"),
        Refused::Store(_) => (StatusCode::SERVICE_UNAVAILABLE, "store_unavailable"),
    };
    refused(status, code, format!("Refused: {}", err.message()))
}

/// A version as the API shows it, without its text.
fn shown(v: &PolicyVersion) -> Value {
    json!({
        "version": v.id,
        "state": v.state,
        "base": v.base,
        "sha256": v.sha256,
        "note": v.note,
        "created_by": v.created_by,
        "created_at": v.created_at,
        "decided_by": v.decided_by,
        "decided_at": v.decided_at,
    })
}

async fn act(state: &AppState, plan: Plan, by: &str) -> Result<Response, Refusal> {
    let Some(reloader) = state.reloader.clone() else {
        return Err(refused(
            StatusCode::NOT_FOUND,
            "unknown_route",
            "Refused: this Gantry serves no policy file, so it has no policy API.",
        ));
    };
    let (policy_path, keys_path) = (
        reloader.policy_path().to_path_buf(),
        reloader.keys_path().to_path_buf(),
    );
    let by = by.to_string();
    match plan {
        Plan::Get => {
            let path = policy_path.clone();
            let text = blocking(move || config::policy_text(&path))
                .await?
                .map_err(|err| {
                    refused(
                        StatusCode::CONFLICT,
                        "policy_file",
                        format!("Refused: {err}"),
                    )
                })?;
            let live = gantry_core::store::policy_store(&policy_path).and_then(|s| s.live_policy());
            let (etag, source) = match &live {
                Some(v) => (format!("\"{}\"", v.id), "store"),
                None => (
                    format!("\"{}\"", &id::sha256_hex(text.as_bytes())[..16]),
                    "file",
                ),
            };
            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/yaml".to_string()),
                    (header::ETAG, etag),
                    (
                        header::HeaderName::from_static("x-gantry-policy-source"),
                        source.to_string(),
                    ),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"gantry.policy.yaml\"".to_string(),
                    ),
                ],
                text,
            )
                .into_response())
        }
        Plan::List => {
            let store = versions::store_for(&policy_path).map_err(|e| refusal(&e))?;
            let all = store
                .policy_versions()
                .map_err(|e| refusal(&Refused::Store(e)))?;
            let list: Vec<Value> = all.iter().map(shown).collect();
            Ok(json_response(StatusCode::OK, &json!({ "versions": list })))
        }
        Plan::Show(n) => {
            let store = versions::store_for(&policy_path).map_err(|e| refusal(&e))?;
            let v = versions::find(&store, n).map_err(|e| refusal(&e))?;
            let mut body = shown(&v);
            body["policy"] = v.text.clone().into();
            body["diff"] = versions::diff_text(&versions::base_text(&store, &v), &v.text).into();
            Ok(json_response(StatusCode::OK, &body))
        }
        Plan::Propose { text, base, note } => {
            let done = blocking(move || {
                versions::propose(&policy_path, &keys_path, &text, base, &note, &by)
            })
            .await?;
            changed(state, done, StatusCode::CREATED).await
        }
        Plan::Decide { id, approve } => {
            let done =
                blocking(move || versions::decide(&policy_path, &keys_path, id, approve, &by))
                    .await?;
            changed(state, done, StatusCode::OK).await
        }
        Plan::Rollback(id) => {
            let done =
                blocking(move || versions::rollback(&policy_path, &keys_path, id, &by)).await?;
            changed(state, done, StatusCode::CREATED).await
        }
        Plan::DryRun { text, hours } => {
            let keys = state.version().policy.clone().unwrap_or_default();
            let (audit_path, draft) = blocking(move || {
                let loaded =
                    config::load(&policy_path, Some(&keys_path)).map_err(Refused::Invalid)?;
                let draft = versions::check(&policy_path, &keys_path, &text, &loaded)
                    .map_err(Refused::Invalid)?;
                Ok::<_, Refused>((loaded.audit_path, draft))
            })
            .await?
            .map_err(|e| refusal(&e))?;
            // With a store every gateway's requests are in its index; without, only this gateway's log has them.
            let run = match gantry_core::insights::attached(&audit_path).index {
                Some(index) => {
                    let lines = versions::shared_lines(index.as_ref(), hours)
                        .await
                        .map_err(|e| refusal(&Refused::Store(e)))?;
                    blocking(move || {
                        versions::dry_run_shared(lines, &audit_path, hours, &draft, &keys)
                    })
                    .await?
                    .map_err(|e| refusal(&Refused::Store(e)))?
                }
                None => blocking(move || versions::dry_run_log(&audit_path, hours, &draft, &keys))
                    .await?
                    .map_err(|e| refusal(&Refused::Store(e)))?,
            };
            Ok(json_response(StatusCode::OK, &json!({ "dry_run": run })))
        }
    }
}

/// The answer to a change: the version, its diff, and whether this gateway uses it yet. Others follow within 2
/// seconds.
pub(crate) async fn changed(
    state: &AppState,
    done: Result<PolicyVersion, Refused>,
    status: StatusCode,
) -> Result<Response, Refusal> {
    let v = done.map_err(|e| refusal(&e))?;
    let in_effect = if v.state == gantry_core::store::LIVE {
        match state.reloader.clone() {
            Some(reloader) => matches!(
                blocking(move || reloader.check(Trigger::Store)).await?,
                crate::Reload::Loaded | crate::Reload::Unchanged
            ),
            None => false,
        }
    } else {
        false
    };
    let mut body = shown(&v);
    body["in_effect"] = in_effect.into();
    body["message"] = match v.state.as_str() {
        "pending" => format!(
            "Version {} is saved and waits for a second admin: POST /admin/policy/versions/{}/approve. The live version stays in force until then.",
            v.id, v.id
        ),
        "live" => format!("Version {} is live. Every gateway on this store uses it within 2 seconds.", v.id),
        _ => format!("Version {} is {}.", v.id, v.state),
    }
    .into();
    Ok(json_response(status, &body))
}
