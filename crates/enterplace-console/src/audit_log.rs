//! The audit log in the console app (`/console/app/#/audit`): every decision and admin change in one hash chain,
//! newest first, with filters, a sheet that tells each record's story, the kill switches on now, and Verify chain now.
//!
//! Every word the page shows is computed here, from the records and the policy that decided them, so the tests pin
//! the words and the app only lays them out. The chain is read, never written, except for Restore traffic, which is
//! recorded first like every console change.

use std::fmt::Write as _;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::{get, post},
};
use enterplace_core::{
    audit, config,
    config::Loaded,
    id::sha256_hex,
    kill::Kill,
    policy::{Permission, Principal, Who},
};
use serde_json::{Value, json};

use crate::{
    Act, Console, Form, NOT_RECORDED,
    api::{Fail, answer, bad, body_of, ok, signed_in, text},
    chain_for,
    figures::{money, time_full, time_list},
    html::{enc, thousands},
    log_for,
    pages::{MONTHS, code_words, day_words, days_in, today},
    read, record, redirect,
};

const PER_PAGE: usize = 50;

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        // The server-rendered page moved to the app: old links (alerts, Requests, saved bookmarks) land on the same
        // view there.
        .route("/audit", get(moved))
        .route("/api/audit", get(list))
        .route("/api/audit/verify", post(verify))
        .route("/api/audit/restore", post(restore))
        .route("/api/audit/stop", post(stop))
        .route("/audit/export", get(export))
        .route("/audit/export.csv", get(export_csv))
}

/// The app's audit route for an old address, keeping its filters, chain and open record. A role that may not read
/// records but may see spend starts on Spend, as the console did when the audit log was its first page.
async fn moved(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    if let Some(admin) = console.admin(&headers).await
        && !admin.may(Permission::SeeRecords)
        && admin.may(Permission::SeeSpend)
    {
        return redirect("/console/spend");
    }
    let query = Form::of(&uri);
    let kept: Vec<String> = ["verdict", "q", "model", "chain", "record", "page"]
        .iter()
        .filter(|name| !query.get(name).is_empty())
        .map(|name| format!("{name}={}", enc(query.get(name))))
        .collect();
    let mut to = "/console/app/#/audit".to_string();
    if !kept.is_empty() {
        to.push('?');
        to.push_str(&kept.join("&"));
    }
    redirect(&to)
}

fn s<'a>(record: &'a Value, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

fn ago(at: std::time::Instant) -> String {
    match at.elapsed().as_secs() {
        0..5 => "just now".into(),
        s @ 5..120 => format!("{s} seconds ago"),
        s @ 120..7200 => format!("{} minutes ago", s / 60),
        s => format!("{} hours ago", s / 3600),
    }
}

/// A Tag as the app draws it: its kind (`allow`, `refused`, `block`, `mask`, `warn` or plain), word and detail.
fn tag(kind: &str, word: &str, detail: &str) -> Value {
    json!({ "kind": kind, "word": word, "detail": detail })
}

async fn list(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            if !admin.may(Permission::SeeRecords) {
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    format!(
                        "Your role, {}, does not have the {} permission this page needs. Ask an Enterplace admin to add it to the role under roles: in the policy.",
                        admin.role,
                        Permission::SeeRecords.word()
                    ),
                ));
            }
            let config = console.config();
            let query = Form::of(&uri);
            let (chain, path) = chain_for(&admin, &config.audit, &query);
            // ponytail: the whole audit log is read and parsed on every poll. Fine for today's logs; an index or a
            // tail read when they reach many megabytes.
            let log = if chain.is_empty() {
                log_for(&admin, read(&path))
            } else {
                read(&path)
            };
            let log = log.map_err(|err| {
                Fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "The audit log did not load: {err} Requests are refused while Enterplace cannot write it: Enterplace does not forward what it cannot record. Check that the file is there and Enterplace may read it, then reload."
                    ),
                )
            })?;
            // Someone kept to no organization may switch between the install's chain and each organization's.
            let mut chains = Vec::new();
            if admin.org.is_none() {
                let orgs = audit::org_chains(&config.audit).unwrap_or_default();
                if !orgs.is_empty() {
                    chains.push(json!({ "label": "Install", "chain": "", "shown": chain.is_empty() }));
                }
                for (org, _) in orgs {
                    chains.push(json!({ "label": org, "chain": org, "shown": org == chain }));
                }
            }
            let kills = enterplace_core::kill::read(&enterplace_core::kill::path_beside(&config.keys));
            let policy = config::policy_text(&config.policy).ok();
            let loaded = config::load(&config.policy, Some(&config.keys)).ok();
            let view = View {
                query: &query,
                log: log.as_deref(),
                chain: &chain,
                policy: policy.as_deref(),
                loaded: loaded.as_ref(),
                verified: console.verified(&chain),
                read_only: admin.read_only,
                kills: kills.as_ref().map_or(&[], Vec::as_slice),
            };
            let mut out = page(&view);
            out["chains"] = Value::Array(chains);
            out["may_restore"] = admin.may(Permission::Kill).into();
            out["stop_agent"] = crate::start::kill_prompt(&crate::base(), None).into();
            out["kills_error"] = kills.as_ref().err().map_or(Value::Null, |err| {
                format!("Every request is refused: the kill switch list cannot be read. {err}").into()
            });
            out["kills"] = kills
                .as_ref()
                .map(|kills| {
                    kills
                        .iter()
                        .map(|k| {
                            json!({
                                "label": k.label(),
                                "since": time_list(&k.at),
                                "by": k.by,
                                "reason": k.reason,
                                "scope": k.scope,
                                "value": k.value,
                                // Without the right to restore, the command an admin runs.
                                "command": crate::pages::unkill_command(k),
                                "agent": crate::start::kill_prompt(&crate::base(), Some(k)),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(ok(out))
        }
        .await,
    )
}

/// Walks the chain, as `enterplace audit verify` does, and keeps the result for the page to show.
async fn verify(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let body = if bytes.is_empty() {
                serde_json::Map::new()
            } else {
                body_of(&bytes)?
            };
            let asked = Form::parse(&format!("chain={}", enc(text(&body, "chain"))));
            let (chain, path) = chain_for(&admin, &console.config().audit, &asked);
            // It reads the whole file, so it runs off the request threads.
            let result = tokio::task::spawn_blocking(move || {
                if path.exists() {
                    audit::verify(&path)
                } else {
                    Ok((0, String::new()))
                }
            })
            .await
            .unwrap_or_else(|err| Err(format!("the check stopped before it finished: {err}.")));
            let message = match &result {
                Ok((0, _)) => "Chain verified: no records yet.".to_string(),
                Ok((n, _)) => format!(
                    "Chain verified: unbroken from record 1 to record {}.",
                    thousands(usize::try_from(*n).unwrap_or(0))
                ),
                Err(err) => format!("The chain is broken: {err}"),
            };
            console
                .0
                .verified
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(chain, (std::time::Instant::now(), result));
            Ok(ok(json!({ "message": message })))
        }
        .await,
    )
}

/// Restore traffic: turns a kill switch off, as `enterplace unkill` and `DELETE /admin/kills` do, recorded first.
async fn restore(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            if !admin.may(Permission::Kill) {
                crate::read_only(&console, &admin, "clear_kill").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    format!(
                        "Your role, {}, does not have the kill permission, so traffic stays stopped. Ask an admin to run the command shown beside the switch.",
                        admin.role
                    ),
                ));
            }
            let body = body_of(&bytes)?;
            let (scope, value) = (text(&body, "scope").to_string(), text(&body, "value").to_string());
            let value = enterplace_core::kill::checked(&scope, &value, "-").map_err(|err| {
                bad(format!("{} Reload the page and press Restore traffic on the switch again.", crate::api::sentence(&err)))
            })?;
            let act = Act {
                action: "clear_kill",
                by: Some((&admin.name, &admin.team)),
                key: None,
                target: json!({ "scope": scope, "value": value }),
            };
            if record(&console, &act, None, None).await.is_err() {
                return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
            }
            let switches = enterplace_core::kill::Switches::open(enterplace_core::kill::path_beside(
                &console.config().keys,
            ));
            let label = Kill {
                scope: scope.clone(),
                value: value.clone(),
                reason: String::new(),
                by: String::new(),
                at: String::new(),
            }
            .label();
            tokio::task::spawn_blocking(move || switches.clear(&scope, &value))
                .await
                .map_err(|_| Fail(StatusCode::SERVICE_UNAVAILABLE, "The switch could not be turned off: the task stopped. Try again.".into()))?
                .map_err(|err| Fail(StatusCode::SERVICE_UNAVAILABLE, format!("The switch could not be turned off: {err} Try again, or run enterplace unkill on the gateway's host.")))?;
            Ok(ok(json!({
                "message": format!("Traffic restored for {label}. Every gateway lets it through within 2 seconds."),
            })))
        }
        .await,
    )
}

/// Stop traffic: turns a kill switch on, as `enterplace kill` and `POST /admin/kills` do, recorded first.
async fn stop(State(console): State<Console>, headers: HeaderMap, bytes: Bytes) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            if !admin.may(Permission::Kill) {
                crate::read_only(&console, &admin, "set_kill").await;
                return Err(Fail(
                    StatusCode::FORBIDDEN,
                    format!(
                        "Your role, {}, does not have the kill permission, so traffic was not stopped. Ask an admin whose role has it.",
                        admin.role
                    ),
                ));
            }
            let body = body_of(&bytes)?;
            let (scope, reason) = (text(&body, "scope").to_string(), text(&body, "reason").trim().to_string());
            let value = enterplace_core::kill::checked(&scope, text(&body, "value"), &reason)
                .map_err(|err| bad(format!("{} Fix it and press Stop traffic again.", crate::api::sentence(&err))))?;
            let act = Act {
                action: "set_kill",
                by: Some((&admin.name, &admin.team)),
                key: None,
                target: json!({ "scope": scope, "value": value, "reason": reason }),
            };
            if record(&console, &act, None, None).await.is_err() {
                return Err(Fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into()));
            }
            let switches = enterplace_core::kill::Switches::open(enterplace_core::kill::path_beside(
                &console.config().keys,
            ));
            let kill = Kill { scope, value, reason, by: admin.name.clone(), at: audit::timestamp() };
            let label = kill.label();
            tokio::task::spawn_blocking(move || switches.set(kill))
                .await
                .map_err(|_| Fail(StatusCode::SERVICE_UNAVAILABLE, "Traffic was not stopped: the task stopped. Try again.".into()))?
                .map_err(|err| Fail(StatusCode::SERVICE_UNAVAILABLE, format!("Traffic was not stopped: {err} Try again, or run enterplace kill on the gateway's host.")))?;
            Ok(ok(json!({
                "message": format!("Traffic stopped for {label}. Every gateway refuses it within 2 seconds. Restore traffic is on the Audit log."),
            })))
        }
        .await,
    )
}

/// The chain as an auditor takes it: the records as written, one JSON object a line, so `enterplace audit verify`
/// checks the file itself. Someone kept to an organization gets only the records they may read.
async fn export(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let (admin, chain, text) = match exportable(&console, &headers, &uri).await {
        Ok(got) => got,
        Err(refused) => return refused,
    };
    let act = Act {
        action: "export_audit",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "chain": chain, "records": text.lines().count() }),
    };
    if record(&console, &act, None, None).await.is_err() {
        return plain_fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into());
    }
    let name = if chain.is_empty() {
        "enterplace-audit.jsonl".to_string()
    } else {
        format!("enterplace-audit-{chain}.jsonl")
    };
    Response::builder()
        .header("content-type", "application/x-ndjson")
        .header(
            "content-disposition",
            format!("attachment; filename=\"{name}\""),
        )
        .header("cache-control", "no-store")
        .body(axum::body::Body::from(text))
        .unwrap_or_default()
}

fn plain_fail(status: StatusCode, text: String) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(axum::body::Body::from(text))
        .unwrap_or_default()
}

/// The person asking for an export, the chain they asked for, and the records of it they may read.
async fn exportable(
    console: &Console,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<(crate::Admin, String, String), Response> {
    let admin = signed_in(console, headers, false)
        .await
        .map_err(|Fail(status, text)| plain_fail(status, text))?;
    if !admin.may(Permission::SeeRecords) {
        return Err(plain_fail(
            StatusCode::FORBIDDEN,
            format!(
                "Your role, {}, does not have the {} permission an export needs. Ask an Enterplace admin to add it to the role under roles: in the policy.",
                admin.role,
                Permission::SeeRecords.word()
            ),
        ));
    }
    let (chain, path) = chain_for(&admin, &console.config().audit, &Form::of(uri));
    let log = if chain.is_empty() {
        log_for(&admin, read(&path))
    } else {
        read(&path)
    };
    match log {
        Ok(text) => Ok((admin, chain, text.unwrap_or_default())),
        Err(err) => Err(plain_fail(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "The audit log did not load: {err} Check that the file is there and Enterplace may read it, then try again."
            ),
        )),
    }
}

/// One CSV field. A field a spreadsheet would run as a formula starts with a quote mark, so a person name or a
/// reason sent by a caller cannot become one.
fn csv_field(text: &str) -> String {
    let text = if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{text}")
    } else {
        text.to_string()
    };
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

/// The rows the Audit log's current filter shows, newest first, as a CSV: what a reviewer takes into a spreadsheet.
/// The full chain stays the export an auditor verifies. Taking it is recorded with the filter it was taken under.
async fn export_csv(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let (admin, chain, text) = match exportable(&console, &headers, &uri).await {
        Ok(got) => got,
        Err(refused) => return refused,
    };
    let query = Form::of(&uri);
    let filter = Filter {
        show: query.get("verdict"),
        q: query.get("q").trim(),
        model: query.get("model"),
    };
    let records = fold_answers(
        text.lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|r| !matches!(s(r, "event"), "attempts" | "usage"))
            .collect(),
    );
    let keys = &console.config().keys;
    let entries = config::read_keys(keys)
        .ok()
        .flatten()
        .and_then(|t| config::key_entries(keys, &t).ok())
        .unwrap_or_default();
    let kind = |record: &Value| {
        let key = s(record, "key");
        if key.is_empty() {
            return "";
        }
        entries
            .iter()
            .find(|e| e.sha256.starts_with(key))
            .map_or("unknown key", |e| {
                match e.options.metadata.get("kind").map(String::as_str) {
                    _ if e.admin => "admin key",
                    Some(crate::PERSON_TOKEN_KIND) => "person token",
                    Some("workload") => "service key",
                    _ => "key",
                }
            })
    };
    let mut out = String::from("time,decision,person,team,key kind,model or tool,verdict,reason\n");
    let mut rows = 0;
    for record in records.iter().rev().filter(|r| filter.keeps(r)) {
        let tag = verdict(record);
        let verdict = format!(
            "{} {}",
            tag["word"].as_str().unwrap_or(""),
            tag["detail"].as_str().unwrap_or("")
        );
        let what = [s(record, "model"), s(record, "tool"), s(record, "prompt")]
            .into_iter()
            .find(|v| !v.is_empty())
            .unwrap_or("");
        let reason = match s(record, "code") {
            "" => s(record, "action").replace('_', " "),
            code => code_words(code),
        };
        let fields = [
            s(record, "time").to_string(),
            rid(record),
            who(record),
            s(record, "team").to_string(),
            kind(record).to_string(),
            what.to_string(),
            verdict.trim().to_string(),
            reason,
        ];
        let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
        rows += 1;
    }
    let act = Act {
        action: "export_audit_csv",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({
            "chain": chain,
            "rows": rows,
            "verdict": filter.show,
            "q": filter.q,
            "model": filter.model,
        }),
    };
    if record(&console, &act, None, None).await.is_err() {
        return plain_fail(StatusCode::SERVICE_UNAVAILABLE, NOT_RECORDED.into());
    }
    let name = if chain.is_empty() {
        "enterplace-audit-rows.csv".to_string()
    } else {
        format!("enterplace-audit-{chain}-rows.csv")
    };
    Response::builder()
        .header("content-type", "text/csv; charset=utf-8")
        .header(
            "content-disposition",
            format!("attachment; filename=\"{name}\""),
        )
        .header("cache-control", "no-store")
        .body(axum::body::Body::from(out))
        .unwrap_or_default()
}

/// What the page reads besides the person: the query, the chain's text, and what the sheets explain records with.
struct View<'a> {
    query: &'a Form,
    log: Option<&'a str>,
    chain: &'a str,
    policy: Option<&'a str>,
    loaded: Option<&'a Loaded>,
    verified: Option<crate::Verified>,
    read_only: bool,
    kills: &'a [Kill],
}

/// The page as JSON: the chain's line, today's figures, the filtered rows of one page, and the open record's sheet.
fn page(view: &View<'_>) -> Value {
    let query = view.query;
    let filter = Filter {
        show: query.get("verdict"),
        q: query.get("q").trim(),
        model: query.get("model"),
    };
    let lead = if view.chain.is_empty() {
        "Every decision and admin change, in one chain.".to_string()
    } else {
        format!(
            "Every decision and change of organization {}, newest first, from its own chain.",
            view.chain
        )
    };
    let (records, usage): (Vec<Value>, Vec<Value>) = view
        .log
        .unwrap_or("")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        // An attempts record repeats its decision's ID with the providers tried: it belongs to that decision.
        .filter(|r| s(r, "event") != "attempts")
        // Usage records are shown on the Spend page; the list is of decisions and changes.
        .partition(|r| s(r, "event") != "usage");
    let records = fold_answers(records);
    // Sign-ins and setup only, or nothing: the page says what fills it, above those records.
    let empty = records
        .iter()
        .all(|r| r.get("event").is_some())
        .then(|| crate::start::empty_for("Audit log", &crate::base()))
        .flatten()
        .map(|e| {
            json!({
                "title": e.title,
                "body": e.body,
                "action": { "label": e.action.0, "href": e.action.1 },
                "docs": format!("{}{}", crate::start::DOCS, e.docs),
            })
        });
    let mut out = json!({
        "lead": lead,
        "chain": view.chain,
        "empty": empty,
        "total": records.len(),
    });
    if records.is_empty() {
        return out;
    }

    // The chain's line, or the banner of a broken chain. `recent`: just verified, so the app moves focus to it.
    let (verified, broken) = match &view.verified {
        None => (
            json!({
                "state": "none",
                // Every record in the chain, usage ones too, as the CLI counts them.
                "text": format!(
                    "The chain has not been verified since Enterplace started. Verify chain now walks all {} records, as enterplace audit verify does.",
                    thousands(records.len() + usage.len())
                ),
            }),
            None,
        ),
        Some((at, Ok((0, _)))) => (
            json!({ "state": "ok", "text": format!("Chain verified {}: no records yet.", ago(*at)), "recent": at.elapsed().as_secs() < 10 }),
            None,
        ),
        Some((at, Ok((n, last)))) => (
            json!({
                "state": "ok",
                "text": format!(
                    "Chain verified {}: unbroken from record 1 to record {}. Its last hash:",
                    ago(*at),
                    thousands(usize::try_from(*n).unwrap_or(0))
                ),
                // The whole hash: --expect-last needs all 64 characters, and a short one reads as records removed.
                "last_hash": last,
                "note": "Keep it somewhere Enterplace's host cannot write. Later, enterplace audit verify --expect-last with it proves no record up to it was changed or removed.",
                "recent": at.elapsed().as_secs() < 10,
            }),
            None,
        ),
        Some((at, Err(err))) => {
            let n = broken_at(err);
            let open = n
                .and_then(|n| records.iter().find(|r| r.get("n").and_then(Value::as_u64) == Some(n)))
                .map(|r| {
                    json!({
                        "label": format!("Open record {}", thousands(n.map_or(0, |n| usize::try_from(n).unwrap_or(0)))),
                        "record": rid(r),
                    })
                });
            (
                json!({
                    "state": "broken",
                    "banner": format!("The chain is broken: {err}"),
                    "open": open,
                    "text": format!(
                        "Last verification {}: {}",
                        ago(*at),
                        match n {
                            Some(n) if n > 1 => format!("records 1 to {} hold, then record {} does not.", n - 1, n),
                            Some(_) => "record 1 does not hold.".to_string(),
                            None => "the log could not be walked.".to_string(),
                        }
                    ),
                    "recent": at.elapsed().as_secs() < 10,
                }),
                Some(n.unwrap_or(0)),
            )
        }
    };

    // Requests only: admin records carry a verdict too, and are not requests through the gateway.
    let today = today();
    let today_where = |keep: &dyn Fn(&Value) -> bool| {
        records
            .iter()
            .filter(|r| s(r, "time").starts_with(&today) && r.get("event").is_none() && keep(r))
            .count()
    };
    // A broken chain hides today's figures: they would count records that cannot be trusted.
    let stats = broken.is_none().then(|| {
        json!({
            "checked": thousands(today_where(&|r| !s(r, "verdict").is_empty())),
            "refused": thousands(today_where(&|r| s(r, "verdict") == "refused" && s(r, "code") != "guardrail_blocked")),
            "blocked": thousands(today_where(&|r| blocked(r))),
        })
    });

    let mut models: Vec<&str> = records
        .iter()
        .map(|r| s(r, "model"))
        .filter(|m| !m.is_empty())
        .collect();
    models.sort_unstable();
    models.dedup();
    let show = if SHOW.iter().any(|(v, _)| *v == filter.show) {
        filter.show
    } else {
        "all"
    };

    let ctx = Context {
        records: &records,
        usage: &usage,
        policy: view.policy,
        loaded: view.loaded,
        broken,
        read_only: view.read_only,
        kills: view.kills,
    };
    let shown: Vec<&Value> = records.iter().rev().filter(|r| filter.keeps(r)).collect();
    let selected = query.get("record");
    let pages = shown.len().div_ceil(PER_PAGE).max(1);
    let page = query.get("page").parse().unwrap_or(1).clamp(1, pages);
    let noun = if show == "changes" {
        "changes"
    } else {
        "decisions"
    };
    let rows: Vec<Value> = shown
        .iter()
        .skip((page - 1) * PER_PAGE)
        .take(PER_PAGE)
        .map(|record| {
            let id = rid(record);
            let sub = match (s(record, "team"), s(record, "key")) {
                ("", "") => String::new(),
                ("", key) => format!("key hash {key}"),
                (team, _) => team.to_string(),
            };
            // An admin action has a decision ID; a change to the files has only its record number.
            let open = if s(record, "id").is_empty() {
                format!("Open record {id}")
            } else {
                format!("Open decision {id}")
            };
            json!({
                "id": id,
                "who": who(record),
                "sub": sub,
                "verdict": verdict(record),
                "time": time_list(s(record, "time")),
                "open": open,
                "model": s(record, "model"),
                // The Changes view says what changed and why, as the AuditChanges screen lays it out.
                "title": if show == "changes" { story(record, &ctx).0 } else { String::new() },
                "selected": id == selected && id != "0",
            })
        })
        .collect();
    let from = (page - 1) * PER_PAGE + 1;
    let to = (page * PER_PAGE).min(shown.len());
    let sheet = (!selected.is_empty()).then(|| {
        let number = |r: &Value| r.get("n").and_then(Value::as_u64).map(|n| n.to_string());
        records
            .iter()
            .find(|r| {
                rid(r) == selected
                    || number(r).as_deref() == Some(selected)
                    || r.get("answer").and_then(number).as_deref() == Some(selected)
            })
            .map_or_else(
                || {
                    json!({
                        "missing": true,
                        "title": "No record has this ID",
                        "lead": format!("No record in this audit log has decision ID or number {selected}. It may be in an older log file, or the ID was cut short when it was copied."),
                    })
                },
                |r| record_sheet(r, &ctx),
            )
    });
    for (k, v) in [
        ("verified", verified),
        ("stats", stats.unwrap_or(Value::Null)),
        ("models", json!(models)),
        ("show", show.into()),
        (
            "shows",
            SHOW.iter()
                .map(|(value, label)| json!({ "value": value, "label": label }))
                .collect(),
        ),
        ("noun", noun.into()),
        ("rows", Value::Array(rows)),
        ("matched", shown.len().into()),
        (
            "pager",
            json!({
                "text": format!("{} to {} of {} {noun}", thousands(from), thousands(to), thousands(shown.len())),
                "page": page,
                "pages": pages,
            }),
        ),
        ("caution", broken.is_some().into()),
        ("record", sheet.unwrap_or(Value::Null)),
    ] {
        out[k] = v;
    }
    out
}

/// The revoke of the key a refused record carried, if it is in this log: who still uses it is the question, who
/// revoked it the start.
fn revoke_of<'a>(record: &Value, ctx: &Context<'a>) -> Option<&'a Value> {
    let key = s(record, "key");
    ctx.records.iter().find(|r| {
        s(r, "action") == "revoke_key"
            && s(r, "verdict") == "allow"
            && !key.is_empty()
            && r.get("target").map(|t| s(t, "sha256_prefix")) == Some(key)
    })
}

/// The policy text a change loaded, against the one loaded before it in this log.
fn change_snippet(record: &Value, ctx: &Context<'_>) -> Value {
    let n = record.get("n").and_then(Value::as_u64).unwrap_or(0);
    let before =
        ctx.records.iter().rev().find(|r| {
            s(r, "event") == "config_loaded" && r.get("n").and_then(Value::as_u64) < Some(n)
        });
    let note = |text: &str, lines: Vec<Value>| json!({ "note": text, "lines": lines });
    match (before.map(|r| s(r, "policy")), s(record, "policy")) {
        (_, "") => Value::Null,
        (None, _) => note(
            "The first version of the policy in this log. The record holds its whole text.",
            Vec::new(),
        ),
        (Some(old), new) if old == new => note(
            "The policy text did not change: only the keys file did.",
            Vec::new(),
        ),
        (Some(old), new) => note(
            "What changed in the policy file, against the version loaded before it.",
            enterplace_core::versions::diff(old, new)
                .into_iter()
                .map(|(n, text, kind)| json!({ "n": n, "text": text, "kind": kind }))
                .collect(),
        ),
    }
}

fn record_sheet(record: &Value, ctx: &Context<'_>) -> Value {
    let (title, lead, extra) = story(record, ctx);
    let id = s(record, "id");
    let both = |a: &str, b: &str| match (a, b) {
        ("", b) => b.to_string(),
        (a, "") => a.to_string(),
        (a, b) => format!("{a}, {b}"),
    };
    let line = record.get("rule_line").and_then(Value::as_u64).unwrap_or(0);
    let n = record.get("n").and_then(Value::as_u64).unwrap_or(0);
    let key_hash = match s(record, "key") {
        "" => record.get("target").map_or("", |t| s(t, "sha256_prefix")),
        key => key,
    };
    let fact = |label: &str, text: String| json!({ "label": label, "text": text });
    let mut facts: Vec<Value> = vec![
        fact("Record", n.to_string()),
        fact("Decision", id.to_string()),
        fact("Time", time_full(s(record, "time"))),
        fact("Person", both(s(record, "person"), s(record, "team"))),
        fact("Client", s(record, "client").to_string()),
        fact("Key hash", key_hash.to_string()),
        fact(
            "Request",
            both(s(record, "method"), s(record, "path")).replace(", ", " "),
        ),
        fact(
            "Model",
            match s(record, "provider") {
                "" => s(record, "model").to_string(),
                provider => format!("{} via {provider}", s(record, "model")),
            },
        ),
        fact(
            "Verdict",
            // The words the list's tag uses, not the record's own codes.
            match (s(record, "verdict"), answer_verdict(record)) {
                (_, "block") => "Allowed, answer withheld".to_string(),
                (_, "mask") => "Allowed, answer masked".to_string(),
                ("allow", _) if !would_refuse(record).is_empty() => {
                    "Allowed, would have been refused".to_string()
                }
                ("allow", _) => "Allowed".to_string(),
                ("refused", _) => format!("Refused: {}", code_words(s(record, "code"))),
                (verdict, _) => both(verdict, s(record, "code")),
            },
        ),
        fact(
            "Rule",
            if line > 0 {
                format!("{}, line {line}", s(record, "rule"))
            } else {
                s(record, "rule").to_string()
            },
        ),
    ];
    // One row per finding: its badge, then which guardrail and how many. Never the matched text.
    let finding = |f: &Value, answer: bool| {
        json!({
            "label": "Finding",
            "tag": badge(s(f, "action"), s(f, "kind")),
            "text": format!(
                "{}, {}{}",
                s(f, "guardrail"),
                f.get("count").and_then(Value::as_u64).unwrap_or(0),
                if answer { ", on the answer" } else { "" }
            ),
        })
    };
    match record.get("guardrails").and_then(Value::as_array) {
        None => {}
        Some(list) if list.is_empty() => facts.push(fact("Guardrails", "Nothing found".into())),
        Some(list) => facts.extend(list.iter().map(|f| finding(f, false))),
    }
    facts.extend(answer_findings(record).iter().map(|f| finding(f, true)));
    match answer_verdict(record) {
        "pass" => facts.push(fact("Answer", "Checked, nothing found".into())),
        "not_run" => facts.push(fact("Answer", "Not checked: streamed".into())),
        _ => {}
    }
    if let Some(answer) = record.get("answer") {
        let n = answer.get("n").and_then(Value::as_u64).unwrap_or(0);
        facts.push(fact("Answer record", n.to_string()));
    }
    let priced = ctx
        .usage
        .iter()
        .find(|u| !id.is_empty() && s(u, "id") == id)
        .map(|u| s(u, "price_source"));
    if let Some(source) = priced {
        facts.push(fact("Price", crate::pages::price_word(source)));
    }
    facts.extend(extra.into_iter().map(|(label, text)| fact(label, text)));
    for (label, key) in [
        ("Policy file", "policy_sha256"),
        ("Keys file", "keys_sha256"),
        ("Record hash", "hash"),
        ("Previous", "prev"),
    ] {
        facts.push(fact(label, s(record, key).to_string()));
    }
    facts.retain(|f| !matches!(s(f, "text"), "" | "0"));
    let same_policy = ctx
        .policy
        .filter(|text| sha256_hex(text.as_bytes()) == s(record, "policy_sha256"));
    let snippet = match (same_policy, line) {
        _ if s(record, "event") == "config_loaded" => change_snippet(record, ctx),
        (_, 0) => Value::Null,
        // The rule's line with one line around it, as the policy reads now.
        (Some(text), line) => {
            let line = usize::try_from(line).unwrap_or(0);
            let lines: Vec<Value> = text
                .lines()
                .enumerate()
                .map(|(i, l)| (i + 1, l))
                .filter(|(n, _)| n + 1 >= line && *n <= line + 1)
                .map(|(n, l)| json!({ "n": n, "text": l, "kind": if n == line { "hit" } else { "" } }))
                .collect();
            json!({ "note": null, "lines": lines })
        }
        (None, _) => json!({
            "note": "The policy file has changed since this decision, so the lines that decided it are not shown. The hash above names the version that did.",
            "lines": [],
        }),
    };
    let mut actions: Vec<Value> = Vec::new();
    let action = |label: String, href: String, quiet: bool| json!({ "label": label, "href": href, "quiet": quiet });
    if line > 0 && same_policy.is_some() {
        actions.push(action(
            format!("Open policy at line {line}"),
            format!("/console/policy?line={line}#line-{line}"),
            false,
        ));
    }
    if let Some(r) = (s(record, "code") == "unknown_key")
        .then(|| revoke_of(record, ctx))
        .flatten()
    {
        actions.push(action(
            format!(
                "Open the revoke, record {}",
                r.get("n").and_then(Value::as_u64).unwrap_or(0)
            ),
            format!("#/audit?record={}", enc(&rid(r))),
            true,
        ));
    }
    let person = s(record, "person");
    if s(record, "code") == "key_expired" && !ctx.read_only {
        actions.push(action(
            "Issue a new key on People".into(),
            format!(
                "#/people?issue=1&name={}&team={}",
                enc(person),
                enc(s(record, "team"))
            ),
            true,
        ));
    }
    if !person.is_empty() && person != "unknown" {
        let mine = Filter {
            show: "",
            q: person,
            model: "",
        };
        actions.push(action(
            format!("See {person}'s other decisions"),
            mine.href(0, ""),
            true,
        ));
    }
    let request = (!s(record, "verdict").is_empty() && !s(record, "method").is_empty())
        .then(|| json!({ "method": s(record, "method"), "path": s(record, "path"), "id": id }));
    json!({
        "id": rid(record),
        "verdict": verdict(record),
        "title": title,
        "lead": lead,
        "request": request,
        "facts": facts,
        "snippet": snippet,
        "actions": actions,
        "broken": (ctx.broken == Some(n) && n > 0).then_some(
            "This record does not match its hash: it, or the record before it, was changed after it was written. What it says cannot be trusted until that is explained."
        ),
    })
}

/// What a record sheet reads besides its own record.
struct Context<'a> {
    /// Decisions and changes, oldest first: what came before a record, and who revoked a key.
    records: &'a [Value],
    /// Usage records, oldest first: what a budget had spent when it refused.
    usage: &'a [Value],
    policy: Option<&'a str>,
    loaded: Option<&'a Loaded>,
    /// The record number the last verification found broken.
    broken: Option<u64>,
    /// No action that changes keys is offered.
    read_only: bool,
    kills: &'a [Kill],
}

/// Whether switch `k` stops the request of `record`. A record names its key by its first 8 hex characters, a switch
/// by 8 or more, so either may be the longer.
fn kill_stops(k: &Kill, record: &Value) -> bool {
    let key = s(record, "key");
    if k.scope == "key_prefix" {
        return !key.is_empty() && (k.value.starts_with(key) || key.starts_with(&k.value));
    }
    let model = Some(s(record, "model")).filter(|m| !m.is_empty());
    k.stops(s(record, "person"), s(record, "team"), "", model)
}

/// The switches on just before `record`, as the admin records before it in this log set and cleared them.
fn kills_before(record: &Value, records: &[Value]) -> Vec<Kill> {
    let n = record.get("n").and_then(Value::as_u64).unwrap_or(0);
    let mut on: Vec<Kill> = Vec::new();
    for r in records
        .iter()
        .take_while(|r| r.get("n").and_then(Value::as_u64).unwrap_or(0) < n)
        .filter(|r| s(r, "event") == "admin" && s(r, "verdict") == "allow")
    {
        let target = r.get("target").unwrap_or(&Value::Null);
        let (scope, value) = (s(target, "scope"), s(target, "value"));
        match s(r, "action") {
            "set_kill" => {
                let kill = Kill {
                    scope: scope.into(),
                    value: value.into(),
                    reason: s(target, "reason").into(),
                    by: s(r, "person").into(),
                    at: s(r, "time").into(),
                };
                match on.iter_mut().find(|k| k.scope == scope && k.value == value) {
                    Some(old) => *old = kill,
                    None => on.push(kill),
                }
            }
            "clear_kill" => on.retain(|k| !(k.scope == scope && k.value == value)),
            _ => {}
        }
    }
    on
}

/// The sheet of a request a kill switch stopped: the switch as the audit log recorded it then, and whether that same
/// switch is on now. A switch set without a record in this log (an older log file) falls back to one on now that
/// stops such a request.
fn killed_story(record: &Value, ctx: &Context<'_>) -> Story {
    let person = String::from(s(record, "person"));
    let whom = if person.is_empty() || person == "unknown" {
        "this request".to_string()
    } else {
        person.clone()
    };
    let none_sent = "Nothing was sent to a provider.";
    let then = kills_before(record, ctx.records)
        .into_iter()
        .find(|k| kill_stops(k, record));
    let Some(kill) = then.or_else(|| ctx.kills.iter().find(|k| kill_stops(k, record)).cloned())
    else {
        return (
            format!("A kill switch stopped {whom}"),
            format!(
                "A kill switch was on for {whom}. It is off now, and this log holds no record of when it was set: an older log file names who set it and why. {none_sent}"
            ),
            vec![("Switch", "Off now".to_string())],
        );
    };
    let still_on = ctx
        .kills
        .iter()
        .any(|k| k.scope == kill.scope && k.value == kill.value);
    let label = String::from(&kill.label());
    let by = String::from(&kill.by);
    let lead = format!(
        "Kill switch {label} was on: {}. {by} set it at {}. {none_sent} {}",
        String::from(kill.reason.trim_end_matches('.')),
        String::from(&time_full(&kill.at)),
        if still_on {
            "It is still on: the people it stops see this reason in their tool."
        } else {
            "It is off now, and traffic flows again."
        }
    );
    let state = if still_on { "still on" } else { "off now" };
    let mut facts = vec![
        ("Switch", format!("{label}, {state}")),
        ("Reason", String::from(&kill.reason)),
        (
            "Set by",
            format!("{by}, {}", String::from(&time_full(&kill.at))),
        ),
    ];
    if still_on {
        facts.push(("Turn off", crate::pages::unkill_command(&kill)));
    }
    (format!("A kill switch stopped {whom}"), lead, facts)
}

/// The filters of the AuditLog design, by their query value.
const SHOW: [(&str, &str); 7] = [
    ("all", "All"),
    ("blocked", "Blocked"),
    ("refused", "Refused"),
    ("would", "Would refuse"),
    ("masked", "Masked"),
    ("warned", "Warned"),
    ("changes", "Changes"),
];

struct Filter<'a> {
    show: &'a str,
    q: &'a str,
    model: &'a str,
}

/// How a record is opened from the list: by its decision ID, or by its number for a change, which has no ID.
fn rid(record: &Value) -> String {
    match s(record, "id") {
        "" => record
            .get("n")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .to_string(),
        id => id.to_string(),
    }
}

fn findings(record: &Value) -> &[Value] {
    record
        .get("guardrails")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The kind of the first finding a guardrail acted on this way, if any did.
fn found<'a>(record: &'a Value, action: &str) -> Option<&'a str> {
    findings(record)
        .iter()
        .find(|f| s(f, "action") == action)
        .map(|f| s(f, "kind"))
}

/// The verdict of the answer guardrails folded into a request record (`block`, `mask`, `pass`, `not_run`), or "".
fn answer_verdict(record: &Value) -> &str {
    record.get("answer").map_or("", |a| s(a, "verdict"))
}

/// What the answer guardrails found, as the request's own findings are kept.
fn answer_findings(record: &Value) -> &[Value] {
    record
        .get("answer")
        .and_then(|a| a.get("guardrails"))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// What observe mode or a shadow period let through that the policy would have refused.
fn would_refuse(record: &Value) -> &[Value] {
    record
        .get("would_refuse")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// A request whose answer a guardrail withheld: blocked, though the request itself was allowed.
fn blocked(record: &Value) -> bool {
    s(record, "code") == "guardrail_blocked" || answer_verdict(record) == "block"
}

/// Each `answer_guardrails` record goes onto the request it checked, as `answer`, with its number: the list shows
/// one row per request, and the request's sheet tells what happened to its answer.
fn fold_answers(records: Vec<Value>) -> Vec<Value> {
    let (answers, mut records): (Vec<Value>, Vec<Value>) = records
        .into_iter()
        .partition(|r| s(r, "event") == "answer_guardrails");
    for answer in answers {
        let request = records
            .iter_mut()
            .rev()
            .find(|r| r.get("event").is_none() && s(r, "id") == s(&answer, "id"));
        match request {
            Some(request) => {
                if let Some(map) = request.as_object_mut() {
                    map.insert("answer".into(), answer);
                }
            }
            // Its request is in an older log file: the record stays a row of its own.
            None => records.push(answer),
        }
    }
    records
}

fn is_change(record: &Value) -> bool {
    matches!(
        s(record, "event"),
        "admin" | "config_loaded" | "config_rejected" | "audit_repaired"
    )
}

/// The keys a record names: the target of an issue or a revoke, and the keys a file change added or removed.
fn keys_named(record: &Value) -> Vec<(&str, &str)> {
    fn pair(k: &Value) -> (&str, &str) {
        (s(k, "name"), s(k, "sha256_prefix"))
    }
    let mut out: Vec<(&str, &str)> = record.get("target").map(pair).into_iter().collect();
    for list in ["keys_added", "keys_removed"] {
        if let Some(keys) = record.get(list).and_then(Value::as_array) {
            out.extend(keys.iter().map(pair));
        }
    }
    out
}

impl Filter<'_> {
    fn href(&self, page: usize, record: &str) -> String {
        let mut out = String::from("#/audit?");
        if !self.show.is_empty() && self.show != "all" {
            let _ = write!(out, "verdict={}&", enc(self.show));
        }
        for (name, value) in [("q", self.q), ("model", self.model), ("record", record)] {
            if !value.is_empty() {
                let _ = write!(out, "{name}={}&", enc(value));
            }
        }
        if page > 1 {
            let _ = write!(out, "page={page}&");
        }
        out.pop();
        out
    }

    fn keeps(&self, record: &Value) -> bool {
        let shown = match self.show {
            "blocked" => blocked(record),
            "refused" => {
                (s(record, "verdict") == "refused" && s(record, "code") != "guardrail_blocked")
                    || s(record, "event") == "config_rejected"
            }
            "masked" => found(record, "mask").is_some() || answer_verdict(record) == "mask",
            "warned" => found(record, "warn").is_some() || found(record, "shadow").is_some(),
            "would" => !would_refuse(record).is_empty(),
            "changes" => is_change(record),
            _ => true,
        };
        shown && (self.model.is_empty() || s(record, "model") == self.model) && self.matches(record)
    }

    /// Person, team or decision ID; and for a key, its hash prefix or its name, so a revoked key can be traced.
    fn matches(&self, record: &Value) -> bool {
        let q = self.q;
        if q.is_empty()
            || s(record, "person").contains(q)
            || s(record, "team") == q
            || s(record, "id") == q
        {
            return true;
        }
        // A prefix of at least 4 characters either way: the records keep 8, a person may paste all 64.
        let hash = |h: &str| h.len() >= 4 && q.len() >= 4 && (h.starts_with(q) || q.starts_with(h));
        hash(s(record, "key"))
            || keys_named(record)
                .iter()
                .any(|(name, prefix)| (!name.is_empty() && name.contains(q)) || hash(prefix))
    }
}

/// An admin action in words: what was done, and what was tried when it was refused.
fn action_word(action: &str) -> (&str, &str) {
    match action {
        "console_sign_in" => ("signed in", "sign-in"),
        "console_sign_out" => ("signed out", "sign-out"),
        "issue_key" => ("issued a key", "key issue"),
        "revoke_key" => ("revoked a key", "key revoke"),
        "list_keys" => ("listed keys", "key list"),
        "set_kill" => ("stopped traffic", "traffic stop"),
        "clear_kill" => ("restored traffic", "traffic restore"),
        "list_kills" => ("listed switches", "switch list"),
        "export_audit" => ("exported the audit log", "audit export"),
        "export_audit_csv" => ("downloaded audit rows", "audit rows download"),
        "start_choice" => ("chose a track", "track choice"),
        "self_issue_key" => ("enterplace login key", "enterplace login"),
        "revoke_own_key" => ("enterplace logout", "enterplace logout"),
        other => (other, other),
    }
}

/// The FindingBadge of one guardrail finding.
fn badge(action: &str, kind: &str) -> Value {
    let (class, word) = match action {
        "block" => ("block", "Block"),
        "mask" => ("mask", "Mask"),
        "warn" => ("warn", "Warn"),
        _ => ("", "Found"),
    };
    tag(class, word, kind)
}

fn verdict(record: &Value) -> Value {
    match s(record, "event") {
        "admin" => {
            let (done, tried) = action_word(s(record, "action"));
            return if s(record, "verdict") == "allow" {
                tag("", "Admin:", done)
            } else {
                tag("refused", "Refused:", tried)
            };
        }
        "config_loaded" => return tag("", "Change", "policy loaded"),
        "config_rejected" => return tag("refused", "Refused", "policy change"),
        "audit_repaired" => return tag("", "Change", "log repaired"),
        _ => {}
    }
    let answer_kind = |action: &str| {
        answer_findings(record)
            .iter()
            .find(|f| s(f, "action") == action)
            .map_or("answer", |f| s(f, "kind"))
    };
    match answer_verdict(record) {
        "block" => return badge("block", answer_kind("block")),
        "mask" => return badge("mask", answer_kind("mask")),
        _ => {}
    }
    match (s(record, "verdict"), s(record, "code")) {
        (_, "guardrail_blocked") => badge("block", found(record, "block").unwrap_or("guardrail")),
        ("refused", code) => tag("refused", "Refused:", &code_words(code)),
        ("allow", _) => match (found(record, "mask"), found(record, "warn")) {
            (Some(kind), _) => badge("mask", kind),
            (None, Some(kind)) => badge("warn", kind),
            // Observe mode or a shadow period let it through: the list says what would have stopped it.
            (None, None) => match would_refuse(record).first() {
                Some(w) if s(w, "code") == "guardrail_blocked" => tag(
                    "warn",
                    "Would block:",
                    found(record, "shadow").unwrap_or("guardrail"),
                ),
                Some(w) => tag("warn", "Would refuse:", &code_words(s(w, "code"))),
                None => match found(record, "shadow") {
                    Some(kind) => tag("warn", "Found:", kind),
                    None => tag("allow", "Allowed", ""),
                },
            },
        },
        _ => tag("", "Change", s(record, "event")),
    }
}

/// Who a record is about, for the list: a change to the files was made by no one Enterplace knows, so it says how.
fn who(record: &Value) -> String {
    match s(record, "event") {
        "config_loaded" | "config_rejected" => trigger_word(s(record, "trigger")).to_string(),
        "audit_repaired" => "enterplace audit repair".to_string(),
        _ => s(record, "person").to_string(),
    }
}

fn trigger_word(trigger: &str) -> &str {
    match trigger {
        "start" => "Enterplace start",
        "file_change" => "file change",
        "signal" => "reload signal",
        other => other,
    }
}

/// A finding kind in words, for a sentence: "an AWS access key".
fn kind_words(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "aws_access_key" => "an AWS access key",
        "private_key" => "a private key",
        "github_token" => "a GitHub token",
        "slack_token" => "a Slack token",
        "enterplace_key" => "an Enterplace key",
        "jwt" => "a signed token (JWT)",
        "api_key" => "an API key",
        "email_address" => "an email address",
        "iban" => "a bank account number (IBAN)",
        "credit_card" => "a credit card number",
        "us_ssn" => "a US social security number",
        "israeli_id" => "an Israeli ID number",
        "phone_number" => "a phone number",
        _ => return None,
    })
}

/// Kinds that are credentials: one that reached Enterplace should be rotated.
const SECRETS: [&str; 7] = [
    "aws_access_key",
    "private_key",
    "github_token",
    "slack_token",
    "enterplace_key",
    "jwt",
    "api_key",
];

/// "1 December", the day after a period that ends with the date of `time`.
fn reset_day(time: &str, per_day: bool) -> String {
    let part = |range: std::ops::Range<usize>| {
        time.get(range)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(1)
    };
    let (year, month, day) = (part(0..4), part(5..7).clamp(1, 12), part(8..10));
    let (month, day) = if per_day && (day as usize) < days_in(year, month) {
        (month, day + 1)
    } else {
        (month % 12 + 1, 1)
    };
    format!("{day} {}", MONTHS[month as usize - 1])
}

/// Title, lead and facts of a budget or rate refusal, from the rule that refused it. `None` when the policy has
/// changed since: the amounts of another version would be wrong.
fn limit_story(record: &Value, ctx: &Context<'_>) -> Option<Story> {
    let loaded = ctx
        .loaded
        .filter(|l| l.policy_sha256 == s(record, "policy_sha256"))?;
    let rule = loaded
        .policy
        .rule_list()
        .iter()
        .find(|r| r.name == s(record, "rule"))?;
    let (person, rule_name) = (String::from(s(record, "person")), String::from(&rule.name));
    let none_sent = "Nothing was sent to a provider.";
    if s(record, "code") == "rate_limited" {
        return rate_story(record, ctx, rule);
    }
    let budget = rule.limits.budget()?;
    let per_day = budget.per == enterplace_core::policy::Period::Day;
    let time = s(record, "time");
    // A team rule counts the team's spend; a name or `any` rule counts the person's.
    let (whose, field, value) = match &rule.who {
        Who::Team(team) => (
            format!("The {} team", String::from(team)),
            "team",
            team.as_str(),
        ),
        _ => (person.clone(), "person", s(record, "person")),
    };
    let spent = spent_before(ctx.usage, time, per_day, |u| s(u, field) == value);
    let (per, reset) = (budget.per.word(), reset_day(time, per_day));
    let summary = format!("{} of {} spent this {per}", money(spent), money(budget.usd));
    Some((
        format!("{whose}'s budget is spent"),
        format!(
            "{summary}, plus what requests in flight held, and this request could have cost more than the rest of the {} that rule {rule_name} at line {} allows. Refused until {reset}. {none_sent}",
            money(budget.usd),
            rule.line
        ),
        vec![
            ("Budget", summary),
            ("Resets", format!("{reset}, 00:00 UTC")),
        ],
    ))
}

/// A rate refusal: requests a minute, tokens a minute of the rule, or tokens a minute of the key. The record does not
/// say which one refused, so with more than one in force the sheet names them all.
fn rate_story(
    record: &Value,
    ctx: &Context<'_>,
    rule: &enterplace_core::policy::Rule,
) -> Option<Story> {
    let (person, rule_name, line) = (
        String::from(s(record, "person")),
        String::from(&rule.name),
        rule.line,
    );
    let none_sent = "Nothing was sent to a provider.";
    let whose = match &rule.who {
        Who::Team(team) => format!("the {} team", String::from(team)),
        _ => person.clone(),
    };
    let key = String::from(s(record, "key"));
    let mut limits: Vec<(&'static str, String)> = Vec::new();
    if let Some(rpm) = rule.limits.rpm {
        limits.push((
            "Limit",
            format!("{} requests a minute", thousands(rpm as usize)),
        ));
    }
    if let Some(tpm) = rule.limits.tpm {
        limits.push((
            "Limit",
            format!("{} tokens a minute", thousands(tpm as usize)),
        ));
    }
    if let Some(tpm) = key_of(record, ctx).and_then(|p| p.tpm) {
        limits.push((
            "Key limit",
            format!("{} tokens a minute", thousands(tpm as usize)),
        ));
    }
    // A record that names the limit that refused it (`limit: { kind, of, value }`) keeps only that one.
    if let Some(limit) = record.get("limit") {
        let word = match s(limit, "kind") {
            "rpm" => "requests a minute",
            _ => "tokens a minute",
        };
        let label = if s(limit, "of") == "key" {
            "Key limit"
        } else {
            "Limit"
        };
        let value = limit.get("value").and_then(Value::as_u64).unwrap_or(0);
        let named = format!("{} {word}", thousands(usize::try_from(value).unwrap_or(0)));
        limits.retain(|(l, text)| *l == label && *text == named);
        if limits.is_empty() {
            limits.push((label, named));
        }
    }
    // A request larger than the whole minute's limit could never pass: it was given no time to send again.
    if let Some(limit) = record.get("limit").filter(|l| s(l, "kind") == "tpm") {
        let (value, could) = (
            limit.get("value").and_then(Value::as_u64).unwrap_or(0),
            limit
                .get("request_could_use")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        if could > value {
            let (who, label) = if s(limit, "of") == "key" {
                (format!("{person}'s key"), "Key limit")
            } else {
                (whose.clone(), "Limit")
            };
            let n = |v: u64| thousands(usize::try_from(v).unwrap_or(usize::MAX));
            return Some((
                format!("This request alone is larger than {who} allows in a minute"),
                format!(
                    "This request could use {} tokens (the prompt and the most the answer may write), more than the {} {who} allows in a minute, so it could never pass and no retry time was given. Send a shorter request or a smaller max_tokens. {none_sent}",
                    n(could),
                    n(value)
                ),
                vec![
                    (label, format!("{} tokens a minute", n(value))),
                    ("Request", format!("{} tokens", n(could))),
                ],
            ));
        }
    }
    let tokens = "Tokens count the prompt and the most the answer may write. The client was told when to send again.";
    let only = |label: &str, word: &str| {
        limits.len() == 1 && limits[0].0 == label && limits[0].1.ends_with(word)
    };
    match (
        only("Limit", "requests a minute"),
        only("Limit", "tokens a minute"),
        limits.len(),
    ) {
        (_, _, 0) => None,
        (true, _, _) => Some((
            format!("{person} sent too many requests"),
            format!(
                "Rule {rule_name} at line {line} allows {} for each person, and {person} had sent them all in the last minute. The client was told when to send again. {none_sent}",
                limits[0].1
            ),
            limits,
        )),
        (_, true, _) => Some((
            format!("{} used up its tokens for the minute", capital(&whose)),
            format!(
                "Rule {rule_name} at line {line} allows {} for {whose}, and this request would have gone past it. {tokens} {none_sent}",
                limits[0].1
            ),
            limits,
        )),
        (_, _, 1) => Some((
            format!("{person}'s key used up its tokens for the minute"),
            format!(
                "The keys file allows key {key} {}, and this request would have gone past it. {tokens} {none_sent}",
                limits[0].1
            ),
            limits,
        )),
        _ => Some((
            format!("{person} passed a rate limit"),
            format!(
                "Rule {rule_name} at line {line} and the keys file set the limits below. One of them refused this request; the record does not say which. {tokens} {none_sent}"
            ),
            limits,
        )),
    }
}

fn capital(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

type Story = (String, String, Vec<(&'static str, String)>);

/// What usage records that `mine` keeps had charged in the period (day or month) of `time`, up to `time`.
fn spent_before(usage: &[Value], time: &str, per_day: bool, mine: impl Fn(&Value) -> bool) -> f64 {
    let period = time.get(..if per_day { 10 } else { 7 }).unwrap_or("");
    usage
        .iter()
        .filter(|u| s(u, "time").starts_with(period) && s(u, "time") <= time && mine(u))
        .filter_map(|u| u.get("charged_usd").and_then(Value::as_f64))
        .sum()
}

/// The key a record was sent with, as the keys file that decided it gave it. `None` when the file has changed since,
/// so an expiry or a budget shown would be another version's.
fn key_of<'a>(record: &Value, ctx: &Context<'a>) -> Option<&'a Principal> {
    let key = s(record, "key");
    ctx.loaded
        .filter(|l| !key.is_empty() && l.keys_sha256 == s(record, "keys_sha256"))?
        .policy
        .entries()
        .map(|(_, p)| p)
        .find(|p| p.key == key)
}

/// The sheet of a refusal by the key's own expiry or budget, from the keys file.
fn key_story(record: &Value, ctx: &Context<'_>) -> Story {
    let (person, key) = (
        String::from(s(record, "person")),
        String::from(s(record, "key")),
    );
    let none_sent = "Nothing was sent to a provider.";
    let entry = key_of(record, ctx);
    if s(record, "code") == "key_expired" {
        return match entry.and_then(|p| p.expires.as_deref()) {
            Some(at) => (
                format!("{person}'s key expired on {}", day_words(at, false)),
                format!(
                    "The keys file gives key {key} an expiry of {} (UTC), and Enterplace refuses it from then on. {none_sent} Issue {person} a new key on People, then revoke this one.",
                    String::from(at)
                ),
                vec![("Expired", String::from(at))],
            ),
            None => (
                format!("{person}'s key had expired"),
                format!(
                    "Key {key} was past the expiry the keys file gave it. The keys file has changed since, so the date is not shown here. {none_sent}"
                ),
                Vec::new(),
            ),
        };
    }
    let Some(budget) = entry.and_then(|p| p.budget) else {
        return (
            format!("{person}'s key budget is spent"),
            format!(
                "The budget the keys file gives key {key} did not cover this request. The keys file has changed since, so its amounts are not shown here. {none_sent}"
            ),
            Vec::new(),
        );
    };
    let per_day = budget.per == enterplace_core::policy::Period::Day;
    let time = s(record, "time");
    let spent = spent_before(ctx.usage, time, per_day, |u| {
        s(u, "key") == s(record, "key")
    });
    let reset = reset_day(time, per_day);
    let summary = format!(
        "{} of {} spent {}",
        money(spent),
        money(budget.usd),
        if per_day { "today" } else { "this month" }
    );
    let until = if per_day {
        "00:00 UTC".to_string()
    } else {
        reset.clone()
    };
    (
        format!("{person}'s key budget is spent"),
        format!(
            "{summary}, plus what requests in flight held, and this request could have cost more than the rest of the {} the keys file gives key {key}. Refused until {until}. {none_sent}",
            money(budget.usd)
        ),
        vec![
            ("Budget", summary),
            ("Resets", format!("{reset}, 00:00 UTC")),
        ],
    )
}

/// What a record says happened, in a sentence, what follows from it, and facts only this kind of record has.
/// Every part is markup.
fn story(record: &Value, ctx: &Context<'_>) -> Story {
    let (person, team, model) = (
        String::from(s(record, "person")),
        String::from(s(record, "team")),
        String::from(s(record, "model")),
    );
    let (rule, line) = (
        String::from(s(record, "rule")),
        record.get("rule_line").and_then(Value::as_u64).unwrap_or(0),
    );
    let none_sent = "Nothing was sent to a provider.";
    match s(record, "event") {
        "admin" => return admin_story(record),
        "config_loaded" | "config_rejected" => return change_story(record),
        "audit_repaired" => return repair_story(record),
        _ => {}
    }
    let plain = |title: &str, lead: String| (title.to_string(), lead, Vec::new());
    match (s(record, "verdict"), s(record, "code")) {
        ("allow", _) => {
            let masked: u64 = findings(record)
                .iter()
                .filter(|f| s(f, "action") == "mask")
                .filter_map(|f| f.get("count").and_then(Value::as_u64))
                .sum();
            let provider = String::from(s(record, "provider"));
            let answer = answer_findings(record);
            let acted = |action: &str| -> Vec<&Value> {
                answer.iter().filter(|f| s(f, "action") == action).collect()
            };
            let kinds = |list: &[&Value]| {
                list.iter()
                    .map(|f| {
                        format!(
                            "{} ({})",
                            String::from(s(f, "kind")),
                            f.get("count").and_then(Value::as_u64).unwrap_or(0)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            match answer_verdict(record) {
                "block" => {
                    let found = acted("block");
                    let guardrail = found.first().map_or("", |f| s(f, "guardrail"));
                    return plain(
                        &format!(
                            "Guardrail {} withheld the answer",
                            String::from(guardrail)
                        ),
                        format!(
                            "{person} asked for {model}. Rule {rule} at line {line} of the policy allows it, and it was sent to {provider}. The model answered; the answer contained {} and the caller got guardrail_blocked instead. Usage still counts it.",
                            kinds(&found)
                        ),
                    );
                }
                "mask" => {
                    let found = acted("mask");
                    return plain(
                        &format!("Sent to {provider}, and the answer was masked"),
                        format!(
                            "{person} asked for {model}. Rule {rule} at line {line} of the policy allows it, and it was sent to {provider}. Its guardrails replaced {} in the answer before it reached the caller. The findings below give each kind, never the text.",
                            kinds(&found)
                        ),
                    );
                }
                _ => {}
            }
            if let Some(first) = would_refuse(record).first() {
                let why: Vec<&str> = would_refuse(record).iter().map(|w| s(w, "message")).collect();
                return plain(
                    if s(first, "by") == "observe" {
                        "Let through by observe mode, would have been refused"
                    } else {
                        "Let through by a shadow period, would have been refused"
                    },
                    format!(
                        "{person} asked for {model}, and it was sent to {provider}. {} Turn on enforcement on Policy to refuse requests like it.",
                        why.join(" ")
                    ),
                );
            }
            if masked > 0 {
                let n = enterplace_core::count(usize::try_from(masked).unwrap_or(0), "finding");
                return plain(
                    &format!("Masked {n}, then sent to {provider}"),
                    format!(
                        "{person} asked for {model}. Rule {rule} at line {line} of the policy allows it. Its guardrails replaced {n} in the request before it was sent to {provider}. The findings below give each kind, never the text."
                    ),
                );
            }
            plain(
                "Allowed and sent to the provider",
                format!(
                    "{person} asked for {model}. Rule {rule} at line {line} of the policy allows it, and it was sent to {provider}."
                ),
            )
        }
        (_, "person_needed") => plain(
            "The request named no person",
            format!(
                "It came with a login that is not an Enterplace key and no person token, and Every request needs a name is on, so Enterplace refused it. {none_sent} Hand its sender a person token (Coding agents, Hand out a person token) and have them set it as x-enterplace-user."
            ),
        ),
        (_, "no_key") => plain(
            "The request carried no Enterplace key",
            format!("Enterplace refuses a request it cannot put a name on. {none_sent}"),
        ),
        (_, "unknown_key") => {
            let key = s(record, "key");
            let mut out = plain(
                "The request carried a key Enterplace did not issue",
                format!(
                    "The hash of the key starts with {}. {none_sent} If it is a revoked key, someone still uses it.",
                    String::from(key)
                ),
            );
            // The sheet links the revoke record itself, as an action under the facts.
            if let Some(r) = revoke_of(record, ctx) {
                out.2.push((
                    "Revoked",
                    format!(
                        "Revoked by {} at {}, record {}",
                        s(r, "person"),
                        time_full(s(r, "time")),
                        r.get("n").and_then(Value::as_u64).unwrap_or(0)
                    ),
                ));
            }
            out
        }
        (_, "no_rule") => plain(
            "No rule names this person",
            format!(
                "Anything the policy does not allow is refused. {none_sent} Add a rule for {person} or team {team} to allow it."
            ),
        ),
        (_, "model_not_allowed") => {
            let rule_allows = ctx
                .loaded
                .filter(|l| l.policy_sha256 == s(record, "policy_sha256"))
                .and_then(|l| {
                    l.policy
                        .rule_list()
                        .iter()
                        .find(|r| r.name == s(record, "rule"))
                })
                .map(|r| r.allows(s(record, "model")));
            let key_models = key_of(record, ctx).and_then(|p| p.models.as_ref());
            // A record that says a key's own list refused it is believed first.
            let by_key = record.get("key_models") == Some(&Value::Bool(true))
                || rule_allows == Some(true)
                || (rule_allows.is_none()
                    && key_models.is_some_and(|m| !m.iter().any(|x| x == s(record, "model"))));
            if !by_key && rule_allows.is_none() {
                return plain(
                    "This model was not allowed for this person",
                    format!(
                        "The policy has changed since this decision, and the record does not say whether rule {rule} or the key's own models refused {model}. {none_sent}"
                    ),
                );
            }
            if !by_key {
                return plain(
                    "This model is not allowed for this person",
                    format!(
                        "Rule {rule} at line {line} decides for {person} and does not list {model}. {none_sent}"
                    ),
                );
            }
            let list = key_models.map(|m| String::from(&m.join(", ")));
            (
                format!("{person}'s key does not allow {model}"),
                format!(
                    "Rule {rule} at line {line} {} for {person}, but the keys file gives key {} its own list of models{}. {none_sent} Add {model} to the key's models in the keys file if {person} needs it.",
                    if rule_allows == Some(true) {
                        format!("allows {model}")
                    } else {
                        "decides".to_string()
                    },
                    String::from(s(record, "key")),
                    list.as_ref().map_or(String::new(), |l| format!(": {l}"))
                ),
                list.map(|l| vec![("Key models", l)]).unwrap_or_default(),
            )
        }
        (_, "guardrail_blocked") => {
            let block = findings(record).iter().find(|f| s(f, "action") == "block");
            let kind = block.map_or("", |f| s(f, "kind"));
            // A vendor's category (moderation's harassment_threatening) has no words of ours: it reads as it is.
            let title = match (kind_words(kind), block) {
                (Some(words), _) => format!("The prompt held {words}"),
                (None, Some(f)) if !kind.is_empty() => format!(
                    "Guardrail {} blocked {}",
                    String::from(s(f, "guardrail")),
                    String::from(&kind.replace('_', " "))
                ),
                _ => "A guardrail blocked this request".to_string(),
            };
            let by = block.map_or(String::new(), |f| {
                format!(" Guardrail {} stops it.", String::from(s(f, "guardrail")))
            });
            let rotate = if SECRETS.contains(&kind) {
                " If it is real, it should be rotated."
            } else {
                ""
            };
            plain(
                &title,
                format!(
                    "Rule {rule} at line {line} allows {model} for {person}.{by} The request went no further: {} The prompt was not stored, and the findings below give each kind, never the text.{rotate}",
                    none_sent.to_lowercase()
                ),
            )
        }
        (_, "budget_exceeded" | "rate_limited") => limit_story(record, ctx).unwrap_or_else(|| {
            let what = if s(record, "code") == "rate_limited" {
                "rate limit"
            } else {
                "budget"
            };
            plain(
                &format!("Refused by the {what} of rule {rule}"),
                format!(
                    "Rule {rule} at line {line} sets a {what}, and this request would have passed it. The policy has changed since, so its amounts are not shown here. {none_sent}"
                ),
            )
        }),
        (_, "key_budget_exceeded" | "key_expired") => key_story(record, ctx),
        (_, "killed") => killed_story(record, ctx),
        (_, "max_tokens_needed") => {
            let field = match s(record, "path") {
                "/v1/responses" => "max_output_tokens",
                "/v1/messages" => "max_tokens",
                _ => "max_tokens (or max_completion_tokens)",
            };
            plain(
                "A budget applies, and the request set no output limit",
                format!(
                    "A budget applies to {person}'s request for {model}, and it did not say how many output tokens it may use, so the most it could cost was unknown. {none_sent} The client sends {field} with the request, or an admin sets max_output for {model} under prices: in the policy."
                ),
            )
        }
        (_, "bad_limits") => plain(
            "The request's limits could not be read",
            format!(
                "A budget or a cache applies to {person}'s request, so Enterplace reads the model, the messages and the token limits to know what it could cost. One of them was sent twice, or a token limit was not a whole number. {none_sent} The client sends each field at most once, token limits as whole numbers."
            ),
        ),
        (_, "wrong_route") => plain(
            "This model is not served on this route",
            format!(
                "{person} sent {model} to {}, and the provider that serves {model} does not take that route through Enterplace. {none_sent} The error the client got names the route to send it to.",
                String::from(s(record, "path"))
            ),
        ),
        (_, "unreadable_request") => plain(
            "Enterplace could not read the request",
            format!(
                "The body was cut short, compressed, or not a JSON object with one model field, so the policy could not be checked. {none_sent} The client sends the request again as plain JSON."
            ),
        ),
        (_, "unknown_model") => plain(
            "No provider serves this model",
            format!("No provider in the policy lists {model}. {none_sent}"),
        ),
        ("refused", code) => plain(
            "Refused",
            format!("Enterplace refused it with the code {}. {none_sent}", String::from(code)),
        ),
        _ => plain(
            "A record in the chain",
            format!(
                "Recorded in the chain between the requests, as {}.",
                String::from(s(record, "event"))
            ),
        ),
    }
}

fn admin_story(record: &Value) -> Story {
    let target = record.get("target").unwrap_or(&Value::Null);
    let name = String::from(s(target, "name"));
    let hash = match s(target, "sha256_prefix") {
        "" => String::new(),
        prefix => format!(", key hash {}", String::from(prefix)),
    };
    let admin_key = target.get("admin") == Some(&Value::Bool(true));
    let (did, tried) = match s(record, "action") {
        "console_sign_in" => (
            "signed in to the console".to_string(),
            "sign in to the console".to_string(),
        ),
        "console_sign_out" => ("signed out of the console".into(), "sign out".into()),
        "issue_key" if admin_key => (
            format!("issued an admin key for {name}{hash}"),
            format!("issue an admin key for {name}"),
        ),
        "issue_key" => (
            format!("issued a key for {name}{hash}"),
            format!("issue a key for {name}"),
        ),
        "revoke_key" => (
            format!("revoked the key of {name}{hash}"),
            format!("revoke the key of {name}{hash}"),
        ),
        "list_keys" => ("listed the keys".into(), "list the keys".into()),
        "revoke_own_key" => (
            format!("gave up their own key with enterplace logout{hash}"),
            format!("give up their own key{hash}"),
        ),
        "self_issue_key" => (
            format!("got a personal key with enterplace login{hash}"),
            "get a personal key with enterplace login".to_string(),
        ),
        "list_kills" => (
            "listed the kill switches".into(),
            "list the kill switches".into(),
        ),
        "set_kill" | "clear_kill" => {
            let what = match (s(target, "scope"), s(target, "value")) {
                ("all", _) => "everyone".to_string(),
                ("key_prefix", v) => format!("key {}", String::from(v)),
                (scope, v) => format!("{} {}", String::from(scope), String::from(v)),
            };
            if s(record, "action") == "set_kill" {
                (
                    format!("stopped traffic for {what}"),
                    format!("stop traffic for {what}"),
                )
            } else {
                (
                    format!("let traffic flow again for {what}"),
                    format!("let traffic flow again for {what}"),
                )
            }
        }
        other => (String::from(other), String::from(other)),
    };
    let who = match s(record, "person") {
        "" | "unknown" => "Someone".to_string(),
        person => String::from(person),
    };
    let reason = match s(target, "reason").trim_end_matches('.') {
        "" => String::new(),
        reason => format!(": {}", String::from(reason)),
    };
    // The title names the act without the hash, which the lead and the facts carry.
    let act = did.strip_suffix(hash.as_str()).unwrap_or(&did);
    // A key that ends: an issued one with an expiry, or one from enterplace login, which always has one.
    let expires = match s(target, "expires") {
        "" => Vec::new(),
        at => vec![("Expires", String::from(&day_words(at, false)))],
    };
    match s(record, "verdict") {
        "allow" => (
            format!("{who} {act}"),
            format!("{who} {did}{reason}."),
            expires,
        ),
        "failed" => (
            format!("{who} {act}, and it failed"),
            format!(
                "{who} {did}. It was allowed and then failed, so nothing changed: {}",
                String::from(s(record, "error"))
            ),
            Vec::new(),
        ),
        _ => (
            format!(
                "{who} was refused: {}",
                tried.strip_suffix(hash.as_str()).unwrap_or(&tried)
            ),
            format!(
                "{who} tried to {tried}. It was refused with the code {}{reason}. Nothing changed.",
                String::from(s(record, "code"))
            ),
            Vec::new(),
        ),
    }
}

fn change_story(record: &Value) -> Story {
    let trigger = s(record, "trigger");
    let mut facts = vec![("Trigger", String::from(trigger_word(trigger)))];
    for (label, key) in [
        ("Policy before", "policy_sha256_before"),
        ("Keys before", "keys_sha256_before"),
    ] {
        facts.push((label, String::from(s(record, key))));
    }
    if s(record, "event") == "config_rejected" {
        let problems: Vec<&str> = record
            .get("problems")
            .and_then(Value::as_array)
            .map(|p| p.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        facts.extend(problems.iter().map(|p| ("Problem", p.to_string())));
        return (
            "A change to the policy or keys file was rejected".into(),
            format!(
                "Enterplace kept deciding with the version it had loaded. The change has {}, listed below: fix them and save again. enterplace check names the same.",
                enterplace_core::count(problems.len(), "problem")
            ),
            facts,
        );
    }
    let mut changed = (0, 0);
    for (label, list, n) in [
        ("Key added", "keys_added", &mut changed.0),
        ("Key removed", "keys_removed", &mut changed.1),
    ] {
        for key in record
            .get(list)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            *n += 1;
            facts.push((
                label,
                String::from(&format!(
                    "{}, {}, key hash {}",
                    s(key, "name"),
                    s(key, "team"),
                    s(key, "sha256_prefix")
                )),
            ));
        }
    }
    let when = match trigger {
        "start" => "as it started",
        "file_change" => "after one of them changed",
        "signal" => "on a reload signal",
        _ => "",
    };
    let keys = match changed {
        (0, 0) => "No key was added or removed.".to_string(),
        (a, r) => format!(
            "{} added and {} removed.",
            enterplace_core::count(a, "key"),
            r
        ),
    };
    // The title names what changed: the files' hashes before and after say which, the keys lists say how.
    let differs = |key: &str| {
        let before = s(record, &format!("{key}_before"));
        !before.is_empty() && before != s(record, key)
    };
    let named: Vec<String> = [("keys_added", "added"), ("keys_removed", "removed")]
        .iter()
        .flat_map(|(list, word)| {
            record
                .get(*list)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(move |k| format!("{} {word}", String::from(s(k, "name"))))
        })
        .collect();
    let title = match (trigger, differs("policy_sha256"), differs("keys_sha256")) {
        ("start", _, _) => "Enterplace started with this policy and keys".to_string(),
        (_, true, true) => "The policy and keys files changed".to_string(),
        (_, true, false) => "The policy file changed".to_string(),
        (_, false, true) if !named.is_empty() => {
            format!("The keys file changed: {}", named.join(", "))
        }
        (_, false, true) => "The keys file changed".to_string(),
        _ => "The policy and keys files were loaded again".to_string(),
    };
    (
        title,
        format!(
            "Enterplace loaded the policy and keys files {when}. {keys} Requests after this record are decided by this version."
        ),
        facts,
    )
}

/// A cut last line removed by `enterplace audit repair`: what was removed is in the record, so nothing is lost silently.
fn repair_story(record: &Value) -> Story {
    let bytes = record
        .get("removed_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    (
        "The cut last line of the audit log was removed".into(),
        format!(
            "The log ended with a line that was cut short as it was written, so it could not be checked. enterplace audit repair removed its {bytes} bytes and wrote this record, which holds them, while Enterplace was stopped. Every record before it still holds."
        ),
        vec![
            ("Removed", format!("{bytes} bytes")),
            ("Removed hash", String::from(s(record, "removed_sha256"))),
            ("Removed text", String::from(s(record, "removed_text"))),
        ],
    )
}

/// The record number a failed verification names: "record 40 ...".
fn broken_at(err: &str) -> Option<u64> {
    err.strip_prefix("record ")
        .and_then(|rest| rest.split(' ').next())
        .and_then(|n| n.parse().ok())
}
