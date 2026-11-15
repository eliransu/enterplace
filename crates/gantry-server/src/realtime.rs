//! Realtime sessions over WebSocket: OpenAI Realtime (`GET /v1/realtime?model=`) and Gemini Live (Google's
//! `BidiGenerateContent` path).
//!
//! A session is decided before the provider sees anything: the caller's key, rule, kill switches and budget at
//! connect, and the model there too (OpenAI names it in the URL) or in the first message (Gemini names it in `setup`,
//! and nothing is sent on until it is decided). Audio and text events are then relayed as they come both ways. Each
//! response is charged from the provider's own usage event (OpenAI's `response.done`, Gemini's `usageMetadata`), one
//! usage record each. A kill switch, checked every second, or a budget a response spent ends the session. The session
//! is recorded when it ends: who, which model, how long, how many responses, what they cost, and why it ended. Never
//! its content.
//!
//! The rule's guardrails read each text the session carries: the caller's text events (`conversation.item.create`,
//! instructions, Gemini's `clientContent` and `realtimeInput.text`) and the transcripts of what was said (OpenAI's
//! input transcription and output transcript, Gemini's input and output transcription and model text). A caller's text
//! event a guardrail blocks is dropped, with an error event (OpenAI) or the end of the session (Gemini, which has no
//! error event); one it masks goes on masked. A transcript is of speech already heard, so a block there ends the
//! session. What they found is recorded with the session, without the text.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{
        State,
        ws::{
            CloseFrame, Message as Down, WebSocket, WebSocketUpgrade,
            rejection::WebSocketUpgradeRejection,
        },
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use gantry_core::{
    audit,
    config::Kind,
    guard::{self, Guardrail},
    policy::{Policy, Principal, Rule},
    usage::{Usage, price_for},
};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls;
use tokio_tungstenite::tungstenite::{Message as Up, client::IntoClientRequest};

use crate::{AppState, Refusal, Seen, Snapshot, Upstream, batch, spend};

pub(crate) const OPENAI: &str = "/v1/realtime";
pub(crate) const GEMINI: &str =
    "/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent";

/// How long a Gemini Live client has to send its `setup` after connecting.
const SETUP_WAIT: Duration = Duration::from_secs(30);

/// How often a session in flight is checked against the kill switches.
const KILL_CHECK: Duration = Duration::from_secs(1);

/// Policy violation (RFC 6455): the close code when Gantry ends a session.
const POLICY_CLOSE: u16 = 1008;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            OPENAI,
            get(
                |State(state): State<AppState>,
                 addr: Option<axum::Extension<crate::ClientAddr>>,
                 headers: HeaderMap,
                 uri: Uri,
                 ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>| async move {
                    open(state, addr.map(|a| a.0), headers, uri, ws, Api::OpenAi).await
                },
            ),
        )
        .route(
            GEMINI,
            get(
                |State(state): State<AppState>,
                 addr: Option<axum::Extension<crate::ClientAddr>>,
                 headers: HeaderMap,
                 uri: Uri,
                 ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>| async move {
                    open(state, addr.map(|a| a.0), headers, uri, ws, Api::Gemini).await
                },
            ),
        )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Api {
    OpenAi,
    Gemini,
    /// A provider's own WebSocket API on `/passthrough/<provider>/<path>`, on paths a rule lists.
    Passthrough,
}

/// A WebSocket to `/passthrough/<provider>/<path>`: a provider's realtime API Gantry has no translation for, relayed
/// frame for frame on the paths a rule's `passthrough:` lists, decided at connect like the other sessions.
pub(crate) async fn passthrough(state: AppState, request: axum::extract::Request) -> Response {
    use axum::extract::FromRequestParts;
    let addr = request.extensions().get::<crate::ClientAddr>().cloned();
    let (mut parts, _) = request.into_parts();
    let ws = WebSocketUpgrade::from_request_parts(&mut parts, &state).await;
    open(state, addr, parts.headers, parts.uri, ws, Api::Passthrough).await
}

impl Api {
    fn path(self) -> &'static str {
        match self {
            Self::OpenAi => OPENAI,
            Self::Gemini => GEMINI,
            Self::Passthrough => "/passthrough",
        }
    }

    fn word(self) -> &'static str {
        match self {
            Self::OpenAi => "openai_realtime",
            Self::Gemini => "gemini_live",
            Self::Passthrough => "websocket_passthrough",
        }
    }
}

/// A session let through at connect, carried into the upgraded connection.
struct Open {
    person: Principal,
    rule: Rule,
    key_sha256: String,
    /// The end customer and tags the session's responses are charged to.
    customer: Option<String>,
    tags: Vec<String>,
    /// Known at connect for OpenAI; decided from `setup` for Gemini.
    model: Option<String>,
    provider: Option<usize>,
    beta: Option<HeaderValue>,
    /// The caller's address and tool, from the connect request: Gemini's decision is recorded after the upgrade, when
    /// the headers are gone, and its record names both as every other decision record does.
    client_ip: Option<String>,
    user_agent: Map<String, Value>,
    /// Set when every budget the session counts against is observed: a spent one does not end it.
    budget_shadow: Option<&'static str>,
    /// What observe mode let through at connect, for Gemini's record, written once the setup names the model.
    would_refuse: Vec<Value>,
    /// What the guardrails found in the session's texts, for its record.
    found: Vec<guard::AuditEntry>,
    /// A passthrough session's path and query at the provider.
    native: Option<String>,
}

async fn open(
    state: AppState,
    addr: Option<crate::ClientAddr>,
    headers: HeaderMap,
    uri: Uri,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    api: Api,
) -> Response {
    let decision = gantry_core::id::decision_id();
    let version = state.version();
    let Some(policy) = version.policy.as_ref() else {
        return crate::unknown_route().respond(&decision, false);
    };
    let client_ip = crate::client_ip(policy, addr.as_ref(), &headers);
    // Holds the person a JWT names, for as long as the record of this session needs it.
    let minted = std::sync::OnceLock::new();
    let mut seen = Seen::default();
    let admitted = admit(
        &state, &version, policy, &headers, &uri, &ws, api, client_ip, &minted, &mut seen,
    )
    .await;
    let refused = admitted.as_ref().err();
    // OpenAI's session is wholly decided now. Gemini's is recorded once its setup names the model, unless refused here.
    if api != Api::Gemini || refused.is_some() {
        if let Err(refusal) = batch::record_decision(
            &state,
            &version,
            &decision,
            client_ip.map(|ip| ip.to_string()).as_deref(),
            "GET",
            if api == Api::Passthrough {
                uri.path()
            } else {
                api.path()
            },
            &seen,
            refused,
            batch::user_agent_of(&headers),
        )
        .await
        {
            return refusal.respond(&decision, false);
        }
    }
    let (open, ws) = match (admitted, ws) {
        (Ok(open), Ok(ws)) => (open, ws),
        (Err(refusal), _) => return refusal.respond(&decision, false),
        // admit refuses a request without an upgrade.
        (Ok(_), Err(rejection)) => return rejection.into_response(),
    };
    let header = HeaderValue::from_str(&decision).ok();
    let mut response =
        ws.on_upgrade(move |socket| session(state, version, open, decision, api, socket));
    if let Some(value) = header {
        response.headers_mut().insert(crate::DECISION, value);
    }
    response
}

#[allow(clippy::too_many_arguments)]
async fn admit<'a>(
    state: &AppState,
    version: &Snapshot,
    policy: &'a Policy,
    headers: &HeaderMap,
    uri: &Uri,
    ws: &Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    api: Api,
    client_ip: Option<std::net::IpAddr>,
    minted: &'a std::sync::OnceLock<Principal>,
    seen: &mut Seen<'a>,
) -> Result<Open, Refusal> {
    let key = crate::caller_key(headers)?;
    let (person, key_sha256) =
        crate::identify(state, policy, key, uri.path(), client_ip, minted, seen).await?;
    if headers.contains_key(crate::CALLER_PROVIDER_KEY) {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "caller_provider_key_not_here",
            format!(
                "Refused: realtime sessions run on the organization's provider account, so {} is not taken on this route. Connect without it.",
                crate::CALLER_PROVIDER_KEY
            ),
        ));
    }
    let rule = crate::rule_or_observed(policy, person, crate::no_rule(person), |r, by| {
        crate::observed(seen, r, by);
    })?;
    seen.rule = Some(rule);
    let by = policy.observing(rule.shadow_until.as_deref());
    // The end customer and tags, as on the model routes. The headers stay as they came: none goes upstream.
    crate::customer_and_tags(&mut headers.clone(), person, rule, seen, by)?;
    if let Some(regions) = &rule.limits.regions {
        // A realtime session goes to the provider's own endpoint, which has no region Gantry can show.
        crate::enforce(
            seen,
            Refusal::new(
                StatusCode::FORBIDDEN,
                "region_not_allowed",
                format!(
                    "Refused: rule \"{}\" keeps requests in {}, and a realtime session goes to the provider's own endpoint, with no region Gantry can show. Connect under a rule without regions:.",
                    rule.name,
                    regions.join(", ")
                ),
            ),
            by,
        )?;
    }
    let mut model = None;
    let mut provider = None;
    let mut native = None;
    let query: Vec<(&str, &str)> = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    match api {
        Api::OpenAi => {
            if let Some((name, _)) = query.iter().find(|(name, _)| *name != "model") {
                return Err(Refusal::new(
                    StatusCode::BAD_REQUEST,
                    "bad_query",
                    format!(
                        "Refused: the query parameter \"{name}\" is not one Gantry forwards on {OPENAI}. Send only model, and configure the session with session.update."
                    ),
                ));
            }
            let named = query
                .iter()
                .find(|(name, _)| *name == "model")
                .map(|(_, value)| *value)
                .filter(|m| {
                    !m.is_empty()
                        && m.len() <= 128
                        && m.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
                })
                .ok_or_else(|| {
                    Refusal::new(
                        StatusCode::BAD_REQUEST,
                        "model_needed",
                        format!("Refused: a realtime session names its model in the URL, so the policy can decide it before it starts. Connect to {OPENAI}?model=<model>."),
                    )
                })?;
            seen.model = Some(named.to_string());
            batch::decide_model(
                policy,
                person,
                rule,
                named,
                "the session",
                &mut seen.would_refuse,
            )?;
            crate::killed(state, person, &key_sha256, Some(named))?;
            provider = Some(serving(version, Kind::OpenAi, named)?);
            seen.provider = provider;
            model = Some(named.to_string());
        }
        Api::Passthrough => {
            let rest = uri
                .path()
                .strip_prefix(crate::PASSTHROUGH)
                .unwrap_or_default();
            let (name, path) = rest.split_once('/').unwrap_or((rest, ""));
            let path = format!("/{path}");
            let index = version
                .providers
                .iter()
                .position(|p| p.name == name)
                .ok_or_else(|| {
                    Refusal::new(
                        StatusCode::NOT_FOUND,
                        "unknown_provider",
                        format!("Refused: no provider is named \"{name}\". Connect to /passthrough/<provider>/<path> with a provider the policy lists."),
                    )
                })?;
            let kind = version.providers[index].kind;
            if kind.bedrock() || matches!(kind, Kind::Vertex | Kind::VertexAnthropic) {
                return Err(Refusal::new(
                    StatusCode::BAD_REQUEST,
                    "passthrough_not_allowed",
                    format!(
                        "Refused: provider \"{name}\" signs each request with cloud credentials, which a WebSocket passthrough does not carry. Use its HTTP passthrough, or a provider with a key."
                    ),
                ));
            }
            let climbs = path
                .split('/')
                .any(|seg| seg == "." || seg == ".." || seg.contains('%'));
            if climbs || !rule.reaches(name, &path) {
                return Err(Refusal::new(
                    StatusCode::FORBIDDEN,
                    "passthrough_not_allowed",
                    format!(
                        "Refused: rule \"{}\" does not list {path} on provider \"{name}\" under passthrough:. Ask a Gantry admin to add it.",
                        rule.name
                    ),
                ));
            }
            crate::killed(state, person, &key_sha256, None)?;
            seen.provider = Some(index);
            provider = Some(index);
            // A passthrough names no model the policy knows: the session's record carries its path.
            model = Some(String::new());
            native = Some(match uri.query() {
                Some(q) => format!("{path}?{q}"),
                None => path,
            });
        }
        Api::Gemini => {
            if !query.is_empty() {
                return Err(Refusal::new(
                    StatusCode::BAD_REQUEST,
                    "bad_query",
                    "Refused: Gantry forwards no query on the Live API: the model goes in the setup message, and your Gantry key as `Authorization: Bearer <key>` or in x-api-key, never in the URL.",
                ));
            }
        }
    }
    let budgets = policy.applied(
        person,
        rule,
        gantry_core::policy::Context {
            sent: model.as_deref().unwrap_or_default(),
            model: model.as_deref().unwrap_or_default(),
            customer: seen.customer.as_deref(),
            tags: &seen.tags,
        },
    );
    let budget_shadow = spend::all_shadowed(
        &budgets
            .iter()
            .filter(|a| matches!(a.limit, gantry_core::policy::Limit::Budget(_)))
            .collect::<Vec<_>>(),
    );
    if !spend::room(&state.spend, &budgets).await {
        crate::enforce(
            seen,
            Refusal::new(
                StatusCode::TOO_MANY_REQUESTS,
                "budget_exceeded",
                format!(
                    "Refused: a budget \"{}\" counts against (of rule \"{}\", its key or the limits: list) is spent for this period, and a realtime session starts only with budget left. It starts again at the next period; ask a Gantry admin to raise it if you need more before then.",
                    person.name, rule.name
                ),
            ),
            budget_shadow,
        )?;
    }
    if ws.is_err() {
        return Err(Refusal::new(
            StatusCode::BAD_REQUEST,
            "websocket_needed",
            format!(
                "Refused: {} is a WebSocket route. Connect with a WebSocket client (Upgrade: websocket).",
                api.path()
            ),
        ));
    }
    Ok(Open {
        person: person.clone(),
        rule: rule.clone(),
        key_sha256,
        customer: seen.customer.clone(),
        tags: seen.tags.clone(),
        model,
        provider,
        beta: headers.get("openai-beta").cloned(),
        client_ip: client_ip.map(|ip| ip.to_string()),
        user_agent: batch::user_agent_of(headers),
        budget_shadow,
        would_refuse: seen.would_refuse.clone(),
        found: Vec::new(),
        native,
    })
}

/// The provider of `kind` that serves `model`.
fn serving(version: &Snapshot, kind: Kind, model: &str) -> Result<usize, Refusal> {
    version
        .providers
        .iter()
        .position(|p| p.kind == kind && p.serves(model))
        .ok_or_else(|| {
            Refusal::new(
                StatusCode::FORBIDDEN,
                "unknown_model",
                format!(
                    "Refused: no provider of kind {} serves model \"{model}\", and its realtime sessions go to such a provider. Check the model name, or ask a Gantry admin to add it to a provider.",
                    kind.word()
                ),
            )
        })
}

/// Ends a session from Gantry's side, telling the caller why: OpenAI clients read an `error` event, and every client
/// gets a close frame naming the code.
async fn tell<S>(down: &mut S, api: Api, decision: &str, code: &str, message: &str)
where
    S: futures_util::Sink<Down> + Unpin,
{
    if api == Api::OpenAi {
        let event = json!({ "type": "error", "error": { "type": "gantry_error", "code": code, "message": format!("{message} Decision {decision}."), "decision": decision } });
        let _ = down.send(Down::Text(event.to_string().into())).await;
    }
    let mut reason = format!("{code}: {message}");
    // A close frame's reason is at most 123 bytes.
    while reason.len() > 123 {
        reason.pop();
    }
    let _ = down
        .send(Down::Close(Some(CloseFrame {
            code: POLICY_CLOSE,
            reason: reason.into(),
        })))
        .await;
}

fn message_of(refusal: &Refusal) -> String {
    refusal
        .message
        .strip_prefix("Refused: ")
        .unwrap_or(&refusal.message)
        .to_string()
}

async fn session(
    state: AppState,
    version: Arc<Snapshot>,
    mut open: Open,
    decision: String,
    api: Api,
    socket: WebSocket,
) {
    let started = Instant::now();
    let (mut down_tx, mut down_rx) = socket.split();
    let mut first = None;
    if api == Api::Gemini {
        match gemini_setup(&state, &version, &mut open, &decision, &mut down_rx).await {
            Ok(setup) => first = Some(setup),
            Err(refusal) => {
                tell(
                    &mut down_tx,
                    api,
                    &decision,
                    refusal.code,
                    &message_of(&refusal),
                )
                .await;
                return;
            }
        }
    }
    let (Some(model), Some(index)) = (open.model.clone(), open.provider) else {
        return;
    };
    let provider = &version.providers[index];
    let upstream = match dial(
        &state,
        provider,
        api,
        &model,
        open.beta.as_ref(),
        open.native.as_deref(),
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(why) => {
            eprintln!(
                "gantry: decision {decision}: the realtime provider at {} could not be reached: {why}",
                provider.url
            );
            tell(&mut down_tx, api, &decision, "upstream_unreachable", "Gantry could not open the session at the provider. Try again. If it keeps happening, tell your Gantry admin.").await;
            end(
                &state,
                &version,
                &open,
                &decision,
                api,
                &model,
                &provider.name,
                started,
                0,
                0.0,
                "provider",
            )
            .await;
            return;
        }
    };
    let (mut up_tx, mut up_rx) = upstream.split();
    if let Some(first) = first
        && up_tx.send(Up::Text(first.into())).await.is_err()
    {
        end(
            &state,
            &version,
            &open,
            &decision,
            api,
            &model,
            &provider.name,
            started,
            0,
            0.0,
            "provider",
        )
        .await;
        return;
    }
    let price = version
        .policy
        .as_ref()
        .and_then(|p| price_for(&model, p.prices()));
    // Every limit the session counts against for its model, its customer and tags, as a model request's.
    let budgets = version.policy.as_ref().map_or_else(Vec::new, |policy| {
        policy.applied(
            &open.person,
            &open.rule,
            gantry_core::policy::Context {
                sent: &model,
                model: &model,
                customer: open.customer.as_deref(),
                tags: &open.tags,
            },
        )
    });
    let counted: Vec<(String, gantry_core::policy::Period)> = budgets
        .iter()
        .filter_map(|a| match a.limit {
            gantry_core::policy::Limit::Budget(b) => Some((a.scope.clone(), b.per)),
            _ => None,
        })
        .collect();
    let mut tick = tokio::time::interval(KILL_CHECK);
    let (mut responses, mut charged) = (0usize, 0.0);
    let guards: Vec<Guardrail> = version
        .policy
        .as_ref()
        .and_then(|p| crate::observed_guards(p, &open.rule.guardrails))
        .unwrap_or_else(|| open.rule.guardrails.clone());
    let mut found: Vec<guard::AuditEntry> = Vec::new();
    // For events plugins: the turn the session is in (one per text of the caller's), and the next event's place in it.
    let mut turn = (0usize, 0usize);
    // Text is read when the rule has a guardrail, or the binary a plugin of its own.
    let screened = !guards.is_empty() || crate::events::active(&state, &guards);
    let ended_by = loop {
        tokio::select! {
            message = down_rx.next() => match message {
                Some(Ok(Down::Text(text))) => {
                    let mut text = text.as_str().to_string();
                    if screened
                        && let Some((mut event, true, pointers)) = event_texts(api, &text, true)
                    {
                        let verdict = screen(&state, &guards, &open, &decision, api, true, &event, &pointers, &mut turn).await;
                        found.extend(verdict.audit.iter().cloned());
                        if let Some(blocked) = verdict.blocked {
                            let message = format!("guardrail \"{}\" refused this text event, so it was not sent. Remove what it names and send it again.", blocked.guardrail);
                            // Only OpenAI's protocol has an error event to answer with; any other session ends.
                            if api != Api::OpenAi {
                                tell(&mut down_tx, api, &decision, guard::BLOCKED_CODE, &message).await;
                                break "guardrail";
                            }
                            let event = json!({ "type": "error", "error": { "type": "gantry_error", "code": guard::BLOCKED_CODE, "message": format!("{message} Decision {decision}."), "decision": decision } });
                            if down_tx.send(Down::Text(event.to_string().into())).await.is_err() {
                                break "client";
                            }
                            continue;
                        }
                        if verdict.changed {
                            for (i, pointer) in pointers.iter().enumerate() {
                                if let (Some(slot), Some(masked)) = (event.pointer_mut(pointer), verdict.body.pointer(&format!("/messages/{i}/content"))) {
                                    *slot = masked.clone();
                                }
                            }
                            text = match event {
                                Value::String(raw) => raw,
                                other => other.to_string(),
                            };
                        }
                    }
                    if up_tx.send(Up::Text(text.into())).await.is_err() {
                        break "provider";
                    }
                }
                Some(Ok(Down::Binary(bytes))) => {
                    if up_tx.send(Up::Binary(bytes)).await.is_err() {
                        break "provider";
                    }
                }
                // Pings are answered by the WebSocket library on each side.
                Some(Ok(Down::Ping(_) | Down::Pong(_))) => {}
                Some(Ok(Down::Close(_)) | Err(_)) | None => break "client",
            },
            message = up_rx.next() => match message {
                Some(Ok(Up::Text(text))) => {
                    if screened
                        && let Some((event, request, pointers)) = event_texts(api, text.as_str(), false)
                    {
                        let verdict = screen(&state, &guards, &open, &decision, api, request, &event, &pointers, &mut turn).await;
                        found.extend(verdict.audit.iter().cloned());
                        if let Some(blocked) = verdict.blocked {
                            tell(&mut down_tx, api, &decision, guard::BLOCKED_CODE, &format!("guardrail \"{}\" refused what was said in this session, so it ends here.", blocked.guardrail)).await;
                            break "guardrail";
                        }
                    }
                    let usage = usage_of(api, text.as_str());
                    if down_tx.send(Down::Text(text.as_str().into())).await.is_err() {
                        break "client";
                    }
                    if let Some((usage, response)) = usage {
                        responses += 1;
                        let mut extra = Map::new();
                        extra.insert("session".into(), decision.as_str().into());
                        extra.insert("response".into(), response.map_or(Value::Null, Value::from));
                        let (cost, record) = spend::charge(&state.spend, spend::Line {
                            decision: &decision,
                            person: &open.person.name,
                            team: &open.person.team,
                            key: &open.person.key,
                            org: &open.person.org,
                            customer: open.customer.as_deref(),
                            tags: &open.tags,
                            counted: &counted,
                            model: &model,
                            provider: &provider.name,
                            version: (&version.policy_sha256, &version.keys_sha256),
                            price: price.clone(),
                            usage: Some(usage),
                            share: 1.0,
                            unreported: 0.0,
                            succeeded: true,
                            extra,
                        });
                        charged += cost;
                        batch::write(&state, record).await;
                        // ponytail: an observed budget spent mid-session is not recorded again; the connect record
                        // and the spend records show it.
                        if open.budget_shadow.is_none() && !spend::room(&state.spend, &budgets).await {
                            tell(&mut down_tx, api, &decision, "budget_exceeded", &format!("this session's responses spent a budget \"{}\" counts against (of rule \"{}\", its key or the limits: list), so it ends here. The budget starts again at the next period.", open.person.name, open.rule.name)).await;
                            break "budget";
                        }
                    }
                }
                Some(Ok(Up::Binary(bytes))) => {
                    if down_tx.send(Down::Binary(bytes)).await.is_err() {
                        break "client";
                    }
                }
                Some(Ok(Up::Close(_)) | Err(_)) | None => {
                    let _ = down_tx.send(Down::Close(None)).await;
                    break "provider";
                }
                Some(Ok(_)) => {}
            },
            _ = tick.tick() => {
                if let Err(refusal) = crate::killed(&state, &open.person, &open.key_sha256, Some(&model)) {
                    tell(&mut down_tx, api, &decision, refusal.code, &message_of(&refusal)).await;
                    break "killed";
                }
            }
        }
    };
    let _ = up_tx.send(Up::Close(None)).await;
    open.found = found;
    end(
        &state,
        &version,
        &open,
        &decision,
        api,
        &model,
        &provider.name,
        started,
        responses,
        charged,
        ended_by,
    )
    .await;
}

/// The text a realtime event carries for the guardrails: the event, whether it is request side (the caller's words,
/// or the transcript of them) and the JSON pointers of its texts. `None` for an event with no text they read.
fn event_texts(api: Api, text: &str, from_caller: bool) -> Option<(Value, bool, Vec<String>)> {
    if api == Api::Passthrough {
        // No shape Gantry knows: every string of a JSON frame is text, and a frame that is not JSON is one text.
        let event = serde_json::from_str::<Value>(text)
            .ok()
            .filter(|v| v.is_object() || v.is_array())
            .unwrap_or_else(|| Value::String(text.to_string()));
        let mut pointers = Vec::new();
        strings(&event, String::new(), &mut pointers);
        return (!pointers.is_empty()).then_some((event, from_caller, pointers));
    }
    let event: Value = serde_json::from_str(text).ok()?;
    let mut pointers = Vec::new();
    let list = |v: &Value| v.as_array().map_or(0, Vec::len);
    let request = match (api, from_caller) {
        (Api::OpenAi, true) => {
            match event["type"].as_str() {
                Some("conversation.item.create") => {
                    for j in 0..list(&event["item"]["content"]) {
                        if event["item"]["content"][j]["text"].is_string() {
                            pointers.push(format!("/item/content/{j}/text"));
                        }
                    }
                }
                Some("session.update") if event["session"]["instructions"].is_string() => {
                    pointers.push("/session/instructions".into());
                }
                Some("response.create") if event["response"]["instructions"].is_string() => {
                    pointers.push("/response/instructions".into());
                }
                _ => {}
            }
            true
        }
        (Api::OpenAi, false) => match event["type"].as_str() {
            Some("conversation.item.input_audio_transcription.completed") => {
                pointers.push("/transcript".into());
                true
            }
            Some("response.output_audio_transcript.done" | "response.audio_transcript.done") => {
                pointers.push("/transcript".into());
                false
            }
            Some("response.output_text.done" | "response.text.done") => {
                pointers.push("/text".into());
                false
            }
            _ => false,
        },
        (Api::Gemini, true) => {
            for i in 0..list(&event["clientContent"]["turns"]) {
                for j in 0..list(&event["clientContent"]["turns"][i]["parts"]) {
                    if event["clientContent"]["turns"][i]["parts"][j]["text"].is_string() {
                        pointers.push(format!("/clientContent/turns/{i}/parts/{j}/text"));
                    }
                }
            }
            if event["realtimeInput"]["text"].is_string() {
                pointers.push("/realtimeInput/text".into());
            }
            true
        }
        (Api::Passthrough, _) => from_caller,
        (Api::Gemini, false) => {
            let content = &event["serverContent"];
            if content["inputTranscription"]["text"].is_string() {
                // The caller's speech: checked as a request, alone.
                return Some((
                    event,
                    true,
                    vec!["/serverContent/inputTranscription/text".into()],
                ));
            }
            if content["outputTranscription"]["text"].is_string() {
                pointers.push("/serverContent/outputTranscription/text".into());
            }
            // ponytail: model text and transcripts arrive in pieces, each read alone; a finding split across two is
            // missed. Join them per turn when that matters.
            for j in 0..list(&content["modelTurn"]["parts"]) {
                if content["modelTurn"]["parts"][j]["text"].is_string() {
                    pointers.push(format!("/serverContent/modelTurn/parts/{j}/text"));
                }
            }
            false
        }
    };
    (!pointers.is_empty()).then_some((event, request, pointers))
}

/// The rule's guardrails that read this side, on the texts at `pointers`: built-in ones, then each webhook in order.
#[allow(clippy::too_many_arguments)]
async fn screen(
    state: &AppState,
    guards: &[Guardrail],
    open: &Open,
    decision: &str,
    api: Api,
    request: bool,
    event: &Value,
    pointers: &[String],
    turn: &mut (usize, usize),
) -> guard::Verdict {
    let role = if request { "user" } else { "assistant" };
    let view = json!({
        "messages": pointers
            .iter()
            .map(|p| json!({"role": role, "content": event.pointer(p).cloned().unwrap_or_default()}))
            .collect::<Vec<_>>()
    });
    let mut verdict = if request {
        guard::check(view, guards)
    } else {
        guard::check_reply(view, guards)
    };
    for guardrail in guards {
        let guard::Check::Webhook(hook) = &guardrail.check else {
            continue;
        };
        let reads = if request {
            guardrail.on.request
        } else {
            guardrail.on.answer
        };
        if !reads || verdict.blocked.is_some() {
            continue;
        }
        let sent = guard::WebhookRequest::new(
            decision,
            &open.person.name,
            &open.person.team,
            api.path(),
            &verdict.body,
        );
        let answer = crate::ask(state, guardrail.action, hook, &sent).await;
        if let Some(cause) = verdict.merge_answer(guardrail, &sent, answer) {
            eprintln!("gantry: decision {decision}: in the realtime session: {cause}");
        }
    }
    // Events plugins see each text as an event of the session: the connection is the session, and each text of the
    // caller's starts a turn.
    if verdict.blocked.is_none() && crate::events::active(state, guards) {
        use gantry_core::events as core;
        let plugins = crate::events::guards_for(state, guards);
        let mut context = crate::events::context_of(
            &open.person,
            &axum::http::HeaderMap::new(),
            decision,
            decision,
            api.path(),
            open.model.as_deref().unwrap_or_default(),
        );
        if request {
            *turn = (turn.0 + 1, 0);
        }
        context.turn_index = turn.0;
        context.turn_id = core::turn_id(&context.session_id, turn.0, "", None);
        context.customer = open.customer.clone();
        context.tags = open.tags.clone();
        let kind = if request {
            core::Kind::RealtimeUserMessage
        } else {
            core::Kind::RealtimeAssistantMessage
        };
        let events: Vec<core::Event> = (0..pointers.len())
            .filter_map(|i| {
                let at = format!("/messages/{i}/content");
                let text = verdict.body.pointer(&at)?.as_str()?.to_string();
                let mut event = core::Event::text(kind, text);
                event.at = vec![at];
                let placed = event.placed(&context.turn_id, turn.1);
                turn.1 += 1;
                Some(placed)
            })
            .collect();
        if let Some(refusal) = crate::events::refused_session(state, &plugins, &context) {
            verdict.blocked = Some(guard::Blocked {
                guardrail: "events".into(),
                message: refusal.message,
            });
        } else {
            let judged = crate::events::judge(
                state,
                &plugins,
                &context,
                "realtime",
                &events,
                None,
                "this text",
            )
            .await;
            verdict.audit.extend(judged.audit);
            verdict.blocked = judged.blocked;
            if verdict.blocked.is_none() && !judged.masks.is_empty() {
                match core::apply_masks(&mut verdict.body, &events, &judged.masks) {
                    Ok(changed) => verdict.changed |= changed,
                    // Never pass on the unmasked text because the masked one could not be written.
                    Err(_) => {
                        verdict.blocked = Some(guard::Blocked {
                            guardrail: "events".into(),
                            message: "An events plugin's mask could not be written.".into(),
                        });
                    }
                }
            }
        }
    }
    // A transcript cannot be rewritten after it was spoken: what a guardrail masks there is only recorded.
    if !request {
        verdict.changed = false;
    }
    verdict
}

/// Reads a Gemini Live client's first message, decides the model its setup names, and records the decision.
/// Returns the setup to send on.
async fn gemini_setup(
    state: &AppState,
    version: &Snapshot,
    open: &mut Open,
    decision: &str,
    down: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Result<String, Refusal> {
    let setup = match tokio::time::timeout(SETUP_WAIT, down.next()).await {
        Ok(Some(Ok(Down::Text(text)))) => text.to_string(),
        _ => {
            return Err(Refusal::new(
                StatusCode::BAD_REQUEST,
                "setup_needed",
                format!(
                    "Refused: a Live session starts with a setup message naming the model, within {} seconds. Send it first.",
                    SETUP_WAIT.as_secs()
                ),
            ));
        }
    };
    let named = serde_json::from_str::<Value>(&setup)
        .ok()
        .and_then(|v| v["setup"]["model"].as_str().map(String::from));
    let mut seen = Seen {
        person: Some(&open.person),
        rule: Some(&open.rule),
        key: Some(open.person.key.clone()),
        model: named
            .as_ref()
            .map(|m| m.trim_start_matches("models/").to_string()),
        would_refuse: open.would_refuse.clone(),
        ..Seen::default()
    };
    let mut observed = Vec::new();
    let decided = (|| {
        let model = seen.model.clone().ok_or_else(|| {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "model_needed",
                "Refused: the first message must be {\"setup\": {\"model\": \"models/<model>\"}}, so the policy can decide the model. Send it first.",
            )
        })?;
        let policy = version.policy.as_ref().ok_or_else(crate::unknown_route)?;
        batch::decide_model(
            policy,
            &open.person,
            &open.rule,
            &model,
            "the session",
            &mut observed,
        )?;
        crate::killed(state, &open.person, &open.key_sha256, Some(&model))?;
        let index = serving(version, Kind::Gemini, &model)?;
        Ok::<_, Refusal>((model, index))
    })();
    if let Ok((_, index)) = &decided {
        seen.provider = Some(*index);
    }
    seen.would_refuse.extend(observed);
    batch::record_decision(
        state,
        version,
        decision,
        open.client_ip.as_deref(),
        "GET",
        GEMINI,
        &seen,
        decided.as_ref().err(),
        open.user_agent.clone(),
    )
    .await?;
    let (model, index) = decided?;
    open.model = Some(model);
    open.provider = Some(index);
    Ok(setup)
}

/// The usage a provider event reports, with the response it belongs to.
/// The JSON pointer of every string in `value`.
fn strings(value: &Value, at: String, out: &mut Vec<String>) {
    match value {
        Value::String(_) => out.push(at),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                strings(item, format!("{at}/{i}"), out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let key = key.replace('~', "~0").replace('/', "~1");
                strings(item, format!("{at}/{key}"), out);
            }
        }
        _ => {}
    }
}

fn usage_of(api: Api, text: &str) -> Option<(Usage, Option<String>)> {
    let count = |v: &Value| v.as_u64().unwrap_or_default();
    match api {
        // ponytail: a provider's own protocol reports usage in no shape Gantry knows, so a passthrough session is
        // recorded (who, what path, how long) and not metered. Read a usage event per API when one is asked for.
        Api::Passthrough => None,
        Api::OpenAi => {
            if !text.contains("response.done") {
                return None;
            }
            let event: Value = serde_json::from_str(text).ok()?;
            if event["type"] != "response.done" {
                return None;
            }
            let usage = &event["response"]["usage"];
            if !usage.is_object() {
                return None;
            }
            // Audio is priced apart from text: the details split each count by modality, cached audio included.
            let details = &usage["input_token_details"];
            let cached = count(&details["cached_tokens"]);
            let cached_audio = count(&details["cached_tokens_details"]["audio_tokens"]).min(cached);
            let input_audio = count(&details["audio_tokens"]).saturating_sub(cached_audio);
            let output = count(&usage["output_tokens"]);
            let output_audio = count(&usage["output_token_details"]["audio_tokens"]).min(output);
            Some((
                Usage {
                    input: count(&usage["input_tokens"]).saturating_sub(cached + input_audio),
                    output: output - output_audio,
                    cache_read: cached - cached_audio,
                    input_audio,
                    output_audio,
                    cache_read_audio: cached_audio,
                    ..Usage::default()
                },
                event["response"]["id"].as_str().map(String::from),
            ))
        }
        Api::Gemini => {
            if !text.contains("usageMetadata") {
                return None;
            }
            let event: Value = serde_json::from_str(text).ok()?;
            // Our reading of the Live API reference: each usageMetadata reports one turn (promptTokenCount is that
            // turn's whole effective prompt), so each is charged as one response. The reference does not say whether
            // the counts are per turn or for the whole session.
            let usage = &event["usageMetadata"];
            if !usage.is_object() {
                return None;
            }
            // The details lists split each count by modality; what they call AUDIO is priced as audio.
            let audio = |key: &str| {
                usage[key].as_array().map_or(0, |parts| {
                    parts
                        .iter()
                        .filter(|p| p["modality"] == "AUDIO")
                        .map(|p| count(&p["tokenCount"]))
                        .sum::<u64>()
                })
            };
            let cached = count(&usage["cachedContentTokenCount"]);
            let cached_audio = audio("cacheTokensDetails").min(cached);
            let input_audio = audio("promptTokensDetails").saturating_sub(cached_audio);
            let output = count(&usage["responseTokenCount"]) + count(&usage["thoughtsTokenCount"]);
            let output_audio = audio("responseTokensDetails").min(output);
            Some((
                Usage {
                    input: (count(&usage["promptTokenCount"])
                        + count(&usage["toolUsePromptTokenCount"]))
                    .saturating_sub(cached + input_audio),
                    output: output - output_audio,
                    cache_read: cached - cached_audio,
                    input_audio,
                    output_audio,
                    cache_read_audio: cached_audio,
                    ..Usage::default()
                },
                None,
            ))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn end(
    state: &AppState,
    version: &Snapshot,
    open: &Open,
    decision: &str,
    api: Api,
    model: &str,
    provider: &str,
    started: Instant,
    responses: usize,
    charged: f64,
    ended_by: &str,
) {
    let mut record = Map::new();
    record.insert("event".into(), "realtime_session".into());
    record.insert("id".into(), decision.into());
    record.insert("time".into(), audit::timestamp().into());
    record.insert("api".into(), api.word().into());
    record.insert("person".into(), open.person.name.as_str().into());
    record.insert("team".into(), open.person.team.as_str().into());
    record.insert("key".into(), open.person.key.as_str().into());
    record.insert("model".into(), model.into());
    record.insert("provider".into(), provider.into());
    // A passthrough's path, never its query, which may carry a credential.
    if let Some(native) = &open.native {
        let path = native.split('?').next().unwrap_or_default();
        record.insert("path".into(), path.into());
    }
    record.insert("seconds".into(), started.elapsed().as_secs_f64().into());
    record.insert("responses".into(), responses.into());
    record.insert("charged_usd".into(), charged.into());
    record.insert("ended_by".into(), ended_by.into());
    if !open.found.is_empty() {
        record.insert(
            "guardrails".into(),
            serde_json::to_value(&open.found).unwrap_or_default(),
        );
    }
    record.insert(
        "policy_sha256".into(),
        version.policy_sha256.as_str().into(),
    );
    record.insert("keys_sha256".into(), version.keys_sha256.as_str().into());
    batch::write(state, record).await;
}

/// Any connection a WebSocket can run over: plain TCP to a local provider, TLS to the rest.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Provider = tokio_tungstenite::WebSocketStream<Box<dyn Io>>;

/// Opens the session at the provider, with Gantry's provider key.
async fn dial(
    state: &AppState,
    provider: &Upstream,
    api: Api,
    model: &str,
    beta: Option<&HeaderValue>,
    native: Option<&str>,
) -> Result<Provider, String> {
    let url = match api {
        Api::Passthrough => gantry_core::config::join(&provider.url, native.unwrap_or("/")),
        Api::OpenAi => gantry_core::config::join(&provider.url, &format!("{OPENAI}?model={model}")),
        // The Live API lives at the host's root, whatever version path the provider's URL carries for REST.
        Api::Gemini => {
            let (scheme, rest) = provider
                .url
                .split_once("://")
                .unwrap_or(("https", &provider.url));
            let host = rest.split('/').next().unwrap_or_default();
            format!("{scheme}://{host}{GEMINI}")
        }
    };
    let (tls, rest) = match url.split_once("://") {
        Some(("https", rest)) => (true, rest),
        Some(("http", rest)) => (false, rest),
        _ => return Err(format!("the provider URL {url} is neither http nor https")),
    };
    let ws_url = format!("{}://{rest}", if tls { "wss" } else { "ws" });
    let mut request = ws_url.into_client_request().map_err(|e| e.to_string())?;
    if let Some((name, value)) = &provider.key {
        request.headers_mut().insert(name.clone(), value.clone());
    }
    if let (Api::OpenAi, Some(beta)) = (api, beta) {
        request
            .headers_mut()
            .insert(HeaderName::from_static("openai-beta"), beta.clone());
    }
    let uri = request.uri().clone();
    let host = uri
        .host()
        .ok_or("the provider URL has no host")?
        .to_string();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    // The provider's own headers (headers_env), and its proxy (proxy_env), as its HTTP requests take them.
    for (name, value) in &provider.headers {
        request.headers_mut().insert(name.clone(), value.clone());
    }
    let connected = async {
        match &provider.proxy {
            Some(proxy) => crate::tunnel(proxy, &host, port).await,
            None => tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|e| e.to_string()),
        }
    };
    let tcp = tokio::time::timeout(state.timeouts.connect, connected)
        .await
        .map_err(|_| {
            format!(
                "no connection within {} seconds",
                state.timeouts.connect.as_secs()
            )
        })??;
    let stream: Box<dyn Io> = if tls {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host).map_err(|e| e.to_string())?;
        Box::new(
            tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, tcp)
                .await
                .map_err(|e| e.to_string())?,
        )
    } else {
        Box::new(tcp)
    };
    tokio::time::timeout(
        state.timeouts.first_byte,
        tokio_tungstenite::client_async(request, stream),
    )
    .await
    .map_err(|_| "the provider did not accept the WebSocket in time".to_string())?
    .map(|(socket, _)| socket)
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    #[test]
    fn gemini_live_texts_and_transcripts_are_found_on_their_side() {
        let client = r#"{"clientContent":{"turns":[{"role":"user","parts":[{"text":"hi"},{"inlineData":{}}]}]},"realtimeInput":{"text":"there"}}"#;
        let found = event_texts(Api::Gemini, client, true).map(|(_, r, p)| (r, p));
        assert_eq!(
            found,
            Some((
                true,
                vec![
                    "/clientContent/turns/0/parts/0/text".to_string(),
                    "/realtimeInput/text".to_string()
                ]
            ))
        );
        let heard = r#"{"serverContent":{"inputTranscription":{"text":"my card"}}}"#;
        assert_eq!(
            event_texts(Api::Gemini, heard, false).map(|(_, r, _)| r),
            Some(true)
        );
        let said = r#"{"serverContent":{"outputTranscription":{"text":"ok"},"modelTurn":{"parts":[{"text":"ok"}]}}}"#;
        assert_eq!(
            event_texts(Api::Gemini, said, false).map(|(_, r, p)| (r, p.len())),
            Some((false, 2))
        );
        assert!(event_texts(Api::Gemini, r#"{"setupComplete":{}}"#, false).is_none());
        assert!(event_texts(Api::OpenAi, r#"{"type":"response.create"}"#, true).is_none());
    }
}
