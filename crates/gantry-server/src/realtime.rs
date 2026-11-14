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
}

impl Api {
    fn path(self) -> &'static str {
        match self {
            Self::OpenAi => OPENAI,
            Self::Gemini => GEMINI,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Self::OpenAi => "openai_realtime",
            Self::Gemini => "gemini_live",
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
    if api == Api::OpenAi || refused.is_some() {
        if let Err(refusal) = batch::record_decision(
            &state,
            &version,
            &decision,
            None,
            "GET",
            api.path(),
            &seen,
            refused,
            Map::new(),
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
    let rule = policy.rule_for(person).ok_or_else(|| {
        Refusal::new(
            StatusCode::FORBIDDEN,
            "no_rule",
            format!(
                "Refused: no rule in the policy names \"{}\" or team \"{}\", so nothing is allowed. Ask a Gantry admin to add a rule.",
                person.name, person.team
            ),
        )
    })?;
    seen.rule = Some(rule);
    // The end customer and tags, as on the model routes. The headers stay as they came: none goes upstream.
    crate::customer_and_tags(&mut headers.clone(), person, rule, seen)?;
    if let Some(regions) = &rule.limits.regions {
        // A realtime session goes to the provider's own endpoint, which has no region Gantry can show.
        return Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "region_not_allowed",
            format!(
                "Refused: rule \"{}\" keeps requests in {}, and a realtime session goes to the provider's own endpoint, with no region Gantry can show. Connect under a rule without regions:.",
                rule.name,
                regions.join(", ")
            ),
        ));
    }
    let mut model = None;
    let mut provider = None;
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
            batch::decide_model(policy, person, rule, named, "the session")?;
            crate::killed(state, person, &key_sha256, Some(named))?;
            provider = Some(serving(version, Kind::OpenAi, named)?);
            seen.provider = provider;
            model = Some(named.to_string());
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
    if !spend::room(&state.spend, &budgets).await {
        return Err(Refusal::new(
            StatusCode::TOO_MANY_REQUESTS,
            "budget_exceeded",
            format!(
                "Refused: a budget \"{}\" counts against (of rule \"{}\", its key or the limits: list) is spent for this period, and a realtime session starts only with budget left. It starts again at the next period; ask a Gantry admin to raise it if you need more before then.",
                person.name, rule.name
            ),
        ));
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
    let upstream = match dial(&state, provider, api, &model, open.beta.as_ref()).await {
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
    let ended_by = loop {
        tokio::select! {
            message = down_rx.next() => match message {
                Some(Ok(Down::Text(text))) => {
                    if up_tx.send(Up::Text(text.as_str().into())).await.is_err() {
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
                        if !spend::room(&state.spend, &budgets).await {
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
        ..Seen::default()
    };
    let decided = (|| {
        let model = seen.model.clone().ok_or_else(|| {
            Refusal::new(
                StatusCode::BAD_REQUEST,
                "model_needed",
                "Refused: the first message must be {\"setup\": {\"model\": \"models/<model>\"}}, so the policy can decide the model. Send it first.",
            )
        })?;
        let policy = version.policy.as_ref().ok_or_else(crate::unknown_route)?;
        batch::decide_model(policy, &open.person, &open.rule, &model, "the session")?;
        crate::killed(state, &open.person, &open.key_sha256, Some(&model))?;
        let index = serving(version, Kind::Gemini, &model)?;
        Ok::<_, Refusal>((model, index))
    })();
    if let Ok((_, index)) = &decided {
        seen.provider = Some(*index);
    }
    batch::record_decision(
        state,
        version,
        decision,
        None,
        "GET",
        GEMINI,
        &seen,
        decided.as_ref().err(),
        Map::new(),
    )
    .await?;
    let (model, index) = decided?;
    open.model = Some(model);
    open.provider = Some(index);
    Ok(setup)
}

/// The usage a provider event reports, with the response it belongs to.
fn usage_of(api: Api, text: &str) -> Option<(Usage, Option<String>)> {
    let count = |v: &Value| v.as_u64().unwrap_or_default();
    match api {
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
            let cached = count(&usage["input_token_details"]["cached_tokens"]);
            Some((
                Usage {
                    input: count(&usage["input_tokens"]).saturating_sub(cached),
                    output: count(&usage["output_tokens"]),
                    cache_read: cached,
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
            let cached = count(&usage["cachedContentTokenCount"]);
            Some((
                Usage {
                    input: (count(&usage["promptTokenCount"])
                        + count(&usage["toolUsePromptTokenCount"]))
                    .saturating_sub(cached),
                    output: count(&usage["responseTokenCount"])
                        + count(&usage["thoughtsTokenCount"]),
                    cache_read: cached,
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
    record.insert("seconds".into(), started.elapsed().as_secs_f64().into());
    record.insert("responses".into(), responses.into());
    record.insert("charged_usd".into(), charged.into());
    record.insert("ended_by".into(), ended_by.into());
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
) -> Result<Provider, String> {
    let url = match api {
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
    let tcp = tokio::time::timeout(
        state.timeouts.connect,
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| {
        format!(
            "no connection within {} seconds",
            state.timeouts.connect.as_secs()
        )
    })?
    .map_err(|e| e.to_string())?;
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
