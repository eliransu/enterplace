//! Delivery of plugin events (contract v2, gantry-core/src/events.rs): `type: events` guardrails and the
//! embedding binary's `Extension::events` plugin.
//!
//! An enforcing plugin is asked on the request path and obeyed: on the request, on the whole answer, on each window
//! of a streamed answer, on MCP tool calls and on realtime text. An observing plugin is never asked on the request
//! path: its envelopes go to a bounded queue a background task empties in batches, and a full queue drops and
//! counts. A rule with no events guardrail, in a binary with no plugin, runs none of this.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::Response,
};
use gantry_core::{
    events::{
        self as core, Context, Envelope, Event, Events, Kind, Markers, Masked, Mode, Verdict,
    },
    guard::{self, AuditEntry, Blocked, Guardrail},
    id,
    policy::{Principal, Rule},
    store::Pending,
};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

use crate::{AppState, Refusal};

/// The url of the guardrail that stands for the embedding binary's plugin. No policy can name it: a guardrail's url
/// is http or https.
const EXTENSION: &str = "extension:";
/// The embedding binary's plugin, as records and envelopes name it.
const EXTENSION_NAME: &str = "extension";
/// Most ended sessions remembered by one process. Past it, the ones that ran out are forgotten first.
const MAX_ENDED: usize = 50_000;

/// A binary's own events plugin, in process: the same envelope and the same verdict a `type: events` service gets
/// and gives, with no HTTP between. It is asked for every request a rule allows.
pub trait EventsPlugin: Send + Sync {
    /// `Enforce` waits for `judge` and obeys it. `Observe` calls it in the background and reads no verdict.
    fn mode(&self) -> Mode {
        Mode::Enforce
    }
    /// A streamed answer's windows, as a guardrail's `stream:`.
    fn stream(&self) -> Option<core::Stream> {
        None
    }
    /// Whether each envelope carries the events before the new ones.
    fn history(&self) -> bool {
        false
    }
    /// The longest `judge` is waited for. Past it the request is refused: a plugin in the binary fails closed.
    fn timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
    /// How long a session it ends is refused.
    fn session_end(&self) -> Duration {
        Duration::from_secs(3600)
    }
    /// The verdict on one envelope. An `Err` is a failure of the plugin: its text is logged, never sent on.
    fn judge(&self, envelope: Envelope) -> Pending<Verdict>;
}

/// What delivery keeps between requests: the binary's plugin, each observing guardrail's queue, and the sessions
/// plugins ended.
#[derive(Default)]
pub(crate) struct Plugins {
    extension: Option<(Arc<dyn EventsPlugin>, Guardrail)>,
    /// By guardrail name: the settings the queue was made for, and its sender. A reload that changes the settings
    /// makes a new queue; the old one's task sends what it holds and ends.
    queues: Mutex<HashMap<String, (Events, tokio::sync::mpsc::Sender<Envelope>)>>,
    /// Session id to when its refusal runs out, and the guardrail that ended it.
    ended: Mutex<HashMap<String, (Instant, String)>>,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Plugins {
    pub(crate) fn new(extension: Option<Arc<dyn EventsPlugin>>) -> Self {
        let extension = extension.map(|plugin| {
            let events = Events {
                hook: guard::Webhook {
                    url: EXTENSION.to_string(),
                    timeout: plugin.timeout(),
                    on_failure: guard::OnFailure::FailClosed,
                    headers_env: Vec::new(),
                    vendor: guard::Vendor::Contract,
                    key_env: None,
                },
                mode: plugin.mode(),
                history: plugin.history(),
                stream: plugin.stream(),
                session_end_seconds: plugin.session_end().as_secs().max(1),
                secret_env: None,
                batch_url: None,
                queue: 0,
                batch_size: 0,
                retries: 0,
            };
            let guardrail = Guardrail {
                name: EXTENSION_NAME.to_string(),
                action: core::guard_action(events.mode),
                check: guard::Check::Events(events),
                on: guard::On {
                    request: false,
                    answer: false,
                },
                shadow_until: None,
            };
            (plugin, guardrail)
        });
        Self {
            extension,
            ..Self::default()
        }
    }
}

/// The events guardrails among a rule's (already put in their shadow period by observe mode), then the binary's
/// plugin. Empty for a rule with none in a binary with none: the caller then does nothing more.
pub(crate) fn guards_for(state: &AppState, guards: &[Guardrail]) -> Vec<Guardrail> {
    guards
        .iter()
        .filter(|g| matches!(g.check, guard::Check::Events(_)))
        .chain(state.events.extension.as_ref().map(|(_, g)| g))
        .cloned()
        .collect()
}

/// Whether any of this would run for a rule with these guardrails.
pub(crate) fn active(state: &AppState, guards: &[Guardrail]) -> bool {
    state.events.extension.is_some()
        || guards
            .iter()
            .any(|g| matches!(g.check, guard::Check::Events(_)))
}

/// What a request's headers say about its session, turn and application.
pub(crate) fn markers(headers: &HeaderMap) -> Markers {
    Markers::read(&|name| headers.get(name).and_then(|v| v.to_str().ok()))
}

fn settings(guardrail: &Guardrail) -> Option<&Events> {
    match &guardrail.check {
        guard::Check::Events(events) => Some(events),
        _ => None,
    }
}

/// Whether a guardrail's verdicts are obeyed now.
fn enforcing(guardrail: &Guardrail) -> bool {
    settings(guardrail).is_some_and(|e| e.mode == Mode::Enforce) && !guardrail.shadowing()
}

// ---------------------------------------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------------------------------------

/// The POST that carries `body` to a plugin: its credentials from the environment, and its signature.
fn call_for(
    events: &Events,
    url: &str,
    id: &str,
    body: Vec<u8>,
) -> Result<gantry_core::vendors::Call, String> {
    // ponytail: read from the environment on each call, as webhook guardrails do. Start and reload refuse a policy
    // whose variables are unset.
    let env = |variable: &str| {
        gantry_core::secrets::var(variable)
            .ok_or_else(|| format!("the environment variable {variable} is not set"))
    };
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    for (name, variable) in &events.hook.headers_env {
        headers.push((name.clone(), env(variable)?));
    }
    headers.push(("webhook-id".into(), id.to_string()));
    if let Some(variable) = &events.secret_env {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        headers.push(("webhook-timestamp".into(), now.to_string()));
        headers.push((
            "webhook-signature".into(),
            core::signature(&env(variable)?, id, now, &body),
        ));
    }
    Ok(gantry_core::vendors::Call {
        url: url.to_string(),
        headers,
        body,
    })
}

/// Asks an enforcing plugin for its verdict on one envelope.
async fn deliver(
    state: &AppState,
    events: &Events,
    envelope: &Envelope,
) -> Result<Verdict, String> {
    let limit = events.hook.timeout;
    let late = || format!("gave no answer within {} ms", limit.as_millis());
    if events.hook.url == EXTENSION {
        let Some((plugin, _)) = &state.events.extension else {
            return Err("the binary has no events plugin".into());
        };
        return tokio::time::timeout(limit, plugin.judge(envelope.clone()))
            .await
            .map_err(|_| late())?;
    }
    let body = serde_json::to_vec(envelope).map_err(|e| e.to_string())?;
    let call = call_for(events, &events.hook.url, &envelope.id(), body)?;
    let bytes = tokio::time::timeout(limit, crate::post_on(&state.client, call))
        .await
        .map_err(|_| late())??;
    core::parse_verdict(&bytes, &envelope.events)
}

/// Sends what an observing guardrail's queue holds, a batch at a time, until the queue is closed and empty.
async fn drain(
    client: crate::HttpClient,
    metrics: Arc<crate::metrics::Metrics>,
    name: String,
    events: Events,
    mut queue: tokio::sync::mpsc::Receiver<Envelope>,
) {
    while let Some(first) = queue.recv().await {
        let mut batch = vec![first];
        while batch.len() < events.batch_size {
            match queue.try_recv() {
                Ok(next) => batch.push(next),
                Err(_) => break,
            }
        }
        // With a batch_url the batch is one POST. Without, each envelope is its own, in the contract's one shape.
        let posts: Vec<(String, String, Vec<u8>, u64)> = match &events.batch_url {
            Some(url) => {
                let body = serde_json::to_vec(&core::Batch {
                    contract: core::CONTRACT,
                    batch: &batch,
                });
                let id = id::sha256_hex(
                    batch
                        .iter()
                        .map(Envelope::id)
                        .collect::<Vec<_>>()
                        .join(",")
                        .as_bytes(),
                );
                vec![(
                    url.clone(),
                    format!("bat_{}", &id[..24]),
                    body.unwrap_or_default(),
                    batch.len() as u64,
                )]
            }
            None => batch
                .iter()
                .map(|envelope| {
                    (
                        events.hook.url.clone(),
                        envelope.id(),
                        serde_json::to_vec(envelope).unwrap_or_default(),
                        1,
                    )
                })
                .collect(),
        };
        for (url, id, body, count) in posts {
            let mut cause = String::new();
            let mut sent = false;
            for attempt in 0..=events.retries {
                if attempt > 0 {
                    // 200 ms, 400 ms, 800 ms, ... capped at 5 s: a plugin that is down is not hammered.
                    let wait = 200u64.saturating_mul(1 << (attempt - 1).min(5)).min(5000);
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                }
                let outcome = match call_for(&events, &url, &id, body.clone()) {
                    Ok(call) => {
                        tokio::time::timeout(events.hook.timeout, crate::post_on(&client, call))
                            .await
                            .unwrap_or_else(|_| {
                                Err(format!(
                                    "gave no answer within {} ms",
                                    events.hook.timeout.as_millis()
                                ))
                            })
                    }
                    Err(cause) => Err(cause),
                };
                match outcome {
                    Ok(_) => {
                        sent = true;
                        break;
                    }
                    Err(why) => cause = why,
                }
            }
            if sent {
                metrics.events(&name, "sent", count);
            } else {
                metrics.events(&name, "failed", count);
                eprintln!(
                    "gantry: events guardrail \"{name}\" at {url}: {cause}. {count} envelope(s) were not delivered after {} tries; observe mode does not hold requests for them.",
                    events.retries + 1
                );
            }
        }
    }
}

/// Hands an envelope to an observing guardrail without waiting. `false` when its queue was full and the envelope
/// was dropped, which the `gantry_events_dropped_total` counter shows.
fn enqueue(state: &AppState, name: &str, events: &Events, envelope: Envelope) -> bool {
    if events.hook.url == EXTENSION {
        if let Some((plugin, _)) = &state.events.extension {
            let judged = plugin.judge(envelope);
            tokio::spawn(async move {
                let _ = judged.await;
            });
        }
        return true;
    }
    let sender = {
        let mut queues = locked(&state.events.queues);
        match queues.get(name) {
            Some((made_for, sender)) if made_for == events => sender.clone(),
            _ => {
                let (sender, receiver) = tokio::sync::mpsc::channel(events.queue);
                tokio::spawn(drain(
                    state.client.clone(),
                    state.metrics.clone(),
                    name.to_string(),
                    events.clone(),
                    receiver,
                ));
                queues.insert(name.to_string(), (events.clone(), sender.clone()));
                sender
            }
        }
    };
    let queued = sender.try_send(envelope).is_ok();
    if !queued {
        state.metrics.events(name, "dropped", 1);
    }
    queued
}

/// What the plugins of a rule made of some events.
#[derive(Default)]
pub(crate) struct Judged {
    pub audit: Vec<AuditEntry>,
    /// One entry per plugin, for the record's `events`.
    pub entries: Vec<Value>,
    pub blocked: Option<Blocked>,
    pub masks: Vec<Masked>,
}

/// Shows `events` to each plugin in order: an observing one gets them queued, an enforcing one is asked and
/// obeyed, and the first to block ends the asking. A plugin that ends the session ends it here.
/// ponytail: each plugin sees the events as they were, not as a plugin before it masked them; the masks of all are
/// written, the last one's last. Chain them in one service if the second must read the first's redactions.
pub(crate) async fn judge(
    state: &AppState,
    guards: &[Guardrail],
    context: &Context,
    phase: &'static str,
    events: &[Event],
    history: Option<&[Event]>,
    what: &str,
) -> Judged {
    let mut out = Judged::default();
    if events.is_empty() {
        return out;
    }
    for guardrail in guards {
        let Some(settings) = settings(guardrail) else {
            continue;
        };
        let envelope = Envelope {
            contract: core::CONTRACT,
            guardrail: guardrail.name.clone(),
            mode: settings.mode.word(),
            phase,
            context: context.clone(),
            events: events.to_vec(),
            history: history.filter(|_| settings.history).map(<[Event]>::to_vec),
        };
        if settings.mode == Mode::Observe {
            let queued = enqueue(state, &guardrail.name, settings, envelope);
            out.entries.push(json!({
                "guardrail": guardrail.name,
                "mode": "observe",
                "events": events.len(),
                "action": if queued { "queued" } else { "dropped" },
            }));
            continue;
        }
        if out.blocked.is_some() {
            continue;
        }
        let outcome = deliver(state, settings, &envelope).await;
        state.metrics.events(
            &guardrail.name,
            if outcome.is_ok() { "sent" } else { "failed" },
            1,
        );
        let settled = core::settle(
            &guardrail.name,
            settings,
            guardrail.shadowing(),
            events,
            outcome,
            what,
        );
        if let Some(cause) = &settled.cause {
            eprintln!("gantry: decision {}: {cause}", context.decision_id);
        }
        if settled.end_session {
            end_session(
                state,
                &context.session_id,
                Duration::from_secs(settings.session_end_seconds),
                &guardrail.name,
            );
        }
        out.audit.extend(settled.audit);
        out.entries.push(settled.entry);
        out.masks.extend(settled.masks);
        out.blocked = settled.blocked;
    }
    out
}

// ---------------------------------------------------------------------------------------------------------
// Ended sessions
// ---------------------------------------------------------------------------------------------------------

/// What the store knows an ended session by. The store's session table holds console sessions by the hash of a
/// random id; this hash is of a text no console session has, so the two never meet.
fn ended_key(session: &str) -> String {
    id::sha256_hex(format!("gantry events: session ended\n{session}").as_bytes())
}

fn end_session(state: &AppState, session: &str, lasts: Duration, by: &str) {
    {
        let mut ended = locked(&state.events.ended);
        if ended.len() >= MAX_ENDED {
            let now = Instant::now();
            ended.retain(|_, (until, _)| *until > now);
        }
        if ended.len() < MAX_ENDED {
            ended.insert(
                session.to_string(),
                (Instant::now() + lasts, by.to_string()),
            );
        }
    }
    // With a store every replica refuses the session: it is written once, and each replica asks.
    if let Some(store) = state.pool.store() {
        let written = store.open_session(ended_key(session), format!("events:{by}"), lasts);
        let session = session.to_string();
        tokio::spawn(async move {
            if let Err(err) = written.await {
                // A session ended twice is already in the table, which is what was wanted.
                if !err.contains("duplicate") {
                    eprintln!(
                        "gantry: the end of session {session} could not be written to the store ({err}); other replicas keep serving it."
                    );
                }
            }
        });
    }
}

/// The guardrail that ended a session, while its refusal lasts.
async fn ended_by(state: &AppState, session: &str) -> Option<String> {
    {
        let mut ended = locked(&state.events.ended);
        match ended.get(session) {
            Some((until, by)) if *until > Instant::now() => return Some(by.clone()),
            Some(_) => {
                ended.remove(session);
            }
            None => {}
        }
    }
    // ponytail: one read of the store per request of a rule with an enforcing plugin. A polled copy in memory, as
    // kill switches have, when that read shows up in a profile.
    let store = state.pool.store()?;
    let who = store.session(ended_key(session)).await.ok()??;
    Some(who.strip_prefix("events:").unwrap_or(&who).to_string())
}

// ---------------------------------------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------------------------------------

/// A request's turn, carried with it to its answer.
#[derive(Clone)]
pub(crate) struct Carry {
    guards: Arc<Vec<Guardrail>>,
    context: Context,
    next_index: usize,
}

/// Who sends a request and what it is, as the decision knows it.
pub(crate) struct Sender<'a> {
    pub person: &'a Principal,
    pub rule: &'a Rule,
    pub decision: &'a str,
    pub path: &'a str,
    pub model: &'a str,
    pub provider: &'a str,
    pub user_agent: Option<&'a str>,
    pub customer: Option<&'a str>,
    pub tags: &'a [String],
    /// Observe mode or the rule's shadow period: what would be refused is let through.
    pub observing: bool,
}

/// What the plugins made of a request.
#[derive(Default)]
pub(crate) struct Requested {
    pub refusal: Option<Refusal>,
    pub audit: Vec<AuditEntry>,
    pub entries: Vec<Value>,
    /// The session and the turn, for the records.
    pub session: Option<(String, String)>,
    pub carry: Option<Carry>,
}

fn refused(status: StatusCode, code: &'static str, message: String) -> Requested {
    Requested {
        refusal: Some(Refusal::new(status, code, message)),
        ..Requested::default()
    }
}

/// The application a request runs as: the rule's own, or the one the caller names where the rule lets it.
fn application(
    sender: &Sender<'_>,
    markers: &Markers,
) -> Result<Option<core::Application>, Refusal> {
    let bad = |message: &str| Refusal::new(StatusCode::BAD_REQUEST, "bad_header", message);
    if markers
        .application
        .as_deref()
        .is_some_and(|name| !gantry_core::config::valid_name(name))
    {
        return Err(bad(
            "Refused: x-gantry-application names an application in letters, digits, dots, dashes, underscores and @ only, at most 100 characters.",
        ));
    }
    if markers
        .intent
        .as_deref()
        .is_some_and(|intent| !core::intent_ok(intent))
    {
        return Err(bad(
            "Refused: x-gantry-application-intent is one line of at most 500 characters saying what the application is for.",
        ));
    }
    match sender
        .rule
        .application(markers.application.as_deref(), markers.intent.as_deref())
    {
        Ok(application) => Ok(application),
        // Observed, the request goes on with no application: what the rule does not list is not passed on as fact.
        Err(_) if sender.observing => Ok(None),
        Err(name) => Err(Refusal::new(
            StatusCode::FORBIDDEN,
            "application_not_allowed",
            format!(
                "Refused: rule \"{}\" does not let a caller run as application \"{name}\" in x-gantry-application. Leave the header out, or ask a Gantry admin to add it (or \"*\") to the rule's applications.",
                sender.rule.name
            ),
        )),
    }
}

/// Shows a request about to be sent to the rule's plugins. An enforcing one may refuse it or mask it: `bytes` is
/// then the masked body.
pub(crate) async fn request(
    state: &AppState,
    guards: Vec<Guardrail>,
    sender: &Sender<'_>,
    markers: &Markers,
    parts: &mut Parts,
    bytes: &mut Bytes,
) -> Requested {
    let enforced = guards.iter().any(enforcing);
    let Ok(mut body) = serde_json::from_slice::<Value>(bytes) else {
        if !enforced {
            return Requested::default();
        }
        return refused(
            StatusCode::BAD_REQUEST,
            "unreadable_request",
            "Refused: the request body is not valid JSON, so the events plugin could not read it. Send a JSON object.".into(),
        );
    };
    let application = match application(sender, markers) {
        Ok(application) => application,
        Err(refusal) => {
            return Requested {
                refusal: Some(refusal),
                ..Requested::default()
            };
        }
    };
    let conversation = core::conversation(&body);
    let (session, _) = core::session_id(
        &sender.person.name,
        &sender.person.key,
        markers,
        &body,
        conversation.first_message(),
    );
    let placed = conversation.placed(&session, markers.turn.as_deref());
    let mut out = Requested {
        session: Some((session.clone(), placed.turn_id.clone())),
        ..Requested::default()
    };
    if enforced && let Some(by) = ended_by(state, &session).await {
        out.refusal = Some(Refusal::new(
            StatusCode::FORBIDDEN,
            core::SESSION_ENDED,
            format!(
                "Refused: guardrail \"{by}\" ended this session, so its requests are refused for a while. Start a new conversation, or ask a Gantry admin about the guardrail."
            ),
        ));
        out.entries
            .push(json!({"guardrail": by, "action": "session_ended"}));
        return out;
    }
    let context = Context {
        session_id: session,
        turn_id: placed.turn_id.clone(),
        turn_index: placed.turn_index,
        decision_id: sender.decision.to_string(),
        person: sender.person.name.clone(),
        team: sender.person.team.clone(),
        org: sender.person.org.clone(),
        customer: sender.customer.map(str::to_string),
        tags: sender.tags.to_vec(),
        model: sender.model.to_string(),
        provider: sender.provider.to_string(),
        route: sender.path.to_string(),
        user_agent: sender.user_agent.map(str::to_string),
        application,
    };
    let judged = judge(
        state,
        &guards,
        &context,
        "request",
        &placed.new,
        Some(&placed.history),
        "this request",
    )
    .await;
    out.audit = judged.audit;
    out.entries = judged.entries;
    if let Some(blocked) = judged.blocked {
        out.refusal = Some(Refusal::new(
            StatusCode::FORBIDDEN,
            guard::BLOCKED_CODE,
            format!("Refused: {}", blocked.message),
        ));
        return out;
    }
    if !judged.masks.is_empty() {
        let written =
            core::apply_masks(&mut body, &placed.new, &judged.masks).and_then(|changed| {
                if changed {
                    serde_json::to_vec(&body)
                        .map(Some)
                        .map_err(|e| e.to_string())
                } else {
                    Ok(None)
                }
            });
        match written {
            Ok(Some(masked)) => {
                parts
                    .headers
                    .insert(header::CONTENT_LENGTH, HeaderValue::from(masked.len()));
                *bytes = Bytes::from(masked);
            }
            Ok(None) => {}
            Err(cause) => {
                eprintln!(
                    "gantry: decision {}: an events plugin's mask could not be written: {cause}",
                    sender.decision
                );
                // Never forward the unmasked body because the masked one could not be written.
                out.refusal = Some(Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    guard::BLOCKED_CODE,
                    "Refused: an events plugin masked this request, and its mask could not be written, so the request was not sent. Tell your Gantry admin.",
                ));
                return out;
            }
        }
    }
    out.carry = Some(Carry {
        guards: Arc::new(guards),
        next_index: placed.next_index,
        context,
    });
    out
}

// ---------------------------------------------------------------------------------------------------------
// The answer
// ---------------------------------------------------------------------------------------------------------

/// The record of what the plugins made of an answer: an `answer_guardrails` record, so the request log counts its
/// findings as it does those of every answer guardrail.
fn answer_record(
    context: &Context,
    verdict: &str,
    audit: &[AuditEntry],
    entries: &[Value],
) -> Map<String, Value> {
    let mut record = Map::new();
    record.insert("event".into(), "answer_guardrails".into());
    record.insert("id".into(), context.decision_id.as_str().into());
    record.insert("time".into(), gantry_core::audit::timestamp().into());
    record.insert("verdict".into(), verdict.into());
    record.insert(
        "guardrails".into(),
        serde_json::to_value(audit).unwrap_or_default(),
    );
    record.insert("events".into(), entries.to_vec().into());
    record.insert("session".into(), context.session_id.as_str().into());
    record.insert("turn".into(), context.turn_id.as_str().into());
    if !context.org.is_empty() {
        record.insert("org".into(), context.org.as_str().into());
    }
    record
}

fn withheld(blocked: &Blocked) -> Refusal {
    Refusal::new(
        StatusCode::FORBIDDEN,
        guard::BLOCKED_CODE,
        format!(
            "Refused: {} The answer was produced and is counted in usage.",
            blocked.message
        ),
    )
}

/// Shows an answer to the plugins of its request before it reaches the caller: a whole answer at once, a streamed
/// one as it comes.
pub(crate) async fn answer(
    state: &AppState,
    carry: Carry,
    response: Response,
) -> Result<Response, Refusal> {
    // An error is the provider's or Gantry's own words, not the model's.
    if !response.status().is_success() {
        return Ok(response);
    }
    if crate::is_type(&response, "text/event-stream") {
        return Ok(streamed(state, carry, response));
    }
    let (mut parts, body) = response.into_parts();
    let bytes = crate::whole(body).await?;
    let enforced = carry.guards.iter().any(enforcing);
    let Ok(mut answer) = serde_json::from_slice::<Value>(&bytes) else {
        if !enforced {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }
        return Err(Refusal::new(
            StatusCode::BAD_GATEWAY,
            guard::BLOCKED_CODE,
            "Refused: the provider's answer is not JSON Gantry can read, and an events plugin must see it before it is passed on. Try again. If it keeps happening, tell your Gantry admin.",
        ));
    };
    let context = &carry.context;
    let events = core::answer_events(&answer, &context.turn_id, carry.next_index);
    if events.is_empty() {
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    }
    let judged = judge(
        state,
        &carry.guards,
        context,
        "answer",
        &events,
        None,
        "the model's answer",
    )
    .await;
    let masked = if judged.blocked.is_some() || judged.masks.is_empty() {
        Ok(false)
    } else {
        core::apply_masks(&mut answer, &events, &judged.masks)
    };
    let word = match (&judged.blocked, &masked) {
        (Some(_), _) | (_, Err(_)) => "block",
        (None, Ok(true)) => "mask",
        (None, Ok(false)) => "pass",
    };
    if let Some(audit) = &state.audit {
        let record = answer_record(context, word, &judged.audit, &judged.entries);
        let (tell, written) = tokio::sync::oneshot::channel();
        audit.log.append_record_then(&record, move |result| {
            let _ = tell.send(result);
        });
        if !matches!(written.await, Ok(Ok(()))) {
            return Err(Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "Refused: Gantry could not write the events plugin's check of this answer to its audit log, and it does not pass on what it cannot record. Tell your Gantry admin.",
            ));
        }
    }
    if let Some(blocked) = &judged.blocked {
        return Err(withheld(blocked));
    }
    match masked {
        Ok(false) => Ok(Response::from_parts(parts, Body::from(bytes))),
        Ok(true) => {
            let written = serde_json::to_vec(&answer).map_err(|_| {
                Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    guard::BLOCKED_CODE,
                    "Refused: the masked answer could not be written, so it was not passed on. Tell your Gantry admin.",
                )
            })?;
            parts.headers.remove(header::CONTENT_LENGTH);
            Ok(Response::from_parts(parts, Body::from(written)))
        }
        Err(cause) => {
            eprintln!(
                "gantry: decision {}: an events plugin's mask of the answer could not be written: {cause}",
                context.decision_id
            );
            Err(Refusal::new(
                StatusCode::BAD_GATEWAY,
                guard::BLOCKED_CODE,
                "Refused: an events plugin masked the model's answer, and its mask could not be written, so the answer was not passed on. Tell your Gantry admin.",
            ))
        }
    }
}

/// Whether a stream's text slot (`crate::event_texts`) is the model's words to the caller: chat content, a messages
/// text block, Responses output text, Gemini text that is not a thought. Tool arguments and thoughts are not.
fn said(slot: &str) -> bool {
    slot.starts_with(['c', 'm', 'r']) || (slot.starts_with('g') && !slot.starts_with("gt"))
}

/// A streamed answer and its plugins. With `stream:` its text is shown to them in windows as it comes; with
/// `hold`, a window's bytes wait for its verdict, so what a plugin blocks never reaches the caller. Without hold
/// the bytes go on at once and a block ends the stream where it lands. When the stream ends, the whole answer is
/// shown as events (the message, its reasoning, its tool calls), held like a window when hold is set. A block ends
/// the stream with an error event in the caller's API; a mask does too, since what was sent cannot be rewritten.
fn streamed(state: &AppState, carry: Carry, response: Response) -> Response {
    let (mut parts, mut body) = response.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    let state = state.clone();
    tokio::spawn(async move {
        let context = &carry.context;
        let windowed: Vec<Guardrail> = carry
            .guards
            .iter()
            .filter(|g| settings(g).is_some_and(|e| e.stream.is_some()))
            .cloned()
            .collect();
        let every = windowed
            .iter()
            .filter_map(|g| settings(g)?.stream.map(|s| s.chunk_chars))
            .min();
        let hold = carry
            .guards
            .iter()
            .any(|g| enforcing(g) && settings(g).is_some_and(|e| e.stream.is_some_and(|s| s.hold)));
        let windowed = Arc::new(windowed);
        let mut seen: Vec<u8> = Vec::new();
        // How far the stream is released to the caller, and how far its events are read.
        let (mut released, mut read) = (0usize, 0usize);
        let mut events: Vec<Value> = Vec::new();
        let mut text = String::new();
        // Where the window before ended in `text`, and the next window's number.
        let (mut shown, mut window) = (0usize, 0usize);
        let (mut audit, mut entries) = (Vec::new(), Vec::new());
        // Verdicts of windows that were not held, as they come.
        let (verdict_tx, mut verdicts) = tokio::sync::mpsc::unbounded_channel::<Judged>();
        let mut pending = 0usize;
        let stop = |judged: &Judged| {
            judged.blocked.clone().or_else(|| {
                (!judged.masks.is_empty()).then(|| Blocked {
                    guardrail: String::new(),
                    message: "An events plugin would rewrite the model's answer, and a streamed answer cannot be rewritten once sent.".into(),
                })
            })
        };
        let blocked = loop {
            let done = tokio::select! {
                frame = body.frame() => match frame {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            seen.extend_from_slice(&data);
                        }
                        false
                    }
                    // The provider's stream ended or broke: what is left is the end.
                    _ => true,
                },
                Some(judged) = verdicts.recv(), if pending > 0 => {
                    pending -= 1;
                    let stopped = stop(&judged);
                    audit.extend(judged.audit);
                    entries.extend(judged.entries);
                    if stopped.is_some() {
                        break stopped;
                    }
                    continue;
                }
            };
            let end = if done {
                seen.len()
            } else {
                crate::whole_events(&seen)
            };
            for (_, event) in crate::stream_events(&seen[read..end]).unwrap_or_default() {
                for (slot, pointer) in crate::event_texts(&event) {
                    if said(&slot) {
                        text.push_str(
                            event
                                .pointer(&pointer)
                                .and_then(Value::as_str)
                                .unwrap_or(""),
                        );
                    }
                }
                events.push(event);
            }
            read = end;
            if !hold && end > released {
                if tx
                    .send(Bytes::copy_from_slice(&seen[released..end]))
                    .await
                    .is_err()
                {
                    // The caller left: the provider's stream is dropped with the body.
                    return;
                }
                released = end;
            }
            let fresh = text[shown..].chars().count();
            if !done && every.is_some_and(|every| fresh >= every) {
                let event = Event {
                    partial: true,
                    window: Some(window),
                    ..Event::text(Kind::AssistantMessage, &text[shown..])
                }
                .placed(&context.turn_id, carry.next_index);
                shown = text.len();
                window += 1;
                if hold {
                    let judged = judge(
                        &state,
                        &windowed,
                        context,
                        "stream",
                        &[event],
                        None,
                        "the model's answer",
                    )
                    .await;
                    let stopped = stop(&judged);
                    audit.extend(judged.audit);
                    entries.extend(judged.entries);
                    if stopped.is_some() {
                        break stopped;
                    }
                    if tx
                        .send(Bytes::copy_from_slice(&seen[released..end]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    released = end;
                } else {
                    let (state, windowed, context, tell) = (
                        state.clone(),
                        windowed.clone(),
                        context.clone(),
                        verdict_tx.clone(),
                    );
                    pending += 1;
                    tokio::spawn(async move {
                        let judged = judge(
                            &state,
                            &windowed,
                            &context,
                            "stream",
                            &[event],
                            None,
                            "the model's answer",
                        )
                        .await;
                        let _ = tell.send(judged);
                    });
                }
            }
            if done {
                // The windows still out are heard before the end is judged.
                let mut stopped = None;
                while pending > 0 && stopped.is_none() {
                    let Some(judged) = verdicts.recv().await else {
                        break;
                    };
                    pending -= 1;
                    stopped = stop(&judged);
                    audit.extend(judged.audit);
                    entries.extend(judged.entries);
                }
                if stopped.is_some() {
                    break stopped;
                }
                let whole = core::answer_events(
                    &core::stream_answer(&events),
                    &context.turn_id,
                    carry.next_index,
                );
                let judged = judge(
                    &state,
                    &carry.guards,
                    context,
                    "answer",
                    &whole,
                    None,
                    "the model's answer",
                )
                .await;
                let stopped = stop(&judged);
                audit.extend(judged.audit);
                entries.extend(judged.entries);
                if stopped.is_none() && end > released {
                    let _ = tx.send(Bytes::copy_from_slice(&seen[released..end])).await;
                }
                break stopped;
            }
        };
        if let Some(log) = &state.audit {
            let word = if blocked.is_some() { "block" } else { "pass" };
            let mut record = answer_record(context, word, &audit, &entries);
            if blocked.is_some() {
                record.insert(
                    "stopped_after_chars".into(),
                    text[..shown.min(text.len())].chars().count().into(),
                );
            }
            log.log.append_record_then(&record, |_| {});
        }
        if let Some(blocked) = blocked {
            let name = if blocked.guardrail.is_empty() {
                "an events plugin".to_string()
            } else {
                format!("guardrail \"{}\"", blocked.guardrail)
            };
            let message = if hold {
                format!(
                    "Refused: {name} stopped the model's answer partway. What came before was checked and sent; the rest was withheld. Ask in another way, or ask a Gantry admin about the guardrail."
                )
            } else {
                format!(
                    "Refused: {name} stopped the model's answer. What came before it was already sent. Ask in another way, or ask a Gantry admin about the guardrail."
                )
            };
            let _ = tx
                .send(Bytes::from(crate::blocked_event(&context.route, &message)))
                .await;
        }
    });
    Response::from_parts(parts, Body::new(crate::Released(rx)))
}

// ---------------------------------------------------------------------------------------------------------
// MCP and realtime
// ---------------------------------------------------------------------------------------------------------

/// The context of events that come from somewhere other than a model request: an MCP tool call, a realtime session.
/// The session is the caller's (`x-gantry-session`, `x-session-id`, or what `fallback` names: the MCP session, the
/// realtime connection), and the turn is `x-gantry-turn` when the caller links the call to a model turn, else the
/// call's own.
pub(crate) fn context_of(
    person: &Principal,
    headers: &HeaderMap,
    fallback: &str,
    decision: &str,
    route: &str,
    model: &str,
) -> Context {
    let mut markers = markers(headers);
    if markers.gantry_session.is_none() && markers.session.is_none() {
        markers.session = headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
    }
    let (session, _) =
        core::session_id(&person.name, &person.key, &markers, &Value::Null, fallback);
    let turn = core::turn_id(&session, 0, decision, markers.turn.as_deref());
    Context {
        session_id: session,
        turn_id: turn,
        turn_index: 0,
        decision_id: decision.to_string(),
        person: person.name.clone(),
        team: person.team.clone(),
        org: person.org.clone(),
        customer: person.customer.clone(),
        tags: person.tags.clone(),
        model: model.to_string(),
        provider: String::new(),
        route: route.to_string(),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        application: None,
    }
}

/// Whether a session a plugin ended is still refused, for the routes that are not model requests.
pub(crate) async fn refused_session(
    state: &AppState,
    guards: &[Guardrail],
    context: &Context,
) -> Option<Refusal> {
    if !guards.iter().any(enforcing) {
        return None;
    }
    let by = ended_by(state, &context.session_id).await?;
    Some(Refusal::new(
        StatusCode::FORBIDDEN,
        core::SESSION_ENDED,
        format!(
            "Refused: guardrail \"{by}\" ended this session, so its requests are refused for a while. Start a new conversation, or ask a Gantry admin about the guardrail."
        ),
    ))
}
