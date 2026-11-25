//! Delivery of plugin events (contract v2, enterplace-core/src/events.rs): `type: events` guardrails and the
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
use enterplace_core::{
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
) -> Result<enterplace_core::vendors::Call, String> {
    // ponytail: read from the environment on each call, as webhook guardrails do. Start and reload refuse a policy
    // whose variables are unset.
    let env = |variable: &str| {
        enterplace_core::secrets::var(variable)
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
    Ok(enterplace_core::vendors::Call {
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
                    "enterplace: events guardrail \"{name}\" at {url}: {cause}. {count} envelope(s) were not delivered after {} tries; observe mode does not hold requests for them.",
                    events.retries + 1
                );
            }
        }
    }
}

/// Hands an envelope to an observing guardrail without waiting. `false` when its queue was full and the envelope
/// was dropped, which the `enterplace_events_dropped_total` counter shows.
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

/// Shows `events` to each plugin in the order of the rule's list (the binary's own last): an observing one gets
/// them queued, an enforcing one is asked and obeyed, and the first to block ends the asking. Each sees the events
/// as the enforcing plugins before it masked them, and the masks of all are written in that order. A plugin that
/// ends the session ends it here.
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
    let mut events = std::borrow::Cow::Borrowed(events);
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
            &events,
            outcome,
            what,
        );
        if !settled.masks.is_empty() {
            events = std::borrow::Cow::Owned(core::masked_events(&events, &settled.masks));
        }
        if let Some(cause) = &settled.cause {
            eprintln!("enterplace: decision {}: {cause}", context.decision_id);
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
    id::sha256_hex(format!("enterplace events: session ended\n{session}").as_bytes())
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
    // With a store every replica refuses the session: it is written once, and each replica reads it with its poll.
    if let Some(store) = state.pool.store() {
        store.end_events_session(ended_key(session), by.to_string(), lasts);
    }
}

/// The guardrail that ended a session, while its refusal lasts. From memory: what this gateway ended, and what the
/// store's poll last read of the others, so no request waits on the store for it.
fn ended_by(state: &AppState, session: &str) -> Option<String> {
    let now = Instant::now();
    {
        let mut ended = locked(&state.events.ended);
        match ended.get(session) {
            Some((until, by)) if *until > now => return Some(by.clone()),
            Some(_) => {
                ended.remove(session);
            }
            None => {}
        }
    }
    let ended = state.pool.store()?.ended_sessions();
    if ended.is_empty() {
        return None;
    }
    ended
        .get(&ended_key(session))
        .filter(|(until, _)| *until > now)
        .map(|(_, by)| by.clone())
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
    /// One of the model APIs, whose answer an enforcing plugin must be able to read: an answer that is not JSON
    /// is refused. On the other routes an answer Enterplace cannot read as events is passed on as it is.
    chat: bool,
    /// The route answers in words (a model API, completions, a passthrough): the answer is read for events.
    answers: bool,
}

impl Carry {
    /// The turn, as the record of a stored response keeps it for the request that goes on from it.
    pub(crate) fn turn_of(&self) -> Value {
        json!({
            "session": self.context.session_id,
            "turn": self.context.turn_id,
            "turn_index": self.context.turn_index,
            "next": self.next_index,
        })
    }
}

/// The session and turn a stored response was answered in, as [`Carry::turn_of`] wrote them with the count of the
/// answer's events added.
pub(crate) fn prior_of(kept: &Value) -> Option<(String, core::Prior)> {
    Some((
        kept["session"].as_str()?.to_string(),
        core::Prior {
            turn_id: kept["turn"].as_str()?.to_string(),
            turn_index: usize::try_from(kept["turn_index"].as_u64()?).ok()?,
            next_index: usize::try_from(kept["next"].as_u64()?).ok()?,
        },
    ))
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
    /// One of the model APIs (chat completions, messages, Responses, generateContent): its body is a conversation
    /// an enforcing plugin must be able to read. Any other route sends events only for the text Enterplace finds in it.
    pub chat: bool,
    /// The route answers in words Enterplace may find: a model API, completions, a passthrough.
    pub answers: bool,
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
        .is_some_and(|name| !enterplace_core::config::valid_name(name))
    {
        return Err(bad(
            "Refused: x-enterplace-application names an application in letters, digits, dots, dashes, underscores and @ only, at most 100 characters.",
        ));
    }
    if markers
        .intent
        .as_deref()
        .is_some_and(|intent| !core::intent_ok(intent))
    {
        return Err(bad(
            "Refused: x-enterplace-application-intent is one line of at most 500 characters saying what the application is for.",
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
                "Refused: rule \"{}\" does not let a caller run as application \"{name}\" in x-enterplace-application. Leave the header out, or ask an Enterplace admin to add it (or \"*\") to the rule's applications.",
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
        // A form or a file (audio, an image to edit) is not a conversation.
        if !enforced || !sender.chat {
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
    // A Responses request that goes on from a stored response holds only what is new: its session and its turn
    // are the ones that response was answered in, as its owner's record keeps them. A response Enterplace does not
    // know as the caller's falls back to the headers and the body.
    let prior = match body.get("previous_response_id").and_then(Value::as_str) {
        Some(id) if sender.chat => crate::batch::turn_of(state, sender.person, id).await,
        _ => None,
    };
    let (session, placed) = match prior {
        Some((session, prior)) => {
            let placed = conversation.placed_after(&session, markers.turn.as_deref(), &prior);
            (session, placed)
        }
        None => {
            let (session, _) = core::session_id(
                &sender.person.name,
                &sender.person.key,
                markers,
                &body,
                conversation.first_message(),
            );
            let placed = conversation.placed(&session, markers.turn.as_deref());
            (session, placed)
        }
    };
    // A route that is not a conversation, with no text Enterplace reads: nothing to show, and no session to record.
    if !sender.chat && placed.new.is_empty() && placed.history.is_empty() {
        return Requested::default();
    }
    let mut out = Requested {
        session: Some((session.clone(), placed.turn_id.clone())),
        ..Requested::default()
    };
    if enforced && let Some(by) = ended_by(state, &session) {
        out.refusal = Some(session_ended(&by));
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
                    "enterplace: decision {}: an events plugin's mask could not be written: {cause}",
                    sender.decision
                );
                // Never forward the unmasked body because the masked one could not be written.
                out.refusal = Some(Refusal::new(
                    StatusCode::BAD_GATEWAY,
                    guard::BLOCKED_CODE,
                    "Refused: an events plugin masked this request, and its mask could not be written, so the request was not sent. Tell your Enterplace admin.",
                ));
                return out;
            }
        }
    }
    out.carry = Some(Carry {
        guards: Arc::new(guards),
        next_index: placed.next_index,
        context,
        chat: sender.chat,
        answers: sender.answers,
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
    record.insert("time".into(), enterplace_core::audit::timestamp().into());
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
    // An error is the provider's or Enterplace's own words, not the model's. Vectors, images and audio are not words.
    if !response.status().is_success() || !carry.answers {
        return Ok(response);
    }
    if crate::is_type(&response, "text/event-stream") {
        return Ok(streamed(state, carry, response));
    }
    // A cloud's binary stream, a file: not an answer Enterplace reads, and not held in memory to find that out.
    if !carry.chat && !crate::is_type(&response, "application/json") {
        return Ok(response);
    }
    let (mut parts, body) = response.into_parts();
    let bytes = crate::whole(body).await?;
    let enforced = carry.guards.iter().any(enforcing);
    let Ok(mut answer) = serde_json::from_slice::<Value>(&bytes) else {
        if !enforced || !carry.chat {
            return Ok(Response::from_parts(parts, Body::from(bytes)));
        }
        return Err(Refusal::new(
            StatusCode::BAD_GATEWAY,
            guard::BLOCKED_CODE,
            "Refused: the provider's answer is not JSON Enterplace can read, and an events plugin must see it before it is passed on. Try again. If it keeps happening, tell your Enterplace admin.",
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
        // With observing plugins only, the answer does not wait for its record: observe mode delays nothing.
        let judged_here = carry
            .guards
            .iter()
            .any(|g| settings(g).is_some_and(|e| e.mode == Mode::Enforce));
        if judged_here && !matches!(written.await, Ok(Ok(()))) {
            return Err(Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "Refused: Enterplace could not write the events plugin's check of this answer to its audit log, and it does not pass on what it cannot record. Tell your Enterplace admin.",
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
                    "Refused: the masked answer could not be written, so it was not passed on. Tell your Enterplace admin.",
                )
            })?;
            parts.headers.remove(header::CONTENT_LENGTH);
            Ok(Response::from_parts(parts, Body::from(written)))
        }
        Err(cause) => {
            eprintln!(
                "enterplace: decision {}: an events plugin's mask of the answer could not be written: {cause}",
                context.decision_id
            );
            Err(Refusal::new(
                StatusCode::BAD_GATEWAY,
                guard::BLOCKED_CODE,
                "Refused: an events plugin masked the model's answer, and its mask could not be written, so the answer was not passed on. Tell your Enterplace admin.",
            ))
        }
    }
}

/// Whether a stream's text slot (`crate::event_texts`) is the model's words to the caller: chat content, a messages
/// text block, Responses output text, Gemini text that is not a thought. Tool arguments and thoughts are not.
fn said(slot: &str) -> bool {
    slot.starts_with(['c', 'm', 'r']) || (slot.starts_with('g') && !slot.starts_with("gt"))
}

/// One event of a stream: its bytes as they came, and the JSON of its `data:` line.
struct Piece {
    raw: Vec<u8>,
    json: Option<Value>,
    /// The JSON was rewritten: the bytes that go on are written from it.
    changed: bool,
}

impl Piece {
    fn of(raw: &[u8]) -> Self {
        let json = std::str::from_utf8(raw).ok().and_then(|text| {
            text.lines()
                .find_map(|line| serde_json::from_str(line.strip_prefix("data:")?.trim()).ok())
        });
        Self {
            raw: raw.to_vec(),
            json,
            changed: false,
        }
    }

    /// The event as it goes to the caller: every line as it came, but the data line when its JSON was rewritten.
    fn bytes(&self) -> Vec<u8> {
        let (Some(json), true, Ok(text)) =
            (&self.json, self.changed, std::str::from_utf8(&self.raw))
        else {
            return self.raw.clone();
        };
        let mut out = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            if line.starts_with("data:") {
                let ending = &line[line.trim_end_matches(['\r', '\n']).len()..];
                out.push_str(&format!("data: {json}{ending}"));
            } else {
                out.push_str(line);
            }
        }
        out.into_bytes()
    }

    /// The model's words in this event, by the text each is a part of.
    fn said(&self) -> Vec<(String, &str)> {
        let Some(json) = &self.json else {
            return Vec::new();
        };
        crate::event_texts(json)
            .into_iter()
            .filter(|(slot, _)| said(slot))
            .filter_map(|(slot, pointer)| Some((slot, json.pointer(&pointer)?.as_str()?)))
            .collect()
    }
}

/// The whole events in `bytes`, each ending with its blank line; what follows the last blank line is one more.
fn pieces(bytes: &[u8]) -> Vec<Piece> {
    let (mut out, mut from, mut at) = (Vec::new(), 0, 0);
    while at < bytes.len() {
        let rest = &bytes[at..];
        let step = if rest.starts_with(b"\n\n") {
            2
        } else if rest.starts_with(b"\r\n\r\n") {
            4
        } else {
            at += 1;
            continue;
        };
        at += step;
        out.push(Piece::of(&bytes[from..at]));
        from = at;
    }
    if from < bytes.len() {
        out.push(Piece::of(&bytes[from..]));
    }
    out
}

/// Whether a stream's event starts or carries a tool call, in any of the four APIs.
fn calls_tool(event: &Value) -> bool {
    let list = |v: &Value| v.as_array().cloned().unwrap_or_default();
    let kind = event["type"].as_str().unwrap_or_default();
    list(&event["choices"])
        .iter()
        .any(|c| !list(&c["delta"]["tool_calls"]).is_empty())
        || (kind == "content_block_start"
            && event["content_block"]["type"]
                .as_str()
                .is_some_and(|t| t.ends_with("tool_use")))
        || kind.starts_with("response.function_call_arguments")
        || kind.starts_with("response.custom_tool_call_input")
        || (kind.starts_with("response.output_item")
            && event["item"]["type"]
                .as_str()
                .is_some_and(|t| t.ends_with("_call")))
        || list(&event["candidates"]).iter().any(|c| {
            list(&c["content"]["parts"])
                .iter()
                .any(|p| p.get("functionCall").is_some())
        })
}

/// How a stream's events map to the whole answer `core::stream_answer` makes of them: which tool call of the
/// answer a chat chunk's `index` is, which block a messages event's `index` is, which part a Gemini part became.
#[derive(Default)]
struct Mapping {
    chat_calls: std::collections::BTreeSet<u64>,
    blocks: std::collections::BTreeSet<u64>,
    /// Gemini: the parts so far, as (is text, is a thought): text of one kind in a row is one part of the answer.
    parts: Vec<(bool, bool)>,
}

impl Mapping {
    fn of<'a>(events: impl Iterator<Item = &'a Value>) -> Self {
        let mut mapping = Self::default();
        for event in events {
            for (j, call) in event["choices"][0]["delta"]["tool_calls"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                mapping
                    .chat_calls
                    .insert(call["index"].as_u64().unwrap_or(j as u64));
            }
            if matches!(
                event["type"].as_str(),
                Some("content_block_start" | "content_block_delta")
            ) {
                mapping.blocks.insert(event["index"].as_u64().unwrap_or(0));
            }
        }
        mapping
    }

    /// Where one event of the stream holds a part of the answer: (pointer into the event, pointer into the whole
    /// answer, whether the event holds a piece of a text the deltas build up or the value whole). Called on every
    /// event in order, so the Gemini parts are counted as the answer counts them.
    fn places(&mut self, event: &Value) -> Vec<(String, String, bool)> {
        let mut found = Vec::new();
        let rank = |set: &std::collections::BTreeSet<u64>, n: u64| set.range(..n).count();
        let kind = event["type"].as_str().unwrap_or_default();
        let choice = &event["choices"][0];
        if choice["delta"]["content"].is_string() {
            found.push((
                "/choices/0/delta/content".into(),
                "/choices/0/message/content".into(),
                true,
            ));
        }
        if choice["text"].is_string() {
            found.push(("/choices/0/text".into(), "/choices/0/text".into(), true));
        }
        for (j, call) in choice["delta"]["tool_calls"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            if call["function"]["arguments"].is_string() {
                let k = rank(&self.chat_calls, call["index"].as_u64().unwrap_or(j as u64));
                found.push((
                    format!("/choices/0/delta/tool_calls/{j}/function/arguments"),
                    format!("/choices/0/message/tool_calls/{k}/function/arguments"),
                    true,
                ));
            }
        }
        if kind == "content_block_delta" {
            let block = rank(&self.blocks, event["index"].as_u64().unwrap_or(0));
            if event["delta"]["text"].is_string() {
                found.push(("/delta/text".into(), format!("/content/{block}/text"), true));
            }
            if event["delta"]["partial_json"].is_string() {
                found.push((
                    "/delta/partial_json".into(),
                    format!("/content/{block}/input"),
                    true,
                ));
            }
        }
        // The Responses API: the deltas, and the whole copies its closing events carry.
        let (item, part) = (&event["output_index"], &event["content_index"]);
        match kind {
            "response.output_text.delta" => found.push((
                "/delta".into(),
                format!("/output/{item}/content/{part}/text"),
                true,
            )),
            "response.output_text.done" => found.push((
                "/text".into(),
                format!("/output/{item}/content/{part}/text"),
                false,
            )),
            "response.content_part.done" => found.push((
                "/part".into(),
                format!("/output/{item}/content/{part}"),
                false,
            )),
            "response.function_call_arguments.delta" => {
                found.push(("/delta".into(), format!("/output/{item}/arguments"), true));
            }
            "response.function_call_arguments.done" => found.push((
                "/arguments".into(),
                format!("/output/{item}/arguments"),
                false,
            )),
            "response.output_item.done" => {
                found.push(("/item".into(), format!("/output/{item}"), false));
            }
            "response.completed" | "response.incomplete" => {
                found.push(("/response".into(), String::new(), false));
            }
            _ => {}
        }
        for (j, part) in event["candidates"][0]["content"]["parts"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let text = part["text"].is_string();
            let thought = part["thought"] == true;
            if !(text && self.parts.last() == Some(&(true, thought))) {
                self.parts.push((text, thought));
            }
            let at = self.parts.len() - 1;
            if text {
                found.push((
                    format!("/candidates/0/content/parts/{j}/text"),
                    format!("/candidates/0/content/parts/{at}/text"),
                    true,
                ));
            } else if part.get("functionCall").is_some() {
                found.push((
                    format!("/candidates/0/content/parts/{j}/functionCall/args"),
                    format!("/candidates/0/content/parts/{at}/functionCall/args"),
                    false,
                ));
            }
        }
        found
    }
}

/// A streamed answer on its way: what the caller has, and what still waits for a verdict.
#[derive(Default)]
struct Flow {
    /// The events not yet with the caller, in order.
    queue: Vec<Piece>,
    /// The JSON of each event the caller has.
    released: Vec<Value>,
    /// Each text as the caller has it so far, by its slot.
    out: HashMap<String, String>,
    /// How many characters of the model's words the caller has.
    sent_chars: usize,
    /// Where the window being filled starts in `queue`.
    window_from: usize,
    /// A tool call has started: with hold, nothing more is released until the whole answer is judged.
    calls: bool,
    /// A window was rewritten: whole copies of the text in later events are rewritten to match.
    rewrote: bool,
}

impl Flow {
    /// Writes a masked window: its text whole in the window's first delta, and the other deltas empty.
    fn rewrite_window(&mut self, text: &str) {
        let mut first = true;
        for piece in &mut self.queue[self.window_from..] {
            let Some(json) = &mut piece.json else {
                continue;
            };
            for (slot, pointer) in crate::event_texts(json) {
                if said(&slot)
                    && let Some(slot) = json.pointer_mut(&pointer)
                {
                    *slot = if first { text } else { "" }.into();
                    first = false;
                    piece.changed = true;
                }
            }
        }
        self.rewrote = true;
    }

    /// After a window was rewritten: the whole copies of a text that the Responses API's closing events carry are
    /// written as the caller got the text, so the original never follows its mask.
    fn fix(&mut self) {
        if !self.rewrote {
            return;
        }
        let mut out = self.out.clone();
        for piece in &mut self.queue {
            let said: Vec<(String, String)> = piece
                .said()
                .into_iter()
                .map(|(slot, text)| (slot, text.to_string()))
                .collect();
            for (slot, text) in said {
                out.entry(slot).or_default().push_str(&text);
            }
            let Some(json) = &mut piece.json else {
                continue;
            };
            let kind = json["type"].as_str().unwrap_or_default().to_string();
            let slot = |item: &Value, part: &Value| format!("r{item}.{part}");
            let mut wrote = false;
            let mut put = |target: Option<&mut Value>, slot: String| {
                if let (Some(target), Some(text)) = (target, out.get(&slot))
                    && target.is_string()
                    && target.as_str() != Some(text)
                {
                    *target = text.as_str().into();
                    wrote = true;
                }
            };
            let (item, part) = (json["output_index"].clone(), json["content_index"].clone());
            match kind.as_str() {
                "response.output_text.done" => put(json.get_mut("text"), slot(&item, &part)),
                "response.content_part.done" => {
                    put(json.pointer_mut("/part/text"), slot(&item, &part));
                }
                "response.output_item.done" => {
                    // By pointer: indexing a missing field for writing would add it.
                    for (c, content) in json
                        .pointer_mut("/item/content")
                        .and_then(Value::as_array_mut)
                        .into_iter()
                        .flatten()
                        .enumerate()
                    {
                        put(content.get_mut("text"), slot(&item, &c.into()));
                    }
                }
                "response.completed" | "response.incomplete" => {
                    for (o, output) in json
                        .pointer_mut("/response/output")
                        .and_then(Value::as_array_mut)
                        .into_iter()
                        .flatten()
                        .enumerate()
                    {
                        for (c, content) in output
                            .get_mut("content")
                            .and_then(Value::as_array_mut)
                            .into_iter()
                            .flatten()
                            .enumerate()
                        {
                            put(content.get_mut("text"), slot(&o.into(), &c.into()));
                        }
                    }
                }
                _ => {}
            }
            piece.changed |= wrote;
        }
    }

    /// Every event of the stream so far, as the caller has it or will: for the whole answer to be read from.
    fn all(&mut self) -> Vec<Value> {
        self.fix();
        self.released
            .iter()
            .chain(self.queue.iter().filter_map(|p| p.json.as_ref()))
            .cloned()
            .collect()
    }

    /// Writes a masked answer into the events that wait: `before` is the whole answer as the events make it,
    /// `after` the same with the masks applied. Each text or tool call's arguments that differ go whole into the
    /// first waiting delta that builds them, the later deltas empty, and each whole copy is replaced.
    fn rewrite_answer(&mut self, before: &Value, after: &Value) {
        let mut mapping = Mapping::of(
            self.released
                .iter()
                .chain(self.queue.iter().filter_map(|p| p.json.as_ref())),
        );
        for event in &self.released {
            mapping.places(event);
        }
        let mut started = std::collections::HashSet::new();
        for piece in &mut self.queue {
            let Some(json) = &mut piece.json else {
                continue;
            };
            for (here, there, delta) in mapping.places(json) {
                let (Some(old), Some(new)) = (before.pointer(&there), after.pointer(&there)) else {
                    continue;
                };
                if old == new {
                    continue;
                }
                let Some(slot) = json.pointer_mut(&here) else {
                    continue;
                };
                *slot = match (delta, started.insert(there)) {
                    (false, _) => new.clone(),
                    (true, false) => "".into(),
                    (true, true) => match new {
                        Value::String(text) => text.as_str().into(),
                        other => other.to_string().into(),
                    },
                };
                piece.changed = true;
            }
        }
    }

    /// Sends what waits to the caller. `false` when the caller left.
    async fn release(&mut self, to: &tokio::sync::mpsc::Sender<Bytes>) -> bool {
        self.fix();
        let mut bytes = Vec::new();
        for piece in self.queue.drain(..) {
            bytes.extend_from_slice(&piece.bytes());
            for (slot, text) in piece.said() {
                self.sent_chars += text.chars().count();
                self.out.entry(slot).or_default().push_str(text);
            }
            self.released.extend(piece.json);
        }
        self.window_from = 0;
        bytes.is_empty() || to.send(Bytes::from(bytes)).await.is_ok()
    }
}

/// A streamed answer and its plugins, on every API that streams as server-sent events. With `stream:` its text is
/// shown to them in windows as it comes. With `hold`, a window's bytes wait for its verdict: what a plugin blocks
/// never reaches the caller, what it masks reaches the caller masked, and a tool call waits for the verdict on
/// the whole answer. Without hold the bytes go on at once: a block ends the stream where it lands, and so does a
/// mask, since what was sent cannot be rewritten. When the stream ends, the whole answer is shown as events (the
/// message, its reasoning, its tool calls). A block ends the stream with an error event in the caller's API.
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
        // How far the stream's events are read.
        let mut read = 0usize;
        let mut flow = Flow::default();
        // The model's words as the provider sent them, for the windows.
        let mut text = String::new();
        // Where the window before ended in `text`, and the next window's number.
        let (mut shown, mut window) = (0usize, 0usize);
        let (mut audit, mut entries) = (Vec::new(), Vec::new());
        let mut masked = false;
        // Verdicts of windows that were not held, as they come.
        let (verdict_tx, mut verdicts) = tokio::sync::mpsc::unbounded_channel::<Judged>();
        let mut pending = 0usize;
        let unwritable = || Blocked {
            guardrail: String::new(),
            message: String::new(),
        };
        // What was already sent cannot be rewritten: a mask of it stops the stream as a block does.
        let stop = |judged: &Judged| {
            judged
                .blocked
                .clone()
                .or_else(|| (!judged.masks.is_empty()).then(unwritable))
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
            for piece in pieces(&seen[read..end]) {
                for (_, said) in piece.said() {
                    text.push_str(said);
                }
                flow.calls |= piece.json.as_ref().is_some_and(calls_tool);
                flow.queue.push(piece);
            }
            read = end;
            if !hold && !flow.release(&tx).await {
                // The caller left: the provider's stream is dropped with the body.
                return;
            }
            let fresh = text[shown..].chars().count();
            // Held, what is left at the end is the last window, so it can be masked like the ones before it. An
            // answer shorter than one window is judged whole, below.
            let due = match every {
                Some(every) if !done => fresh >= every,
                Some(_) => hold && window > 0 && fresh > 0,
                None => false,
            };
            if due {
                let event = Event {
                    partial: true,
                    window: Some(window),
                    held: hold,
                    ..Event::text(Kind::AssistantMessage, &text[shown..])
                }
                .placed(&context.turn_id, carry.next_index);
                window += 1;
                if hold {
                    let judged = judge(
                        &state,
                        &windowed,
                        context,
                        "stream",
                        std::slice::from_ref(&event),
                        None,
                        "the model's answer",
                    )
                    .await;
                    audit.extend(judged.audit);
                    entries.extend(judged.entries);
                    if judged.blocked.is_some() {
                        break judged.blocked;
                    }
                    // Each plugin saw the window as the one before it masked it: the last mask is the text.
                    if let Some(mask) = judged.masks.iter().rev().find_map(|m| m.content.as_deref())
                    {
                        flow.rewrite_window(mask);
                        masked = true;
                    }
                    flow.window_from = flow.queue.len();
                    // A tool call waits for the end, where the whole answer is judged.
                    if !flow.calls && !flow.release(&tx).await {
                        return;
                    }
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
                shown = text.len();
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
                // The whole answer, as the caller has it or will: a masked window is in it as its mask.
                let answer = core::stream_answer(&flow.all());
                let mut whole = core::answer_events(&answer, &context.turn_id, carry.next_index);
                // What still waits whole can be masked: a tool call, and a message none of which was sent.
                let messages = whole
                    .iter()
                    .filter(|e| e.kind == Kind::AssistantMessage)
                    .count();
                for event in &mut whole {
                    event.held = hold
                        && match event.kind {
                            Kind::ToolCall => true,
                            Kind::AssistantMessage => flow.sent_chars == 0 && messages == 1,
                            _ => false,
                        };
                }
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
                audit.extend(judged.audit);
                entries.extend(judged.entries);
                if judged.blocked.is_some() {
                    break judged.blocked;
                }
                if !judged.masks.is_empty() {
                    let waits = judged
                        .masks
                        .iter()
                        .all(|m| whole.iter().any(|e| e.event_index == m.event && e.held));
                    let mut after = answer.clone();
                    if !waits || core::apply_masks(&mut after, &whole, &judged.masks).is_err() {
                        break Some(unwritable());
                    }
                    flow.rewrite_answer(&answer, &after);
                    masked = true;
                }
                let _ = flow.release(&tx).await;
                break None;
            }
        };
        if let Some(log) = &state.audit {
            let word = match (&blocked, masked) {
                (Some(_), _) => "block",
                (None, true) => "mask",
                (None, false) => "pass",
            };
            let mut record = answer_record(context, word, &audit, &entries);
            if blocked.is_some() {
                record.insert(
                    "stopped_after_chars".into(),
                    if hold {
                        flow.sent_chars
                    } else {
                        text[..shown.min(text.len())].chars().count()
                    }
                    .into(),
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
            let message = if blocked.guardrail.is_empty() {
                format!(
                    "Refused: {name} would rewrite a part of the model's answer that was already sent, and what was sent cannot be rewritten, so the answer ends here. Ask in another way, or ask an Enterplace admin about the guardrail: with stream.hold it masks each window before it is sent."
                )
            } else if hold {
                format!(
                    "Refused: {name} stopped the model's answer partway. What came before was checked and sent; the rest was withheld. Ask in another way, or ask an Enterplace admin about the guardrail."
                )
            } else {
                format!(
                    "Refused: {name} stopped the model's answer. What came before it was already sent. Ask in another way, or ask an Enterplace admin about the guardrail."
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
// Batches and jobs
// ---------------------------------------------------------------------------------------------------------

/// Whose batch a line is of, and which line: what its events' ids follow from, at the upload and again when its
/// result is read, with nothing kept between the two.
pub(crate) struct Line<'a> {
    pub person: &'a str,
    pub team: &'a str,
    pub org: &'a str,
    /// The decision the batch's lines were checked under: the batch is the session.
    pub checked: &'a str,
    /// The line's `custom_id`: the line is the turn.
    pub custom_id: &'a str,
    /// The decision of this call.
    pub decision: &'a str,
    pub route: &'a str,
    pub model: &'a str,
}

impl Line<'_> {
    fn context(&self) -> Context {
        let markers = Markers {
            enterplace_session: Some(format!("batch {}", self.checked)),
            ..Markers::default()
        };
        let (session, _) = core::session_id(self.person, "", &markers, &Value::Null, "");
        Context {
            turn_id: core::turn_id(&session, 0, "", Some(self.custom_id)),
            session_id: session,
            turn_index: 0,
            decision_id: self.decision.to_string(),
            person: self.person.to_string(),
            team: self.team.to_string(),
            org: self.org.to_string(),
            model: self.model.to_string(),
            route: self.route.to_string(),
            ..Context::default()
        }
    }
}

/// What the plugins made of one line of a batch, or of one line of its results.
#[derive(Default)]
pub(crate) struct Lined {
    /// Why the line is refused: a block, a session a plugin ended, a mask that could not be written.
    pub refused: Option<(&'static str, String)>,
    pub audit: Vec<AuditEntry>,
    pub entries: Vec<Value>,
    /// The plugins masked `body`.
    pub changed: bool,
}

/// Shows one line of a batch (or a job's request: a video's prompt) to the plugins before it is uploaded, as the
/// request of its turn. An enforcing plugin may refuse it or mask it: `body` is then the masked line.
pub(crate) async fn batch_line(
    state: &AppState,
    guards: &[Guardrail],
    line: &Line<'_>,
    body: &mut Value,
) -> Lined {
    let context = line.context();
    let mut out = Lined::default();
    if guards.iter().any(enforcing)
        && let Some(by) = ended_by(state, &context.session_id)
    {
        out.entries
            .push(json!({"guardrail": by, "action": "session_ended"}));
        out.refused = Some((core::SESSION_ENDED, session_ended(&by).message));
        return out;
    }
    let placed = core::conversation(body).placed(&context.session_id, Some(line.custom_id));
    let judged = judge(
        state,
        guards,
        &context,
        "batch",
        &placed.new,
        Some(&placed.history),
        "this line",
    )
    .await;
    lined(judged, body, &placed.new)
}

/// Shows the answer in one line of a batch's results to the plugins before the caller reads it, in the line's
/// turn. Its events count from 0 again: the line's request is not at hand to count on from.
pub(crate) async fn batch_result(
    state: &AppState,
    guards: &[Guardrail],
    line: &Line<'_>,
    answer: &mut Value,
) -> Lined {
    let context = line.context();
    let events = core::answer_events(answer, &context.turn_id, 0);
    let judged = judge(
        state,
        guards,
        &context,
        "batch_result",
        &events,
        None,
        "the model's answer",
    )
    .await;
    lined(judged, answer, &events)
}

fn lined(judged: Judged, body: &mut Value, events: &[Event]) -> Lined {
    let mut out = Lined {
        audit: judged.audit,
        entries: judged.entries,
        ..Lined::default()
    };
    if let Some(blocked) = judged.blocked {
        out.refused = Some((guard::BLOCKED_CODE, format!("Refused: {}", blocked.message)));
    } else if !judged.masks.is_empty() {
        match core::apply_masks(body, events, &judged.masks) {
            Ok(changed) => out.changed = changed,
            // Never pass on the unmasked line because the masked one could not be written.
            Err(_) => {
                out.refused = Some((
                    guard::BLOCKED_CODE,
                    "Refused: an events plugin masked it, and its mask could not be written, so it was not passed on. Tell your Enterplace admin.".into(),
                ));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------
// MCP and realtime
// ---------------------------------------------------------------------------------------------------------

/// The context of events that come from somewhere other than a model request: an MCP tool call, a realtime session.
/// The session is the caller's (`x-enterplace-session`, `x-session-id`, or what `fallback` names: the MCP session, the
/// realtime connection), and the turn is `x-enterplace-turn` when the caller links the call to a model turn, else the
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
    if markers.enterplace_session.is_none() && markers.session.is_none() {
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
pub(crate) fn refused_session(
    state: &AppState,
    guards: &[Guardrail],
    context: &Context,
) -> Option<Refusal> {
    if !guards.iter().any(enforcing) {
        return None;
    }
    let by = ended_by(state, &context.session_id)?;
    Some(session_ended(&by))
}

fn session_ended(by: &str) -> Refusal {
    Refusal::new(
        StatusCode::FORBIDDEN,
        core::SESSION_ENDED,
        format!(
            "Refused: guardrail \"{by}\" ended this session, so its requests are refused for a while. Start a new conversation, or ask an Enterplace admin about the guardrail."
        ),
    )
}
