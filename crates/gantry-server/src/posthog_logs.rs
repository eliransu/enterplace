//! A dedicated PostHog OTLP log exporter.
//!
//! This deliberately has no connection to Gantry's existing audit output or
//! stderr diagnostics: only the lifecycle records emitted in this module's
//! callers are sent to PostHog Logs.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    http::{Request, header},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde_json::{Value, json};

static LOGGER: OnceLock<Arc<Logger>> = OnceLock::new();
const BATCH: usize = 100;

struct Logger {
    endpoint: String,
    authorization: String,
    records: Mutex<Vec<Value>>,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Starts the dedicated exporter when PostHog configuration is present.
///
/// The sender runs in the background so a slow ingestion host never delays
/// the gateway from accepting requests.
pub(crate) async fn init() {
    if LOGGER.get().is_some() {
        return;
    }

    let token = std::env::var("POSTHOG_PROJECT_TOKEN").unwrap_or_default();
    let host = std::env::var("POSTHOG_HOST").unwrap_or_default();
    for (name, value) in [
        ("POSTHOG_PROJECT_TOKEN", token.trim()),
        ("POSTHOG_HOST", host.trim()),
    ] {
        if value.is_empty() {
            if cfg!(debug_assertions) {
                eprintln!(
                    "{name} variable required by PostHog is missing or un-configured, this causes events to be silently missed. This error stops appearing once {name} is configured"
                );
            }
            return;
        }
    }

    let logger = Arc::new(Logger {
        endpoint: format!("{}/i/v1/logs", host.trim_end_matches('/')),
        authorization: format!("Bearer {token}"),
        records: Mutex::default(),
    });
    if LOGGER.set(logger.clone()).is_ok() {
        tokio::spawn(logger.run());
    }
}

/// Adds an INFO record to this exporter only. Existing Gantry loggers and audit
/// records intentionally remain outside the PostHog Logs stream.
pub(crate) fn info(message: &'static str) {
    let Some(logger) = LOGGER.get() else {
        return;
    };
    let mut records = locked(&logger.records);
    if records.len() < BATCH {
        records.push(json!({
            "timeUnixNano": now_ns().to_string(),
            "severityNumber": 9,
            "severityText": "INFO",
            "body": { "stringValue": message },
        }));
    }
}

/// Sends all queued records during graceful server shutdown.
pub(crate) async fn shutdown() {
    let Some(logger) = LOGGER.get() else {
        return;
    };
    while let Some(records) = logger.take() {
        if logger.send(records).await.is_err() {
            break;
        }
    }
}

impl Logger {
    async fn run(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            while let Some(records) = self.take() {
                if self.send(records).await.is_err() {
                    break;
                }
            }
        }
    }

    fn take(&self) -> Option<Vec<Value>> {
        let mut records = locked(&self.records);
        (!records.is_empty()).then(|| records.drain(..records.len().min(BATCH)).collect())
    }

    async fn send(&self, records: Vec<Value>) -> Result<(), String> {
        let client = client();
        let body = json!({ "resourceLogs": [{
            "resource": { "attributes": [{
                "key": "service.name",
                "value": { "stringValue": "gantry" },
            }] },
            "scopeLogs": [{
                "scope": { "name": "gantry.posthog" },
                "logRecords": records,
            }],
        }]});
        let request = Request::post(&self.endpoint)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, &self.authorization)
            .body(Body::from(body.to_string()))
            .map_err(|error| error.to_string())?;
        let response = tokio::time::timeout(Duration::from_secs(5), client.request(request))
            .await
            .map_err(|_| "no answer in 5 seconds".to_string())?
            .map_err(|error| error.to_string())?;
        response
            .status()
            .is_success()
            .then_some(())
            .ok_or_else(|| format!("it answered {}", response.status()))
    }
}

fn client() -> Client<HttpsConnector<HttpConnector>, Body> {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    connector.enforce_http(false);
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);
    Client::builder(TokioExecutor::new()).build(connector)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
}
