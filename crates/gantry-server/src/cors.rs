//! `cors:` in the policy: browser pages on the listed origins (the Claude add-in for Office, an Open WebUI direct
//! connection) may call the gateway's routes. Off by default. The preflight is answered here; the call itself is
//! governed and recorded as any other, and its answer names the origin. Credentials are never allowed: callers
//! authenticate with a key in a header, and the console's cookie must never be usable from another origin. The
//! console is nested outside this layer, and the admin API is skipped, so neither answers another origin.

use axum::{
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::AppState;

/// Every method a route of Gantry answers.
const METHODS: HeaderValue = HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE");
/// The answer headers a page may read: the decision ID above all, to quote it to an admin.
const EXPOSE: HeaderValue = HeaderValue::from_static(
    "x-gantry-decision, x-gantry-cache, x-gantry-note, x-gantry-provider, x-gantry-policy-source",
);
/// How long a browser may keep a preflight's answer.
const MAX_AGE: HeaderValue = HeaderValue::from_static("600");

pub(crate) async fn layer(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let allowed = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|_| !request.uri().path().starts_with("/admin"))
        .and_then(|origin| {
            let version = state.version();
            let allow = version.policy.as_ref()?.cors()?.allow(origin)?;
            HeaderValue::from_str(allow).ok()
        });
    let Some(allowed) = allowed else {
        return next.run(request).await;
    };
    if request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
    {
        // A preflight carries no key and asks for nothing: answered here, not recorded.
        let asked = request
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .cloned();
        let mut response = StatusCode::NO_CONTENT.into_response();
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allowed);
        headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, METHODS);
        if let Some(asked) = asked {
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, asked);
        }
        headers.insert(header::ACCESS_CONTROL_MAX_AGE, MAX_AGE);
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        return response;
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allowed);
    headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, EXPOSE);
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    response
}
