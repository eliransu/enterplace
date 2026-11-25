//! Identity from an authenticating proxy (oauth2-proxy, an ingress with OIDC, Cloudflare Access behind a tunnel,
//! an AWS ALB): behind a proxy the policy lists in `trusted_proxies`, the headers `identity_headers:` names say who
//! the caller is. On the model routes a request without a Enterplace key is then that person's; in the console they are
//! signed in with the role their groups give them. Groups map to roles and teams through `sso_values`, as single
//! sign-on's do.
//!
//! The headers are read only on a connection whose peer address is a trusted proxy. Anyone else can write a header,
//! so from anywhere else they are ignored, and a header sent twice is refused: a proxy that appended its value to a
//! caller's instead of replacing it must not let the caller's through.

use std::net::IpAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use enterplace_console::{Admin, Via};
use enterplace_core::policy::{IdentityHeaders, JwtIdentity, Policy, Principal, team_of};
use enterplace_server::{IDENTITY_HEADERS, Identify, PolicyNow};

pub const FEATURE: &str = "auth_proxy";

/// Who the headers name: the person, and their groups.
struct Named {
    user: String,
    groups: Vec<String>,
}

/// What the configured headers say. `None`: the user header is absent. `Err`: it is there and cannot be taken.
fn named(setting: &IdentityHeaders, headers: &HeaderMap) -> Option<Result<Named, String>> {
    let one = |name: &str| -> Option<Result<String, String>> {
        let mut values = headers.get_all(name).iter();
        let first = values.next()?;
        if values.next().is_some() {
            return Some(Err(format!(
                "the {name} header arrived more than once, so one of its values did not come from the proxy. Make the proxy replace the header a caller sends, not add to it."
            )));
        }
        Some(
            first
                .to_str()
                .map(|v| v.trim().to_string())
                .map_err(|_| format!("the {name} header is not text")),
        )
    };
    let user = match one(&setting.user)? {
        Ok(user) => user.to_lowercase(),
        Err(why) => return Some(Err(why)),
    };
    if !enterplace_core::config::valid_name(&user) {
        return Some(Err(format!(
            "the {} header does not hold a name Enterplace takes (letters, digits, dots, dashes, underscores and @, at most 100 characters). Make the proxy send the person's email or user name in it.",
            setting.user
        )));
    }
    let groups = match setting.groups.as_deref().and_then(one) {
        None => Vec::new(),
        Some(Err(why)) => return Some(Err(why)),
        Some(Ok(groups)) => groups
            .split(',')
            .map(|g| g.trim().to_string())
            .filter(|g| !g.is_empty())
            .collect(),
    };
    Some(Ok(Named { user, groups }))
}

struct ModelRoutes;

impl Identify for ModelRoutes {
    fn identify(
        &self,
        policy: &Policy,
        headers: &HeaderMap,
    ) -> Option<Result<Principal, (&'static str, String)>> {
        let setting = policy.identity_headers()?;
        let refused = |why: String| ("identity_invalid", format!("Refused: {why}"));
        let named = match named(setting, headers)? {
            Ok(named) => named,
            Err(why) => return Some(Err(refused(why))),
        };
        let groups: Vec<&str> = named.groups.iter().map(String::as_str).collect();
        let team = team_of(policy.teams(), &named.user, &groups)
            .map(|team| team.name.clone())
            .or_else(|| setting.team.clone());
        let Some(team) = team else {
            return Some(Err(refused(format!(
                "{} is in no team: the policy's teams list neither the name nor any of its groups under members or sso_values, and identity_headers sets no team. Ask a Enterplace admin to add one.",
                named.user
            ))));
        };
        Some(Ok(Principal {
            // Records and per-key counters name the person the way they name a key: by 8 hex characters.
            key: enterplace_core::id::sha256_hex(
                format!("{IDENTITY_HEADERS}\n{}", named.user).as_bytes(),
            )[..8]
                .to_string(),
            jwt: Some(JwtIdentity {
                issuer: IDENTITY_HEADERS.to_string(),
                subject: named.user.clone(),
            }),
            name: named.user,
            team,
            ..Principal::default()
        }))
    }
}

/// The console admin a request's headers name, when it came through a trusted proxy and the person's groups give
/// them a role: the first of the policy's roles whose `sso_values` holds one of them. No role, no console.
fn console_admin(policy: &Policy, headers: &HeaderMap, peer: Option<IpAddr>) -> Option<Admin> {
    let setting = policy.identity_headers()?;
    if !peer.is_some_and(|peer| policy.trusted_proxy(peer)) {
        return None;
    }
    let named = named(setting, headers)?.ok()?;
    let has = |values: &[String]| values.iter().any(|v| named.groups.contains(v));
    let role = policy.roles().iter().find(|role| has(&role.sso_values))?;
    let groups: Vec<&str> = named.groups.iter().map(String::as_str).collect();
    let team = team_of(policy.teams(), &named.user, &groups).map_or("", |team| team.name.as_str());
    Some(Admin::with_role(&named.user, team, role, Via::Sso))
}

/// Turns the policy's `identity_headers:` on, for the model routes and the console.
pub fn register(extension: &mut enterplace_server::Extension, policy: PolicyNow) {
    extension.identity = Some(Arc::new(ModelRoutes));
    extension.console.proxy_admin = Some(Arc::new(move |headers, peer| {
        policy
            .with(|policy| console_admin(policy, headers, peer))
            .flatten()
    }));
}

#[cfg(test)]
mod tests;
