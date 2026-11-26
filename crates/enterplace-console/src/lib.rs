//! The admin console: server-rendered pages the server mounts at `/console`.
//!
//! An admin signs in with an Enterplace key whose keys file entry says `admin: true`, or through the identity provider the
//! policy file names under `console.sso`. The browser gets a random session ID, never the key or a token. Every page
//! reads the policy, keys and audit files when it is asked for.

mod analytics;
mod api;
mod audit_log;
mod callers;
pub mod cli;
mod credentials;
mod edit;
mod figures;
pub mod html;
mod insights;
mod pages;
mod people;
mod prices;
mod raw_policy;
mod requests;
mod saml;
mod spend;
mod sso;
mod start;
mod teams;
pub mod tested;
pub use api::{Answer, Fail, answer, bad, body_of, ok, signed_in, text};
pub use start::{empty_json, empty_page, origin as gateway_origin, task_prompt};
pub mod tls;

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use enterplace_core::{
    audit::{self, AuditLog},
    config, id, keyfile,
    policy::{Permission, Role, builtin_role},
};
use serde_json::{Map, Value, json};

/// The names of the client certificate a connection presented and Enterplace verified (`tls: { client_ca_file }`): its
/// subject common name and subject alternative names. The server puts it on each request of that connection.
#[derive(Clone, Debug)]
pub struct ClientCert(pub Arc<Vec<String>>);

impl ClientCert {
    /// Whether the certificate carries `name`, the `cert:` a key is bound to.
    pub fn is(&self, name: &str) -> bool {
        self.0.iter().any(|n| n == name)
    }
}

/// The files the console reads and the keys file it writes.
#[derive(Clone, Debug)]
pub struct ConsoleConfig {
    pub policy: PathBuf,
    pub keys: PathBuf,
    pub audit: PathBuf,
    /// The server's open audit log, where sign-ins, issues and revocations are recorded in the same chain as
    /// requests. `None` refuses every action: the console does not act on what it cannot record.
    pub log: Option<Arc<AuditLog>>,
}

const COOKIE: &str = "enterplace_console";
/// Where a signed-in person lands: Start here, the console home.
pub const HOME: &str = "/console/start";
const SESSION: Duration = Duration::from_secs(8 * 60 * 60);

const SSO_COOKIE: &str = "enterplace_sso";
/// Set beside `enterplace_sso` when the sign-in was started by `enterplace login`: where to hand the code, sealed to that
/// sign-in's state.
const CLI_COOKIE: &str = "enterplace_cli";
/// How long `enterplace login` has to trade its code for the key.
const CLI_CODE: Duration = Duration::from_secs(2 * 60);
/// Most codes waiting to be traded at once.
const MAX_CODES: usize = 1000;
/// How long a person has to finish signing in at the identity provider.
const SSO_PENDING: Duration = Duration::from_secs(10 * 60);
/// Most finished sign-ins remembered to refuse a second use of their state. A full list forgets the one that expires
/// first; the provider's code is one use too, so a replay of a forgotten state still fails there.
const MAX_USED: usize = 10_000;
/// Failed sign-ins from one source address, or to one account, within [`SignInLimit::window`] that lock it out, and
/// for how long: within what PCI DSS 8.3.4 asks (at most 10 attempts, at least 30 minutes).
// ponytail: fixed. A policy setting (console: { lockout: ... }) when someone's rules ask for other numbers.
const SIGN_IN_LIMIT: enterplace_core::store::SignInLimit = enterplace_core::store::SignInLimit {
    max: 5,
    window: Duration::from_secs(15 * 60),
    lock: Duration::from_secs(30 * 60),
};

/// Sign-ins started within one minute that make the console write one record about it, at most once a minute.
const FLOOD: u64 = 100;

#[derive(Clone)]
enum Who {
    /// Signed in with an admin key, by its hash.
    Key(String),
    /// Signed in through single sign-on (OpenID Connect or SAML), with the role the identity provider's claim gave:
    /// `admin`, `read_only` or a role from the policy's `roles:`; and the team `teams:` put them in, or "".
    Sso {
        email: String,
        role: String,
        team: String,
    },
    /// Signed in to an account an [`Extension`] keeps, by its ID. The extension says who it is on every request.
    Account(String),
}

/// Says who the account a session was opened for is now. `None` ends the session: the account was removed, or may
/// no longer sign in. Asked on every request, so a change takes effect at once on every gateway.
pub type Accounts =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Option<Admin>> + Send>> + Send + Sync>;

/// Says who a console request with no session is from its headers and the address the connection came from (the
/// proxy's), or `None` for no one. The extension must answer only for an address it trusts: anyone can write a
/// header. Asked on every such request, so a change at the proxy or in the policy applies at once.
pub type ProxyAdmin = Arc<dyn Fn(&HeaderMap, Option<IpAddr>) -> Option<Admin> + Send + Sync>;

/// What a binary that embeds the console adds to it: pages beside the built-in ones with their nav entries, another
/// way to sign in, and the accounts that way signs in. Its handlers take `State<Console>` and use
/// [`Console::signed_in`], [`Console::page`] and [`Console::audit`], so they share the console's sessions, look and
/// audit records.
#[derive(Clone, Default)]
pub struct Extension {
    /// Nav entries after the built-in ones, as (path, label). A page passes its label as `current` to be marked.
    pub nav: Vec<(String, String)>,
    /// Routes nested at /console beside the built-in ones. A path the console already serves panics at start.
    pub routes: Router<Console>,
    /// A link under the sign-in form, as (path, label), to the extension's own way in.
    pub sign_in: Option<(String, String)>,
    /// Answers for sessions opened with [`Console::sign_in_account`].
    pub accounts: Option<Accounts>,
    /// Names who a request with no session is, from what an authenticating proxy put on it.
    pub proxy_admin: Option<ProxyAdmin>,
    /// Watch mode, when the binary has it licensed and its store answers: Start here makes watch tokens with it.
    pub watch: Option<Watch>,
}

/// A future an extension hook answers with.
pub type Boxed<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// What Start here asks of watch mode. Both are the binary's own flows, checked and recorded as its API does.
#[derive(Clone)]
pub struct Watch {
    /// Makes a watch token for a team, for the person signed in. `Ok` is the token, shown once.
    #[allow(clippy::type_complexity)]
    pub token: Arc<dyn Fn(Console, Admin, String) -> Boxed<Result<String, String>> + Send + Sync>,
    /// How many watch tokens the person can see.
    pub tokens: Arc<dyn Fn(Admin) -> Boxed<Result<usize, String>> + Send + Sync>,
}

impl std::fmt::Debug for Extension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extension")
            .field("nav", &self.nav)
            .field("sign_in", &self.sign_in)
            .field("accounts", &self.accounts.is_some())
            .field("watch", &self.watch.is_some())
            .finish_non_exhaustive()
    }
}

struct Session {
    who: Who,
    expires: Instant,
}

/// Who a session is for, as the store keeps it.
fn who_text(who: &Who) -> String {
    match who {
        Who::Key(sha) => format!("key {sha}"),
        // `read` is how sessions opened before custom roles name the read-only role.
        Who::Sso { email, role, team } => {
            let role = if role == "read_only" { "read" } else { role };
            if team.is_empty() {
                format!("sso {role} {email}")
            } else {
                format!("sso {role} {email} {team}")
            }
        }
        Who::Account(account) => format!("account {account}"),
    }
}

fn who_of(text: &str) -> Option<Who> {
    let (kind, rest) = text.split_once(' ')?;
    Some(match kind {
        "key" => Who::Key(rest.to_string()),
        "sso" => {
            let (role, rest) = rest.split_once(' ')?;
            // Sessions opened before teams have no team after the email.
            let (email, team) = rest.split_once(' ').unwrap_or((rest, ""));
            Who::Sso {
                email: email.to_string(),
                role: if role == "read" { "read_only" } else { role }.to_string(),
                team: team.to_string(),
            }
        }
        "account" => Who::Account(rest.to_string()),
        _ => return None,
    })
}

/// The outcome of the last "Verify chain now", and when it ran.
type Verified = (Instant, Result<(u64, String), String>);

/// One scope's failed sign-ins: how many, since when, and until when it is locked out.
type Failures = (u32, Instant, Option<Instant>);

struct Inner {
    config: ConsoleConfig,
    /// Sessions without a store. With one (`store:` in the policy), sessions are rows in it, so a sign-in is good on
    /// every gateway and a sign-out ends it on all at once; a restart then signs no one out.
    sessions: Mutex<HashMap<String, Session>>,
    /// Seals the state cookie of a started sign-in and derives its nonce and PKCE verifier, so starting a sign-in
    /// keeps nothing on the server and a flood of starts fills nothing. None when the system gave no randomness.
    // ponytail: one key per process, so a restart ends sign-ins in progress and the callback must reach the node
    // that started it. A shared key comes with more than one node.
    seal: Option<ring::hmac::Key>,
    /// States of sign-ins that finished, until they expire, so each is used once. Only a state whose ID token
    /// verified is kept: anyone can start and fail a sign-in, so a list of refused ones could be flushed by a flood.
    used: Mutex<HashMap<String, Instant>>,
    /// The minute sign-in starts are counted in, and how many so far.
    starts: Mutex<(Instant, u64)>,
    /// Refused sign-ins per client address in its current minute, recorded one by one only up to [`FLOOD`] a
    /// minute per address, so one flooding address hides nobody else's refusals (QA12-3).
    refusals: Mutex<HashMap<String, Refusals>>,
    /// Discovery and keys of the identity provider, refetched after `sso::CACHE`.
    provider: Mutex<Option<Arc<sso::Provider>>>,
    client: sso::HttpClient,
    /// The last check of each chain: `""` the install's, else the organization's.
    verified: Mutex<std::collections::HashMap<String, Verified>>,
    /// Codes handed to `enterplace login` and not traded yet, by code.
    codes: Mutex<HashMap<String, Pending>>,
    /// The one-time setup link's token, and whether it was used.
    setup: Mutex<Option<(String, bool)>>,
    /// Each signed-in person's own person token, made for them this run, by name. The keys file keeps only its hash;
    /// kept here so Start here can put it in the lines its owner copies. Lost on restart, when they make a new one.
    mine: Mutex<HashMap<String, String>>,
    accounts: Option<Accounts>,
    watch: Option<Watch>,
    proxy_admin: Option<ProxyAdmin>,
    /// Failed sign-ins per scope without a store: how many, since when, and until when the scope is locked out.
    /// With a store they are rows in it, so every gateway counts and refuses together.
    failures: Mutex<HashMap<String, Failures>>,
    /// Nav entries and the sign-in link an extension added, set on every request for the pages to draw.
    extra: Arc<html::Extra>,
}

/// A person who signed in for `enterplace login`, until their CLI trades the code for a key.
struct Pending {
    email: String,
    team: String,
    days: u32,
    /// The PKCE challenge the CLI started with: only the CLI that holds its verifier gets the key.
    challenge: String,
    expires: Instant,
}

/// Where a `enterplace login` sign-in hands its code: the CLI's port on 127.0.0.1, its state and its PKCE challenge.
struct CliStart {
    port: u16,
    state: String,
    challenge: String,
}

/// The console's state, which an [`Extension`]'s handlers take as `State<Console>`.
#[derive(Clone)]
pub struct Console(Arc<Inner>);

/// One client address's refused sign-ins in its minute.
struct Refusals {
    since: tokio::time::Instant,
    count: u64,
    codes: BTreeMap<&'static str, u64>,
}

tokio::task_local! {
    /// The address of the client whose request is being handled, for its records (MIN-8).
    static CLIENT: Option<IpAddr>;
}

/// Runs a console request with its client's address and the extension's nav at hand. The server puts the peer
/// address on each request.
async fn with_client(
    State(console): State<Console>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let client = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let extra = console.0.extra.clone();
    let tls: Tls = request
        .extensions()
        .get::<axum::http::uri::Scheme>()
        .cloned()
        .map(axum::Extension);
    let base = start::origin(request.headers(), request.uri(), &tls);
    // Pages only: the policy is read again for each one, as the role check already does, so a change shows at once.
    let path = request.uri().path();
    let observe = request.method() == axum::http::Method::GET
        && !path.starts_with("/console/assets/")
        && !path.ends_with(".json")
        && config::load(&console.config().policy, Some(&console.config().keys))
            .is_ok_and(|l| l.policy.mode() == enterplace_core::policy::Mode::Observe);
    CLIENT
        .scope(
            client,
            BASE.scope(
                base,
                html::EXTRA.scope(extra, html::OBSERVE.scope(observe, next.run(request))),
            ),
        )
        .await
}

tokio::task_local! {
    /// The gateway's address as the browser reached it, for the lines a page gives to paste.
    static BASE: String;
}

/// The gateway's address as the browser of this request reached it, for an extension's pages.
pub fn request_base() -> String {
    base()
}

/// The gateway's address as the browser of this request reached it.
pub(crate) fn base() -> String {
    BASE.try_with(Clone::clone)
        .unwrap_or_else(|_| "http://127.0.0.1:8080".into())
}

fn client() -> Option<IpAddr> {
    CLIENT.try_with(|c| *c).ok().flatten()
}

/// The address refusals are counted under. An IPv6 client is counted by its /64, which one host usually holds whole.
fn flood_key(client: Option<IpAddr>) -> String {
    match client {
        Some(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Some(IpAddr::V6(v6)) => v6
            .to_ipv4_mapped()
            .map_or_else(String::new, |v4| v4.to_string()),
        Some(IpAddr::V4(v4)) => v4.to_string(),
        None => "unknown".into(),
    }
}

/// Who a console request is signed in as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admin {
    pub name: String,
    /// Empty for a person signed in through single sign-on: the identity provider gives no Enterplace team.
    pub team: String,
    /// May look but not issue or revoke keys.
    pub read_only: bool,
    /// The role the pages show under the name.
    pub role: String,
    pub via: Via,
    /// What the person may do. Each page and action checks the one it needs.
    pub permissions: Vec<Permission>,
    /// The organization whose keys, records and spend alone the person sees, when the role keeps them to one.
    pub org: Option<String>,
    /// The teams whose keys, records and spend alone the person sees, when the role keeps them to some.
    pub teams: Vec<String>,
    /// The end customers whose keys, records and spend alone the person sees, when the role keeps them to some.
    pub customers: Vec<String>,
}

/// How a person signed in to the console.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Via {
    /// An admin key.
    Key,
    /// Single sign-on.
    Sso,
    /// An account an [`Extension`] keeps, by its ID.
    Account(String),
}

impl Admin {
    /// Someone with a role of the policy (or a built-in one), as single sign-on signs them in: for an extension
    /// that maps people to roles itself.
    pub fn with_role(name: &str, team: &str, role: &Role, via: Via) -> Admin {
        admin_of(name.to_string(), team.to_string(), role, via)
    }

    /// An admin of everything, or a read-only viewer of everything, as before roles: for extensions and tests.
    pub fn of_role(name: &str, team: &str, read_only: bool, via: Via) -> Admin {
        let role = builtin_role(if read_only { "read_only" } else { "admin" });
        Admin {
            name: name.to_string(),
            team: team.to_string(),
            read_only,
            role: sso_role(read_only),
            via,
            permissions: role.map(|r| r.permissions).unwrap_or_default(),
            org: None,
            teams: Vec::new(),
            customers: Vec::new(),
        }
    }

    /// Whether the person is kept to part of the install: an organization, teams or customers.
    pub fn confined(&self) -> bool {
        self.org.is_some() || !self.teams.is_empty() || !self.customers.is_empty()
    }

    /// Whether a key of this organization, team and end customer is one the person may see and act on.
    pub fn covers(&self, org: &str, team: &str, customer: Option<&str>) -> bool {
        self.org.as_ref().is_none_or(|o| o == org)
            && (self.teams.is_empty() || self.teams.iter().any(|t| t == team))
            && (self.customers.is_empty()
                || customer.is_some_and(|c| self.customers.iter().any(|x| x == c)))
    }

    /// Whether a key file entry is within the person's reach.
    pub fn covers_entry(&self, entry: &config::KeyEntry) -> bool {
        self.covers(&entry.org, &entry.team, entry.customer.as_deref())
    }

    /// Whether the person holds `permission`.
    pub fn may(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Whether a record (an audit log line) is one this person may see: every record for someone not kept to part
    /// of the install, else only those of their organization, teams and customers.
    pub fn sees(&self, line: &str) -> bool {
        if !self.confined() {
            return true;
        }
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            return false;
        };
        let field = |name: &str| record.get(name).and_then(Value::as_str);
        self.covers(
            field("org").unwrap_or_default(),
            field("team").unwrap_or_default(),
            field("customer"),
        )
    }

    /// How the pages show who is signed in.
    fn label(&self) -> String {
        format!("{}, {}", self.name, self.role)
    }
}

fn sso_role(read_only: bool) -> String {
    if read_only { "read only" } else { "admin" }.to_string()
}

/// The person a role signs in, with the role's permissions and organization.
fn admin_of(name: String, team: String, role: &Role, via: Via) -> Admin {
    let read_only = !role.may(Permission::IssueKeys);
    Admin {
        name,
        team,
        read_only,
        role: match role.name.as_str() {
            "admin" | "read_only" => sso_role(read_only),
            custom => custom.to_string(),
        },
        via,
        permissions: role.permissions.clone(),
        org: role.org.clone(),
        teams: role.teams.clone(),
        customers: role.customers.clone(),
    }
}

/// What an admin record says: what was done, by whom, to what.
struct Act<'a> {
    action: &'static str,
    by: Option<(&'a str, &'a str)>,
    /// First 8 hex characters of the hash of a key that is not an admin's, for a refused sign-in.
    key: Option<String>,
    target: Value,
}

const NOT_RECORDED: &str = "Enterplace could not write this to its audit log, so nothing was done. Tell whoever runs Enterplace: it does not act on what it cannot record.";

/// Writes an admin record, as the admin API does, and waits for it. `Err` means it is not on file.
async fn record(
    console: &Console,
    act: &Act<'_>,
    code: Option<&str>,
    error: Option<&str>,
) -> Result<(), ()> {
    let Some(log) = &console.config().log else {
        return Err(());
    };
    let verdict = match (code, error) {
        (None, _) => "allow",
        (Some(_), None) => "refused",
        (Some(_), Some(_)) => "failed",
    };
    let hash = |path: &std::path::Path| {
        std::fs::read(path).map_or_else(|_| String::new(), |bytes| id::sha256_hex(&bytes))
    };
    let mut record = Map::new();
    record.insert("event".into(), "admin".into());
    record.insert("via".into(), "console".into());
    record.insert("id".into(), id::decision_id().into());
    record.insert("time".into(), audit::timestamp().into());
    record.insert("person".into(), act.by.map_or("unknown", |b| b.0).into());
    record.insert(
        "team".into(),
        act.by.map(|b| b.1).filter(|t| !t.is_empty()).into(),
    );
    record.insert(
        "client".into(),
        client().map_or(Value::Null, |c| c.to_string().into()),
    );
    record.insert("key".into(), act.key.clone().into());
    record.insert("action".into(), act.action.into());
    record.insert("target".into(), act.target.clone());
    record.insert("verdict".into(), verdict.into());
    record.insert("code".into(), code.into());
    if let Some(error) = error {
        record.insert("error".into(), error.into());
    }
    // The files as they are on disk now, which is what the action read and changed.
    // The policy in force: the store's live version when it is kept there.
    record.insert(
        "policy_sha256".into(),
        config::policy_text(&console.config().policy)
            .map_or_else(|_| String::new(), |text| id::sha256_hex(text.as_bytes()))
            .into(),
    );
    record.insert("keys_sha256".into(), hash(&console.config().keys).into());
    let (tell, written) = tokio::sync::oneshot::channel();
    log.append_record_then(&record, move |result| {
        let _ = tell.send(result);
    });
    match written.await {
        Ok(Ok(())) => Ok(()),
        _ => {
            eprintln!(
                "enterplace: the audit log could not be written, so console action {} was not done",
                act.action
            );
            Err(())
        }
    }
}

/// The console's routes, to be nested at `/console`.
pub fn router(config: ConsoleConfig) -> Router {
    router_with_setup(config, None)
}

/// The console's routes, with a one-time setup link at `/console/setup/<token>` that makes the first admin key.
pub fn router_with_setup(config: ConsoleConfig, setup: Option<String>) -> Router {
    router_with(config, setup, Extension::default())
}

/// The console's routes with what an embedding binary adds to them.
pub fn router_with(config: ConsoleConfig, setup: Option<String>, extension: Extension) -> Router {
    let state = Console(Arc::new(Inner {
        config,
        sessions: Mutex::default(),
        seal: {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key)
                .ok()
                .map(|()| ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key))
        },
        used: Mutex::default(),
        starts: Mutex::new((Instant::now(), 0)),
        refusals: Mutex::default(),
        provider: Mutex::default(),
        client: sso::client(),
        verified: Mutex::default(),
        codes: Mutex::default(),
        setup: Mutex::new(setup.map(|token| (token, false))),
        mine: Mutex::default(),
        accounts: extension.accounts,
        watch: extension.watch,
        proxy_admin: extension.proxy_admin,
        failures: Mutex::default(),
        extra: Arc::new(html::Extra {
            nav: extension.nav,
            sign_in: extension.sign_in,
        }),
    }));
    Router::new()
        .route("/setup/{token}", get(setup_page).post(setup_done))
        .route("/", get(root))
        .route("/sign-in", get(sign_in_page).post(sign_in))
        .route("/sign-in/{code}", get(sign_in_link))
        .route("/sign-out", get(sign_out))
        .route("/sso/start", get(sso_start))
        .route("/sso/callback", get(sso_callback))
        .route("/saml/start", get(saml_start))
        .route("/saml/acs", post(saml_acs))
        .route("/saml/metadata", get(saml_metadata))
        // `enterplace login` opens the browser here: the same sign-in, then a personal key for the CLI instead of a session.
        .route("/cli/login", get(sso_start))
        .route("/cli/token", post(cli_token))
        .route(
            "/cli/done",
            get(|uri: Uri| async move {
                page(
                    StatusCode::OK,
                    pages::cli_done(Form::of(&uri).get("ok") == "1"),
                )
            }),
        )
        .merge(edit::routes())
        .merge(api::routes())
        .merge(people::routes())
        .merge(teams::routes())
        .merge(raw_policy::routes())
        .merge(prices::routes())
        .merge(credentials::routes())
        .merge(analytics::routes())
        .merge(requests::routes())
        .merge(callers::routes())
        .merge(spend::routes())
        .merge(audit_log::routes())
        .merge(start::routes())
        .route("/live.json", get(live_json))
        .route("/events", get(events))
        .route("/kills/restore", post(restore_traffic))
        .route("/assets/{file}", get(asset))
        .route("/assets/fonts/{file}", get(font))
        .merge(extension.routes)
        .fallback(|| async {
            page(
                StatusCode::NOT_FOUND,
                pages::notice(
                    "No console page here",
                    "This address is not a page of the console. The overview is where it starts.",
                    HOME,
                    "Open the overview",
                ),
            )
        })
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            with_client,
        ))
        .layer(axum::middleware::from_fn(return_after_sign_in))
        .layer(axum::middleware::from_fn(edit::preview_scope))
        .with_state(state)
}

/// The cookie that holds where a person was going when the console sent them to sign in. It is no secret, and the
/// sign-in page adds the part after `#` to it (an app route), which a server never sees.
const NEXT_COOKIE: &str = "enterplace_next";

/// A console page to return to after signing in: a path under /console/ on this origin, nothing that signs in or out,
/// and nothing that could leave the console. `None` for anything else, so a link cannot send a person elsewhere.
pub(crate) fn next_page(next: &str) -> Option<&str> {
    let ok = next.starts_with("/console/")
        && next.len() <= 512
        && !next.contains("//")
        && !next.contains('\\')
        && !next.contains("..")
        && next.bytes().all(|b| b.is_ascii_graphic())
        && ![
            "/console/sign-in",
            "/console/sign-out",
            "/console/sso",
            "/console/saml",
            "/console/cli",
            "/console/setup",
        ]
        .iter()
        .any(|p| next.starts_with(p));
    ok.then_some(next)
}

/// Returns a person to where they were going once they sign in, by every way of signing in (key, single sign-on,
/// SAML): a page that sends them to sign in names itself in `next`, the sign-in page keeps it in a cookie, and the
/// redirect that follows a new session goes there instead of Start here.
async fn return_after_sign_in(
    request: axum::extract::Request,
    run: axum::middleware::Next,
) -> Response {
    // Nested under /console, the router sees the path without it.
    let path = request.uri().clone();
    let wanted = path
        .path_and_query()
        .map_or_else(|| path.path().to_string(), |p| p.as_str().to_string());
    let wanted = if wanted.starts_with("/console/") {
        wanted
    } else {
        format!("/console{wanted}")
    };
    let get = request.method() == axum::http::Method::GET;
    let on_sign_in = path.path().ends_with("/sign-in");
    let from_query = Form::of(&path).get("next").to_string();
    let from_cookie = cookie_value(request.headers(), NEXT_COOKIE)
        .map(|v| Form::parse(&format!("v={v}")).get("v").to_string())
        .unwrap_or_default();
    let mut response = run.run(request).await;
    if response.status() != StatusCode::SEE_OTHER {
        if get && on_sign_in && next_page(&from_query).is_some() {
            let cookie = format!(
                "{NEXT_COOKIE}={}; Path=/console; SameSite=Lax; Max-Age=600",
                html::enc(&from_query)
            );
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
        }
        return response;
    }
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if get && location == "/console/sign-in" && next_page(&wanted).is_some() {
        if let Ok(value) =
            HeaderValue::from_str(&format!("/console/sign-in?next={}", html::enc(&wanted)))
        {
            response.headers_mut().insert(header::LOCATION, value);
        }
        return response;
    }
    let signed_in_now = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| {
            v.to_str()
                .is_ok_and(|v| v.starts_with("enterplace_console="))
        });
    if location == HOME && (signed_in_now || on_sign_in) {
        let next = [from_query.as_str(), from_cookie.as_str()]
            .into_iter()
            .find_map(next_page)
            .map(str::to_string);
        if let Some(Ok(value)) = next.map(|n| HeaderValue::from_str(&n)) {
            response.headers_mut().insert(header::LOCATION, value);
            if let Ok(clear) = HeaderValue::from_str(&format!(
                "{NEXT_COOKIE}=; Path=/console; SameSite=Lax; Max-Age=0"
            )) {
                response.headers_mut().append(header::SET_COOKIE, clear);
            }
        }
    }
    response
}

/// Query or form pairs, decoded.
pub struct Form(Vec<(String, String)>);

impl Form {
    pub fn parse(text: &str) -> Self {
        let decode = |part: &str| {
            let bytes = part.as_bytes();
            let mut out = Vec::with_capacity(bytes.len());
            let mut i = 0;
            while i < bytes.len() {
                match bytes[i] {
                    b'+' => out.push(b' '),
                    b'%' if i + 2 < bytes.len() => {
                        let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                        match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                            Some(b) => {
                                out.push(b);
                                i += 2;
                            }
                            None => out.push(b'%'),
                        }
                    }
                    b => out.push(b),
                }
                i += 1;
            }
            String::from_utf8_lossy(&out).into_owned()
        };
        Self(
            text.split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| {
                    let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                    (decode(k), decode(v))
                })
                .collect(),
        )
    }

    pub fn of(uri: &Uri) -> Self {
        Self::parse(uri.query().unwrap_or(""))
    }

    /// Every name and value, in the order given.
    pub fn pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The last value given for a name, or "".
    pub fn get(&self, name: &str) -> &str {
        self.0
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map_or("", |(_, v)| v.as_str())
    }
}

/// Headers every console page carries: nothing of it is cached, framed by another site or run from elsewhere.
fn guarded(mut response: Response) -> Response {
    let headers = response.headers_mut();
    let set = [
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'self'; form-action 'self'; base-uri 'none'",
        ),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        // Not no-referrer: under it Chrome sends `Origin: null` on the console's own forms, and they are refused.
        // same-origin still sends nothing to another site.
        (header::REFERRER_POLICY, "same-origin"),
        (header::CACHE_CONTROL, "no-store"),
    ];
    for (name, value) in set {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

fn page(status: StatusCode, body: String) -> Response {
    guarded(
        (
            status,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            body,
        )
            .into_response(),
    )
}

/// A 303 to `to`, with the headers every console page carries.
pub fn redirect(to: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(to) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    guarded(response)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            pair.trim()
                .strip_prefix(&format!("{name}="))
                .map(str::to_string)
        })
}

/// Set on a request by `enterplace serve --tls-cert`: the connection is TLS terminated by Enterplace itself. An origin-form
/// request's URI has no scheme to say so (QA14-6).
pub type Tls = Option<axum::Extension<axum::http::uri::Scheme>>;

/// The cookie is Secure when the browser reached Enterplace over TLS, directly or through a proxy that says so.
fn secure(headers: &HeaderMap, uri: &Uri, tls: &Tls) -> bool {
    tls.is_some()
        || uri.scheme_str() == Some("https")
        || headers
            .get("x-forwarded-proto")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"https"))
}

/// A form must come from a console page on this same address. SameSite=Strict covers signed-in forms;
/// this also covers the sign-in form, which has no cookie yet.
pub fn same_origin(headers: &HeaderMap) -> bool {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    match (get("host"), get("origin")) {
        (Some(host), Some(origin)) if origin != "null" => {
            origin == format!("http://{host}") || origin == format!("https://{host}")
        }
        // A browser may send `Origin: null` (a privacy setting, an old cached page). Its fetch metadata still says
        // where the form came from, and no page can set that header. With neither, the form is refused.
        _ => get("sec-fetch-site") == Some("same-origin"),
    }
}

/// The answer to a form [`same_origin`] refused.
pub fn foreign() -> Response {
    page(
        StatusCode::FORBIDDEN,
        pages::notice(
            "This form came from somewhere else",
            "The form was not sent from a console page at this address, so it was refused and nothing was changed. Open the sign-in page and try again from there.",
            "/console/sign-in",
            "Open the sign-in page",
        ),
    )
}

impl Console {
    fn config(&self) -> &ConsoleConfig {
        &self.0.config
    }

    /// The person token made for `name` this run, if any.
    pub(crate) fn mine(&self, name: &str) -> Option<String> {
        self.0
            .mine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    pub(crate) fn keep_mine(&self, name: &str, token: String) {
        self.0
            .mine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_string(), token);
    }

    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        // A panic while the lock was held leaves the map as it was: still usable.
        self.0
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The admin of a request: the one its session is for, else the one an authenticating proxy names.
    async fn admin(&self, headers: &HeaderMap) -> Option<Admin> {
        if let Some(admin) = self.session_admin(headers).await {
            return Some(admin);
        }
        self.0
            .proxy_admin
            .as_ref()
            .and_then(|named| named(headers, client()))
    }

    /// The admin of a signed-in request. The keys file is read every time, so a key revoked or no longer
    /// marked admin ends its sessions at once.
    async fn session_admin(&self, headers: &HeaderMap) -> Option<Admin> {
        let id = cookie_value(headers, COOKIE)?;
        let who = match self.store() {
            // A store that cannot be reached signs no one in: the session may have ended on another gateway.
            Some(store) => who_of(&store.session(id::sha256_hex(id.as_bytes())).await.ok()??)?,
            None => {
                let mut sessions = self.sessions();
                match sessions.get(&id) {
                    Some(s) if s.expires > Instant::now() => s.who.clone(),
                    Some(_) => {
                        sessions.remove(&id);
                        return None;
                    }
                    None => return None,
                }
            }
        };
        let admin = match who {
            // The key's role is read with the policy every time, so a role taken away ends its sessions at once.
            Who::Key(sha) => admin_entry(&self.config().keys, &sha).and_then(|e| {
                let role = self.role(e.role.as_deref().unwrap_or("admin"), &e.org)?;
                Some(admin_of(e.name, e.team, &role, Via::Key))
            }),
            // The policy file is read every time, so removing console.sso or a person's email ends their session at once.
            Who::Sso { email, role, team } => {
                let allowed = self.sign_in_config().ok().is_some_and(|(sso, saml)| {
                    sso.is_some_and(|sso| sso::Access::of_sso(&sso).lets_in(&email))
                        || saml.is_some_and(|saml| sso::Access::of_saml(&saml).lets_in(&email))
                });
                allowed
                    .then(|| self.role(&role, ""))
                    .flatten()
                    .map(|role| admin_of(email, team, &role, Via::Sso))
            }
            Who::Account(account) => match &self.0.accounts {
                Some(accounts) => accounts(account).await,
                None => None,
            },
        };
        if admin.is_none() {
            self.end_session(&id);
        }
        admin
    }

    /// The store the console's keys are served from, which holds its sessions too.
    fn store(&self) -> Option<Arc<dyn enterplace_core::store::Store>> {
        enterplace_core::store::attached(&self.config().keys)
    }

    fn end_session(&self, id: &str) {
        match self.store() {
            Some(store) => store.end_session(id::sha256_hex(id.as_bytes())),
            None => {
                self.sessions().remove(id);
            }
        }
    }

    /// `console.sso` from the policy file as it is now. `Err` when the file has problems: no one signs in through it then.
    /// A role by name, from the policy as it is now, kept to `org` when the key has one. Only the built-in ones
    /// when the policy does not load: a custom role then signs no one in.
    fn role(&self, name: &str, org: &str) -> Option<Role> {
        let c = self.config();
        let mut role = match config::load(&c.policy, Some(&c.keys)) {
            Ok(loaded) => loaded.policy.role(name),
            Err(_) => builtin_role(name),
        }?;
        if !org.is_empty() {
            role.org = Some(org.to_string());
        }
        Some(role)
    }

    /// The roles of the policy as it is now, for single sign-on.
    fn roles(&self) -> Vec<Role> {
        let c = self.config();
        config::load(&c.policy, Some(&c.keys))
            .map(|loaded| loaded.policy.roles().to_vec())
            .unwrap_or_default()
    }

    fn sso_config(&self) -> Result<Option<config::Sso>, String> {
        self.sign_in_config().map(|(sso, _)| sso)
    }

    /// `console.sso` and `console.saml` from the policy as it is now.
    fn sign_in_config(&self) -> Result<(Option<config::Sso>, Option<config::Saml>), String> {
        let c = self.config();
        let text = config::policy_text(&c.policy)?;
        let keys = config::read_keys(&c.keys)?.unwrap_or_default();
        config::load_texts(&c.policy, &text, &c.keys, &keys)
            .map(|loaded| (loaded.sso, loaded.saml))
            .map_err(|errors| errors.join(" "))
    }

    /// The `teams:` of the policy as it is now, for single sign-on.
    fn teams(&self) -> Vec<enterplace_core::policy::Team> {
        let c = self.config();
        config::load(&c.policy, Some(&c.keys))
            .map(|loaded| loaded.policy.teams().to_vec())
            .unwrap_or_default()
    }

    fn used(&self) -> std::sync::MutexGuard<'_, HashMap<String, Instant>> {
        let mut used = self
            .0
            .used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        used.retain(|_, until| *until > now);
        used
    }

    /// Marks a verified sign-in's state as used for the `left` seconds its cookie lives. False if it already was.
    fn remember(&self, state: &str, left: u64) -> bool {
        let mut used = self.used();
        // ponytail: past MAX_USED verified sign-ins in 10 minutes the oldest is forgotten early; only an identity
        // provider's real sign-ins can get there, and its one-use code still refuses a replay.
        if used.len() >= MAX_USED {
            let first = used
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(s, _)| s.clone());
            if let Some(first) = first {
                used.remove(&first);
            }
        }
        used.insert(
            state.to_string(),
            Instant::now() + Duration::from_secs(left),
        )
        .is_none()
    }

    /// Counts a sign-in start, and says how many there were when this minute just reached [`FLOOD`].
    fn refusals(&self) -> std::sync::MutexGuard<'_, HashMap<String, Refusals>> {
        self.0
            .refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Counts a refused sign-in from one client address and returns how many it has had in its minute. A minute past
    /// [`FLOOD`] is closed by the task that records its summary, not here.
    fn count_refusal(&self, key: &str, code: &'static str) -> u64 {
        let now = tokio::time::Instant::now();
        let fresh =
            |r: &Refusals| r.count > FLOOD || now.duration_since(r.since) < Duration::from_secs(60);
        let mut all = self.refusals();
        // ponytail: one entry per address seen this minute; many addresses refused at once grow the map until
        // their minutes end.
        if all.len() >= 4096 {
            all.retain(|_, r| fresh(r));
        }
        let entry = all.entry(key.to_string()).or_insert_with(|| Refusals {
            since: now,
            count: 0,
            codes: BTreeMap::new(),
        });
        if !fresh(entry) {
            *entry = Refusals {
                since: now,
                count: 0,
                codes: BTreeMap::new(),
            };
        }
        entry.count += 1;
        *entry.codes.entry(code).or_default() += 1;
        entry.count
    }

    fn count_start(&self) -> Option<u64> {
        (per_minute(&self.0.starts) == FLOOD).then_some(FLOOD)
    }

    /// Opens a session and returns its ID, or what to tell the person when it could not be opened.
    async fn open_session(&self, who: Who) -> Result<String, String> {
        let session = random_hex().ok_or(NO_RANDOM)?;
        if let Some(store) = self.store() {
            // The store keeps the ID's hash: whoever reads the database cannot sign in with it.
            store
                .open_session(id::sha256_hex(session.as_bytes()), who_text(&who), SESSION)
                .await
                .map_err(|err| {
                    html::esc(&format!(
                        "The session could not be saved in the store ({err}), so you are not signed in. Ask your Enterplace admin to check the store the policy's store: section names (its Postgres database, or on Cloudflare the Worker, with npx wrangler tail), then sign in again."
                    ))
                })?;
            return Ok(session);
        }
        let mut sessions = self.sessions();
        let now = Instant::now();
        sessions.retain(|_, s| s.expires > now);
        sessions.insert(
            session.clone(),
            Session {
                who,
                expires: now + SESSION,
            },
        );
        Ok(session)
    }

    fn verified(&self, chain: &str) -> Option<Verified> {
        self.0
            .verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(chain)
            .cloned()
    }
}

/// What a sign-in attempt is counted under: its source address, and the account it names when it names one.
/// From [`Console::sign_in_guard`], for [`Console::sign_in_failed`] and [`Console::sign_in_succeeded`].
pub struct SignInGuard(Vec<String>);

/// Sign-in lockout: after [`SIGN_IN_LIMIT`] failed sign-ins from one source address or to one account, every
/// sign-in from that address or to that account is refused until the lockout ends, on every gateway of a store.
impl Console {
    /// The client's own address for a sign-in: the connection's, or the one a trusted proxy names, so people
    /// behind one load balancer are not counted as one source.
    fn source(&self, headers: &HeaderMap) -> String {
        let peer = client();
        let c = self.config();
        let forwarded: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let resolved = match (peer, config::load(&c.policy, Some(&c.keys))) {
            (Some(peer), Ok(loaded)) => Some(loaded.policy.client_ip(peer, &forwarded)),
            (peer, _) => peer,
        };
        flood_key(resolved)
    }

    async fn locked(&self, scope: &str, failed: bool) -> Option<u64> {
        let limit = failed.then_some(SIGN_IN_LIMIT);
        if let Some(store) = self.store() {
            // A store that cannot be reached locks no one out: it opens no session either.
            return store.sign_in_lock(scope.to_string(), limit).await.ok()?;
        }
        let now = Instant::now();
        let mut all = self
            .0
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stale = |(_, since, locked): &Failures| {
            now.duration_since(*since) > SIGN_IN_LIMIT.window
                && locked.is_none_or(|until| until <= now)
        };
        // ponytail: one entry per address or account that failed within the window; a flood from many addresses
        // grows the map until their windows end.
        if all.len() >= 4096 {
            all.retain(|_, entry| !stale(entry));
        }
        if failed {
            let entry = all.entry(scope.to_string()).or_insert((0, now, None));
            if stale(entry) {
                *entry = (0, now, None);
            }
            entry.0 += 1;
            if entry.0 >= SIGN_IN_LIMIT.max {
                entry.2 = Some(now + SIGN_IN_LIMIT.lock);
            }
        }
        let until = all.get(scope).and_then(|entry| entry.2)?;
        (until > now).then(|| until.duration_since(now).as_secs().max(1))
    }

    /// Call before checking a credential. `Err` is the answer to send when the source address, or `account` (an
    /// email, say), is locked out: 429 with Retry-After, and the credential must not be checked.
    pub async fn sign_in_guard(
        &self,
        headers: &HeaderMap,
        account: Option<&str>,
    ) -> Result<SignInGuard, Response> {
        let mut scopes = vec![format!("source:{}", self.source(headers))];
        if let Some(account) = account.filter(|a| !a.is_empty()) {
            // By hash: what a stranger typed as an account name is not kept.
            let hash = id::sha256_hex(account.to_lowercase().as_bytes());
            scopes.push(format!("account:{}", &hash[..32]));
        }
        let mut left = None;
        for scope in &scopes {
            left = left.max(self.locked(scope, false).await);
        }
        match left {
            None => Ok(SignInGuard(scopes)),
            Some(seconds) => {
                let mut response = bare_page(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many failed sign-ins",
                    &format!(
                        r#"<h1 class="t-lg" style="margin: 0">Too many failed sign-ins</h1><p class="t-lead g-muted" style="margin: 0">Sign-in from this address or to this account is locked for {} more minute{} after {} failed attempts. Wait, or ask an Enterplace admin: the lockout is in the audit log as console_sign_in_locked.</p><p class="t-small g-muted" style="margin: 0">Code: sign_in_locked</p>"#,
                        seconds.div_ceil(60),
                        if seconds.div_ceil(60) == 1 { "" } else { "s" },
                        SIGN_IN_LIMIT.max
                    ),
                );
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, seconds.into());
                Err(response)
            }
        }
    }

    /// Counts a failed sign-in. The attempt that locks a scope out is recorded as `console_sign_in_locked`;
    /// attempts refused while it is locked are not recorded one by one, so a flood cannot fill the audit log.
    pub async fn sign_in_failed(&self, guard: &SignInGuard) {
        for scope in &guard.0 {
            if let Some(seconds) = self.locked(scope, true).await {
                let act = Act {
                    action: "console_sign_in_locked",
                    by: None,
                    key: None,
                    target: json!({
                        "scope": scope,
                        "failures": SIGN_IN_LIMIT.max,
                        "within_seconds": SIGN_IN_LIMIT.window.as_secs(),
                        "locked_seconds": seconds,
                    }),
                };
                let _ = record(self, &act, None, None).await;
            }
        }
    }

    /// Forgets the failures counted for this attempt's source and account, after a good sign-in.
    pub fn sign_in_succeeded(&self, guard: &SignInGuard) {
        for scope in &guard.0 {
            match self.store() {
                Some(store) => store.sign_in_clear(scope.clone()),
                None => {
                    self.0
                        .failures
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(scope);
                }
            }
        }
    }
}

/// What an [`Extension`]'s handlers use: the console's sessions, look and audit records.
impl Console {
    /// Who finished a single sign-on started at `/console/sso/cli/login?cli_port=0`, as (email, team), in exchange
    /// for its one-use code and the PKCE verifier it started with. The MCP gateway's OAuth authorization uses it.
    pub fn take_sign_in(&self, code: &str, verifier: &str) -> Option<(String, String)> {
        let pending = self.codes().remove(code)?;
        let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
        (sso::b64url(digest.as_ref()) == pending.challenge).then_some((pending.email, pending.team))
    }

    /// The admin a key file entry is when its key is sent as a bearer token: its role read from the policy now and
    /// kept to the key's organization, as a console sign-in with the key gives. `None` when the role is not known.
    pub fn admin_of_key(&self, entry: &config::KeyEntry) -> Option<Admin> {
        let role = self.role(entry.role.as_deref().unwrap_or("admin"), &entry.org)?;
        Some(admin_of(
            entry.name.clone(),
            entry.team.clone(),
            &role,
            Via::Key,
        ))
    }

    /// Who the request is signed in as, checked again now. `None` when no one is: send them to /console/sign-in.
    pub async fn signed_in(&self, headers: &HeaderMap) -> Option<Admin> {
        self.admin(headers).await
    }

    /// A console page: the nav with the extension's entries, who is signed in, and `main` (markup from [`html`]).
    /// `current` is the nav label to mark, and `here` the page's own path, for the phone menu.
    pub fn page(
        &self,
        status: StatusCode,
        admin: &Admin,
        current: &str,
        uri: &Uri,
        main: &str,
    ) -> Response {
        page(
            status,
            pages::tool_page(
                current,
                &admin.label(),
                uri.path(),
                &Form::of(uri),
                main,
                "",
            ),
        )
    }

    /// Writes an admin record (`event: admin`, `via: console`) to the audit log, in the same chain as requests, and
    /// waits for it. `code` marks a refusal. `Err` holds the message to show: the action must not be done.
    pub async fn audit(
        &self,
        by: Option<&Admin>,
        action: &'static str,
        target: Value,
        code: Option<&str>,
    ) -> Result<(), &'static str> {
        let act = Act {
            action,
            by: by.map(|a| (a.name.as_str(), a.team.as_str())),
            key: None,
            target,
        };
        record(self, &act, code, None)
            .await
            .map_err(|()| NOT_RECORDED)
    }

    /// Records the sign-in and opens a session for `account`, which [`Extension::accounts`] answers for from then
    /// on, then sends the browser to the audit log. `admin` is who the account is now, for the record.
    pub async fn sign_in_account(
        &self,
        account: &str,
        admin: &Admin,
        headers: &HeaderMap,
        uri: &Uri,
        tls: &Tls,
    ) -> Response {
        let target = json!({ "via": "account", "role": admin.role });
        if self
            .audit(Some(admin), "console_sign_in", target, None)
            .await
            .is_err()
        {
            return page(
                StatusCode::SERVICE_UNAVAILABLE,
                pages::sign_in("", NOT_RECORDED, self.sso_on()),
            );
        }
        let session = match self.open_session(Who::Account(account.to_string())).await {
            Ok(session) => session,
            Err(err) => {
                return page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    pages::sign_in("", &err, self.sso_on()),
                );
            }
        };
        let mut response = redirect(HOME);
        set_cookie(&mut response, &session_cookie(&session, headers, uri, tls));
        response
    }
}

/// A page with no nav, for someone not signed in (an invite, another sign-in form): the brand, then `inner`.
pub fn bare_page(status: StatusCode, title: &str, inner: &str) -> Response {
    page(status, pages::setup_shell(title, inner))
}

fn admin_entry(keys: &std::path::Path, sha256: &str) -> Option<config::KeyEntry> {
    let text = config::read_keys(keys).ok()??;
    config::key_entries(keys, &text)
        .ok()?
        .into_iter()
        .find(|e| (e.admin || e.role.is_some()) && e.sha256 == sha256)
}

async fn root(State(console): State<Console>, headers: HeaderMap) -> Response {
    match console.admin(&headers).await {
        Some(_) => redirect(HOME),
        None => redirect("/console/sign-in"),
    }
}

async fn sign_in_page(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    if console.admin(&headers).await.is_some() {
        return redirect(HOME);
    }
    if Form::of(&uri).get("out") == "1" {
        return page(StatusCode::OK, pages::signed_out(console.sso_on()));
    }
    page(StatusCode::OK, pages::sign_in("", "", console.sso_on()))
}

async fn sign_in(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    cert: Option<axum::Extension<ClientCert>>,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let form = Form::parse(&body);
    let key = pasted_key(form.get("key"));
    let guard = match console.sign_in_guard(&headers, None).await {
        Ok(guard) => guard,
        Err(locked) => return locked,
    };
    let keys = &console.config().keys;
    let entry = if key.is_empty() {
        None
    } else {
        admin_entry(keys, &id::sha256_hex(key.as_bytes()))
    };
    let Some(entry) = entry else {
        if !key.is_empty() {
            let act = Act {
                action: "console_sign_in",
                by: None,
                key: Some(id::sha256_hex(key.as_bytes())[..8].to_string()),
                target: Value::Null,
            };
            // The refusal stands whether or not it was recorded.
            let _ = record(&console, &act, Some("not_admin"), None).await;
            console.sign_in_failed(&guard).await;
        }
        // One message for an unknown key and a key that is not an admin's: the page does not tell which keys exist.
        let error = if key.is_empty() {
            "Paste an Enterplace key. It starts with enterplace_.".to_string()
        } else if !key.starts_with("enterplace_") {
            "That is not an Enterplace key: Enterplace keys start with enterplace_. Paste the admin key enterplace start printed, or open the sign-in link it printed.".to_string()
        } else {
            "This key is not an admin key, so it does not sign in here. Check that you pasted the whole admin key enterplace start printed, or ask an admin to make you one: enterplace key new your-name --team your-team --admin.".to_string()
        };
        return page(
            StatusCode::UNAUTHORIZED,
            pages::sign_in_kept(&error, form.get("key"), console.sso_on()),
        );
    };
    let act = Act {
        action: "console_sign_in",
        by: Some((&entry.name, &entry.team)),
        key: None,
        target: Value::Null,
    };
    // A key bound to a client certificate signs in only on a connection that presented it, as on every other route.
    if let Some(bound) = &entry.options.cert
        && !cert.is_some_and(|cert| cert.0.is(bound))
    {
        let _ = record(&console, &act, Some("cert_required"), None).await;
        return page(
            StatusCode::FORBIDDEN,
            pages::sign_in(
                &format!(
                    "This key is bound to the client certificate named {}, and this connection did not present it. Connect with that certificate.",
                    html::esc(bound)
                ),
                "",
                console.sso_on(),
            ),
        );
    }
    if record(&console, &act, None, None).await.is_err() {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::sign_in("", NOT_RECORDED, console.sso_on()),
        );
    }
    console.sign_in_succeeded(&guard);
    let session = match console.open_session(Who::Key(entry.sha256)).await {
        Ok(session) => session,
        Err(err) => {
            return page(
                StatusCode::SERVICE_UNAVAILABLE,
                pages::sign_in("", &err, console.sso_on()),
            );
        }
    };
    let mut response = redirect(HOME);
    set_cookie(
        &mut response,
        &session_cookie(&session, &headers, &uri, &tls),
    );
    response
}

/// How long the sign-in link `enterplace start` prints works.
pub const START_LINK_TTL: Duration = Duration::from_secs(10 * 60);

/// The one-time sign-in link `enterplace start` prints, kept as the hash of its code only.
struct StartLink {
    sha256: String,
    expires: Instant,
    /// The admin key it signs in as, by its hash.
    admin: String,
    /// In a container the browser's address is the container network's, never loopback.
    any_address: bool,
}

// One per process: the gateway prints one link when it starts.
static START_LINK: std::sync::Mutex<Option<StartLink>> = std::sync::Mutex::new(None);

/// Makes the code of the one-time sign-in link for the admin key whose hash is `admin`, replacing any earlier one.
/// It works once, for [`START_LINK_TTL`], and only from this machine unless `any_address`. `None` when the system
/// gave no randomness.
pub fn offer_start_link(admin: &str, any_address: bool) -> Option<String> {
    let code = random_hex()?;
    *START_LINK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(StartLink {
        sha256: id::sha256_hex(code.as_bytes()),
        expires: Instant::now() + START_LINK_TTL,
        admin: admin.to_string(),
        any_address,
    });
    Some(code)
}

pub(crate) use keyfile::PERSON_TOKEN_KIND;

fn person_token_attributes(mut attributes: keyfile::Attributes) -> keyfile::Attributes {
    attributes
        .options
        .metadata
        .insert("kind".into(), PERSON_TOKEN_KIND.into());
    attributes
}

/// Makes the first admin's own person token and keeps it for them this run, so the Claude Code lines on Coding agents
/// name them from the first request. Only the setup link does this: nobody holds a token there yet. A start link
/// signs in someone enterplace start already printed a token for, so it makes none. The token reaches no model on
/// its own; a failure here changes nothing else, and Coding agents offers Make my person token.
async fn first_admin_token(console: &Console, name: &str, team: &str) {
    let Ok(token) = id::new_person_token() else {
        return;
    };
    let act = Act {
        action: "issue_key",
        by: Some((name, team)),
        key: None,
        target: json!({ "name": name, "team": team, "sha256_prefix": &id::sha256_hex(token.as_bytes())[..8], "admin": false, "person_token": true }),
    };
    if record(console, &act, None, None).await.is_ok()
        && keyfile::add_with(
            name,
            team,
            &token,
            &person_token_attributes(keyfile::Attributes::default()),
            &console.config().keys,
        )
        .is_ok()
    {
        console.keep_mine(name, token);
    }
}

/// Signs in with the one-time link `enterplace start` printed: recorded as a console sign-in, then the link is spent.
async fn sign_in_link(
    State(console): State<Console>,
    Path(code): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
) -> Response {
    let hash = id::sha256_hex(code.as_bytes());
    let local = client().is_some_and(|ip| match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    });
    let refused = |message: &str| {
        page(
            StatusCode::FORBIDDEN,
            pages::notice(
                "This sign-in link does not work",
                message,
                "/console/sign-in",
                "Sign in with the admin key",
            ),
        )
    };
    let admin = {
        let mut link = START_LINK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match link.as_ref() {
            Some(l) if l.sha256 == hash && !(l.any_address || local) => {
                return refused(
                    "It works only in a browser on the machine that runs Enterplace. Open it there, or sign in with the admin key enterplace start printed.",
                );
            }
            Some(l) if l.sha256 == hash && l.expires > Instant::now() => {
                link.take().map(|l| l.admin)
            }
            Some(l) if l.sha256 == hash => {
                *link = None;
                None
            }
            _ => None,
        }
    };
    let Some(entry) = admin.and_then(|sha| admin_entry(&console.config().keys, &sha)) else {
        return refused(
            "It was used already or is older than 10 minutes: each link signs in once. Run enterplace start again for a new one, or sign in with the admin key it printed.",
        );
    };
    let act = Act {
        action: "console_sign_in",
        by: Some((&entry.name, &entry.team)),
        key: None,
        target: json!({ "via": "start_link" }),
    };
    if record(&console, &act, None, None).await.is_err() {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::sign_in("", NOT_RECORDED, console.sso_on()),
        );
    }
    let session = match console.open_session(Who::Key(entry.sha256)).await {
        Ok(session) => session,
        Err(err) => {
            return page(
                StatusCode::SERVICE_UNAVAILABLE,
                pages::sign_in("", &err, console.sso_on()),
            );
        }
    };
    let mut response = redirect(HOME);
    set_cookie(
        &mut response,
        &session_cookie(&session, &headers, &uri, &tls),
    );
    response
}

/// The key in what was pasted: the whole `export ENTERPLACE_KEY=...` line `enterplace start` prints is taken too.
fn pasted_key(raw: &str) -> &str {
    let raw = raw.trim();
    let raw = raw.strip_prefix("export ").unwrap_or(raw).trim_start();
    let raw = raw.strip_prefix("ENTERPLACE_KEY=").unwrap_or(raw);
    raw.trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace())
}

// A session ID that could be guessed is worse than no session.
const NO_RANDOM: &str = "The system gave no randomness for a session. Try again in a moment.";

fn random_hex() -> Option<String> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).ok()?;
    Some(id::hex(&random))
}

fn session_cookie(session: &str, headers: &HeaderMap, uri: &Uri, tls: &Tls) -> String {
    format!(
        "{COOKIE}={session}; Path=/console; Max-Age={}; HttpOnly; SameSite=Strict{}",
        SESSION.as_secs(),
        if secure(headers, uri, tls) {
            "; Secure"
        } else {
            ""
        }
    )
}

fn set_cookie(response: &mut Response, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

impl Console {
    /// Whether the sign-in page offers single sign-on.
    fn sso_on(&self) -> bool {
        matches!(self.sign_in_config(), Ok((Some(_), _) | (_, Some(_))))
    }

    /// The identity provider's discovery and keys, from the cache while it is fresh.
    async fn provider(&self, sso: &config::Sso) -> Result<Arc<sso::Provider>, sso::Refusal> {
        let cached = self
            .0
            .provider
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(p) =
            cached.filter(|p| p.issuer == sso.issuer && p.fetched.elapsed() < sso::CACHE)
        {
            return Ok(p);
        }
        let fresh = Arc::new(sso::discover(&self.0.client, sso).await?);
        self.cache(&fresh);
        Ok(fresh)
    }

    fn cache(&self, provider: &Arc<sso::Provider>) {
        *self
            .0
            .provider
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(provider.clone());
    }

    /// Records a refused single sign-on and shows why on the sign-in page. The refusal stands whether or not it was
    /// recorded. Anyone can make a sign-in fail, so past [`FLOOD`] in a minute from one client address the rest are
    /// summed up in one record written when that minute closes, with the true count per refusal code.
    async fn sso_refused(&self, email: Option<&str>, refusal: &sso::Refusal) -> Response {
        self.sign_in_refused("sso", email, refusal).await
    }

    /// [`Console::sso_refused`], for the way in named by `via`: `sso` or `saml`.
    async fn sign_in_refused(
        &self,
        via: &'static str,
        email: Option<&str>,
        refusal: &sso::Refusal,
    ) -> Response {
        let key = flood_key(client());
        let seen = self.count_refusal(&key, refusal.code);
        if seen <= FLOOD {
            let act = Act {
                action: "console_sign_in",
                by: email.map(|e| (e, "")),
                key: None,
                target: json!({ "via": via, "reason": refusal.message }),
            };
            let _ = record(self, &act, Some(refusal.code), None).await;
        } else if seen == FLOOD + 1 {
            let console = self.clone();
            tokio::spawn(CLIENT.scope(client(), async move {
                let closes = console
                    .refusals()
                    .get(&key)
                    .map(|r| r.since + Duration::from_secs(60));
                if let Some(closes) = closes {
                    tokio::time::sleep_until(closes).await;
                }
                let Some(flood) = console.refusals().remove(&key) else {
                    return;
                };
                let act = Act {
                    action: "console_sso_refusals",
                    by: None,
                    key: None,
                    target: json!({ "via": "sso", "client": key, "refusals": flood.count, "codes": flood.codes, "within_seconds": 60, "reason": "many refused single sign-ons from one client address within a minute, likely a flood. Past the first refusals they are counted here, not recorded one by one; other addresses and sign-ins that finish are recorded as usual." }),
                };
                let _ = record(&console, &act, None, None).await;
            }));
        }
        let mut response = page(
            StatusCode::UNAUTHORIZED,
            pages::sign_in("", &html::esc(&refusal.message), self.sso_on()),
        );
        set_cookie(
            &mut response,
            &format!("{SSO_COOKIE}=; Path=/console/sso; Max-Age=0; HttpOnly; SameSite=Lax"),
        );
        response
    }
}

/// Sends the browser to the identity provider with a fresh state, nonce and PKCE verifier.
async fn sso_start(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
) -> Response {
    let refused = |code, message: String| sso::Refusal { code, message };
    let cli = match cli_start(&Form::of(&uri)) {
        Ok(cli) => cli,
        Err(message) => {
            // Recorded and counted as any refused sign-in; the page is enterplace login's, not the console's.
            let _ = console
                .sso_refused(None, &refused("cli_login", message.into()))
                .await;
            return page(StatusCode::UNAUTHORIZED, pages::cli_bad_link(message));
        }
    };
    // Anyone can start a sign-in. Each start is not recorded, or a flood would fill the disk; a minute with many is,
    // once.
    if let Some(starts) = console.count_start() {
        let act = Act {
            action: "console_sso_starts",
            by: None,
            key: None,
            target: json!({ "via": "sso", "starts": starts, "within_seconds": 60, "reason": "many single sign-on starts within a minute: a flood, or many people signing in at once. Starts are not recorded one by one; each finished or refused sign-in is." }),
        };
        let _ = record(&console, &act, None, None).await;
    }
    let sso = match console.sign_in_config() {
        Ok((Some(sso), _)) => sso,
        // SAML is the only single sign-on set up: the sign-in page's button, and enterplace login, lead there.
        Ok((None, Some(_))) => {
            return redirect(&match uri.query().filter(|_| cli.is_some()) {
                Some(query) => format!("/console/saml/start?{query}"),
                None => "/console/saml/start".to_string(),
            });
        }
        Ok((None, _)) => {
            let message = "Single sign-on is not set up. Sign in with an admin key, or ask an admin to set up single sign-on in the policy file.".to_string();
            return console
                .sso_refused(None, &refused("sso_config", message))
                .await;
        }
        Err(errors) => {
            let message = format!(
                "Single sign-on is off because the policy file has problems: {errors} Run enterplace check, fix them, and try again."
            );
            return console
                .sso_refused(None, &refused("sso_config", message))
                .await;
        }
    };
    if cli.is_some() && sso.self_issue.is_none() {
        let message = "enterplace login is off: single sign-on does not let people get their own keys yet. Ask an admin to turn that on, or for a key.".to_string();
        return console
            .sso_refused(None, &refused("sso_self_issue", message))
            .await;
    }
    if enterplace_core::secrets::var(&sso.client_secret_env).is_none_or(|v| v.is_empty()) {
        let message = format!(
            "Single sign-on is unavailable: the client secret variable {} is not set where Enterplace runs. Set it and restart Enterplace.",
            sso.client_secret_env
        );
        return console
            .sso_refused(None, &refused("sso_secret", message))
            .await;
    }
    let provider = match console.provider(&sso).await {
        Ok(p) => p,
        Err(refusal) => return console.sso_refused(None, &refusal).await,
    };
    let (Some(state), Some(seal)) = (random_hex(), console.0.seal.as_ref()) else {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::sign_in("", NO_RANDOM, true),
        );
    };
    let (nonce, verifier) = derived(seal, &state);
    let target = sso::authorize_url(&provider, &sso, &state, &nonce, &verifier);
    let expires = unix_now() + SSO_PENDING.as_secs();
    let sealed = format!("{state}.{expires}");
    let cookie = format!("{sealed}.{}", mac(seal, &sealed));
    let mut response = redirect(&target);
    // Lax, not Strict: the browser comes back from the provider's site, and must bring this cookie with it.
    set_cookie(
        &mut response,
        &format!(
            "{SSO_COOKIE}={cookie}; Path=/console/sso; Max-Age={}; HttpOnly; SameSite=Lax{}",
            SSO_PENDING.as_secs(),
            if secure(&headers, &uri, &tls) {
                "; Secure"
            } else {
                ""
            }
        ),
    );
    let secure = if secure(&headers, &uri, &tls) {
        "; Secure"
    } else {
        ""
    };
    // A console sign-in clears what an abandoned `enterplace login` left, so it never ends in a key for the CLI.
    let cli_cookie = match cli {
        Some(c) => format!(
            "{CLI_COOKIE}={}.{}.{}.{}; Path=/console/sso; Max-Age={}; HttpOnly; SameSite=Lax{secure}",
            c.port,
            c.state,
            c.challenge,
            mac(seal, &cli_seal(&state, &c)),
            SSO_PENDING.as_secs()
        ),
        None => {
            format!("{CLI_COOKIE}=; Path=/console/sso; Max-Age=0; HttpOnly; SameSite=Lax{secure}")
        }
    };
    set_cookie(&mut response, &cli_cookie);
    response
}

const SAML_COOKIE: &str = "enterplace_saml";

/// `console.saml` as it is now, or why there is none.
fn saml_config(console: &Console) -> Result<config::Saml, sso::Refusal> {
    match console.sign_in_config() {
        Ok((_, Some(saml))) => Ok(saml),
        Ok((_, None)) => Err(sso::Refusal {
            code: "sso_config",
            message: "SAML sign-in is not set up. Sign in with an admin key, or ask an admin to set up SAML sign-in in the policy file.".into(),
        }),
        Err(errors) => Err(sso::Refusal {
            code: "sso_config",
            message: format!(
                "SAML sign-in is off because the policy file has problems: {errors} Run enterplace check, fix them, and try again."
            ),
        }),
    }
}

/// The service provider metadata, for an identity provider that imports it.
async fn saml_metadata(State(console): State<Console>) -> Response {
    match saml_config(&console) {
        Ok(saml) => guarded(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
                saml::metadata(&saml),
            )
                .into_response(),
        ),
        Err(refusal) => page(
            StatusCode::NOT_FOUND,
            pages::sign_in("", &html::esc(&refusal.message), console.sso_on()),
        ),
    }
}

/// Sends the browser to the identity provider with a request whose ID only this browser's sealed cookie holds.
async fn saml_start(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
) -> Response {
    if let Some(starts) = console.count_start() {
        let act = Act {
            action: "console_sso_starts",
            by: None,
            key: None,
            target: json!({ "via": "saml", "starts": starts, "within_seconds": 60, "reason": "many SAML sign-in starts within a minute: a flood, or many people signing in at once. Starts are not recorded one by one; each finished or refused sign-in is." }),
        };
        let _ = record(&console, &act, None, None).await;
    }
    let cli = match cli_start(&Form::of(&uri)) {
        Ok(cli) => cli,
        Err(message) => {
            let refusal = sso::Refusal {
                code: "cli_login",
                message: message.into(),
            };
            let _ = console.sign_in_refused("saml", None, &refusal).await;
            return page(StatusCode::UNAUTHORIZED, pages::cli_bad_link(message));
        }
    };
    let saml = match saml_config(&console) {
        Ok(saml) => saml,
        Err(refusal) => return console.sign_in_refused("saml", None, &refusal).await,
    };
    if cli.is_some() && saml.self_issue.is_none() {
        let refusal = sso::Refusal {
            code: "sso_self_issue",
            message: "enterplace login is off: SAML sign-in does not let people get their own keys yet. Ask an admin to turn that on, or for a key.".into(),
        };
        return console.sign_in_refused("saml", None, &refusal).await;
    }
    let (Some(id), Some(seal)) = (random_hex(), console.0.seal.as_ref()) else {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::sign_in("", NO_RANDOM, true),
        );
    };
    // An ID starts with a letter or underscore (xs:ID).
    let id = format!("_{id}");
    let now = unix_now();
    let expires = now + SSO_PENDING.as_secs();
    let sealed = format!("{id}.{expires}");
    let cookie = format!("{sealed}.{}", mac(seal, &sealed));
    let mut response = redirect(&saml::authn_url(
        &saml,
        &id,
        i64::try_from(now).unwrap_or(i64::MAX),
        &id,
    ));
    // The identity provider posts the answer from its own site: only a SameSite=None cookie comes with a
    // cross-site POST, and browsers take one only when it is Secure. Over plain http (a provider on this machine,
    // the same site) Lax comes with it.
    let site = if secure(&headers, &uri, &tls) {
        "None; Secure"
    } else {
        "Lax"
    };
    set_cookie(
        &mut response,
        &format!(
            "{SAML_COOKIE}={cookie}; Path=/console/saml; Max-Age={}; HttpOnly; SameSite={site}",
            SSO_PENDING.as_secs()
        ),
    );
    // As for OpenID Connect: sealed over this request's ID, so it fits this sign-in only, and a console sign-in
    // clears what an abandoned `enterplace login` left.
    let cli_cookie = match cli {
        Some(c) => format!(
            "{CLI_COOKIE}={}.{}.{}.{}; Path=/console/saml; Max-Age={}; HttpOnly; SameSite={site}",
            c.port,
            c.state,
            c.challenge,
            mac(seal, &cli_seal(&id, &c)),
            SSO_PENDING.as_secs()
        ),
        None => format!("{CLI_COOKIE}=; Path=/console/saml; Max-Age=0; HttpOnly; SameSite={site}"),
    };
    set_cookie(&mut response, &cli_cookie);
    response
}

/// Where the identity provider posts its answer: checks everything, then opens a session.
async fn saml_acs(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
    body: String,
) -> Response {
    let refused = |code, message: &str| sso::Refusal {
        code,
        message: message.to_string(),
    };
    if body.len() > saml::MAX_RESPONSE {
        return console
            .sign_in_refused("saml", None, &refused("saml_response", "The identity provider's response is larger than Enterplace takes. Remove attributes the console does not need from the SAML app."))
            .await;
    }
    let form = Form::parse(&body);
    let relay = form.get("RelayState");
    let cookie = cookie_value(&headers, SAML_COOKIE).unwrap_or_default();
    let now = unix_now();
    let checked = console
        .0
        .seal
        .as_ref()
        .map_or(Err(BadState::Foreign), |seal| {
            state_left(seal, &cookie, relay, now)
        });
    let left = match checked {
        Ok(left) => left,
        Err(BadState::Expired) => {
            return console
                .sign_in_refused("saml", None, &refused("saml_replay", "This sign-in has expired. Start again from the sign-in page and finish within 10 minutes."))
                .await;
        }
        Err(BadState::Foreign) => {
            return console
                .sign_in_refused("saml", None, &refused("saml_replay", "The identity provider answered a sign-in this browser did not start, so it was refused: Enterplace takes only sign-ins started from its own sign-in page, not from the identity provider's app list. Start again from the console's sign-in page; if it repeats, allow cookies for this address."))
                .await;
        }
    };
    let saml = match saml_config(&console) {
        Ok(saml) => saml,
        Err(refusal) => return console.sign_in_refused("saml", None, &refusal).await,
    };
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    let signed = match saml::verify(form.get("SAMLResponse"), &saml, relay, now) {
        Ok(signed) => signed,
        Err(refusal) => return console.sign_in_refused("saml", None, &refusal).await,
    };
    // Each request answers once, and each assertion is used once, for as long as it would be taken.
    let lasts = u64::try_from(signed.until.saturating_sub(now) + 60).unwrap_or(left);
    if !console.remember(&format!("saml-request:{relay}"), left)
        || !console.remember(
            &format!("saml-assertion:{}", signed.id),
            lasts.min(24 * 3600),
        )
    {
        return console
            .sign_in_refused(
                "saml",
                Some(&signed.email),
                &refused(
                    "saml_replay",
                    "This sign-in was already used. Start again from the sign-in page.",
                ),
            )
            .await;
    }
    let groups: Vec<&str> = signed.groups.iter().map(String::as_str).collect();
    if let Some(cli) = cli_cookie(&console, &headers, relay) {
        let admitted = sso::admit_self_person(
            signed.email,
            &groups,
            &sso::Access::of_saml(&saml),
            saml.self_issue.as_ref(),
            &console.teams(),
        );
        return cli_finish(&console, "saml", &cli, admitted).await;
    }
    let admitted = sso::admit_person(
        signed.email,
        &groups,
        &sso::Access::of_saml(&saml),
        &console.roles(),
        &console.teams(),
    );
    let (email, role, team) = match admitted {
        Ok(admitted) => admitted,
        Err((email, refusal)) => {
            return console
                .sign_in_refused("saml", email.as_deref(), &refusal)
                .await;
        }
    };
    let act = Act {
        action: "console_sign_in",
        by: Some((&email, &team)),
        key: None,
        target: json!({ "via": "saml", "role": role }),
    };
    if record(&console, &act, None, None).await.is_err() {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::sign_in("", NOT_RECORDED, true),
        );
    }
    let session = match console.open_session(Who::Sso { email, role, team }).await {
        Ok(session) => session,
        Err(err) => {
            return page(
                StatusCode::SERVICE_UNAVAILABLE,
                pages::sign_in("", &err, true),
            );
        }
    };
    let mut response = page(StatusCode::OK, pages::signed_in_sso());
    set_cookie(
        &mut response,
        &session_cookie(&session, &headers, &uri, &tls),
    );
    set_cookie(
        &mut response,
        &format!("{SAML_COOKIE}=; Path=/console/saml; Max-Age=0; HttpOnly; SameSite=Lax"),
    );
    response
}

/// What the CLI's sign-in cookie is sealed over: the sign-in's own state too, so it fits that sign-in only.
fn cli_seal(state: &str, c: &CliStart) -> String {
    format!("cli:{state}:{}:{}:{}", c.port, c.state, c.challenge)
}

fn url_safe(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The CLI's parameters of a sign-in `enterplace login` started, if it did.
fn cli_start(query: &Form) -> Result<Option<CliStart>, &'static str> {
    let (port, state, challenge) = (
        query.get("cli_port"),
        query.get("cli_state"),
        query.get("cli_challenge"),
    );
    if port.is_empty() && state.is_empty() && challenge.is_empty() {
        return Ok(None);
    }
    // Port 0 is no CLI: it is Enterplace's own MCP authorization, which takes the code back at /console/mcp/sso-return.
    let port = port.parse::<u16>().ok();
    match port {
        Some(port)
            if (16..=128).contains(&state.len())
                && url_safe(state)
                && challenge.len() == 43
                && url_safe(challenge) =>
        {
            Ok(Some(CliStart {
                port,
                state: state.to_string(),
                challenge: challenge.to_string(),
            }))
        }
        _ => Err(
            "This sign-in link from enterplace login is incomplete or was changed. Run enterplace login again and use the link it opens.",
        ),
    }
}

/// The CLI parameters of the sign-in coming back with `state`, if `enterplace login` started it on this browser.
fn cli_cookie(console: &Console, headers: &HeaderMap, state: &str) -> Option<CliStart> {
    let cookie = cookie_value(headers, CLI_COOKIE)?;
    let mut parts = cookie.splitn(4, '.');
    let c = CliStart {
        port: parts.next()?.parse().ok()?,
        state: parts.next()?.to_string(),
        challenge: parts.next()?.to_string(),
    };
    let sig = sso::b64url_decode(parts.next()?)?;
    ring::hmac::verify(
        console.0.seal.as_ref()?,
        cli_seal(state, &c).as_bytes(),
        &sig,
    )
    .ok()?;
    Some(c)
}

/// Where the identity provider sends the browser back: checks everything, then opens a session.
async fn sso_callback(
    State(console): State<Console>,
    headers: HeaderMap,
    uri: Uri,
    tls: Tls,
) -> Response {
    let query = Form::of(&uri);
    let finished = sso_finish(&console, &headers, &query).await;
    if let Some(cli) = cli_cookie(&console, &headers, query.get("state")) {
        let teams = console.teams();
        let admitted = finished.and_then(|(claims, sso)| sso::admit_self(&claims, &sso, &teams));
        return cli_finish(&console, "sso", &cli, admitted).await;
    }
    let (roles, teams) = (console.roles(), console.teams());
    match finished.and_then(|(claims, sso)| sso::admit(&claims, &sso, &roles, &teams)) {
        Ok((email, role, team)) => {
            let act = Act {
                action: "console_sign_in",
                by: Some((&email, &team)),
                key: None,
                target: json!({ "via": "sso", "role": role }),
            };
            if record(&console, &act, None, None).await.is_err() {
                return page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    pages::sign_in("", NOT_RECORDED, true),
                );
            }
            let session = match console.open_session(Who::Sso { email, role, team }).await {
                Ok(session) => session,
                Err(err) => {
                    return page(
                        StatusCode::SERVICE_UNAVAILABLE,
                        pages::sign_in("", &err, true),
                    );
                }
            };
            // A page, not a redirect: the browser arrived from the provider's site, and would not send a
            // SameSite=Strict cookie on a redirect that follows. The refresh starts from this site, so it does.
            let mut response = page(StatusCode::OK, pages::signed_in_sso());
            set_cookie(
                &mut response,
                &session_cookie(&session, &headers, &uri, &tls),
            );
            set_cookie(
                &mut response,
                &format!("{SSO_COOKIE}=; Path=/console/sso; Max-Age=0; HttpOnly; SameSite=Lax"),
            );
            response
        }
        Err((email, refusal)) => console.sso_refused(email.as_deref(), &refusal).await,
    }
}

type SsoResult = Result<(Value, config::Sso), (Option<String>, sso::Refusal)>;

/// Ends a sign-in `enterplace login` started: the browser goes back to the CLI on 127.0.0.1 with a one-use code, or with
/// why it was refused. The key itself is only ever handed to the CLI, in exchange for the code and its PKCE verifier.
async fn cli_finish(
    console: &Console,
    via: &'static str,
    cli: &CliStart,
    admitted: Result<(String, String, u32), (Option<String>, sso::Refusal)>,
) -> Response {
    let back = if cli.port == 0 {
        format!("/console/mcp/sso-return?state={}", cli.state)
    } else {
        format!("http://127.0.0.1:{}/callback?state={}", cli.port, cli.state)
    };
    let to = match admitted {
        Ok((email, team, days)) => {
            let Some(code) = random_hex() else {
                return page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    pages::sign_in("", NO_RANDOM, true),
                );
            };
            let mut codes = console.codes();
            if codes.len() >= MAX_CODES {
                return page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    pages::sign_in(
                        "",
                        "Too many enterplace login sign-ins are waiting to finish. Run enterplace login again in a few minutes.",
                        true,
                    ),
                );
            }
            codes.insert(
                code.clone(),
                Pending {
                    email,
                    team,
                    days,
                    challenge: cli.challenge.clone(),
                    expires: Instant::now() + CLI_CODE,
                },
            );
            format!("{back}&code={code}")
        }
        Err((email, refusal)) => {
            // Recorded, and counted against floods, as any refused sign-in is. The page it renders is not shown:
            // the CLI shows the reason in the terminal.
            let _ = console
                .sign_in_refused(via, email.as_deref(), &refusal)
                .await;
            format!(
                "{back}&error={}&message={}",
                refusal.code,
                html::enc(&refusal.message)
            )
        }
    };
    let mut response = redirect(&to);
    let path = if via == "saml" {
        "/console/saml"
    } else {
        "/console/sso"
    };
    let pending = if via == "saml" {
        SAML_COOKIE
    } else {
        SSO_COOKIE
    };
    for name in [pending, CLI_COOKIE] {
        set_cookie(
            &mut response,
            &format!("{name}=; Path={path}; Max-Age=0; HttpOnly; SameSite=Lax"),
        );
    }
    response
}

impl Console {
    /// Codes waiting for `enterplace login`, without the expired ones.
    fn codes(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        let mut codes = self
            .0
            .codes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        codes.retain(|_, p| p.expires > now);
        codes
    }
}

fn json_answer(status: StatusCode, body: &Value) -> Response {
    guarded(
        (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response(),
    )
}

fn cli_refused(status: StatusCode, code: &str, message: &str) -> Response {
    json_answer(
        status,
        &json!({ "error": { "code": code, "message": format!("Refused ({code}): {message}") } }),
    )
}

/// Trades a `enterplace login` code and its PKCE verifier for a personal key, issued now and recorded first. The code
/// works once, for two minutes, whatever the outcome.
async fn cli_token(State(console): State<Console>, body: String) -> Response {
    let form = Form::parse(&body);
    let pending = console.codes().remove(form.get("code"));
    let Some(pending) = pending else {
        return cli_refused(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "this sign-in code is unknown, used or older than two minutes. Run enterplace login again.",
        );
    };
    let digest = ring::digest::digest(&ring::digest::SHA256, form.get("verifier").as_bytes());
    if sso::b64url(digest.as_ref()) != pending.challenge {
        return cli_refused(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the verifier does not match the sign-in this code came from. Run enterplace login again.",
        );
    }
    // QA14-13: a key is named by the email, and a name the keys file cannot hold (such as one with +) is refused
    // here, before the issue is recorded, rather than after.
    if !enterplace_core::config::valid_name(&pending.email) {
        return cli_refused(
            StatusCode::BAD_REQUEST,
            "unusable_email",
            &format!(
                "a key is named by your email, and \"{}\" has characters a key name cannot hold (letters, digits, dots, dashes, underscores and @ only). Ask an Enterplace admin for a key with enterplace key new instead.",
                pending.email
            ),
        );
    }
    let key = match id::new_key() {
        Ok(key) => key,
        Err(err) => {
            return cli_refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "no_randomness",
                &format!("{err}. Try again."),
            );
        }
    };
    let later =
        std::time::SystemTime::now() + Duration::from_secs(u64::from(pending.days) * 86_400);
    let mut attributes = keyfile::Attributes {
        expires: Some(format!("{}Z", &audit::rfc3339(later)[..19])),
        ..keyfile::Attributes::default()
    };
    // A key a person gives themselves holds to the policy's key_bounds: never longer than max_days, and with the
    // budget and models the bounds set.
    if bound(&console, None, &mut attributes).await.is_err() {
        // Over the bound on lifetime only, the key gets the longest one allowed; anything else is refused.
        attributes.expires = None;
        if let Err(problem) = bound(&console, None, &mut attributes).await {
            return cli_refused(StatusCode::FORBIDDEN, "key_bounds_exceeded", &problem);
        }
    }
    let expires = attributes.expires.clone().unwrap_or_default();
    let target = json!({
        "via": "enterplace login",
        "name": pending.email,
        "team": pending.team,
        "sha256_prefix": &id::sha256_hex(key.as_bytes())[..8],
        "expires": expires,
    });
    let act = Act {
        action: "self_issue_key",
        by: Some((&pending.email, &pending.team)),
        key: None,
        target,
    };
    if record(&console, &act, None, None).await.is_err() {
        return cli_refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
            NOT_RECORDED,
        );
    }
    let (keys, name, team, k) = (
        console.config().keys.clone(),
        pending.email.clone(),
        pending.team.clone(),
        key.clone(),
    );
    let added = tokio::task::spawn_blocking(move || {
        keyfile::add_with(&name, &team, &k, &attributes, &keys)
    })
    .await
    .unwrap_or_else(|_| Err("the change stopped before it finished".into()));
    if let Err(err) = added {
        // The record above says the key was issued; this one says it was not.
        let _ = record(&console, &act, Some("keys_file"), Some(&err)).await;
        return cli_refused(StatusCode::CONFLICT, "keys_file", &err);
    }
    // With a passthrough provider, Claude Code keeps its subscription login and the key only names the person.
    let subscriptions = config::load(&console.config().policy, Some(&console.config().keys))
        .is_ok_and(|l| l.providers.iter().any(|p| p.passthrough));
    json_answer(
        StatusCode::OK,
        &json!({ "key": key, "name": pending.email, "team": pending.team, "expires": expires, "subscriptions": subscriptions }),
    )
}

/// Counts one event in the current minute and returns the count so far.
fn per_minute(minute: &Mutex<(Instant, u64)>) -> u64 {
    let mut minute = minute
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    if now.duration_since(minute.0) >= Duration::from_secs(60) {
        *minute = (now, 0);
    }
    minute.1 += 1;
    minute.1
}

/// Why a state cookie is refused.
#[derive(Debug, PartialEq)]
enum BadState {
    /// Not sealed by this process, or sealed for another state.
    Foreign,
    Expired,
}

/// Checks a sign-in's state cookie (`state.expires.mac`) against the state the provider sent back, at `now` (Unix
/// seconds). Returns the seconds it has left.
fn state_left(
    seal: &ring::hmac::Key,
    cookie: &str,
    state: &str,
    now: u64,
) -> Result<u64, BadState> {
    let expires = (|| {
        let (sealed, sig) = cookie.rsplit_once('.')?;
        let (cookie_state, expires) = sealed.split_once('.')?;
        let sig = sso::b64url_decode(sig)?;
        ring::hmac::verify(seal, sealed.as_bytes(), &sig).ok()?;
        (!state.is_empty() && cookie_state == state).then_some(())?;
        expires.parse::<u64>().ok()
    })()
    .ok_or(BadState::Foreign)?;
    match expires.saturating_sub(now) {
        0 => Err(BadState::Expired),
        left => Ok(left),
    }
}

/// The base64url HMAC of `text` under the process's seal.
fn mac(seal: &ring::hmac::Key, text: &str) -> String {
    sso::b64url(ring::hmac::sign(seal, text.as_bytes()).as_ref())
}

/// The nonce and the PKCE verifier of a sign-in, from its state. Only this process can make them, and the verifier
/// (43 characters, as PKCE asks) never leaves it but to the token endpoint.
fn derived(seal: &ring::hmac::Key, state: &str) -> (String, String) {
    (
        mac(seal, &format!("nonce:{state}")),
        mac(seal, &format!("verifier:{state}")),
    )
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn sso_finish(console: &Console, headers: &HeaderMap, query: &Form) -> SsoResult {
    let no = |code, message: &str| {
        (
            None,
            sso::Refusal {
                code,
                message: message.to_string(),
            },
        )
    };
    let state = query.get("state");
    // The state must be the one this browser was given, under this process's seal: a sign-in started elsewhere,
    // or a cookie written by anyone else, is never finished here.
    let cookie = cookie_value(headers, SSO_COOKIE).unwrap_or_default();
    let checked = console
        .0
        .seal
        .as_ref()
        .map_or(Err(BadState::Foreign), |seal| {
            state_left(seal, &cookie, state, unix_now())
        });
    const SPENT: &str = "This sign-in has expired or was already used. Start again from the sign-in page and finish within 10 minutes.";
    let left = match checked {
        Ok(left) => left,
        Err(BadState::Expired) => return Err(no("sso_state", SPENT)),
        Err(BadState::Foreign) => {
            return Err(no(
                "sso_state",
                "The sign-in came back with a state this browser did not start, so it was refused. Start again from the sign-in page; if it repeats, allow cookies for this address.",
            ));
        }
    };
    if console.used().contains_key(state) {
        return Err(no("sso_state", SPENT));
    }
    let Some(seal) = console.0.seal.as_ref() else {
        return Err(no("sso_state", NO_RANDOM));
    };
    let (nonce, verifier) = derived(seal, state);
    if !query.get("error").is_empty() {
        let message = format!(
            "The identity provider refused the sign-in: {} {}. Fix it at the provider, or ask its admin, then start again.",
            query.get("error"),
            query.get("error_description")
        );
        return Err((
            None,
            sso::Refusal {
                code: "sso_provider",
                message,
            },
        ));
    }
    let code = query.get("code");
    if code.is_empty() {
        return Err(no(
            "sso_provider",
            "The identity provider sent the browser back without a sign-in code. Start again from the sign-in page.",
        ));
    }
    let sso = match console.sso_config() {
        Ok(Some(sso)) => sso,
        _ => {
            return Err(no(
                "sso_config",
                "Single sign-on was turned off or the policy file has problems. Run enterplace check and fix them, then start again.",
            ));
        }
    };
    let secret = enterplace_core::secrets::var(&sso.client_secret_env).unwrap_or_default();
    if secret.is_empty() {
        let message = format!(
            "The client secret variable {} is not set where Enterplace runs. Set it and restart Enterplace.",
            sso.client_secret_env
        );
        return Err((
            None,
            sso::Refusal {
                code: "sso_secret",
                message,
            },
        ));
    }
    let provider = console.provider(&sso).await.map_err(|r| (None, r))?;
    let client = &console.0.client;
    let token = sso::exchange(client, &provider, &sso, &secret, code, &verifier)
        .await
        .map_err(|r| (None, r))?;
    let claims = match sso::verify(&token, &provider, &sso, &nonce) {
        // The provider may have rotated its keys since they were cached: fetch them once more.
        Err(r) if r.code == "sso_unknown_key" => {
            let fresh = Arc::new(sso::discover(client, &sso).await.map_err(|r| (None, r))?);
            console.cache(&fresh);
            sso::verify(&token, &fresh, &sso, &nonce)
        }
        other => other,
    }
    .map_err(|r| (None, r))?;
    // Kept only now that the token verified, so only real sign-ins fill the list. Two callbacks of one state that
    // race past the check above meet here, and the second is refused.
    if !console.remember(state, left) {
        return Err(no("sso_state", SPENT));
    }
    Ok((claims, sso))
}

async fn sign_out(State(console): State<Console>, headers: HeaderMap) -> Response {
    if let Some(admin) = console.admin(&headers).await {
        let act = Act {
            action: "console_sign_out",
            by: Some((&admin.name, &admin.team)),
            key: None,
            target: Value::Null,
        };
        // Signing out goes ahead even if it cannot be recorded: ending a session never needs a record to be safe.
        let _ = record(&console, &act, None, None).await;
    }
    if let Some(id) = cookie_value(&headers, COOKIE) {
        console.end_session(&id);
    }
    let mut response = redirect("/console/sign-in?out=1");
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "enterplace_console=; Path=/console; Max-Age=0; HttpOnly; SameSite=Strict",
        ),
    );
    response
}

/// Reads a file the console shows. `None` when it does not exist yet.
fn read(path: &std::path::Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("{} cannot be read: {err}.", path.display())),
    }
}

/// When the console's data last changed: the audit log's size and time of change (a record was written), and the
/// policy and keys files' times of change. A stat of three files, no read, so it is cheap to ask often.
fn live_state(config: &ConsoleConfig) -> (String, Option<u64>) {
    let ms = |m: &std::fs::Metadata| {
        m.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| u64::try_from(d.as_millis()).ok())
    };
    let audit = std::fs::metadata(&config.audit).ok();
    // The log's time of change is when the last record was written; null before the first.
    let last = audit.as_ref().and_then(ms);
    let other = |p: &std::path::Path| std::fs::metadata(p).ok().as_ref().and_then(ms).unwrap_or(0);
    let signature = format!(
        "{}-{}-{}-{}",
        audit.as_ref().map_or(0, std::fs::Metadata::len),
        last.unwrap_or(0),
        other(&config.policy),
        other(&config.keys)
    );
    (signature, last)
}

fn not_signed_in() -> Response {
    let body = serde_json::json!({ "error": { "code": "not_signed_in", "message": "Sign in to the console again." } });
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// What the server-rendered pages ask every 2 seconds. The console app listens to /console/events instead.
async fn live_json(State(console): State<Console>, headers: HeaderMap) -> Response {
    if console.admin(&headers).await.is_none() {
        return not_signed_in();
    }
    let (signature, last) = live_state(console.config());
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "signature": signature, "last_request_ms": last }).to_string(),
    )
        .into_response()
}

/// The console app's live feed, as server-sent events: a `change` event at once, then one each time a request is
/// recorded or the policy or keys change, so open pages reload the moment there is something new. A comment every
/// 15 seconds keeps proxies from closing it; the browser reconnects by itself when it drops.
// ponytail: each open stream stats three files every 500 ms. A notification from the audit writer is the upgrade if
// streams are counted in hundreds.
async fn events(State(console): State<Console>, headers: HeaderMap) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    if console.admin(&headers).await.is_none() {
        return not_signed_in();
    }
    let stream =
        futures_util::stream::unfold((console, String::new()), |(console, seen)| async move {
            loop {
                let (signature, last) = live_state(console.config());
                if signature != seen {
                    let data =
                        serde_json::json!({ "signature": signature, "last_request_ms": last })
                            .to_string();
                    let event = Event::default().event("change").data(data);
                    return Some((
                        Ok::<_, std::convert::Infallible>(event),
                        (console, signature),
                    ));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// The chain a person reads on the audit page, by organization (`""` for the install's) and path. Someone kept to an
/// organization reads its own chain when it has one (`audit: { per_org: true }`); anyone else may pick one with
/// `?chain=<org>`.
fn chain_for(admin: &Admin, audit: &std::path::Path, query: &Form) -> (String, std::path::PathBuf) {
    let wanted = match &admin.org {
        Some(org) => org.clone(),
        None => query.get("chain").trim().to_string(),
    };
    let own = audit::org_path(audit, &wanted);
    if !wanted.is_empty() && own.exists() {
        (wanted, own)
    } else {
        (String::new(), audit.to_path_buf())
    }
}

/// The records a person may see on the spend and people pages: their organization's chain, or their records in the
/// install's; for someone kept to no organization, every chain one after another.
fn records_for(admin: &Admin, audit: &std::path::Path) -> Result<Option<String>, String> {
    if let Some(org) = &admin.org {
        let own = audit::org_path(audit, org);
        if own.exists() {
            return read(&own);
        }
        return log_for(admin, read(audit));
    }
    let mut text = read(audit)?;
    for (_, at) in audit::org_chains(audit).unwrap_or_default() {
        if let Some(more) = read(&at)? {
            text.get_or_insert_with(String::new).push_str(&more);
        }
    }
    Ok(text)
}

/// The audit log as a person may see it: whole, or only their organization's records.
fn log_for(admin: &Admin, log: Result<Option<String>, String>) -> Result<Option<String>, String> {
    if !admin.confined() {
        return log;
    }
    log.map(|text| {
        text.map(|text| {
            text.lines()
                .filter(|line| admin.sees(line))
                .map(|line| format!("{line}\n"))
                .collect()
        })
    })
}

/// Restore traffic: turns a kill switch off, as `enterplace unkill` and `DELETE /admin/kills` do, recorded first.
async fn restore_traffic(
    State(console): State<Console>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    if !admin.may(Permission::Kill) {
        read_only(&console, &admin, "clear_kill").await;
        return redirect("/console/audit");
    }
    let form = Form::parse(&body);
    let (scope, value) = (form.get("scope").to_string(), form.get("value").to_string());
    let Ok(value) = enterplace_core::kill::checked(&scope, &value, "-") else {
        return redirect("/console/audit");
    };
    let act = Act {
        action: "clear_kill",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "scope": scope, "value": value }),
    };
    if record(&console, &act, None, None).await.is_err() {
        return redirect("/console/audit");
    }
    let switches = enterplace_core::kill::Switches::open(enterplace_core::kill::path_beside(
        &console.config().keys,
    ));
    let _ = tokio::task::spawn_blocking(move || switches.clear(&scope, &value)).await;
    redirect("/console/audit")
}

/// The keys file as a person may see it: whole, or written again with only their organization's keys.
fn keys_for(
    admin: &Admin,
    path: &std::path::Path,
    text: Result<Option<String>, String>,
) -> Result<Option<String>, String> {
    if !admin.confined() {
        return text;
    }
    text.map(|text| {
        text.map(|text| {
            let entries = config::key_entries(path, &text).unwrap_or_default();
            let mine: Vec<config::KeyEntry> = entries
                .into_iter()
                .filter(|e| admin.covers_entry(e))
                .collect();
            keyfile::keys_text(&mine)
        })
    })
}

/// Holds a key about to be issued to the policy's `key_bounds:` for `role` (`None`: a key from `enterplace login`).
async fn bound(
    console: &Console,
    role: Option<&str>,
    attributes: &mut keyfile::Attributes,
) -> Result<(), String> {
    let (policy, keys) = (
        console.config().policy.clone(),
        console.config().keys.clone(),
    );
    let loaded = tokio::task::spawn_blocking(move || config::load(&policy, Some(&keys)))
        .await
        .map_err(|_| {
            "the policy could not be read to check the key's bounds. Try again.".to_string()
        })?
        .map_err(|problems| problems.join("\n"))?;
    config::bound_key(
        &loaded.policy,
        role,
        &mut attributes.expires,
        &mut attributes.budget,
        &mut attributes.models,
    )
    .map_err(|problem| {
        let mut chars = problem.chars();
        let first: String = chars
            .next()
            .into_iter()
            .flat_map(char::to_uppercase)
            .collect();
        format!("{first}{}.", chars.as_str())
    })
}

/// Makes a key and adds it to the keys file, recorded first: the record names the key by its hash prefix, so the
/// key is made before the record and shown only after both.
async fn issued(
    console: &Console,
    admin: &Admin,
    name: &str,
    team: &str,
    attributes: keyfile::Attributes,
) -> Result<(String, bool), String> {
    issued_as(console, admin, name, team, attributes, false).await
}

/// `issued`, or with `person_token` a person token (`enterplace_u_...`): it names the person for Claude subscription
/// passthrough and reaches no model on its own.
async fn issued_as(
    console: &Console,
    admin: &Admin,
    name: &str,
    team: &str,
    mut attributes: keyfile::Attributes,
    person_token: bool,
) -> Result<(String, bool), String> {
    // What the person's role may grant (`key_bounds:`): what the key leaves unset takes the bound.
    bound(console, Some(&admin.role), &mut attributes).await?;
    let admin_key = attributes.admin;
    let mut act = Act {
        action: "issue_key",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "name": name, "team": team, "admin": admin_key }),
    };
    if !config::valid_name(name) || !config::valid_name(team) {
        let _ = record(console, &act, Some("invalid_request"), None).await;
        return Err("A name and a team use letters, digits, dots, dashes and underscores only, for example maya.cohen and payments.".into());
    }
    let key = if person_token {
        attributes = person_token_attributes(attributes);
        id::new_person_token()?
    } else {
        id::new_key()?
    };
    act.target = json!({ "name": name, "team": team, "sha256_prefix": &id::sha256_hex(key.as_bytes())[..8], "admin": admin_key });
    if person_token {
        act.target["person_token"] = true.into();
    }
    record(console, &act, None, None)
        .await
        .map_err(|()| NOT_RECORDED.to_string())?;
    let (n, t, k, path) = (
        name.to_string(),
        team.to_string(),
        key.clone(),
        console.config().keys.clone(),
    );
    let added =
        tokio::task::spawn_blocking(move || keyfile::add_with(&n, &t, &k, &attributes, &path))
            .await
            .unwrap_or_else(|err| Err(format!("The key was not made: {err}. Try again.")));
    match added {
        Ok(rotated) => Ok((key, rotated)),
        Err(error) => {
            // The record above says it was allowed; this one says it did not happen.
            let _ = record(console, &act, Some("keys_file"), Some(&error)).await;
            Err(error)
        }
    }
}

/// Records a change refused to a read-only person. The page says why in its banner.
async fn read_only(console: &Console, admin: &Admin, action: &'static str) {
    let act = Act {
        action,
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "reason": "signed in read only" }),
    };
    let _ = record(console, &act, Some("read_only"), None).await;
}

/// Removes a key's entry, recorded first. The last admin key is never removed: nobody could sign in again.
async fn revoked(console: &Console, admin: &Admin, entry: &config::KeyEntry) -> Result<(), String> {
    let act = Act {
        action: "revoke_key",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "name": entry.name, "team": entry.team, "sha256_prefix": &entry.sha256[..8], "admin": entry.admin }),
    };
    let keys = console.config().keys.clone();
    // ponytail: checked here and not inside the file change, so two admins revoking the last two admin keys at the
    // same moment could both pass. The keys file can always be edited by hand to add one back.
    let admins = config::read_keys(&keys)
        .ok()
        .flatten()
        .and_then(|text| config::key_entries(&keys, &text).ok())
        .map_or(0, |entries| entries.iter().filter(|e| e.admin).count());
    if entry.admin && admins <= 1 {
        let _ = record(console, &act, Some("last_admin"), None).await;
        return Err("This is the only admin key. Make another key an admin key first, so someone can still sign in.".into());
    }
    record(console, &act, None, None)
        .await
        .map_err(|()| NOT_RECORDED.to_string())?;
    let sha256 = entry.sha256.clone();
    let done = tokio::task::spawn_blocking(move || keyfile::revoke(&keys, &sha256))
        .await
        .unwrap_or_else(|err| Err(format!("Nothing was changed: {err}. Try again.")));
    let error = match done {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {
            "The keys file no longer has this key: someone removed it already. Nothing was changed."
                .to_string()
        }
        Err(error) => error,
    };
    let _ = record(console, &act, Some("keys_file"), Some(&error)).await;
    Err(error)
}

/// Static files are served without a session: the sign-in page needs them.
async fn asset(Path(file): Path<String>) -> Response {
    let (kind, body): (&str, &'static str) = match file.as_str() {
        "tokens.css" => (
            "text/css; charset=utf-8",
            include_str!("../assets/tokens.css"),
        ),
        "bundle.css" => (
            "text/css; charset=utf-8",
            include_str!("../assets/bundle.css"),
        ),
        "console.css" => (
            "text/css; charset=utf-8",
            include_str!("../assets/console.css"),
        ),
        "console.js" => (
            "text/javascript; charset=utf-8",
            include_str!("../assets/console.js"),
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut response = ([(header::CONTENT_TYPE, kind)], body).into_response();
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn font(Path(file): Path<String>) -> Response {
    let body: &'static [u8] = match file.as_str() {
        "FamiljenGrotesk-Variable.woff2" => {
            include_bytes!("../assets/fonts/FamiljenGrotesk-Variable.woff2")
        }
        "FragmentMono-Regular.woff2" => {
            include_bytes!("../assets/fonts/FragmentMono-Regular.woff2")
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        Body::from(body),
    )
        .into_response()
}

// ---- First run ----

/// Where the setup link stands for this token.
enum SetupState {
    Open,
    Used,
    Unknown,
}

fn setup_state(console: &Console, token: &str) -> SetupState {
    let setup = console
        .0
        .setup
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match setup.as_ref() {
        Some((known, used))
            if id::sha256_hex(known.as_bytes()) == id::sha256_hex(token.as_bytes()) =>
        {
            if *used {
                SetupState::Used
            } else {
                SetupState::Open
            }
        }
        _ => SetupState::Unknown,
    }
}

fn setup_closed(state: SetupState) -> Response {
    match state {
        SetupState::Used => page(
            StatusCode::GONE,
            pages::setup_message(
                "This setup link was used",
                "The first admin key was made with it, and it works once. Sign in to the console with that key, or make another with enterplace key new <name> --team <team> --admin.",
            ),
        ),
        _ => page(
            StatusCode::NOT_FOUND,
            pages::setup_message(
                "No such setup link",
                "Use the link enterplace serve printed when it started. It is offered only while no admin key exists.",
            ),
        ),
    }
}

async fn setup_page(State(console): State<Console>, Path(token): Path<String>) -> Response {
    match setup_state(&console, &token) {
        SetupState::Open => page(StatusCode::OK, pages::setup_form(&token, "")),
        other => setup_closed(other),
    }
}

async fn setup_done(
    State(console): State<Console>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let form = Form::parse(&body);
    let (name, team) = (
        form.get("name").trim().to_string(),
        form.get("team").trim().to_string(),
    );
    if !config::valid_name(&name) || !config::valid_name(&team) {
        return match setup_state(&console, &token) {
            SetupState::Open => page(
                StatusCode::BAD_REQUEST,
                pages::setup_form(
                    &token,
                    "A name and a team use letters, digits, dots, dashes and underscores only, for example maya.cohen and platform.",
                ),
            ),
            other => setup_closed(other),
        };
    }
    // Taken under the lock, so two submissions at once make one key.
    {
        let mut setup = console
            .0
            .setup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match setup.as_mut() {
            Some((known, used)) if *known == token && !*used => *used = true,
            Some((known, true)) if *known == token => return setup_closed(SetupState::Used),
            _ => return setup_closed(SetupState::Unknown),
        }
    }
    let reopen = || {
        if let Some((_, used)) = console
            .0
            .setup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            *used = false;
        }
    };
    let act = Act {
        action: "first_setup",
        by: None,
        key: None,
        target: json!({ "name": name, "team": team, "admin": true }),
    };
    // Recorded before the key exists: Enterplace does not make what it cannot record.
    if record(&console, &act, None, None).await.is_err() {
        reopen();
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::setup_message("Not done", NOT_RECORDED),
        );
    }
    let attributes = keyfile::Attributes {
        admin: true,
        ..keyfile::Attributes::default()
    };
    let issued = match keyfile::issue_with(&name, &team, &attributes, &console.config().keys) {
        Ok(issued) => issued,
        Err(err) => {
            reopen();
            return page(
                StatusCode::INTERNAL_SERVER_ERROR,
                pages::setup_message("Not done", &err),
            );
        }
    };
    first_admin_token(&console, &name, &team).await;
    let origin = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map_or_else(
            || "http://127.0.0.1:8080".to_string(),
            |host| format!("http://{host}"),
        );
    // The models this policy serves, for the test call and the prompt for a coding agent.
    let mut models: Vec<String> =
        config::load(&console.config().policy, Some(&console.config().keys))
            .map(|l| {
                l.providers
                    .iter()
                    .flat_map(|p| p.models.clone())
                    .filter(|m| m != "*")
                    .collect()
            })
            .unwrap_or_default();
    models.dedup();
    page(
        StatusCode::OK,
        pages::setup_result(&issued.key, &origin, &models),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_a_session_is_for_reads_back_as_written() {
        for who in [
            Who::Key("ab12".into()),
            Who::Sso {
                email: "maya@acme.com".into(),
                role: "read_only".into(),
                team: String::new(),
            },
            Who::Sso {
                email: "lee@acme.com".into(),
                role: "admin".into(),
                team: "payments".into(),
            },
            Who::Sso {
                email: "fin@acme.com".into(),
                role: "finance".into(),
                team: String::new(),
            },
            Who::Account("acct 7".into()),
        ] {
            let text = who_text(&who);
            assert_eq!(who_of(&text).map(|w| who_text(&w)), Some(text));
        }
        assert!(who_of("root everything").is_none());
        // A session opened before teams reads back with no team.
        assert!(
            matches!(who_of("sso admin lee@acme.com"), Some(Who::Sso { team, .. }) if team.is_empty())
        );
    }

    #[test]
    fn a_sealed_state_cookie_expires_and_only_fits_its_own_state() {
        // QA11-3: the expiry is checked on a cookie whose seal is valid, not only on one whose seal is broken.
        let seal = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test seal");
        let cookie = |state: &str, expires: u64| {
            let sealed = format!("{state}.{expires}");
            format!("{sealed}.{}", mac(&seal, &sealed))
        };
        let now = 1_800_000_000;
        assert_eq!(
            state_left(&seal, &cookie("s1", now + 600), "s1", now),
            Ok(600)
        );
        assert_eq!(
            state_left(&seal, &cookie("s1", now - 1), "s1", now),
            Err(BadState::Expired)
        );
        assert_eq!(
            state_left(&seal, &cookie("s1", now), "s1", now),
            Err(BadState::Expired)
        );
        assert_eq!(
            state_left(&seal, &cookie("s1", now + 600), "s2", now),
            Err(BadState::Foreign)
        );
        let other = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"another process");
        assert_eq!(
            state_left(&other, &cookie("s1", now + 600), "s1", now),
            Err(BadState::Foreign)
        );
        assert_eq!(
            state_left(&seal, &cookie("", now + 600), "", now),
            Err(BadState::Foreign)
        );
    }
}
