//! Cloud credentials for Amazon Bedrock and Vertex AI, taken from the platform Gantry runs on and renewed before
//! they expire, so a pod, task or VM needs no static key and no restart. Each source is a documented HTTP call; no
//! cloud SDK is linked.
//!
//! AWS, in the order of the AWS SDKs' default chain, as documented on 2026-11-13:
//! - access keys in the environment;
//! - a web identity token file exchanged at STS, as IRSA on EKS sets it up
//!   (<https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html>);
//! - the container credentials endpoint of ECS tasks and EKS Pod Identity
//!   (<https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html>);
//! - the EC2 instance metadata service, IMDSv2
//!   (<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-retrieval.html>).
//!
//! With a `role_arn` on the provider, the credentials found then assume that role
//! (<https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html>).
//!
//! Google, in the order of Application Default Credentials
//! (<https://cloud.google.com/docs/authentication/application-default-credentials>):
//! - the file in GOOGLE_APPLICATION_CREDENTIALS: a service account key signed into a token with a JWT
//!   (<https://developers.google.com/identity/protocols/oauth2/service-account#httprest>), or a gcloud user file;
//! - gcloud's application default credentials file;
//! - the metadata server of GCE, GKE with Workload Identity, and Cloud Run
//!   (<https://cloud.google.com/compute/docs/access/authenticate-workloads#applications>).

use std::sync::{Arc, RwLock, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::http::{HeaderValue, Method, Request, Uri};
use gantry_core::sigv4;
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use serde_json::Value;

/// Renewal starts this long before credentials expire, or halfway through their life when that comes first.
const MARGIN: Duration = Duration::from_secs(300);
/// After a failed renewal, the next try. The credentials in hand are used meanwhile.
const RETRY: Duration = Duration::from_secs(30);
/// One call to a credential endpoint. The metadata services answer in milliseconds where they exist; where they
/// do not, a short connect timeout keeps the start quick.
const CALL: Duration = Duration::from_secs(5);
const CONNECT: Duration = Duration::from_secs(1);
const FORM: &str = "application/x-www-form-urlencoded";
const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
const SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

type Http = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Looks up an environment variable. `governed` passes the process environment; tests pass a map.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Credentials kept current by a thread of their own. Clones share them, and reading never waits on a renewal.
#[derive(Clone)]
pub struct Live<T> {
    value: Arc<RwLock<T>>,
    source: Arc<str>,
}

impl<T: Clone> Live<T> {
    /// Credentials that never change, such as access keys handed over by an embedding program or a test.
    pub fn fixed(value: T, source: &str) -> Self {
        Live {
            value: Arc::new(RwLock::new(value)),
            source: source.into(),
        }
    }

    pub fn get(&self) -> T {
        match self.value.read() {
            Ok(value) => value.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Where the credentials come from, for the start line. It never holds a secret.
    pub fn source(&self) -> &str {
        &self.source
    }
}

impl<T> std::fmt::Debug for Live<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[credentials from {}]", self.source)
    }
}

impl From<sigv4::Credentials> for Live<sigv4::Credentials> {
    fn from(credentials: sigv4::Credentials) -> Self {
        Live::fixed(credentials, "the access key given")
    }
}

struct Fetched<T> {
    value: T,
    expires: Option<SystemTime>,
}

trait Source {
    type Out;
    fn describe(&self) -> String;
    async fn fetch(&self, http: &Http) -> Result<Fetched<Self::Out>, String>;
}

/// The AWS credentials for a Bedrock provider: the first source of the default chain that answers, renewed in the
/// background. Blocks until that first answer, at start.
pub fn aws(
    provider: &str,
    region: &str,
    role_arn: Option<&str>,
    env: Env<'_>,
) -> Result<Live<sigv4::Credentials>, String> {
    let var = |name: &str| {
        env(name)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let mut chain = Vec::new();
    if let (Some(id), Some(secret)) = (var("AWS_ACCESS_KEY_ID"), var("AWS_SECRET_ACCESS_KEY")) {
        chain.push(Aws::Env(sigv4::Credentials {
            access_key_id: id,
            secret_access_key: secret,
            session_token: var("AWS_SESSION_TOKEN"),
        }));
    }
    let sts_region = var("AWS_REGION")
        .or_else(|| var("AWS_DEFAULT_REGION"))
        .unwrap_or_else(|| region.to_string());
    let sts = var("AWS_ENDPOINT_URL_STS")
        .or_else(|| var("AWS_ENDPOINT_URL"))
        .unwrap_or_else(|| format!("https://sts.{sts_region}.amazonaws.com"))
        .trim_end_matches('/')
        .to_string();
    if let (Some(token_file), Some(role)) =
        (var("AWS_WEB_IDENTITY_TOKEN_FILE"), var("AWS_ROLE_ARN"))
    {
        chain.push(Aws::WebIdentity {
            token_file,
            role,
            session: var("AWS_ROLE_SESSION_NAME").unwrap_or_else(|| "gantry".into()),
            sts: sts.clone(),
        });
    }
    let container = var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        .map(|path| format!("http://169.254.170.2{path}"))
        .or_else(|| var("AWS_CONTAINER_CREDENTIALS_FULL_URI"));
    if let Some(url) = container {
        chain.push(Aws::Container {
            url,
            token_file: var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"),
            token: var("AWS_CONTAINER_AUTHORIZATION_TOKEN"),
        });
    }
    if !var("AWS_EC2_METADATA_DISABLED").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        chain.push(Aws::Imds {
            endpoint: var("AWS_EC2_METADATA_SERVICE_ENDPOINT")
                .unwrap_or_else(|| "http://169.254.169.254".into())
                .trim_end_matches('/')
                .to_string(),
        });
    }
    let chain = chain
        .into_iter()
        .map(|base| Assumed {
            base,
            role: role_arn.map(String::from),
            sts: sts.clone(),
            region: sts_region.clone(),
        })
        .collect();
    start(provider, chain).map_err(|tried| {
        format!(
            "provider \"{provider}\" is on Amazon Bedrock, and Gantry found no AWS credentials. It tried, in order: {tried}. Run Gantry with a role (IRSA or Pod Identity on EKS, a task role on ECS, an instance profile on EC2), or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, and start again."
        )
    })
}

/// The OAuth access token for a Vertex AI provider, as the `Authorization` header it is sent in: the first source
/// of Application Default Credentials that answers, renewed in the background. Blocks until that first answer.
pub fn google(provider: &str, env: Env<'_>) -> Result<Live<HeaderValue>, String> {
    let var = |name: &str| {
        env(name)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let mut chain = Vec::new();
    if let Some(path) = var("GOOGLE_APPLICATION_CREDENTIALS") {
        chain.push(Google::File {
            path,
            named_by: "GOOGLE_APPLICATION_CREDENTIALS",
        });
    }
    let well_known = var("CLOUDSDK_CONFIG")
        .or_else(|| var("HOME").map(|home| format!("{home}/.config/gcloud")))
        .map(|dir| format!("{dir}/application_default_credentials.json"));
    // Only when it is there: most servers have no gcloud sign-in, and its absence is not a failure.
    if let Some(path) = well_known.filter(|p| std::path::Path::new(p).is_file()) {
        chain.push(Google::File {
            path,
            named_by: "gcloud auth application-default login",
        });
    }
    chain.push(Google::Metadata {
        host: var("GCE_METADATA_HOST").unwrap_or_else(|| "169.254.169.254".into()),
    });
    start(provider, chain).map_err(|tried| {
        format!(
            "provider \"{provider}\" is on Vertex AI, and Gantry found no Google credentials. It tried, in order: {tried}. Run Gantry with a service account (attached to the VM or Cloud Run service, or through GKE Workload Identity), set GOOGLE_APPLICATION_CREDENTIALS to a service account key file, or set key_env to a variable holding an access token, and start again."
        )
    })
}

/// Finds the first source that answers, on a thread with a runtime of its own so that it works from any caller,
/// and keeps renewing from that source on the same thread until the credentials are no longer used.
/// ponytail: one thread per cloud provider in the policy; share one when policies list many such providers.
fn start<S>(provider: &str, chain: Vec<S>) -> Result<Live<S::Out>, String>
where
    S: Source + Send + 'static,
    S::Out: Clone + Send + Sync + 'static,
{
    let (tell, hear) = mpsc::channel();
    let name = provider.to_string();
    std::thread::Builder::new()
        .name("gantry-credentials".into())
        .spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(keep(name, chain, tell)),
                Err(err) => {
                    let _ = tell.send(Err(format!("no runtime could be started ({err})")));
                }
            }
        })
        .map_err(|err| format!("the thread that fetches credentials could not start ({err})"))?;
    hear.recv()
        .map_err(|_| "the thread that fetches credentials stopped".to_string())?
}

async fn keep<S: Source>(
    provider: String,
    chain: Vec<S>,
    tell: mpsc::Sender<Result<Live<S::Out>, String>>,
) where
    S::Out: Clone,
{
    let http = client();
    let mut failures = Vec::new();
    let mut chosen = None;
    for source in chain {
        match source.fetch(&http).await {
            Ok(first) => {
                chosen = Some((source, first));
                break;
            }
            Err(err) => failures.push(format!("{} ({err})", source.describe())),
        }
    }
    let Some((source, first)) = chosen else {
        let tried = if failures.is_empty() {
            "nothing, as no source is set up".to_string()
        } else {
            failures.join("; ")
        };
        let _ = tell.send(Err(tried));
        return;
    };
    let live = Live {
        value: Arc::new(RwLock::new(first.value)),
        source: source.describe().into(),
    };
    let held = Arc::downgrade(&live.value);
    let Some(mut expires) = first.expires else {
        let _ = tell.send(Ok(live));
        return;
    };
    if tell.send(Ok(live)).is_err() {
        return;
    }
    let mut wait = renew_in(expires);
    loop {
        tokio::time::sleep(wait).await;
        let Some(value) = held.upgrade() else {
            return;
        };
        match source.fetch(&http).await {
            Ok(next) => {
                match value.write() {
                    Ok(mut slot) => *slot = next.value,
                    Err(poisoned) => *poisoned.into_inner() = next.value,
                }
                let Some(at) = next.expires else {
                    return;
                };
                expires = at;
                wait = renew_in(expires);
            }
            Err(err) => {
                eprintln!(
                    "gantry: provider \"{provider}\" could not renew its credentials from {}: {err}. It keeps the ones it has, which expire at {}, and tries again in {} seconds.",
                    source.describe(),
                    gantry_core::audit::rfc3339(expires),
                    RETRY.as_secs()
                );
                wait = RETRY;
            }
        }
    }
}

fn renew_in(expires: SystemTime) -> Duration {
    let left = expires
        .duration_since(SystemTime::now())
        .unwrap_or_default();
    left.saturating_sub(MARGIN)
        .max(left / 2)
        .max(Duration::from_secs(1))
}

fn client() -> Http {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(CONNECT));
    connector.enforce_http(false);
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);
    Client::builder(TokioExecutor::new()).build(connector)
}

/// One call. A non-2xx answer is an error that carries the status and the start of the body, which from these
/// endpoints is an error code, never a credential.
async fn call(
    http: &Http,
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> Result<String, String> {
    let mut request = Request::builder().method(method).uri(url);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .map_err(|err| format!("{url} cannot be called ({err})"))?;
    let answer = tokio::time::timeout(CALL, async {
        let response = http
            .request(request)
            .await
            .map_err(|err| format!("{url} could not be reached: {err}"))?;
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|err| format!("{url} broke off its answer: {err}"))?
            .to_bytes();
        Ok::<_, String>((status, String::from_utf8_lossy(&bytes).into_owned()))
    })
    .await
    .map_err(|_| format!("{url} did not answer within {} seconds", CALL.as_secs()))?;
    let (status, text) = answer?;
    if !status.is_success() {
        let start: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let start: String = start.chars().take(200).collect();
        return Err(format!("{url} answered {status}: {start}"));
    }
    Ok(text)
}

fn form(fields: &[(&str, &str)]) -> Vec<u8> {
    fields
        .iter()
        .map(|(name, value)| format!("{name}={}", sigv4::uri_encode(value, false)))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

fn read_trimmed(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|text| text.trim().to_string())
        .map_err(|err| format!("{path} cannot be read: {err}"))
}

enum Aws {
    Env(sigv4::Credentials),
    WebIdentity {
        token_file: String,
        role: String,
        session: String,
        sts: String,
    },
    Container {
        url: String,
        token_file: Option<String>,
        token: Option<String>,
    },
    Imds {
        endpoint: String,
    },
}

impl Source for Aws {
    type Out = sigv4::Credentials;

    fn describe(&self) -> String {
        match self {
            Aws::Env(_) => "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment".into(),
            Aws::WebIdentity {
                token_file, role, ..
            } => format!(
                "the web identity token in {token_file} for role {role} (AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN, as IRSA sets them)"
            ),
            Aws::Container { url, .. } => format!(
                "the container credentials endpoint {url} (the ECS task role or EKS Pod Identity)"
            ),
            Aws::Imds { endpoint } => {
                format!(
                    "the EC2 instance profile, from the instance metadata service at {endpoint}"
                )
            }
        }
    }

    async fn fetch(&self, http: &Http) -> Result<Fetched<sigv4::Credentials>, String> {
        match self {
            Aws::Env(credentials) => Ok(Fetched {
                value: credentials.clone(),
                expires: None,
            }),
            Aws::WebIdentity {
                token_file,
                role,
                session,
                sts,
            } => {
                // Read at every renewal: the platform rotates the file.
                let token = read_trimmed(token_file)?;
                let body = form(&[
                    ("Action", "AssumeRoleWithWebIdentity"),
                    ("Version", "2011-06-15"),
                    ("RoleArn", role),
                    ("RoleSessionName", session),
                    ("WebIdentityToken", &token),
                ]);
                let xml = call(
                    http,
                    Method::POST,
                    &format!("{sts}/"),
                    &[("content-type", FORM)],
                    body,
                )
                .await?;
                sts_credentials(&xml)
            }
            Aws::Container {
                url,
                token_file,
                token,
            } => {
                local_or_tls(url)?;
                let token = match (token_file, token) {
                    (Some(path), _) => Some(read_trimmed(path)?),
                    (None, token) => token.clone(),
                };
                let headers: Vec<(&str, &str)> = token
                    .as_deref()
                    .map(|t| ("authorization", t))
                    .into_iter()
                    .collect();
                let json = call(http, Method::GET, url, &headers, Vec::new()).await?;
                json_credentials(&json)
            }
            Aws::Imds { endpoint } => {
                let token = call(
                    http,
                    Method::PUT,
                    &format!("{endpoint}/latest/api/token"),
                    &[("x-aws-ec2-metadata-token-ttl-seconds", "21600")],
                    Vec::new(),
                )
                .await?;
                let token = token.trim();
                let auth = [("x-aws-ec2-metadata-token", token)];
                let roles = format!("{endpoint}/latest/meta-data/iam/security-credentials/");
                let list = call(http, Method::GET, &roles, &auth, Vec::new()).await?;
                let Some(role) = list.lines().map(str::trim).find(|l| !l.is_empty()) else {
                    return Err("the instance has no instance profile. Attach one whose role may call bedrock:InvokeModel".into());
                };
                let json = call(
                    http,
                    Method::GET,
                    &format!("{roles}{role}"),
                    &auth,
                    Vec::new(),
                )
                .await?;
                json_credentials(&json)
            }
        }
    }
}

/// The SDKs accept a plain HTTP credentials URL only on this machine or at the addresses ECS and EKS use, so a
/// mistyped variable cannot send a pod's token across the network unencrypted.
fn local_or_tls(url: &str) -> Result<(), String> {
    let uri: Uri = url.parse().map_err(|_| {
        format!("AWS_CONTAINER_CREDENTIALS_FULL_URI is \"{url}\", which is not a URL")
    })?;
    if uri.scheme_str() == Some("https") {
        return Ok(());
    }
    let host = uri.host().unwrap_or_default().trim_matches(['[', ']']);
    let allowed = host == "localhost"
        || ["169.254.170.2", "169.254.170.23", "fd00:ec2::23"].contains(&host)
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if allowed {
        Ok(())
    } else {
        Err(format!(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI is {url}: plain HTTP is used only for a loopback address or the ECS and EKS addresses (169.254.170.2, 169.254.170.23). Use https or one of those"
        ))
    }
}

/// The base source, then, when the provider names a role, that role assumed with what the base source gave.
struct Assumed {
    base: Aws,
    role: Option<String>,
    sts: String,
    region: String,
}

impl Source for Assumed {
    type Out = sigv4::Credentials;

    fn describe(&self) -> String {
        match &self.role {
            Some(role) => format!("{}, assuming role {role}", self.base.describe()),
            None => self.base.describe(),
        }
    }

    async fn fetch(&self, http: &Http) -> Result<Fetched<sigv4::Credentials>, String> {
        let base = self.base.fetch(http).await?;
        let Some(role) = &self.role else {
            return Ok(base);
        };
        let url = format!("{}/", self.sts);
        let uri: Uri = url
            .parse()
            .map_err(|_| format!("the STS endpoint {url} is not a URL"))?;
        let host = uri
            .authority()
            .map(|a| a.as_str().to_string())
            .unwrap_or_default();
        let body = form(&[
            ("Action", "AssumeRole"),
            ("Version", "2011-06-15"),
            ("RoleArn", role),
            ("RoleSessionName", "gantry"),
        ]);
        let signed = sigv4::sign(
            &base.value,
            &self.region,
            "sts",
            &sigv4::Request {
                method: "POST",
                path: "/",
                query: "",
                headers: &[("host", &host), ("content-type", FORM)],
                payload: &body,
            },
            &sigv4::amz_date_now(),
        );
        let mut headers = vec![("content-type", FORM)];
        headers.extend(signed.iter().map(|(name, value)| (*name, value.as_str())));
        let xml = call(http, Method::POST, &url, &headers, body)
            .await
            .map_err(|err| format!("assuming {role} failed: {err}"))?;
        sts_credentials(&xml)
    }
}

fn sts_credentials(xml: &str) -> Result<Fetched<sigv4::Credentials>, String> {
    let tag = |name: &str| {
        xml.split(&format!("<{name}>"))
            .nth(1)?
            .split(&format!("</{name}>"))
            .next()
            .map(|v| v.trim().to_string())
    };
    match (tag("AccessKeyId"), tag("SecretAccessKey")) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Fetched {
            value: sigv4::Credentials {
                access_key_id,
                secret_access_key,
                session_token: tag("SessionToken"),
            },
            expires: tag("Expiration").as_deref().and_then(parse_time),
        }),
        _ => Err("STS answered without credentials".into()),
    }
}

fn json_credentials(text: &str) -> Result<Fetched<sigv4::Credentials>, String> {
    let json: Value =
        serde_json::from_str(text).map_err(|_| "the answer is not JSON".to_string())?;
    let field = |name: &str| json.get(name).and_then(Value::as_str).map(String::from);
    if let Some(code) = field("Code").filter(|c| c != "Success") {
        return Err(format!(
            "the answer says {code}: {}",
            field("Message").unwrap_or_default()
        ));
    }
    match (field("AccessKeyId"), field("SecretAccessKey")) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Fetched {
            value: sigv4::Credentials {
                access_key_id,
                secret_access_key,
                session_token: field("Token"),
            },
            expires: field("Expiration").as_deref().and_then(parse_time),
        }),
        _ => Err("the answer holds no AccessKeyId and SecretAccessKey".into()),
    }
}

/// `2026-11-13T12:00:00Z` as a time. Calendar date to days by Howard Hinnant's days-from-civil.
fn parse_time(text: &str) -> Option<SystemTime> {
    let num = |at: std::ops::Range<usize>| text.get(at)?.parse::<i64>().ok();
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).ok()?))
}

enum Google {
    File {
        path: String,
        named_by: &'static str,
    },
    Metadata {
        host: String,
    },
}

impl Source for Google {
    type Out = HeaderValue;

    fn describe(&self) -> String {
        match self {
            Google::File { path, named_by } => format!("the credentials file {path} ({named_by})"),
            Google::Metadata { host } => format!(
                "the metadata server at {host} (the service account of the GCE VM, GKE pod with Workload Identity, or Cloud Run service)"
            ),
        }
    }

    async fn fetch(&self, http: &Http) -> Result<Fetched<HeaderValue>, String> {
        let json = match self {
            Google::Metadata { host } => {
                call(
                    http,
                    Method::GET,
                    &format!(
                        "http://{host}/computeMetadata/v1/instance/service-accounts/default/token"
                    ),
                    &[("metadata-flavor", "Google")],
                    Vec::new(),
                )
                .await?
            }
            Google::File { path, .. } => {
                let text = std::fs::read_to_string(path)
                    .map_err(|err| format!("{path} cannot be read: {err}"))?;
                let file: Value = serde_json::from_str(&text)
                    .map_err(|_| format!("{path} is not a JSON credentials file"))?;
                let field = |name: &str| file.get(name).and_then(Value::as_str).unwrap_or_default();
                let token_uri = Some(field("token_uri"))
                    .filter(|u| !u.is_empty())
                    .unwrap_or(GOOGLE_TOKEN);
                let body = match field("type") {
                    "service_account" => {
                        let jwt = assertion(
                            field("client_email"),
                            field("private_key"),
                            field("private_key_id"),
                            token_uri,
                        )
                        .map_err(|err| format!("{path}: {err}"))?;
                        form(&[
                            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                            ("assertion", &jwt),
                        ])
                    }
                    "authorized_user" => form(&[
                        ("grant_type", "refresh_token"),
                        ("client_id", field("client_id")),
                        ("client_secret", field("client_secret")),
                        ("refresh_token", field("refresh_token")),
                    ]),
                    other => {
                        return Err(format!(
                            "{path} is of type \"{other}\", which Gantry does not sign in with. Use a service account key (type service_account) or `gcloud auth application-default login` (type authorized_user), or run on Google Cloud with a service account attached"
                        ));
                    }
                };
                call(
                    http,
                    Method::POST,
                    token_uri,
                    &[("content-type", FORM)],
                    body,
                )
                .await?
            }
        };
        let answer: Value =
            serde_json::from_str(&json).map_err(|_| "the token answer is not JSON".to_string())?;
        let token = answer
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or("the token answer holds no access_token")?;
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| "the access token cannot go in an HTTP header".to_string())?;
        value.set_sensitive(true);
        let lasts = answer
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(3600);
        Ok(Fetched {
            value,
            expires: Some(SystemTime::now() + Duration::from_secs(lasts)),
        })
    }
}

/// A JWT signed with the service account's key (RS256), which Google's token endpoint trades for an access token.
fn assertion(email: &str, pem: &str, key_id: &str, audience: &str) -> Result<String, String> {
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": key_id});
    let claims = serde_json::json!({
        "iss": email, "scope": SCOPE, "aud": audience, "iat": now, "exp": now + 3600,
    });
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(claims.to_string().as_bytes())
    );
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64_decode(body.trim()).ok_or(
        "its private_key is not a PEM block. Download a new JSON key for the service account",
    )?;
    let pair = RsaKeyPair::from_pkcs8(&der).map_err(|_| {
        "its private_key is not an RSA key in PKCS #8 form. Download a new JSON key for the service account"
            .to_string()
    })?;
    let mut signature = vec![0; pair.public().modulus_len()];
    pair.sign(
        &RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| "its private_key could not sign".to_string())?;
    Ok(format!("{input}.{}", b64url(&signature)))
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(URL_SAFE[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for byte in text.trim_end_matches('=').bytes() {
        let value = STANDARD.iter().position(|c| *c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_expiry_times_are_read() {
        let at = parse_time("2026-11-13T12:00:00Z");
        assert_eq!(
            at.map(gantry_core::audit::rfc3339).as_deref(),
            Some("2026-11-13T12:00:00.000Z")
        );
        assert_eq!(
            parse_time("2024-02-29T23:59:59Z")
                .map(gantry_core::audit::rfc3339)
                .as_deref(),
            Some("2024-02-29T23:59:59.000Z")
        );
        assert!(parse_time("soon").is_none());
    }

    #[test]
    fn renewal_comes_before_expiry() {
        let in_an_hour = SystemTime::now() + Duration::from_secs(3600);
        let wait = renew_in(in_an_hour);
        assert!(wait <= Duration::from_secs(3300) && wait > Duration::from_secs(3200));
        // Short-lived credentials renew halfway through, never at or after expiry.
        let soon = renew_in(SystemTime::now() + Duration::from_secs(60));
        assert!(soon <= Duration::from_secs(30) && soon >= Duration::from_secs(29));
        assert_eq!(renew_in(SystemTime::UNIX_EPOCH), Duration::from_secs(1));
    }

    #[test]
    fn base64_matches_rfc_4648() {
        assert_eq!(b64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64_decode("Zm9vYg=="), Some(b"foob".to_vec()));
        assert_eq!(base64_decode("a-b"), None);
    }
}
