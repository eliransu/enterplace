//! Updates, on the console's Health page: whether a newer Enterplace release exists, how this deployment takes it,
//! and each gateway's progress while it rolls (`/console/api/updates`).
//!
//! A release is offered only when its `SHA256SUMS` carries a good signature of the release key, the check
//! `install.sh` and `scripts/signing.py verify` make (`ssh-keygen -Y verify`, namespace `enterplace-release`), and
//! the signed list names that version's tarballs. The image digest comes from the release notes; the steps check the
//! image's own cosign signature before it is used.
//!
//! The gateway never replaces itself. On every target the orchestrator that started it does the rolling (a
//! StatefulSet, wrangler, Compose, Terraform, a service manager), because that is the one that can wait for a new
//! gateway's /readyz before stopping an old one, and the one that would undo a change made behind its back. So
//! Update records who updated to what, shows the exact steps for this deployment with "Copy for your agent", and then
//! follows each gateway's version and health from its heartbeat.
//!
//! The release list is read only when someone opens Health, at most every 6 hours (30 minutes after a failure), so a
//! gateway with no way out sends nothing and logs nothing. `ENTERPLACE_UPDATE_CHECK=off` turns the check off;
//! `ENTERPLACE_RELEASE_FEED` points it at a mirror of the GitHub releases API, and `ENTERPLACE_ALLOWED_SIGNERS` at an
//! allowed_signers file whose key signs that mirror's releases (as in install.sh).

use std::time::{Duration, Instant};

use axum::{
    Extension,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
};
use enterplace_console::{Console, Fail, answer, body_of, ok, signed_in, text};
use http_body_util::{BodyExt, Limited};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::{Value, json};

use crate::{AppState, health::Gateway, store::semver};

const FEED: &str = "https://api.github.com/repos/eliransu/enterplace/releases?per_page=20";
/// The release key, as in release/allowed_signers and install.sh. Change all three together.
const RELEASE_KEY: &str = "release@enterplace ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK9+t0WEkM/799u9M6gxLDZY8KlA50qMWHCwqkRdVNeu";
const IDENTITY: &str = "release@enterplace";
const NAMESPACE: &str = "enterplace-release";
const IMAGE: &str = "ghcr.io/eliransu/enterplace";
const DOC: &str = "/operations/updates/";
/// How long a release list is used before it is read again, and after a failed read.
const FRESH: Duration = Duration::from_secs(6 * 3600);
const RETRY: Duration = Duration::from_secs(30 * 60);
const TIMEOUT: Duration = Duration::from_secs(5);
/// A rollout no gateway finished within this is shown as stalled, with the way back.
const STALLED: Duration = Duration::from_secs(15 * 60);
/// Releases whose signature is checked in one read, newest first.
const CHECKED: usize = 3;
const SETTING: &str = "update_rollout";

// ---------------------------------------------------------------- the release signature

/// Reads an SSH wire string (a 4-byte big-endian length, then that many bytes) off the front of `buf`.
fn ssh_string<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let out = buf.get(4..4 + len)?;
    *buf = &buf[4 + len..];
    Some(out)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Checks an `ssh-keygen -Y sign` signature (the SSHSIG format of OpenSSH's PROTOCOL.sshsig) of `message`, as
/// `ssh-keygen -Y verify -I release@enterplace -n enterplace-release` does against `signers`. Ed25519 only: the
/// release key is one.
pub(crate) fn verify_signature(signers: &str, message: &[u8], armored: &str) -> Result<(), String> {
    let trusted: Vec<Vec<u8>> = signers
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let principals = parts.next()?;
            if !principals.split(',').any(|p| p == IDENTITY) || parts.next()? != "ssh-ed25519" {
                return None;
            }
            enterplace_core::eventstream::base64_decode(parts.next()?)
        })
        .collect();
    if trusted.is_empty() {
        return Err(format!(
            "the allowed signers name no ssh-ed25519 key for {IDENTITY}"
        ));
    }
    let body: String = armored
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    let blob = enterplace_core::eventstream::base64_decode(&body)
        .ok_or("the signature is not an SSH signature")?;
    let bad = || "the signature is not an SSH signature".to_string();
    let mut rest = blob.strip_prefix(b"SSHSIG").ok_or_else(bad)?;
    let version = rest.get(..4).ok_or_else(bad)?;
    rest = &rest[4..];
    if version != [0, 0, 0, 1] {
        return Err(bad());
    }
    let key = ssh_string(&mut rest).ok_or_else(bad)?;
    let namespace = ssh_string(&mut rest).ok_or_else(bad)?;
    let reserved = ssh_string(&mut rest).ok_or_else(bad)?;
    let hash = ssh_string(&mut rest).ok_or_else(bad)?;
    let mut sig = ssh_string(&mut rest).ok_or_else(bad)?;
    if !trusted.iter().any(|t| t == key) {
        return Err("the signature was made with another key than the release key".into());
    }
    if namespace != NAMESPACE.as_bytes() {
        return Err(format!("the signature is not for {NAMESPACE}"));
    }
    let digest = match hash {
        b"sha512" => ring::digest::digest(&ring::digest::SHA512, message),
        b"sha256" => ring::digest::digest(&ring::digest::SHA256, message),
        _ => return Err("the signature uses a hash other than sha512 or sha256".into()),
    };
    let ed25519 = Some(b"ssh-ed25519".as_slice());
    let mut key_rest = key;
    let (kind, Some(public)) = (ssh_string(&mut key_rest), ssh_string(&mut key_rest)) else {
        return Err("the signing key is not ssh-ed25519".into());
    };
    let (sig_kind, Some(raw)) = (ssh_string(&mut sig), ssh_string(&mut sig)) else {
        return Err("the signature is not ssh-ed25519".into());
    };
    if kind != ed25519 || sig_kind != ed25519 {
        return Err("the signature is not ssh-ed25519".into());
    }
    let mut signed = b"SSHSIG".to_vec();
    put_string(&mut signed, namespace);
    put_string(&mut signed, reserved);
    put_string(&mut signed, hash);
    put_string(&mut signed, digest.as_ref());
    UnparsedPublicKey::new(&ED25519, public)
        .verify(&signed, raw)
        .map_err(|_| {
            "the signature does not match SHA256SUMS: it changed after signing".to_string()
        })
}

// ---------------------------------------------------------------- the release list

/// A verified release newer than this gateway.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Release {
    pub version: String,
    pub url: String,
    /// The first lines of its changes, from the CHANGELOG section in its notes.
    pub summary: Vec<String>,
    pub more: usize,
    /// `ghcr.io/eliransu/enterplace@sha256:...`, as the release notes name it.
    pub digest: Option<String>,
}

impl Release {
    /// The image to run: the version tag pinned to its digest when the notes name one.
    fn image(&self) -> String {
        image(&self.version, self.digest.as_deref())
    }
}

fn image(version: &str, digest: Option<&str>) -> String {
    match digest.and_then(|d| d.split_once('@')) {
        Some((_, sha)) => format!("{IMAGE}:{version}@{sha}"),
        None => format!("{IMAGE}:{version}"),
    }
}

#[derive(Clone, Debug, Default)]
struct Found {
    /// Verified releases newer than this gateway, newest first.
    releases: Vec<Release>,
    /// Newer releases not offered, and why.
    skipped: Vec<String>,
    error: Option<String>,
    when: String,
}

/// A release in the feed, before its signature is checked.
#[derive(Debug, PartialEq)]
struct Candidate {
    version: String,
    url: String,
    body: String,
    sums: Option<String>,
    sig: Option<String>,
}

/// `X.Y.Z` from a tag `vX.Y.Z`; a pre-release or another name is never offered.
fn stable(tag: &str) -> Option<String> {
    let version = tag.strip_prefix('v')?;
    let parts: Vec<&str> = version.split('.').collect();
    (parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())))
    .then(|| version.to_string())
}

/// The feed's published, stable releases newer than `running`, newest first.
fn candidates(feed: &Value, running: &str) -> Vec<Candidate> {
    let mut list: Vec<Candidate> = feed
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["draft"] != true && r["prerelease"] != true)
        .filter_map(|r| {
            let version = stable(r["tag_name"].as_str()?)?;
            let asset = |name: &str| {
                r["assets"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|a| a["name"] == name)
                    .and_then(|a| a["browser_download_url"].as_str().map(str::to_string))
            };
            Some(Candidate {
                url: r["html_url"].as_str().unwrap_or_default().to_string(),
                body: r["body"].as_str().unwrap_or_default().to_string(),
                sums: asset("SHA256SUMS"),
                sig: asset("SHA256SUMS.sig"),
                version,
            })
        })
        .filter(|c| semver(&c.version) > semver(running))
        .collect();
    list.sort_by_key(|c| std::cmp::Reverse(semver(&c.version)));
    list
}

/// The image digest the notes name, and their first change lines.
fn notes(body: &str) -> (Option<String>, Vec<String>, usize) {
    let marker = format!("{IMAGE}@sha256:");
    let digest = body.find(&marker).and_then(|at| {
        let hex: String = body[at + marker.len()..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        (hex.len() == 64).then(|| format!("{marker}{hex}"))
    });
    let bullets: Vec<String> = body
        .lines()
        .filter_map(|l| l.strip_prefix("- "))
        .map(|l| l.trim().to_string())
        .collect();
    let shown: Vec<String> = bullets.iter().take(5).cloned().collect();
    let more = bullets.len() - shown.len();
    (digest, shown, more)
}

/// Where releases are read from and whose key signs them; `None` when the check is off.
fn source() -> Option<(String, String)> {
    let off = std::env::var("ENTERPLACE_UPDATE_CHECK").is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "off" | "false" | "0" | "no"
        )
    });
    if off {
        return None;
    }
    let feed = std::env::var("ENTERPLACE_RELEASE_FEED")
        .ok()
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| FEED.into());
    let signers = std::env::var("ENTERPLACE_ALLOWED_SIGNERS")
        .ok()
        .filter(|f| !f.is_empty())
        .map(|path| std::fs::read_to_string(&path).unwrap_or_default())
        .unwrap_or_else(|| RELEASE_KEY.into());
    Some((feed, signers))
}

/// A GET that follows up to 3 redirects (GitHub's asset links redirect to its storage) and reads at most `max` bytes.
async fn fetch(state: &AppState, url: &str, max: usize) -> Result<Bytes, String> {
    let mut url = url.to_string();
    for _ in 0..4 {
        let request = axum::http::Request::get(&url)
            .header(
                header::USER_AGENT,
                concat!("enterplace/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                header::ACCEPT,
                "application/vnd.github+json, application/octet-stream",
            )
            .body(Body::empty())
            .map_err(|_| format!("{url} is not a URL"))?;
        let response = tokio::time::timeout(TIMEOUT, state.client.request(request))
            .await
            .map_err(|_| format!("{url} did not answer within {} seconds", TIMEOUT.as_secs()))?
            .map_err(|_| format!("{url} could not be reached"))?;
        if response.status().is_redirection() {
            url = response
                .headers()
                .get(header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .ok_or_else(|| format!("{url} redirected nowhere"))?
                .to_string();
            continue;
        }
        if !response.status().is_success() {
            return Err(format!(
                "{url} answered HTTP {}",
                response.status().as_u16()
            ));
        }
        return Ok(tokio::time::timeout(
            TIMEOUT,
            Limited::new(response.into_body(), max).collect(),
        )
        .await
        .map_err(|_| format!("{url} stopped sending"))?
        .map_err(|_| format!("{url} sent more than expected"))?
        .to_bytes());
    }
    Err(format!("{url} redirected too many times"))
}

/// Reads the release list and checks the signature of the newest few releases above `running`.
async fn read(state: &AppState, feed: &str, signers: &str, running: &str) -> Found {
    let when = enterplace_core::audit::timestamp();
    let listed = match fetch(state, feed, 4 << 20).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return Found {
                error: Some(error),
                when,
                ..Found::default()
            };
        }
    };
    let Ok(feed_json) = serde_json::from_slice::<Value>(&listed) else {
        return Found {
            error: Some(format!("{feed} did not answer with a release list")),
            when,
            ..Found::default()
        };
    };
    let mut found = Found {
        when,
        ..Found::default()
    };
    for c in candidates(&feed_json, running).into_iter().take(CHECKED) {
        match checked(state, signers, &c).await {
            Ok(()) => {
                let (digest, summary, more) = notes(&c.body);
                found.releases.push(Release {
                    version: c.version,
                    url: c.url,
                    summary,
                    more,
                    digest,
                });
            }
            Err(why) => found.skipped.push(format!("{}: {why}", c.version)),
        }
    }
    found
}

/// Whether the release's SHA256SUMS is signed by the release key and lists that version's own tarballs.
async fn checked(state: &AppState, signers: &str, c: &Candidate) -> Result<(), String> {
    let (Some(sums), Some(sig)) = (&c.sums, &c.sig) else {
        return Err("it has no signed SHA256SUMS".into());
    };
    let sums = fetch(state, sums, 64 << 10).await?;
    let sig = fetch(state, sig, 16 << 10).await?;
    verify_signature(signers, &sums, &String::from_utf8_lossy(&sig))?;
    // A signed list of another version, put under this tag, names other files.
    let own = format!("enterplace-{}-", c.version);
    if !String::from_utf8_lossy(&sums).lines().any(|l| {
        l.split_whitespace()
            .nth(1)
            .is_some_and(|f| f.starts_with(&own))
    }) {
        return Err(format!(
            "its signed SHA256SUMS names no tarball of {}",
            c.version
        ));
    }
    Ok(())
}

/// The last read, and when it was made. One read at a time: a page opened twice waits for the first.
static FOUND: tokio::sync::Mutex<Option<(Instant, Found)>> = tokio::sync::Mutex::const_new(None);

async fn found(state: &AppState) -> Option<Found> {
    let (feed, signers) = source()?;
    let mut last = FOUND.lock().await;
    let fresh = last
        .as_ref()
        .is_some_and(|(at, f)| at.elapsed() < if f.error.is_some() { RETRY } else { FRESH });
    if !fresh {
        *last = Some((
            Instant::now(),
            read(state, &feed, &signers, enterplace_core::VERSION).await,
        ));
    }
    last.as_ref().map(|(_, f)| f.clone())
}

// ---------------------------------------------------------------- versions side by side

/// Whether gateways of every version in `running` may share a store with `to`, and so roll to it one at a time and
/// back: the store's rule (`store::newer_allowed`), at most one minor version ahead. Says why not, with the fix.
fn may_roll(running: &[String], to: &str) -> Result<(), String> {
    for v in running {
        if v != to && !crate::store::newer_allowed(v, to) {
            return Err(format!(
                "A gateway runs {v}, and {to} is more than one minor version ahead of it (or older). Two versions share one store only one minor version apart, so {v} could not run beside {to} during the rollout, nor come back after it. Update to the newest {}.x first, then to {to}.",
                next_minor(v)
            ));
        }
    }
    Ok(())
}

fn next_minor(v: &str) -> String {
    semver(v).map_or_else(
        || v.to_string(),
        |(major, minor, _)| format!("{major}.{}", minor + 1),
    )
}

/// Whether gateways may go back to `from` once `newest` has run on the store: `from` must accept the schema
/// `newest` left.
fn may_return(from: &str, newest: &str) -> Result<(), String> {
    if from == newest || crate::store::newer_allowed(from, newest) {
        return Ok(());
    }
    Err(format!(
        "{newest} has run on this store, and {from} refuses a store a version more than one minor version ahead has written. Roll back by restoring the store backup taken before the update, or fix forward with a newer release."
    ))
}

// ---------------------------------------------------------------- deployment targets

/// Where this gateway runs, from what its platform sets in its environment, or `ENTERPLACE_DEPLOY_TARGET`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Target {
    Kubernetes { release: String, namespace: String },
    Cloudflare,
    Docker,
    Ecs,
    CloudRun,
    ContainerApps,
    Homebrew,
    Binary,
}

pub(crate) fn target(env: &dyn Fn(&str) -> Option<String>) -> Target {
    let set = |name: &str| env(name).filter(|v| !v.is_empty());
    let kubernetes = || Target::Kubernetes {
        release: set("ENTERPLACE_HELM_RELEASE").unwrap_or_else(|| "<release>".into()),
        namespace: set("ENTERPLACE_HELM_NAMESPACE").unwrap_or_else(|| "<namespace>".into()),
    };
    match set("ENTERPLACE_DEPLOY_TARGET").as_deref() {
        Some("kubernetes" | "helm") => return kubernetes(),
        Some("cloudflare") => return Target::Cloudflare,
        Some("docker" | "compose") => return Target::Docker,
        Some("ecs") => return Target::Ecs,
        Some("cloud-run") => return Target::CloudRun,
        Some("container-apps") => return Target::ContainerApps,
        Some("binary") => return Target::Binary,
        _ => {}
    }
    if set("ENTERPLACE_CLOUDFLARE_STORE_URL").is_some() {
        Target::Cloudflare
    } else if set("KUBERNETES_SERVICE_HOST").is_some() {
        kubernetes()
    } else if set("ECS_CONTAINER_METADATA_URI_V4").is_some() {
        Target::Ecs
    } else if set("K_SERVICE").is_some() {
        Target::CloudRun
    } else if set("CONTAINER_APP_NAME").is_some() {
        Target::ContainerApps
    } else if set("ENTERPLACE_IN_DOCKER").is_some() {
        Target::Docker
    } else if set("ENTERPLACE_EXE").is_some_and(|p| p.contains("/Cellar/")) {
        Target::Homebrew
    } else {
        Target::Binary
    }
}

fn this_target() -> Target {
    target(&|name| match name {
        // The image has no shell and no files but the binary: /.dockerenv, which Docker adds, tells it apart.
        "ENTERPLACE_IN_DOCKER" => std::path::Path::new("/.dockerenv")
            .exists()
            .then(|| "1".into()),
        "ENTERPLACE_EXE" => std::env::current_exe()
            .ok()
            .map(|p| p.display().to_string()),
        _ => std::env::var(name).ok(),
    })
}

/// How a target takes a version: its name, why the gateway does not do it, what it costs in downtime, and the
/// exact steps.
#[derive(Debug)]
pub(crate) struct Steps {
    pub label: &'static str,
    pub why: String,
    pub downtime: String,
    pub command: String,
}

fn cosign(version: &str) -> String {
    format!(
        "cosign verify {IMAGE}:{version} \\\n  --certificate-identity https://github.com/eliransu/enterplace/.github/workflows/image.yml@refs/tags/v{version} \\\n  --certificate-oidc-issuer https://token.actions.githubusercontent.com"
    )
}

pub(crate) fn steps(target: &Target, version: &str, image: &str, gateways: usize) -> Steps {
    let several = gateways >= 2;
    let restart = |how: &str| {
        if several {
            format!(
                "No downtime if you update one gateway at a time: {how}, wait until its /readyz answers 200, then the next."
            )
        } else {
            "One gateway: Enterplace restarts, so requests get no answer for a few seconds (it finishes requests in flight first, up to 30 seconds). Run two gateways on one store behind a load balancer for updates with no downtime.".into()
        }
    };
    let tag = image.strip_prefix(&format!("{IMAGE}:")).unwrap_or(version);
    match target {
        Target::Kubernetes { release, namespace } => Steps {
            label: "Kubernetes (Helm)",
            why: "Helm updates it, not the gateway: for the pod to patch its own StatefulSet it would need a Role that can rewrite the whole pod spec (RBAC cannot limit a patch to the image), and the next helm upgrade would undo a change Helm did not make.".into(),
            downtime: if several {
                "No downtime: the StatefulSet replaces one pod at a time and starts the next only once the new pod's /readyz answers 200; each old pod finishes its requests first. --atomic puts the previous version back if a pod is not ready within 15 minutes.".into()
            } else {
                "One replica: requests get no answer for a few seconds while the pod is replaced. Run 2 or more replicas (with a store) for updates with no downtime. --atomic puts the previous version back if the new pod is not ready within 15 minutes.".into()
            },
            command: format!(
                "{}\nhelm upgrade {release} oci://ghcr.io/eliransu/charts/enterplace --version {version} \\\n  --namespace {namespace} --reset-then-reuse-values --set image.tag={tag} \\\n  --atomic --timeout 15m",
                cosign(version)
            ),
        },
        Target::Cloudflare => Steps {
            label: "Cloudflare",
            why: "wrangler updates it, not the Worker: the Worker and its store object ship with each release and change with the image (the store object adds its own tables), Cloudflare cannot pull the image from ghcr.io so wrangler builds it with your policy and pushes it to your account's registry, and an API token that may change container applications reaches every application on the account.".into(),
            downtime: if several {
                "No downtime: wrangler deploy rolls the gateway instances when the image changes, and each stopping instance finishes its requests and writes its audit segments to R2 first.".into()
            } else {
                "GATEWAYS is 1: requests wait while the one instance restarts. Set GATEWAYS to 2 or more (and max_instances one higher) for updates with no downtime.".into()
            },
            command: format!(
                "# In your enterplace-cloudflare folder:\n{}\ndocker create --name enterplace-files {image}\ndocker cp enterplace-files:/deploy/cloudflare/src ./ && docker cp enterplace-files:/deploy/cloudflare/package.json ./ \\\n  && docker cp enterplace-files:/deploy/cloudflare/package-lock.json ./ && docker rm enterplace-files\nnpm ci\n# In wrangler.jsonc set: \"image_vars\": {{ \"ENTERPLACE_IMAGE\": \"{image}\" }}\nnpx wrangler deploy",
                cosign(version)
            ),
        },
        Target::Docker => Steps {
            label: "Docker Compose",
            why: "Compose updates it, not the gateway: replacing its own container would need the Docker socket, which is root on the host.".into(),
            downtime: restart("run the up command for one service"),
            command: format!(
                "{}\n# In .env beside compose.yaml:\nENTERPLACE_IMAGE={image}\n# Then:\ndocker compose pull enterplace && docker compose up -d enterplace",
                cosign(version)
            ),
        },
        Target::Ecs => Steps {
            label: "AWS ECS (Terraform)",
            why: "Terraform updates it, not the gateway: the task's role has no rights on its own service, and Terraform would undo a change it did not make.".into(),
            downtime: "A short outage: the aws-ecs module stops each replica's task before it starts the new one (two tasks on one audit folder would write one chain twice), and one apply replaces every replica. The deployment circuit breaker puts the previous task definition back if the new task fails its health check.".into(),
            command: format!(
                "{}\n# In the module \"enterplace\" block of your Terraform configuration:\nimage = \"{image}\"\n# Then:\nterraform apply",
                cosign(version)
            ),
        },
        Target::CloudRun => Steps {
            label: "Google Cloud Run (Terraform)",
            why: "Terraform updates it, not the gateway: its service account has no rights on its own service, and Terraform would undo a change it did not make.".into(),
            downtime: "No downtime: Cloud Run starts the new revision, waits for its startup probe, then moves traffic to it while the old instance finishes its requests.".into(),
            command: format!(
                "{}\n# In the module \"enterplace\" block (Cloud Run pulls from Artifact Registry: use your remote repository in front of ghcr.io):\nimage = \"<your Artifact Registry path>/enterplace:{tag}\"\n# Then:\nterraform apply",
                cosign(version)
            ),
        },
        Target::ContainerApps => Steps {
            label: "Azure Container Apps (Terraform)",
            why: "Terraform updates it, not the gateway: its identity has no rights on its own app, and Terraform would undo a change it did not make.".into(),
            downtime: "No downtime: in single revision mode the new revision takes traffic once its readiness probe passes, and the old one finishes its requests (up to 40 seconds).".into(),
            command: format!(
                "{}\n# In the module \"enterplace\" block of your Terraform configuration:\nimage = \"{image}\"\n# Then:\nterraform apply",
                cosign(version)
            ),
        },
        Target::Homebrew => Steps {
            label: "Homebrew",
            why: "Homebrew owns the binary, and whoever started Enterplace (launchd, a shell) starts the new one.".into(),
            downtime: restart("restart one"),
            command: "brew update && brew upgrade eliransu/tap/enterplace\n# Then restart Enterplace the way you run it.".into(),
        },
        Target::Binary => Steps {
            label: "Binary",
            why: "The gateway does not replace its own binary: whoever runs it (systemd, launchd, a shell) starts the new one.".into(),
            downtime: restart("restart one"),
            command: format!(
                "# install.sh checks the release signature and the tarball's SHA256 before it installs:\ncurl -fsSL https://enterplace.dev/install.sh | ENTERPLACE_VERSION=v{version} sh\n# Then restart Enterplace the way you run it, for example:\nsudo systemctl restart enterplace"
            ),
        },
    }
}

/// The steps as the page shows them, with the prompt for "Copy for your agent".
fn steps_json(
    target: &Target,
    from: &str,
    to: &str,
    image: &str,
    gateways: usize,
    base: &str,
    back: bool,
) -> Value {
    let s = steps(target, to, image, gateways);
    let goal = if back {
        format!("Roll Enterplace back from {from} to {to} on {}", s.label)
    } else {
        format!("Update Enterplace from {from} to {to} on {}", s.label)
    };
    let agent = enterplace_console::task_prompt(
        base,
        &goal,
        &[("Version", to.to_string()), ("Image", image.to_string())],
        &[
            "1. Find where this Enterplace deployment is defined (Helm values, wrangler.jsonc, compose.yaml and .env, Terraform, or the service that runs the binary), and ask me if it is not in this project.".into(),
            "2. Run or apply these steps there. A failed cosign verify means stop: do not run that image.".into(),
            format!("```\n{}\n```", s.command),
            format!("3. {}", s.downtime),
        ],
        &format!("Health at {base}/console/app/#/deployments lists every gateway on {to} and healthy."),
        DOC,
    );
    json!({
        "label": s.label,
        "why": s.why,
        "downtime": s.downtime,
        "command": s.command,
        "agent": agent,
    })
}

// ---------------------------------------------------------------- rollout

/// An update an admin started: kept in the store, so every gateway's page shows it, or in this process without one.
static ROLLOUT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

async fn rollout_get(state: &AppState) -> Option<Value> {
    let text = match state.pool.store().filter(|s| s.keeps_settings()).cloned() {
        Some(store) => tokio::task::spawn_blocking(move || store.setting(SETTING))
            .await
            .ok()?
            .ok()?,
        None => ROLLOUT.lock().ok()?.clone(),
    }?;
    serde_json::from_str(&text).ok()
}

async fn rollout_set(state: &AppState, value: &Value) -> Result<(), String> {
    let text = value.to_string();
    match state.pool.store().filter(|s| s.keeps_settings()).cloned() {
        Some(store) => tokio::task::spawn_blocking(move || store.set_setting(SETTING, &text))
            .await
            .map_err(|err| err.to_string())?,
        None => {
            if let Ok(mut r) = ROLLOUT.lock() {
                *r = Some(text);
            }
            Ok(())
        }
    }
}

/// One gateway now: host, version, healthy, and when its heartbeat was last written.
struct Now {
    host: String,
    version: String,
    healthy: bool,
    seen: String,
}

async fn gateways_now(state: &AppState) -> Vec<Now> {
    let before = enterplace_core::audit::rfc3339(
        std::time::SystemTime::now()
            .checked_sub(crate::health::STOPPED_AFTER)
            .unwrap_or(std::time::UNIX_EPOCH),
    );
    match state.pool.store() {
        Some(store) => store
            .replicas()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.healthy || !crate::health::stopped(&r.seen, &before))
            .map(|r| Now {
                host: if r.host.is_empty() { r.gateway } else { r.host },
                version: r.version,
                healthy: r.healthy,
                seen: r.seen,
            })
            .collect(),
        None => vec![Now {
            host: std::env::var("HOSTNAME")
                .ok()
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "this gateway".into()),
            version: enterplace_core::VERSION.into(),
            healthy: true,
            seen: enterplace_core::audit::timestamp(),
        }],
    }
}

/// Each gateway's place in the rollout, and the rollout's state: rolling, done, failed (a gateway on the new version
/// stopped answering its heartbeat) or stalled (not done within 15 minutes).
fn progress(rollout: &Value, now: &[Now], elapsed: Duration) -> (Vec<Value>, &'static str) {
    let to = rollout["to"].as_str().unwrap_or_default();
    let at = rollout["at"].as_str().unwrap_or_default();
    let rows: Vec<Value> = now
        .iter()
        // A silent gateway on another version was replaced: it is gone, not failing.
        .filter(|g| g.healthy || (g.version == to && g.seen.get(..19) >= at.get(..19)))
        .map(|g| {
            let state = match (g.version == to, g.healthy) {
                (true, true) => "updated",
                (true, false) => "failed",
                _ => "waiting",
            };
            json!({ "host": g.host, "version": g.version, "state": state })
        })
        .collect();
    let overall = if rows.iter().any(|r| r["state"] == "failed") {
        "failed"
    } else if !rows.is_empty() && rows.iter().all(|r| r["state"] == "updated") {
        "done"
    } else if elapsed > STALLED {
        "stalled"
    } else {
        "rolling"
    };
    (rows, overall)
}

// ---------------------------------------------------------------- the page's API

fn may_update(admin: &enterplace_console::Admin) -> bool {
    admin.may(enterplace_core::policy::Permission::EditPolicy) && !admin.confined()
}

async fn view(state: &AppState, admin: &enterplace_console::Admin, base: &str) -> Value {
    let running = enterplace_core::VERSION;
    let now = gateways_now(state).await;
    let versions: Vec<String> = now
        .iter()
        .filter(|g| g.healthy)
        .map(|g| g.version.clone())
        .collect();
    let target = this_target();
    let found = found(state).await;
    let check = match (&found, source()) {
        (None, _) | (_, None) => {
            "The release check is off (ENTERPLACE_UPDATE_CHECK=off), so no update is offered."
                .to_string()
        }
        (Some(f), Some((feed, _))) => match &f.error {
            Some(error) => format!(
                "The release list could not be read ({error}), so no update is offered. Enterplace tries again in 30 minutes, when this page is open."
            ),
            None => format!(
                "Releases read from {feed} at {} UTC. A release is offered only when its signature checks against the Enterplace release key.",
                f.when.get(..16).unwrap_or(&f.when).replace('T', " ")
            ),
        },
    };
    let releases = found
        .as_ref()
        .map(|f| f.releases.clone())
        .unwrap_or_default();
    let release_json = |r: &Release| json!({ "version": r.version, "url": r.url, "summary": r.summary, "more": r.more, "image": r.image() });
    // The newest release every running gateway may roll to and come back from.
    let offer = releases
        .iter()
        .find(|r| may_roll(&versions, &r.version).is_ok());
    let newest = releases.first();
    let held = match (newest, offer) {
        (Some(n), o) if o.map(|o| &o.version) != Some(&n.version) => {
            may_roll(&versions, &n.version).err()
        }
        _ => None,
    };
    let rollout = match rollout_get(state).await {
        Some(r) => {
            let started = r["started"].as_u64().unwrap_or(0);
            let elapsed = Duration::from_secs(unix_now().saturating_sub(started));
            let (rows, overall) = progress(&r, &now, elapsed);
            let from = r["from"].as_str().unwrap_or_default();
            let to = r["to"].as_str().unwrap_or_default();
            let newest_running = now
                .iter()
                .map(|g| g.version.as_str())
                .max_by_key(|v| semver(v))
                .unwrap_or(to);
            let back = may_return(from, newest_running);
            // A finished rollout stays on the page for a day, then the page is quiet again.
            (overall != "done" || elapsed < Duration::from_secs(86_400)).then(|| {
                json!({
                    "from": from, "to": to, "by": r["by"], "at": r["at"], "back": r["back"] == true,
                    "state": overall, "gateways": rows,
                    "steps": steps_json(&target, from, to, r["image"].as_str().unwrap_or(&image(to, None)), now.len(), base, r["back"] == true),
                    "rollback": {
                        "refused": back.err(),
                        "steps": steps_json(&target, to, from, &image(from, None), now.len(), base, true),
                    },
                })
            })
        }
        None => None,
    };
    let gateways = now.len().max(1);
    json!({
        "running": running,
        "check": check,
        "skipped": found.map(|f| f.skipped).unwrap_or_default(),
        "newest": newest.map(release_json),
        "held": held,
        "offer": offer.map(|r| {
            let mut o = release_json(r);
            o["steps"] = steps_json(&target, running, &r.version, &r.image(), gateways, base, false);
            o["gateways"] = gateways.into();
            o
        }),
        "rollout": rollout,
        "may_update": may_update(admin),
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) async fn get(
    State(console): State<Console>,
    Extension(state): Extension<Gateway>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, false).await?;
            let state = crate::health::gateway(&state)?;
            let base = enterplace_console::gateway_origin(&headers, &uri, &None);
            Ok(ok(view(&state, &admin, &base).await))
        }
        .await,
    )
}

/// Update (`{"action": "update", "version": ...}`) or roll back (`{"action": "rollback"}`): checked, recorded in
/// the audit log as `update` or `rollback` with who, from and to, and kept as the rollout the page follows.
pub(crate) async fn post(
    State(console): State<Console>,
    Extension(state): Extension<Gateway>,
    headers: HeaderMap,
    uri: Uri,
    bytes: Bytes,
) -> Response {
    answer(
        async {
            let admin = signed_in(&console, &headers, true).await?;
            let state = crate::health::gateway(&state)?;
            let body = body_of(&bytes)?;
            let action = if text(&body, "action") == "rollback" { "rollback" } else { "update" };
            let wanted = text(&body, "version").to_string();
            let now = gateways_now(&state).await;
            let versions: Vec<String> = now.iter().filter(|g| g.healthy).map(|g| g.version.clone()).collect();
            let target = this_target();
            let label = steps(&target, "", "", 0).label;
            let checked: Result<(String, String, String), (&str, StatusCode, String)> = async {
                if !may_update(&admin) {
                    return Err(("not_permitted", StatusCode::FORBIDDEN, "Your role may not update Enterplace: it needs edit_policy and the whole install. Ask an admin who has both.".to_string()));
                }
                if action == "update" {
                    let releases = found(&state).await.map(|f| f.releases).unwrap_or_default();
                    let Some(release) = releases.iter().find(|r| r.version == wanted) else {
                        return Err(("no_such_release", StatusCode::NOT_FOUND, format!("{wanted} is not a verified release newer than {}. Reload the page to see the releases on offer.", enterplace_core::VERSION)));
                    };
                    may_roll(&versions, &release.version).map_err(|why| ("cannot_roll_back", StatusCode::CONFLICT, why))?;
                    return Ok((enterplace_core::VERSION.to_string(), release.version.clone(), release.image()));
                }
                let Some(r) = rollout_get(&state).await else {
                    return Err(("no_rollout", StatusCode::CONFLICT, "No update was started from the console, so there is nothing to roll back. Set the previous version in your deployment to go back.".to_string()));
                };
                let (from, to) = (r["from"].as_str().unwrap_or_default().to_string(), r["to"].as_str().unwrap_or_default().to_string());
                let newest = now.iter().map(|g| g.version.clone()).max_by_key(|v| semver(v)).unwrap_or_else(|| to.clone());
                may_return(&from, &newest).map_err(|why| ("cannot_roll_back", StatusCode::CONFLICT, why))?;
                let back = image(&from, None);
                Ok((to, from, back))
            }
            .await;
            let (from, to, image) = match checked {
                Ok(pair) => pair,
                Err((code, status, message)) => {
                    let _ = console
                        .audit(Some(&admin), action, json!({ "version": wanted, "target": label }), Some(code))
                        .await;
                    return Err(Fail(status, message));
                }
            };
            let record = json!({ "from": from, "to": to, "target": label, "gateways": now.len() });
            console.audit(Some(&admin), action, record, None).await.map_err(|message| {
                Fail(StatusCode::SERVICE_UNAVAILABLE, format!("The {action} could not be recorded: {message} Check that the audit log can be written, then try again."))
            })?;
            let rollout = json!({
                "from": from, "to": to, "by": admin.name, "at": enterplace_core::audit::timestamp(),
                "started": unix_now(), "back": action == "rollback", "image": image,
            });
            rollout_set(&state, &rollout).await.map_err(|err| {
                Fail(StatusCode::SERVICE_UNAVAILABLE, format!("The {action} was recorded, but the store could not keep it ({err}). Check the store, then reload the page."))
            })?;
            let base = enterplace_console::gateway_origin(&headers, &uri, &None);
            let mut view = view(&state, &admin, &base).await;
            view["message"] = format!(
                "{} to {to} recorded in the audit log. Run the steps shown to roll it through the gateways.",
                if action == "update" { "Update" } else { "Rollback" }
            )
            .into();
            Ok(ok(view))
        }
        .await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;

    // Made with `ssh-keygen -t ed25519` and `ssh-keygen -Y sign -n enterplace-release`, and checked with
    // `ssh-keygen -Y verify`.
    const SIGNERS: &str = "release@enterplace ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDgWPy9RFntvdcPMhS0vnaz25XQAC3ts2RXqzed03G7s";
    const SUMS: &str = "abc  enterplace-0.3.0-123-x86_64-unknown-linux-musl.tar.gz\n";
    const SIG: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgOBY/L1EWe291w8yFLS+drPbldA
ALe2zZFerN53TcbuwAAAASZW50ZXJwbGFjZS1yZWxlYXNlAAAAAAAAAAZzaGE1MTIAAABT
AAAAC3NzaC1lZDI1NTE5AAAAQHCcrvgsy2OZQCN8KFKQVPS9XLjonO6osCo5MIDS0WpMPU
9ORHF/2taoTCVyX7xCCBW+5eHZ60OeBd+IIXUNSg0=
-----END SSH SIGNATURE-----
";

    #[test]
    fn a_release_signature_verifies_as_ssh_keygen_verifies_it() -> TestResult {
        verify_signature(SIGNERS, SUMS.as_bytes(), SIG)?;
        let changed = verify_signature(SIGNERS, b"abc  enterplace-9.9.9-x.tar.gz\n", SIG)
            .err()
            .unwrap_or_default();
        assert!(changed.contains("changed after signing"), "{changed}");
        let other = verify_signature(RELEASE_KEY, SUMS.as_bytes(), SIG)
            .err()
            .unwrap_or_default();
        assert!(other.contains("another key"), "{other}");
        let stranger = verify_signature(
            &SIGNERS.replace(IDENTITY, "someone@else"),
            SUMS.as_bytes(),
            SIG,
        )
        .err()
        .unwrap_or_default();
        assert!(stranger.contains("no ssh-ed25519 key"), "{stranger}");
        assert!(verify_signature(SIGNERS, SUMS.as_bytes(), "not a signature").is_err());
        Ok(())
    }

    #[test]
    fn the_release_key_is_the_one_in_the_repository() -> TestResult {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../release/allowed_signers");
        let file = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        assert_eq!(
            file.trim(),
            RELEASE_KEY,
            "change RELEASE_KEY in update.rs with release/allowed_signers"
        );
        Ok(())
    }

    #[test]
    fn only_stable_published_newer_releases_are_candidates_newest_first() {
        let feed = json!([
            { "tag_name": "edge", "prerelease": true, "assets": [] },
            { "tag_name": "v0.3.0", "html_url": "u3", "body": "b", "assets": [
                { "name": "SHA256SUMS", "browser_download_url": "s" }, { "name": "SHA256SUMS.sig", "browser_download_url": "g" } ] },
            { "tag_name": "v0.4.0-rc.1", "assets": [] },
            { "tag_name": "v0.5.0", "draft": true, "assets": [] },
            { "tag_name": "v0.10.0", "assets": [] },
            { "tag_name": "v0.2.0", "assets": [] },
        ]);
        let list = candidates(&feed, "0.2.0");
        let versions: Vec<&str> = list.iter().map(|c| c.version.as_str()).collect();
        assert_eq!(versions, ["0.10.0", "0.3.0"]);
        assert_eq!(list[1].sums.as_deref(), Some("s"));
        assert_eq!(list[0].sig, None);
    }

    #[test]
    fn the_notes_give_the_digest_and_the_first_changes() {
        let digest = "a".repeat(64);
        let body = format!(
            "Image: `{IMAGE}:0.3.0`\n\nDigest: `{IMAGE}@sha256:{digest}` (amd64 and arm64).\n\n### Added\n\n- One\n- Two\n- Three\n- Four\n- Five\n- Six\n"
        );
        let (found, summary, more) = notes(&body);
        assert_eq!(found, Some(format!("{IMAGE}@sha256:{digest}")));
        assert_eq!(summary, ["One", "Two", "Three", "Four", "Five"]);
        assert_eq!(more, 1);
        assert_eq!(
            image("0.3.0", found.as_deref()),
            format!("{IMAGE}:0.3.0@sha256:{digest}")
        );
        assert_eq!(notes("no digest").0, None);
    }

    #[test]
    fn versions_roll_one_minor_step_and_come_back_only_within_it() {
        let running = vec!["0.2.0".to_string(), "0.2.1".to_string()];
        assert!(may_roll(&running, "0.3.0").is_ok());
        assert!(may_roll(&running, "0.2.5").is_ok());
        let far = may_roll(&running, "0.4.0").err().unwrap_or_default();
        assert!(
            far.contains("one minor version") && far.contains("0.3.x first"),
            "{far}"
        );
        assert!(may_return("0.2.0", "0.3.0").is_ok());
        assert!(may_return("0.2.0", "0.2.0").is_ok());
        let back = may_return("0.2.0", "0.4.0").err().unwrap_or_default();
        assert!(back.contains("backup"), "{back}");
    }

    #[test]
    fn each_platform_is_told_apart_and_gets_its_own_steps() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        let k8s = target(&env(&[
            ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
            ("ENTERPLACE_HELM_RELEASE", "gw"),
            ("ENTERPLACE_HELM_NAMESPACE", "ai"),
        ]));
        assert_eq!(
            k8s,
            Target::Kubernetes {
                release: "gw".into(),
                namespace: "ai".into()
            }
        );
        // The Worker passes the store's address, and Kubernetes would be wrong for a Cloudflare container.
        assert_eq!(
            target(&env(&[("ENTERPLACE_CLOUDFLARE_STORE_URL", "http://store")])),
            Target::Cloudflare
        );
        assert_eq!(
            target(&env(&[("K_SERVICE", "enterplace")])),
            Target::CloudRun
        );
        assert_eq!(
            target(&env(&[("ECS_CONTAINER_METADATA_URI_V4", "http://x")])),
            Target::Ecs
        );
        assert_eq!(
            target(&env(&[("CONTAINER_APP_NAME", "enterplace")])),
            Target::ContainerApps
        );
        assert_eq!(
            target(&env(&[("ENTERPLACE_IN_DOCKER", "1")])),
            Target::Docker
        );
        assert_eq!(
            target(&env(&[(
                "ENTERPLACE_EXE",
                "/opt/homebrew/Cellar/enterplace/0.2.0/bin/enterplace"
            )])),
            Target::Homebrew
        );
        assert_eq!(
            target(&env(&[
                ("ENTERPLACE_DEPLOY_TARGET", "compose"),
                ("KUBERNETES_SERVICE_HOST", "x")
            ])),
            Target::Docker
        );
        assert_eq!(target(&env(&[])), Target::Binary);

        let pinned = format!("{IMAGE}:0.3.0@sha256:{}", "b".repeat(64));
        let helm = steps(&k8s, "0.3.0", &pinned, 3);
        assert!(
            helm.command.contains(
                "helm upgrade gw oci://ghcr.io/eliransu/charts/enterplace --version 0.3.0"
            ),
            "{}",
            helm.command
        );
        assert!(
            helm.command
                .contains(&format!("image.tag=0.3.0@sha256:{}", "b".repeat(64))),
            "{}",
            helm.command
        );
        assert!(
            helm.command.contains("--atomic") && helm.command.contains("cosign verify"),
            "{}",
            helm.command
        );
        assert!(
            helm.downtime.starts_with("No downtime"),
            "{}",
            helm.downtime
        );
        assert!(
            steps(&k8s, "0.3.0", &pinned, 1)
                .downtime
                .starts_with("One replica")
        );
        let compose = steps(&Target::Docker, "0.3.0", &pinned, 1);
        assert!(
            compose
                .command
                .contains(&format!("ENTERPLACE_IMAGE={pinned}")),
            "{}",
            compose.command
        );
        assert!(
            compose.downtime.contains("a few seconds"),
            "{}",
            compose.downtime
        );
        assert!(
            steps(&Target::Docker, "0.3.0", &pinned, 2)
                .downtime
                .starts_with("No downtime if")
        );
        let cloudflare = steps(&Target::Cloudflare, "0.3.0", &pinned, 2);
        assert!(
            cloudflare.command.contains("npx wrangler deploy")
                && cloudflare.command.contains("image_vars"),
            "{}",
            cloudflare.command
        );
        for t in [Target::Ecs, Target::CloudRun, Target::ContainerApps] {
            let s = steps(&t, "0.3.0", &pinned, 1);
            assert!(
                s.command.contains("terraform apply") && s.command.contains("image = \""),
                "{}",
                s.command
            );
        }
        assert!(
            steps(&Target::Binary, "0.3.0", &pinned, 1)
                .command
                .contains("ENTERPLACE_VERSION=v0.3.0 sh")
        );
        for t in [
            k8s,
            Target::Cloudflare,
            Target::Docker,
            Target::Ecs,
            Target::CloudRun,
            Target::ContainerApps,
            Target::Homebrew,
            Target::Binary,
        ] {
            let s = steps(&t, "0.3.0", &pinned, 2);
            for text in [&s.why, &s.downtime, &s.command] {
                assert!(
                    !text.contains('\u{2014}') && !text.contains('\u{2013}'),
                    "{text}"
                );
            }
        }
    }

    #[test]
    fn a_rollout_is_done_failed_or_stalled_from_the_heartbeats() {
        let rollout = json!({ "from": "0.2.0", "to": "0.3.0", "at": "2026-11-26T10:00:00.000Z" });
        let g = |host: &str, version: &str, healthy: bool, seen: &str| Now {
            host: host.into(),
            version: version.into(),
            healthy,
            seen: seen.into(),
        };
        let rolling = [
            g("a", "0.3.0", true, "2026-11-26T10:01:00Z"),
            g("b", "0.2.0", true, "2026-11-26T10:01:00Z"),
        ];
        let (rows, state) = progress(&rollout, &rolling, Duration::from_secs(60));
        assert_eq!(state, "rolling");
        assert_eq!(rows[0]["state"], "updated");
        assert_eq!(rows[1]["state"], "waiting");
        assert_eq!(
            progress(&rollout, &rolling, STALLED + Duration::from_secs(1)).1,
            "stalled"
        );
        // The old gateway went silent once replaced: not a failure.
        let done = [
            g("a", "0.3.0", true, "x"),
            g("b2", "0.3.0", true, "x"),
            g("b", "0.2.0", false, "2026-11-26T10:02:00Z"),
        ];
        assert_eq!(progress(&rollout, &done, Duration::from_secs(90)).1, "done");
        let failed = [
            g("a", "0.3.0", false, "2026-11-26T10:01:00Z"),
            g("b", "0.2.0", true, "x"),
        ];
        assert_eq!(
            progress(&rollout, &failed, Duration::from_secs(90)).1,
            "failed"
        );
    }
}
