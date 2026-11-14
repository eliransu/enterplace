//! Commercial edition. Runs the open source server, and runs it as a node managed by the Gantry control plane
//! (hybrid: at the customer; hosted: in Gantry's cloud).

mod device;
mod enterprise;
mod license;
mod node;
mod secrets;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage:
  gantry node --control-plane <url> [--dir <folder>] [--listen <host:port>] [--interval <seconds>]
      [--secrets NAME=<source>]... [--secrets-interval <seconds>]
      Run a gateway managed by the control plane. The node token goes in GANTRY_NODE_TOKEN.
      --secrets gives the provider key the policy names NAME (key_env) from a source polled every
      --secrets-interval seconds (default 60), rotated without restarting the gateway. Sources:
      file:/path, env:OTHER, vault:<KV v2 URL>#field (token in VAULT_TOKEN),
      aws-sm:<secret ARN>[#field] (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
      The gateway's environment starts empty: it gets PATH, HOME, TZ, LANG, SSL_CERT_*, OTEL_*, every *_PROVIDER_KEY,
      and the names in --pass-env A,B (for example AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY for Bedrock).
      --max-offline <seconds> stops serving when the control plane has not answered for that long (fail closed).
      --metrics <host:port> serves Prometheus metrics at GET /metrics on that address.
      HTTPS_PROXY is used to reach the control plane and secret sources.
  gantry device --control-plane <url> [--interval <seconds>] [--dry-run] [--once] [--home <folder>]
      Point the signed-in user's Claude Code and Codex at the gateway every --interval seconds (default 300) and
      report each coding tool's state (installed, through Gantry, or direct to a provider). --control-plane is the
      gateway's address (license feature devices). The enrolment token goes in GANTRY_DEVICE_TOKEN, or in the file
      GANTRY_DEVICE_TOKEN_FILE names (default /Library/Application Support/Gantry/device-token, which the MDM profile
      installs).
  gantry serve <policy> [--keys <file>] [--listen <host:port>] [--metrics <host:port>]
      Run the gateway on local files, as `gantry serve` does.
  gantry serve --unchecked
  gantry license show [--keys <file>]
      Show the license in GANTRY_LICENSE (or the file GANTRY_LICENSE_FILE names): customer, features, seats used
      (people in the keys file, default gantry.keys.yaml) of allowed, expiry and grace state. Checked offline.
  gantry license keygen --out <file>                         (Gantry staff builds only)
  gantry license issue --signing-key <file> --customer <name> --id <id> --features <a,b|all>
      --seats <n> --issued <YYYY-MM-DD> --expires <YYYY-MM-DD>              (Gantry staff builds only)
  gantry <gantry command>
      Every other command runs as the open source `gantry` runs it: check, init, key new|list|revoke|prune,
      store import, import litellm, audit verify|repair, prices, providers, kill, unkill, login, logout, version.";

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// The device enrolment token: GANTRY_DEVICE_TOKEN, else the file an MDM drops.
fn device_token() -> Option<String> {
    let set = |v: String| Some(v.trim().to_owned()).filter(|v| !v.is_empty());
    std::env::var("GANTRY_DEVICE_TOKEN")
        .ok()
        .and_then(set)
        .or_else(|| {
            let path = std::env::var("GANTRY_DEVICE_TOKEN_FILE")
                .unwrap_or_else(|_| "/Library/Application Support/Gantry/device-token".to_owned());
            std::fs::read_to_string(path).ok().and_then(set)
        })
}

/// Loads the license and says once what it unlocks; warns when more people hold keys than it has seats.
fn start_license(keys: PathBuf) -> Result<(), String> {
    let status = license::start()?;
    // A keys file that does not read is reported by the server itself, with the fix.
    if let Ok(Some(text)) = gantry_core::config::read_keys(&keys)
        && let Ok(used) = license::seats_used(&text)
        && let Some(warning) = status.seats_warning(used)
    {
        eprintln!("{warning}");
    }
    Ok(())
}

fn license_command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("show") => {
            let status = license::from_env()?;
            let Some(l) = &status.license else {
                println!("{}", status.describe());
                return Ok(());
            };
            let keys = PathBuf::from(flag(args, "--keys").unwrap_or("gantry.keys.yaml"));
            let seats =
                match gantry_core::config::read_keys(&keys)?.map(|t| license::seats_used(&t)) {
                    Some(Ok(used)) => format!("{used} used of {}", l.seats),
                    Some(Err(err)) => format!(
                        "{} allowed ({} does not read: {err})",
                        l.seats,
                        keys.display()
                    ),
                    None => format!(
                        "{} allowed (no keys file at {}; give it with --keys)",
                        l.seats,
                        keys.display()
                    ),
                };
            let state = match status.state {
                license::State::Grace => {
                    "expired, in its 30-day grace period: features stay on, then turn off"
                }
                license::State::Lapsed => {
                    "expired, grace period over: enterprise features are off, model traffic is still served"
                }
                _ => "valid",
            };
            println!(
                "Customer: {}\nLicense:  {}\nFeatures: {}\nSeats:    {seats}\nIssued:   {}\nExpires:  {} ({state})",
                l.customer,
                l.id,
                l.features.join(", "),
                l.issued,
                l.expires
            );
            Ok(())
        }
        #[cfg(feature = "issuer")]
        Some("keygen") => {
            let out = flag(args, "--out")
                .ok_or("`license keygen` needs --out <file>, a path that does not exist yet.")?;
            let public = license::keygen(Path::new(out))?;
            println!(
                "Signing key written to {out} (mode 600). Public key, for PUBLIC_KEY in src/license.rs:\n{public}"
            );
            Ok(())
        }
        #[cfg(feature = "issuer")]
        Some("issue") => {
            let need = |name: &str| {
                flag(args, name)
                    .map(str::to_owned)
                    .ok_or_else(|| format!("`license issue` needs {name}.\n{USAGE}"))
            };
            let issued = license::License {
                customer: need("--customer")?,
                id: need("--id")?,
                features: need("--features")?
                    .split(',')
                    .map(|f| f.trim().to_owned())
                    .filter(|f| !f.is_empty())
                    .collect(),
                seats: need("--seats")?.parse().map_err(|_| {
                    "--seats is a whole number of people, for example --seats 50.".to_owned()
                })?,
                issued: need("--issued")?,
                expires: need("--expires")?,
            };
            println!(
                "{}",
                license::issue(Path::new(&need("--signing-key")?), &issued)?
            );
            Ok(())
        }
        #[cfg(not(feature = "issuer"))]
        Some("keygen" | "issue") => Err(
            "this build cannot sign licenses. Gantry staff build with `--features issuer`."
                .to_owned(),
        ),
        _ => Err(USAGE.to_owned()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let name = format!("gantry enterprise {}", gantry_core::VERSION);
    let result: Result<(), String> = match args.first().map(String::as_str) {
        Some("node") => match flag(&args, "--control-plane") {
            Some(cp) => {
                if let Err(err) = license::start() {
                    eprintln!("error: {err}");
                    return ExitCode::from(2);
                }
                let interval = flag(&args, "--interval")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(5);
                let secrets = match args
                    .windows(2)
                    .filter(|w| w[0] == "--secrets")
                    .map(|w| secrets::parse(&w[1]))
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(secrets) => secrets,
                    Err(err) => {
                        eprintln!("error: {err}");
                        return ExitCode::from(2);
                    }
                };
                let secrets_interval = flag(&args, "--secrets-interval")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(60);
                let opts = node::Options {
                    control_plane: cp.to_owned(),
                    dir: PathBuf::from(flag(&args, "--dir").unwrap_or("/var/lib/gantry")),
                    listen: flag(&args, "--listen")
                        .unwrap_or("127.0.0.1:8080")
                        .to_owned(),
                    interval: Duration::from_secs(interval),
                    secrets,
                    secrets_interval: Duration::from_secs(secrets_interval),
                    max_offline: flag(&args, "--max-offline")
                        .and_then(|s| s.parse().ok())
                        .map(Duration::from_secs),
                    metrics: flag(&args, "--metrics").map(str::to_owned),
                    pass_env: args
                        .windows(2)
                        .filter(|w| w[0] == "--pass-env")
                        .flat_map(|w| w[1].split(',').map(|s| s.trim().to_owned()).collect::<Vec<_>>())
                        .filter(|s| !s.is_empty())
                        .collect(),
                };
                // SIGTERM (a rollout, `docker stop`) and Ctrl-C stop the node cleanly: it ships what is left and
                // stops the gateway with it instead of leaving it serving on its own.
                tokio::spawn(async {
                    #[cfg(unix)]
                    {
                        if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                            tokio::select! {
                                _ = term.recv() => {}
                                _ = tokio::signal::ctrl_c() => {}
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = tokio::signal::ctrl_c().await;
                    }
                    node::STOP.store(true, std::sync::atomic::Ordering::SeqCst);
                });
                // The node loop blocks; it runs on its own thread so the runtime stays free.
                tokio::task::spawn_blocking(move || node::run(opts))
                    .await
                    .unwrap_or_else(|err| Err(err.to_string()))
            }
            None => Err(format!("`node` needs --control-plane.\n{USAGE}")),
        },
        Some("device") => match (flag(&args, "--control-plane"), device_token()) {
            (Some(cp), Some(token)) => {
                let opts = device::Options {
                    control_plane: cp.to_owned(),
                    token,
                    interval: Duration::from_secs(
                        flag(&args, "--interval")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(300),
                    ),
                    dry_run: args.iter().any(|a| a == "--dry-run"),
                    once: args.iter().any(|a| a == "--once"),
                    home: flag(&args, "--home").map(PathBuf::from),
                };
                tokio::task::spawn_blocking(move || device::run(opts))
                    .await
                    .unwrap_or_else(|err| Err(err.to_string()))
            }
            (None, _) => Err(format!("`device` needs --control-plane.\n{USAGE}")),
            (_, None) => Err("no enrolment token: set GANTRY_DEVICE_TOKEN, or GANTRY_DEVICE_TOKEN_FILE to a file holding it. An owner or admin creates one on the console's Devices page.".to_owned()),
        },
        Some("license") => license_command(&args[1..]),
        Some("serve") if args.get(1).map(String::as_str) == Some("--unchecked") => {
            gantry_server::serve_from_env(&name, true)
                .await
                .map_err(|err| err.to_string())
        }
        Some("serve") if args.len() >= 2 => match start_license(
            flag(&args, "--keys")
                .map(PathBuf::from)
                .unwrap_or_else(|| gantry_core::config::keys_path_for(Path::new(&args[1]))),
        ) {
            Err(err) => Err(err),
            Ok(()) => match enterprise::restore_audit(
                Path::new(&args[1]),
                flag(&args, "--keys").map(Path::new),
            ) {
                Err(err) => Err(err),
                Ok(()) => {
                    let served = gantry_server::serve_policy_with(
                        &name,
                        Path::new(&args[1]),
                        flag(&args, "--keys").map(Path::new),
                        flag(&args, "--listen"),
                        flag(&args, "--metrics"),
                        None,
                        &|host| enterprise::extend(license::current(), host),
                    )
                    .await
                    .map_err(|err| err.to_string());
                    tokio::task::spawn_blocking(enterprise::finish_audit)
                        .await
                        .ok();
                    served
                }
            },
        },
        // `serve` without a policy and `help` stay here, so the open source server never starts unlicensed from this binary.
        Some(command) if !matches!(command, "serve" | "help" | "--help" | "-h") => {
            return gantry_cli::run(&args).await;
        }
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}
