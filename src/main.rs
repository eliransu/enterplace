//! Commercial edition. Runs the open source server, and runs it as a node managed by the Gantry control plane
//! (hybrid: at the customer; hosted: in Gantry's cloud).

mod device;
mod node;
mod secrets;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage:
  gantry-enterprise node --control-plane <url> [--dir <folder>] [--listen <host:port>] [--interval <seconds>]
      [--secrets NAME=<source>]... [--secrets-interval <seconds>]
      Run a gateway managed by the control plane. The node token goes in GANTRY_NODE_TOKEN.
      --secrets gives the provider key the policy names NAME (key_env) from a source polled every
      --secrets-interval seconds (default 60), rotated without restarting the gateway. Sources:
      file:/path, env:OTHER, vault:<KV v2 URL>#field (token in VAULT_TOKEN),
      aws-sm:<secret ARN>[#field] (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
      The gateway's environment starts empty: it gets PATH, HOME, TZ, LANG, SSL_CERT_*, every *_PROVIDER_KEY,
      and the names in --pass-env A,B (for example AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY for Bedrock).
      --max-offline <seconds> stops serving when the control plane has not answered for that long (fail closed).
      HTTPS_PROXY is used to reach the control plane and secret sources.
  gantry-enterprise device --control-plane <url> [--interval <seconds>] [--dry-run] [--once] [--home <folder>]
      Point the signed-in user's coding tools at the org's gateway every --interval seconds (default 300) and
      report coverage. The enrolment token goes in GANTRY_DEVICE_TOKEN, or in the file GANTRY_DEVICE_TOKEN_FILE
      names (default /Library/Application Support/Gantry/device-token, which the MDM profile installs).
  gantry-enterprise serve <policy> [--keys <file>] [--listen <host:port>]
      Run the gateway on local files, as `gantry serve` does.
  gantry-enterprise serve --unchecked";

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

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let name = format!("gantry enterprise {}", gantry_core::VERSION);
    let result: Result<(), String> = match args.first().map(String::as_str) {
        Some("node") => match flag(&args, "--control-plane") {
            Some(cp) => {
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
            (_, None) => Err("no enrolment token: set GANTRY_DEVICE_TOKEN, or GANTRY_DEVICE_TOKEN_FILE to a file holding it. Owners create one under Devices in the app.".to_owned()),
        },
        Some("serve") if args.get(1).map(String::as_str) == Some("--unchecked") => {
            gantry_server::serve_from_env(&name, true)
                .await
                .map_err(|err| err.to_string())
        }
        Some("serve") if args.len() >= 2 => gantry_server::serve_policy(
            &name,
            Path::new(&args[1]),
            flag(&args, "--keys").map(Path::new),
            flag(&args, "--listen"),
            None,
            None,
        )
        .await
        .map_err(|err| err.to_string()),
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
