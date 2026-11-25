//! Commercial edition. Runs the open source server, and runs it as a node managed by the Enterplace control plane
//! (hybrid: at the customer; hosted: in Enterplace's cloud).

mod device;
mod enterprise;
mod license;
mod managers;
mod node;
mod secrets;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage:
  enterplace node --control-plane <url> [--dir <folder>] [--listen <host:port>] [--interval <seconds>]
      [--secrets NAME=<source>]... [--secrets-interval <seconds>]
      Run a gateway managed by the control plane. The node token goes in ENTERPLACE_NODE_TOKEN.
      --secrets gives the provider key the policy names NAME (key_env) from a source polled every
      --secrets-interval seconds (default 60), rotated without restarting the gateway. Sources:
      file:/path, env:OTHER, vault:<KV v2 URL>#field (token in VAULT_TOKEN),
      aws-sm:<secret ARN>[#field] (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN).
      The gateway's environment starts empty: it gets PATH, HOME, TZ, LANG, SSL_CERT_*, OTEL_*, every *_PROVIDER_KEY,
      and the names in --pass-env A,B (for example AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY for Bedrock).
      --max-offline <seconds> stops serving when the control plane has not answered for that long (fail closed).
      --metrics <host:port> serves Prometheus metrics at GET /metrics on that address.
      HTTPS_PROXY is used to reach the control plane and secret sources.
  enterplace device --control-plane <url> [--interval <seconds>] [--dry-run] [--once] [--home <folder>]
      Point the signed-in user's Claude Code and Codex at the gateway every --interval seconds (default 300) and
      report each coding tool's state (installed, through Enterplace, or direct to a provider) and the MCP servers
      configured in Claude Desktop, Claude Code, Cursor, VS Code and Zed. --control-plane is the gateway's address
      (license feature devices). The enrolment token goes in ENTERPLACE_DEVICE_TOKEN, or in the file
      ENTERPLACE_DEVICE_TOKEN_FILE names (default /Library/Application Support/Enterplace/device-token on macOS, which the MDM
      profile installs; /etc/enterplace/device-token on Linux; C:\\ProgramData\\Enterplace\\device-token on Windows).
  enterplace watch setup --gateway <url> (--team <team> | --person <name>) [--org <org>] [--label <text>] [--days <n>] [--token <token>]
      Print the Claude Code managed settings that send its telemetry to the gateway's watch receiver (license feature
      watch): for people on Claude Team or Enterprise seats, whose requests cannot go through a gateway. Creates a
      watch token through the admin API with the admin key in ENTERPLACE_ADMIN_KEY, or uses the one --token gives.
  enterplace serve <policy> [--keys <file>] [--listen <host:port>] [--metrics <host:port>]
      [--tls-cert <pem> --tls-key <pem>] [--admin-listen <host:port>] [--no-migrate]
      Run the gateway on local files, as `enterplace serve` does, with the same flags.
  enterplace serve --unchecked
  enterplace store migrate [--policy <file>] [--keys <file>]
      Create or update every table of the store, those of the licensed features included, then stop: the step
      to run before gateways started with `serve --no-migrate`.
  enterplace license show [--keys <file>]
      Show the license in ENTERPLACE_LICENSE (or the file ENTERPLACE_LICENSE_FILE names): customer, features, seats used
      (people in the keys file, default enterplace.keys.yaml) of allowed, expiry and grace state. Checked offline.
  enterplace license keygen --out <file>                         (Enterplace staff builds only)
  enterplace license issue --signing-key <file> --customer <name> --id <id> --features <a,b|all>
      --seats <n> --issued <YYYY-MM-DD> --expires <YYYY-MM-DD>              (Enterplace staff builds only)
  enterplace <enterplace command>
      Every other command runs as the open source `enterplace` runs it: check, init, key new|list|revoke|prune,
      store import, import litellm, audit verify|repair, prices, providers, kill, unkill, login, logout, version.";

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// The device enrolment token: ENTERPLACE_DEVICE_TOKEN, else the file an MDM drops.
fn device_token() -> Option<String> {
    let set = |v: String| Some(v.trim().to_owned()).filter(|v| !v.is_empty());
    std::env::var("ENTERPLACE_DEVICE_TOKEN")
        .ok()
        .and_then(set)
        .or_else(|| {
            let default = if cfg!(target_os = "windows") {
                r"C:\ProgramData\Enterplace\device-token"
            } else if cfg!(target_os = "macos") {
                "/Library/Application Support/Enterplace/device-token"
            } else {
                "/etc/enterplace/device-token"
            };
            let path = std::env::var("ENTERPLACE_DEVICE_TOKEN_FILE")
                .unwrap_or_else(|_| default.to_owned());
            std::fs::read_to_string(path).ok().and_then(set)
        })
}

/// Loads the license and says once what it unlocks; warns when more people hold keys than it has seats.
fn start_license(keys: PathBuf) -> Result<(), String> {
    let status = license::start()?;
    // A keys file that does not read is reported by the server itself, with the fix.
    if let Ok(Some(text)) = enterplace_core::config::read_keys(&keys)
        && let Ok(used) = license::seats_used(&text)
        && let Some(warning) = status.seats_warning(used)
    {
        eprintln!("{warning}");
    }
    Ok(())
}

/// Lets `*_env` variables point at secret managers (feature `secrets`), and reads them again every
/// ENTERPLACE_SECRETS_REFRESH_SECONDS (300 unless set): a key rotated in the manager is used within that time, or at once
/// on SIGHUP.
fn start_secret_managers() {
    let env: managers::Env = std::sync::Arc::new(|name: &str| std::env::var(name).ok());
    enterplace_core::secrets::install(std::sync::Arc::new(managers::Managers::new(env)));
    let every = std::env::var("ENTERPLACE_SECRETS_REFRESH_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s >= 10)
        .unwrap_or(300);
    let spawned = std::thread::Builder::new()
        .name("enterplace-secrets".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(every));
                for problem in enterplace_core::secrets::refresh() {
                    eprintln!("enterplace: {problem}");
                }
            }
        });
    if let Err(err) = spawned {
        eprintln!(
            "enterplace: the thread that reads secret managers again could not start ({err}). Secrets are read at start and on SIGHUP only."
        );
    }
}

fn license_command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("show") => {
            let status = license::from_env()?;
            let Some(l) = &status.license else {
                println!("{}", status.describe());
                return Ok(());
            };
            let keys = PathBuf::from(flag(args, "--keys").unwrap_or("enterplace.keys.yaml"));
            let seats =
                match enterplace_core::config::read_keys(&keys)?.map(|t| license::seats_used(&t)) {
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
            "this build cannot sign licenses. Enterplace staff build with `--features issuer`."
                .to_owned(),
        ),
        _ => Err(USAGE.to_owned()),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let name = format!("enterplace enterprise {}", enterplace_core::VERSION);
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
                    dir: PathBuf::from(flag(&args, "--dir").unwrap_or("/var/lib/enterplace")),
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
            (_, None) => Err("no enrolment token: set ENTERPLACE_DEVICE_TOKEN, or ENTERPLACE_DEVICE_TOKEN_FILE to a file holding it. An owner or admin creates one on the console's Devices page.".to_owned()),
        },
        Some("watch") => {
            let rest = args[1..].to_vec();
            // Creating the token is a blocking call to the gateway.
            tokio::task::spawn_blocking(move || enterprise::watch::setup(&rest))
                .await
                .unwrap_or_else(|err| Err(err.to_string()))
                .map(|out| println!("{out}"))
        }
        Some("license") => license_command(&args[1..]),
        Some("serve") if args.get(1).map(String::as_str) == Some("--unchecked") => {
            enterplace_server::serve_from_env(&name, true)
                .await
                .map_err(|err| err.to_string())
        }
        Some("serve") if args.len() >= 2 => {
            let rest: Vec<&str> = args[1..].iter().map(String::as_str).collect();
            // The same flags as the open source `enterplace serve`, an unknown one refused as it is there.
            match enterplace_cli::serve_args(&rest) {
                None => Err(format!(
                    "`enterplace {}` is missing an argument or has one Enterplace does not know.\nUsage: enterplace serve <policy> [--keys <file>] [--listen <host:port>] [--metrics <host:port>] [--tls-cert <pem> --tls-key <pem>] [--admin-listen <host:port>] [--no-migrate]",
                    args.join(" ")
                )),
                Some((policy, options)) => match start_license(
                    options
                        .keys
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| enterplace_core::config::keys_path_for(policy)),
                )
                .and_then(|()| enterprise::restore_audit(policy, options.keys))
                {
                    Err(err) => Err(err),
                    Ok(()) => {
                        if license::unlocked("secrets") {
                            start_secret_managers();
                        }
                        let served =
                            enterplace_server::serve_policy_with(&name, policy, &options, &|host| {
                                enterprise::extend(license::current(), host)
                            })
                            .await
                            .map_err(|err| err.to_string());
                        tokio::task::spawn_blocking(enterprise::finish_audit)
                            .await
                            .ok();
                        served
                    }
                },
            }
        }
        // The open source tables, then those of the features the license unlocks: what `serve` would create.
        Some("store") if args.get(1).map(String::as_str) == Some("migrate") => {
            match (license::start(), flag(&args, "--policy"), flag(&args, "--keys")) {
                (Err(err), _, _) => Err(err),
                (Ok(_), policy, keys) if args.len() == 2 + 2 * (usize::from(policy.is_some()) + usize::from(keys.is_some())) => {
                    enterplace_cli::store_migrate(
                        Path::new(policy.unwrap_or("enterplace.policy.yaml")),
                        keys.map(Path::new),
                        &|pg| enterprise::migrate_unlocked(license::current(), pg),
                    )
                }
                _ => Err("Usage: enterplace store migrate [--policy <file>] [--keys <file>]".to_owned()),
            }
        }
        // `serve` without a policy and `help` stay here, so the open source server never starts unlicensed from this binary.
        Some(command) if !matches!(command, "serve" | "help" | "--help" | "-h") => {
            return enterplace_cli::run(&args).await;
        }
        // Asked for help: every command, the open source ones first (start is the first one a person runs).
        Some("help" | "--help" | "-h") => {
            let enterprise = USAGE.strip_prefix("usage:\n").unwrap_or(USAGE);
            println!("{}\nEnterprise commands:\n{enterprise}", enterplace_cli::USAGE);
            return ExitCode::SUCCESS;
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
