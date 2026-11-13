//! Commercial edition. Runs the open source server, and runs it as a node managed by the Gantry control plane
//! (hybrid: at the customer; hosted: in Gantry's cloud).

mod node;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage:
  gantry-enterprise node --control-plane <url> [--dir <folder>] [--listen <host:port>] [--interval <seconds>]
      Run a gateway managed by the control plane. The node token goes in GANTRY_NODE_TOKEN.
  gantry-enterprise serve <policy> [--keys <file>] [--listen <host:port>]
      Run the gateway on local files, as `gantry serve` does.
  gantry-enterprise serve --unchecked";

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
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
                let opts = node::Options {
                    control_plane: cp.to_owned(),
                    dir: PathBuf::from(flag(&args, "--dir").unwrap_or("/var/lib/gantry")),
                    listen: flag(&args, "--listen")
                        .unwrap_or("127.0.0.1:8080")
                        .to_owned(),
                    interval: Duration::from_secs(interval),
                };
                // The node loop blocks; it runs on its own thread so the runtime stays free.
                tokio::task::spawn_blocking(move || node::run(opts))
                    .await
                    .unwrap_or_else(|err| Err(err.to_string()))
            }
            None => Err(format!("`node` needs --control-plane.\n{USAGE}")),
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
