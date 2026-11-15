//! `gantry start`: step 1 of the five steps (See). Writes an observe policy with the demo model and any provider
//! whose key is in the environment, an admin key and a master key, then runs the gateway. The gateway prints the
//! dashboard link that signs in once; providers are connected from the dashboard. No provider key is needed.

use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
};

use gantry_core::{catalog::START_PROVIDERS, keyfile};

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";

/// What the image's default command (`start --container`) uses in place of the defaults above.
pub const CONTAINER_DIR: &str = "/var/lib/gantry";
pub const CONTAINER_LISTEN: &str = "0.0.0.0:8080";
/// A policy mounted here is served as it is, as the image always did.
const MOUNTED_POLICY: &str = "/etc/gantry/gantry.policy.yaml";
/// The variable Render, Railway, Fly, App Platform and Heroku set to the Postgres they attach. In a container it
/// makes the store, so keys and the policy outlive a disk that a redeploy wipes. Only in a container: a shell's
/// DATABASE_URL may belong to another program.
const STORE_ENV: &str = "DATABASE_URL";
const MASTER_ENV: &str = "GANTRY_MASTER_KEY";
const MASTER_FILE_ENV: &str = "GANTRY_MASTER_KEY_FILE";
/// The master key `gantry start` makes beside the policy, which seals the provider keys pasted in the console.
const MASTER_FILE: &str = "gantry-master.key";

pub struct Options<'a> {
    pub dir: &'a Path,
    pub providers: Option<&'a str>,
    pub force: bool,
    pub serve: bool,
    pub listen: &'a str,
    /// Open the dashboard in the browser once the gateway listens (when stdout is a terminal and there is a display).
    pub open: bool,
    /// The image's default command: serve a mounted policy, or the one an earlier start wrote on the volume, and
    /// write one only when there is neither.
    pub container: bool,
}

#[derive(Default)]
struct Chosen {
    id: &'static str,
    /// `<ID>_PROVIDER_KEY`, the variable the policy reads the key from.
    key_env: String,
    /// Where the key was found: `key_env` itself or `<ID>_API_KEY`, passed on to the gateway under `key_env`.
    found_in: String,
}

/// The variable holding a provider's key: the `_PROVIDER_KEY` form the policy reads first, then the provider's own.
/// The policy always names `<ID>_PROVIDER_KEY`, so the tools may set `<ID>_API_KEY` to the Gantry key in the same
/// shell without taking the gateway's provider key away.
fn key_env(id: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<(String, String)> {
    let id = id.to_ascii_uppercase();
    let key_env = format!("{id}_PROVIDER_KEY");
    [key_env.clone(), format!("{id}_API_KEY")]
        .into_iter()
        .find(|name| env(name).is_some_and(|v| !v.trim().is_empty()))
        .map(|found_in| (key_env, found_in))
}

/// The providers to set up from keys in the environment: every one found, or those `--providers` names. None found
/// is fine: the demo model answers until a provider is connected in the console.
fn choose(
    asked: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<Chosen>, String> {
    let known = || {
        START_PROVIDERS
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let Some(asked) = asked else {
        return Ok(START_PROVIDERS
            .iter()
            .filter_map(|(id, _)| {
                key_env(id, env).map(|(key_env, found_in)| Chosen {
                    id,
                    key_env,
                    found_in,
                })
            })
            .collect());
    };
    let mut chosen = Vec::new();
    for id in asked.split(',').map(str::trim).filter(|id| !id.is_empty()) {
        let Some((id, _)) = START_PROVIDERS.iter().find(|(known, _)| *known == id) else {
            return Err(format!(
                "gantry start does not know the models of provider \"{id}\". It sets up {}. For another provider, run gantry init --provider {id} --models <a,b>.",
                known()
            ));
        };
        let Some((key_env, found_in)) = key_env(id, env) else {
            let upper = id.to_ascii_uppercase();
            return Err(format!(
                "{upper}_PROVIDER_KEY is not set, so there is no key for provider {id}. Set it (or {upper}_API_KEY) to your {id} key, leave out --providers and paste the key in the dashboard, or leave {id} out of --providers."
            ));
        };
        if chosen.iter().all(|c: &Chosen| c.id != *id) {
            chosen.push(Chosen {
                id,
                key_env,
                found_in,
            });
        }
    }
    Ok(chosen)
}

fn policy(chosen: &[Chosen], store: bool, env: &dyn Fn(&str) -> Option<String>) -> String {
    let mut text = String::from(
        "# Written by gantry start. Every key may use every model. Observe mode: nothing is blocked, and what a\n# rule would refuse is recorded as would_refuse. Reference: https://gantry-docs.eliran.me/governance/policy/\nversion: 1\nmode: observe\nproviders:\n  # Answered inside Gantry with a sample text, free: a first request works before any provider key is set.\n  - name: demo\n    preset: demo\n    models: [gantry-demo]\n",
    );
    for c in chosen {
        if let Some(lines) =
            gantry_core::catalog::start_provider(c.id, &format!("key_env: {}", c.key_env), env)
        {
            text.push_str(&lines);
        }
    }
    text.push_str(
        "rules:\n  - name: everyone\n    principals: { any: true }\n    models: [\"*\"]\n",
    );
    if store {
        // The policy lives in the store too, so the console edits it and a wiped disk does not undo the edits.
        text.push_str(&format!(
            "store: {{ postgres_url_env: {STORE_ENV}, policy_from: store }}\n"
        ));
    }
    text
}

/// The master key file beside the policy, made once (0600) unless a master key is already set in the environment.
/// `Ok(None)` when the environment sets one.
fn master_key(dir: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>, String> {
    let set = |name: &str| env(name).is_some_and(|v| !v.trim().is_empty());
    if set(MASTER_ENV) || set(MASTER_FILE_ENV) {
        return Ok(None);
    }
    let path = dir.join(MASTER_FILE);
    if path.exists() {
        return Ok(Some(path));
    }
    let secret = gantry_core::id::secret_hex(32)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(&path)
        .and_then(|mut file| {
            std::io::Write::write_all(&mut file, format!("{secret}\n").as_bytes())
        })
        .map_err(|e| {
            format!(
                "could not write {}: {e}. Check that the folder is writable, or give another with --dir.",
                path.display()
            )
        })?;
    Ok(Some(path))
}

/// How the gateway shows its dashboard link: opened in the browser only for a person at a terminal with a display.
fn mode(options: &Options<'_>, env: &dyn Fn(&str) -> Option<String>) -> &'static str {
    let display = cfg!(target_os = "macos")
        || cfg!(windows)
        || env("DISPLAY").is_some_and(|v| !v.is_empty())
        || env("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
    if options.container {
        "container"
    } else if options.open && display && std::io::stdout().is_terminal() {
        "open"
    } else {
        "print"
    }
}

pub async fn run(options: &Options<'_>) -> Result<(), String> {
    let env = |name: &str| std::env::var(name).ok();
    let mode = mode(options, &env);
    let restart = if options.container {
        "docker restart gantry"
    } else {
        "gantry start"
    };
    std::fs::create_dir_all(options.dir).map_err(|e| {
        format!(
            "could not make {}: {e}. Give another folder with --dir.",
            options.dir.display()
        )
    })?;
    let dir = std::fs::canonicalize(options.dir).unwrap_or_else(|_| options.dir.to_path_buf());
    let policy_path = dir.join("gantry.policy.yaml");
    let keys_path = dir.join("gantry.keys.yaml");
    let store = options.container && env(STORE_ENV).is_some_and(|v| !v.trim().is_empty());
    // With a store, credentials are sealed in the database, and a key made on a disk a redeploy wipes would leave
    // them sealed under a key nobody has: the platform's GANTRY_MASTER_KEY seals them instead.
    let master = if store { None } else { master_key(&dir, &env)? };
    // A start on a folder (or volume) that has a policy serves it: no second admin key, a fresh sign-in link.
    let existing = if options.container {
        [Path::new(MOUNTED_POLICY), policy_path.as_path()]
            .into_iter()
            .find(|p| p.exists())
            .map(Path::to_path_buf)
    } else {
        (policy_path.exists() && !options.force).then(|| policy_path.clone())
    };
    if let Some(policy) = existing {
        // No keys found is not an error here: the policy may read other variables, and serve names any unset.
        let chosen = choose(None, &env).unwrap_or_default();
        if !options.serve {
            println!(
                "{} exists: it is kept. Start the gateway with {restart}.",
                policy.display()
            );
            return Ok(());
        }
        return serve(
            &chosen,
            &policy,
            options.listen,
            mode,
            None,
            master.as_deref(),
            &env,
        );
    }
    let chosen = choose(options.providers, &env)?;
    std::fs::write(&policy_path, policy(&chosen, store, &env))
        .map_err(|e| format!("could not write {}: {e}. Check that the folder is writable, or give another with --dir.", policy_path.display()))?;
    // Held until serve replaces this process: while it is open, the key below goes to the store, not the file.
    let opened = if store {
        gantry_server::open_store(&policy_path, &keys_path, &env)?
    } else {
        None
    };
    if let Some(opened) = &opened {
        let admins = gantry_core::config::key_entries(&keys_path, &opened.keys_text())
            .map(|entries| entries.iter().any(|e| e.admin))
            .unwrap_or(false);
        if admins {
            if !options.serve {
                println!(
                    "The store named by {STORE_ENV} already holds an admin key, printed at the first start. Lost it? From any machine that reaches the database, with {STORE_ENV} set: gantry key new <name> --team admin --admin --policy {}",
                    policy_path.display()
                );
                return Ok(());
            }
            return serve(
                &chosen,
                &policy_path,
                options.listen,
                mode,
                None,
                master.as_deref(),
                &env,
            );
        }
    }
    let admin = keyfile::Attributes {
        admin: true,
        ..Default::default()
    };
    let issued = keyfile::issue_with("admin", "admin", &admin, &keys_path)?;
    if !options.serve {
        let kept = if opened.is_some() {
            format!("the store named by {STORE_ENV}")
        } else {
            keys_path.display().to_string()
        };
        println!(
            "Wrote {}.\n\nAdmin key, shown once (only its hash is kept, in {kept}):\n\n  export GANTRY_KEY={}\n",
            policy_path.display(),
            issued.key
        );
        if let Some(master) = &master {
            println!(
                "Provider keys pasted in the dashboard are sealed with the master key in {}: keep it with the policy.\n",
                master.display()
            );
        }
        println!("Start the gateway with {restart}.");
        return Ok(());
    }
    serve(
        &chosen,
        &policy_path,
        options.listen,
        mode,
        Some(&issued.key),
        master.as_deref(),
        &env,
    )
}

/// Runs `gantry serve` in place of this process, with each provider key under the name the policy reads: a key
/// found as `<ID>_API_KEY` is passed on as `<ID>_PROVIDER_KEY`. The same binary serves, so an image's `gantry`
/// serves with what it adds. The gateway prints the start block (`gantry_server::START_ENV`) once it listens.
fn serve(
    chosen: &[Chosen],
    policy: &Path,
    listen: &str,
    mode: &str,
    admin_key: Option<&str>,
    master: Option<&Path>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| {
        format!(
            "could not find the gantry binary to serve with: {e}. Run gantry serve {} --listen {listen}.",
            policy.display()
        )
    })?;
    let mut command = std::process::Command::new(exe);
    command.arg("serve").arg(policy).args(["--listen", listen]);
    command.env(gantry_server::START_ENV, mode);
    // The admin key reaches the gateway only to be printed once; the browser it opens does not get it.
    match admin_key {
        Some(key) => command.env(gantry_server::START_KEY_ENV, key),
        None => command.env_remove(gantry_server::START_KEY_ENV),
    };
    if let Some(master) = master {
        command.env(MASTER_FILE_ENV, master);
    }
    for c in chosen.iter().filter(|c| c.found_in != c.key_env) {
        if let Some(value) = env(&c.found_in) {
            command.env(&c.key_env, value);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = command.exec();
        Err(format!(
            "could not start gantry serve: {err}. Run gantry serve {} --listen {listen}.",
            policy.display()
        ))
    }
    #[cfg(not(unix))]
    {
        let status = command.status().map_err(|e| {
            format!(
                "could not start gantry serve: {e}. Run gantry serve {} --listen {listen}.",
                policy.display()
            )
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("gantry serve stopped with {status}."))
        }
    }
}
