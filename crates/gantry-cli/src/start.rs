//! `gantry start`: step 1 of the five steps (See). Writes an observe policy and an admin key, prints the tool
//! settings and runs the gateway.

use std::{
    ffi::OsString,
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

use gantry_core::keyfile;

/// The providers `gantry start` knows the models of, with the models people use most from each. A policy lists
/// exact model names, so a provider without a list here is set up with `gantry init` instead.
const PROVIDERS: &[(&str, &[&str])] = &[
    (
        "openai",
        &["gpt-5", "gpt-5-mini", "gpt-5-codex", "gpt-4o-mini"],
    ),
    ("anthropic", &["claude-sonnet-5-5", "claude-haiku-5-5"]),
    ("gemini", &["gemini-2.5-pro", "gemini-2.5-flash"]),
];

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

pub struct Options<'a> {
    pub dir: &'a Path,
    pub providers: Option<&'a str>,
    pub yes: bool,
    pub force: bool,
    pub serve: bool,
    pub listen: &'a str,
    pub all_tools: bool,
    /// The image's default command: serve a mounted policy, or the one an earlier start wrote on the volume, and
    /// write one only when there is neither.
    pub container: bool,
}

#[derive(Default)]
struct Chosen {
    id: &'static str,
    models: &'static [&'static str],
    /// `<ID>_PROVIDER_KEY`, the variable the policy reads the key from.
    key_env: String,
    /// Where the key was found: `key_env` itself or `<ID>_API_KEY`, which the tools' own settings below reuse.
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

/// The coding tools found on this machine: a program on `PATH`, or Codex's `~/.codex` folder.
#[derive(Default)]
struct Tools {
    claude: bool,
    codex: bool,
    cursor: bool,
    vscode: bool,
}

impl Tools {
    fn all() -> Self {
        Self {
            claude: true,
            codex: true,
            cursor: true,
            vscode: true,
        }
    }

    fn found(path: Option<OsString>, home: Option<PathBuf>) -> Self {
        let dirs: Vec<PathBuf> = path
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        let on_path = |name: &str| {
            dirs.iter()
                .any(|dir| dir.join(name).is_file() || dir.join(format!("{name}.exe")).is_file())
        };
        Self {
            claude: on_path("claude"),
            codex: on_path("codex") || home.is_some_and(|h| h.join(".codex").is_dir()),
            cursor: on_path("cursor"),
            vscode: on_path("code"),
        }
    }

    fn none(&self) -> bool {
        !(self.claude || self.codex || self.cursor || self.vscode)
    }
}

fn choose(
    asked: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<Chosen>, String> {
    let known = || {
        PROVIDERS
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let Some(asked) = asked else {
        let found: Vec<Chosen> = PROVIDERS
            .iter()
            .filter_map(|(id, models)| {
                key_env(id, env).map(|(key_env, found_in)| Chosen {
                    id,
                    models,
                    key_env,
                    found_in,
                })
            })
            .collect();
        if found.is_empty() {
            let names: Vec<String> = PROVIDERS
                .iter()
                .map(|(id, _)| format!("{}_PROVIDER_KEY", id.to_ascii_uppercase()))
                .collect();
            return Err(format!(
                "no provider key was found in the environment. Set one of {} to your provider key (OPENAI_API_KEY, ANTHROPIC_API_KEY and GEMINI_API_KEY are read too), then run gantry start again.",
                names.join(", ")
            ));
        }
        return Ok(found);
    };
    let mut chosen = Vec::new();
    for id in asked.split(',').map(str::trim).filter(|id| !id.is_empty()) {
        let Some((id, models)) = PROVIDERS.iter().find(|(known, _)| *known == id) else {
            return Err(format!(
                "gantry start does not know the models of provider \"{id}\". It sets up {}. For another provider, run gantry init --provider {id} --models <a,b>.",
                known()
            ));
        };
        let Some((key_env, found_in)) = key_env(id, env) else {
            let upper = id.to_ascii_uppercase();
            return Err(format!(
                "{upper}_PROVIDER_KEY is not set, so there is no key for provider {id}. Set it (or {upper}_API_KEY) to your {id} key, or leave {id} out of --providers."
            ));
        };
        if chosen.iter().all(|c: &Chosen| c.id != *id) {
            chosen.push(Chosen {
                id,
                models,
                key_env,
                found_in,
            });
        }
    }
    if chosen.is_empty() {
        return Err(format!(
            "--providers names no provider. Give a list such as --providers {}.",
            known()
        ));
    }
    Ok(chosen)
}

fn policy(chosen: &[Chosen], store: bool) -> String {
    let mut text = String::from(
        "# Written by gantry start. Step 1, See: every key may use every model, and in observe mode\n# nothing is blocked; what a rule would refuse is recorded. Reference: https://gantry-docs.eliran.me/governance/policy/\nversion: 1\nmode: observe\nproviders:\n",
    );
    for c in chosen {
        text.push_str(&format!(
            "  - name: {id}\n    preset: {id}\n    key_env: {env}\n    models: [{models}]\n",
            id = c.id,
            env = c.key_env,
            models = c.models.join(", ")
        ));
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

/// Asks once which providers to use, the ones found in the environment by default.
fn ask(found: &[Chosen]) -> Result<Option<String>, String> {
    let list: Vec<&str> = found.iter().map(|c| c.id).collect();
    print!("Providers to put behind Gantry [{}]: ", list.join(","));
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| {
        format!("could not read the answer: {e}. Run gantry start --yes to take the defaults.")
    })?;
    let line = line.trim();
    Ok((!line.is_empty()).then(|| line.to_string()))
}

pub async fn run(options: &Options<'_>) -> Result<(), String> {
    let env = |name: &str| std::env::var(name).ok();
    if options.container {
        let written = options.dir.join("gantry.policy.yaml");
        if let Some(policy) = [Path::new(MOUNTED_POLICY), written.as_path()]
            .into_iter()
            .find(|p| p.exists())
        {
            // No keys found is not an error here: the policy may read other variables, and serve names any unset.
            let chosen = choose(None, &env).unwrap_or_default();
            println!(
                "Serving {} (its keys file beside it). The admin key was printed at the first start.",
                policy.display()
            );
            if !options.serve {
                return Ok(());
            }
            return serve(&chosen, policy, options.listen, &env);
        }
    }
    let mut chosen = choose(options.providers, &env)?;
    if !options.yes && options.providers.is_none() && std::io::stdin().is_terminal() {
        if let Some(answer) = ask(&chosen)? {
            chosen = choose(Some(&answer), &env)?;
        }
    }
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
    if policy_path.exists() && !options.force {
        return Err(format!(
            "{} exists, and gantry start does not write over a policy. Run gantry serve {} to use it, or gantry start --force to replace it.",
            policy_path.display(),
            policy_path.display()
        ));
    }
    std::fs::write(&policy_path, policy(&chosen, store))
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
            println!(
                "The store named by {STORE_ENV} already holds an admin key, printed at the first start. Lost it? From any machine that reaches the database, with {STORE_ENV} set: gantry key new <name> --team admin --admin --policy {}",
                policy_path.display()
            );
            if !options.serve {
                return Ok(());
            }
            return serve(&chosen, &policy_path, options.listen, &env);
        }
    }
    let admin = keyfile::Attributes {
        admin: true,
        ..Default::default()
    };
    let issued = keyfile::issue_with("admin", "admin", &admin, &keys_path)?;
    let tools = if options.all_tools {
        Tools::all()
    } else {
        Tools::found(
            std::env::var_os("PATH"),
            std::env::var_os("HOME").map(PathBuf::from),
        )
    };
    // An address that listens everywhere is opened on this machine as localhost.
    let url = format!(
        "http://{}",
        options.listen.replacen("0.0.0.0:", "localhost:", 1)
    );
    print!(
        "{}",
        report(
            &chosen,
            &policy_path,
            &if opened.is_some() {
                format!("the store named by {STORE_ENV}")
            } else {
                keys_path.display().to_string()
            },
            &issued,
            &url,
            &tools
        )
    );
    let listen = if options.listen == DEFAULT_LISTEN {
        String::new()
    } else {
        format!(" --listen {}", options.listen)
    };
    if !options.serve {
        println!(
            "Start the gateway with:\n\n  gantry serve {}{listen}",
            policy_path.display()
        );
        return Ok(());
    }
    println!(
        "Starting the gateway. Stop it with Ctrl-C, start it again with gantry serve {}{listen}.\n",
        policy_path.display()
    );
    serve(&chosen, &policy_path, options.listen, &env)
}

/// Runs `gantry serve` in place of this process, with each provider key under the name the policy reads: a key
/// found as `<ID>_API_KEY` is passed on as `<ID>_PROVIDER_KEY`. The same binary serves, so an image's `gantry`
/// serves with what it adds.
fn serve(
    chosen: &[Chosen],
    policy: &Path,
    listen: &str,
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

fn report(
    chosen: &[Chosen],
    policy: &Path,
    keys: &str,
    issued: &keyfile::Issued,
    url: &str,
    tools: &Tools,
) -> String {
    let has = |id: &str| chosen.iter().find(|c| c.id == id);
    let ids: Vec<&str> = chosen.iter().map(|c| c.id).collect();
    let mut out = format!(
        "Wrote {}: observe mode and one rule that lets every key use every model of {}. Nothing is blocked, and every request is recorded.\n",
        policy.display(),
        ids.join(", "),
    );
    // The policy reads <ID>_PROVIDER_KEY. A key found under the provider's own name is passed to the gateway this
    // command starts; to run gantry serve later, it needs the provider name too.
    let moved: Vec<&Chosen> = chosen.iter().filter(|c| c.found_in != c.key_env).collect();
    if !moved.is_empty() {
        out.push_str(
            "\nThe policy reads each provider key from <PROVIDER>_PROVIDER_KEY, so the tool settings below can set the providers' own variables to the Gantry key in the same shell. The gateway started here gets the keys; before you run gantry serve yourself, export them:\n\n",
        );
        for c in &moved {
            out.push_str(&format!("  export {}=${}\n", c.key_env, c.found_in));
        }
    }
    out.push_str(&format!(
        "\nAdmin key, shown once and kept nowhere (only its hash is in {}):\n\n  export GANTRY_KEY={}\n\nThe same key signs in to the console at {url}/console.\n",
        keys,
        issued.key
    ));
    if issued.rotated {
        out.push_str(
            "The keys file already had an admin key. Both work until you remove the old entry.\n",
        );
    }
    if tools.claude {
        match has("anthropic") {
            Some(c) => out.push_str(&format!(
                "\nClaude Code:\n\n  export ANTHROPIC_BASE_URL={url}\n  export ANTHROPIC_API_KEY=$GANTRY_KEY\n  export ANTHROPIC_MODEL={}\n  export ANTHROPIC_SMALL_FAST_MODEL={}\n  claude\n",
                c.models[0], c.models[1]
            )),
            None => out.push_str("\nClaude Code needs the anthropic provider: set ANTHROPIC_PROVIDER_KEY and run gantry start --force.\n"),
        }
    }
    let openai = has("openai").is_some();
    if openai && tools.codex {
        out.push_str(&format!(
            "\nCodex, in ~/.codex/config.toml:\n\n  model = \"gpt-5-codex\"\n  model_provider = \"gantry\"\n\n  [model_providers.gantry]\n  name = \"Gantry\"\n  base_url = \"{url}/v1\"\n  env_key = \"GANTRY_KEY\"\n  wire_api = \"responses\"\n  stream_max_retries = 0\n"
        ));
    }
    if openai {
        out.push_str(&format!(
            "\nOpenAI SDKs:\n\n  export OPENAI_BASE_URL={url}/v1\n  export OPENAI_API_KEY=$GANTRY_KEY\n"
        ));
    }
    if openai && tools.cursor {
        out.push_str(&format!(
            "\nCursor, in Settings, Models. Cursor's servers send its requests, so it reaches Gantry only on a public HTTPS address in place of this one:\n\n  OpenAI API Key:            the GANTRY_KEY above\n  Override OpenAI Base URL:  {url}/v1\n  Model name:                gpt-4o-mini\n"
        ));
    }
    if openai && tools.vscode {
        out.push_str(&format!(
            "\nVS Code extensions (Cline, Continue, Roo Code, Kilo Code): an OpenAI-compatible provider with base URL {url}/v1 and the GANTRY_KEY above. Each has a guide at https://gantry-docs.eliran.me/integrations/coding-tools/\n"
        ));
    }
    if !openai && (tools.codex || tools.cursor || tools.vscode) {
        out.push_str("\nCodex, Cursor and VS Code extensions need the openai provider: set OPENAI_PROVIDER_KEY and run gantry start --force.\n");
    }
    if tools.none() {
        out.push_str("\nNo coding tool (claude, codex, cursor, code) was found on PATH. gantry start --all-tools prints the settings for each.\n");
    }
    out.push('\n');
    out
}
