//! `gantry start`: step 1 of the five steps (See). Writes an observe policy and an admin key, prints the tool
//! settings and runs the gateway.

use std::{
    io::{BufRead, IsTerminal, Write},
    path::Path,
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

const URL: &str = "http://127.0.0.1:8080";

pub struct Options<'a> {
    pub dir: &'a Path,
    pub providers: Option<&'a str>,
    pub yes: bool,
    pub force: bool,
    pub serve: bool,
}

struct Chosen {
    id: &'static str,
    models: &'static [&'static str],
    key_env: String,
}

/// The variable holding a provider's key: the `_PROVIDER_KEY` form the docs use first, then the provider's own.
fn key_env(id: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let id = id.to_ascii_uppercase();
    [format!("{id}_PROVIDER_KEY"), format!("{id}_API_KEY")]
        .into_iter()
        .find(|name| env(name).is_some_and(|v| !v.trim().is_empty()))
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
                key_env(id, env).map(|key_env| Chosen {
                    id,
                    models,
                    key_env,
                })
            })
            .collect();
        if found.is_empty() {
            let names: Vec<String> = PROVIDERS
                .iter()
                .map(|(id, _)| format!("{}_API_KEY", id.to_ascii_uppercase()))
                .collect();
            return Err(format!(
                "no provider key was found in the environment. Set one of {} to your provider key (or the _PROVIDER_KEY form, such as OPENAI_PROVIDER_KEY), then run gantry start again.",
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
        let Some(key_env) = key_env(id, env) else {
            let upper = id.to_ascii_uppercase();
            return Err(format!(
                "{upper}_API_KEY is not set, so there is no key for provider {id}. Set it (or {upper}_PROVIDER_KEY) to your {id} key, or leave {id} out of --providers."
            ));
        };
        if chosen.iter().all(|c: &Chosen| c.id != *id) {
            chosen.push(Chosen {
                id,
                models,
                key_env,
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

fn policy(chosen: &[Chosen]) -> String {
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
    if policy_path.exists() && !options.force {
        return Err(format!(
            "{} exists, and gantry start does not write over a policy. Run gantry serve {} to use it, or gantry start --force to replace it.",
            policy_path.display(),
            policy_path.display()
        ));
    }
    std::fs::write(&policy_path, policy(&chosen))
        .map_err(|e| format!("could not write {}: {e}. Check that the folder is writable, or give another with --dir.", policy_path.display()))?;
    let admin = keyfile::Attributes {
        admin: true,
        ..Default::default()
    };
    let issued = keyfile::issue_with("admin", "admin", &admin, &keys_path)?;
    print!("{}", report(&chosen, &policy_path, &keys_path, &issued));
    if !options.serve {
        println!(
            "Start the gateway with:\n\n  gantry serve {}",
            policy_path.display()
        );
        return Ok(());
    }
    println!(
        "Starting the gateway. Stop it with Ctrl-C, start it again with gantry serve {}.\n",
        policy_path.display()
    );
    let name = format!("gantry {}", gantry_core::VERSION);
    gantry_server::serve_policy(&name, &policy_path, None, None, None, None)
        .await
        .map_err(|e| e.to_string())
}

fn report(chosen: &[Chosen], policy: &Path, keys: &Path, issued: &keyfile::Issued) -> String {
    let has = |id: &str| chosen.iter().find(|c| c.id == id);
    let ids: Vec<&str> = chosen.iter().map(|c| c.id).collect();
    let mut out = format!(
        "Wrote {}: observe mode and one rule that lets every key use every model of {}. Nothing is blocked, and every request is recorded.\n\nAdmin key, shown once and kept nowhere (only its hash is in {}). Run this line in the shell of each tool below:\n\n  export GANTRY_KEY={}\n\nThe same key signs in to the console at {URL}/console.\n",
        policy.display(),
        ids.join(", "),
        keys.display(),
        issued.key
    );
    if issued.rotated {
        out.push_str(
            "The keys file already had an admin key. Both work until you remove the old entry.\n",
        );
    }
    match has("anthropic") {
        Some(c) => out.push_str(&format!(
            "\nClaude Code:\n\n  export ANTHROPIC_BASE_URL={URL}\n  export ANTHROPIC_API_KEY=$GANTRY_KEY\n  export ANTHROPIC_MODEL={}\n  export ANTHROPIC_SMALL_FAST_MODEL={}\n  claude\n",
            c.models[0], c.models[1]
        )),
        None => out.push_str("\nClaude Code needs the anthropic provider: set ANTHROPIC_API_KEY and run gantry start --force.\n"),
    }
    if has("openai").is_some() {
        out.push_str(&format!(
            "\nCodex, in ~/.codex/config.toml:\n\n  model = \"gpt-5-codex\"\n  model_provider = \"gantry\"\n\n  [model_providers.gantry]\n  name = \"Gantry\"\n  base_url = \"{URL}/v1\"\n  env_key = \"GANTRY_KEY\"\n  wire_api = \"responses\"\n  stream_max_retries = 0\n\nOpenAI SDKs:\n\n  export OPENAI_BASE_URL={URL}/v1\n  export OPENAI_API_KEY=$GANTRY_KEY\n\nCursor, in Settings, Models. Cursor's servers send its requests, so it reaches Gantry only on a public HTTPS address in place of this one:\n\n  OpenAI API Key:            the GANTRY_KEY above\n  Override OpenAI Base URL:  {URL}/v1\n  Model name:                gpt-4o-mini\n"
        ));
    } else {
        out.push_str("\nCodex, Cursor and the OpenAI SDKs need the openai provider: set OPENAI_API_KEY and run gantry start --force.\n");
    }
    let shared: Vec<&str> = chosen
        .iter()
        .map(|c| c.key_env.as_str())
        .filter(|v| matches!(*v, "ANTHROPIC_API_KEY" | "OPENAI_API_KEY"))
        .collect();
    if !shared.is_empty() {
        out.push_str(&format!(
            "\nThe gateway reads your provider key from {}, which the lines above set to the Gantry key. Run the tools in another shell than the gateway.\n",
            shared.join(" and ")
        ));
    }
    out.push('\n');
    out
}
