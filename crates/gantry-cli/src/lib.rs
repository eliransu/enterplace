//! The `gantry` command line as a library: the `gantry` binary runs it, and so can a binary that adds commands of
//! its own and hands every other one to [`run`].

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::ExitCode,
};

use gantry_core::{
    audit, config, keyfile,
    policy::{Budget, Period},
    usage::PriceSource,
};

const USAGE: &str = "\
Usage: gantry <command>

Commands:
  check <policy> [--keys <file>]
        Check a policy file and its keys file. Prints every problem with its file and line.
  explain <policy> --key <hash prefix or name> --model <model> [--customer <name>] [--tags <a,b>] [--keys <file>]
        Say why a request from that key for that model would be allowed or refused: the rules passed over, the
        rule that decides, and every limit that applies (rule, key, organization, team, person, customer, tag,
        model, global) with where it is written and what it overrides. A running gateway adds what each budget
        has spent: GET /admin/explain.
  key new <name> --team <team> [--admin] [--expires <date>] [--budget <usd>/<period>] [--models <a,b>] [--tpm <n>]
          [--org <org>] [--customer <name>] [--tags <a,b>] [--parallel <n>] [--role <role>]
          [--url <gateway url>] [--quiet] [--keys <file>]
        Make a key for a person or a workload. The key is printed once, with the lines that point
        Claude Code and OpenAI SDKs at Gantry (--url, default http://127.0.0.1:8080). Only its hash is
        saved. --admin makes a key that may sign in to the console and call the admin API (the first
        admin starts here). --expires 2026-12-31 refuses the key from that UTC day on (or a time:
        2026-12-31T18:00:00Z). --budget 20/month caps what this key alone may spend. --models
        gpt-4o-mini,o3 narrows its rule's models for this key; --tpm 200000 caps its tokens per minute.
        The period of --budget is day, week, month, year, hour, minute or a count such as 6h, with @<zone>
        for a time zone: --budget 100/month@America/New_York. --org puts the key in an organization the
        policy lists; --customer makes every request with it for that end customer; --tags tags them;
        --parallel 4 caps its requests in flight; --role names a console role from the policy.
        --quiet prints the key alone.
  key list [--keys <file>]
        List the keys in the keys file: name, team, hash prefix, admin, expiry, budget,
        models and tpm. Never a key.
  key revoke <hash prefix> [--keys <file>]
        Remove the key whose hash starts with the prefix (at least 8 hex characters, as `key list` shows
        it). A running Gantry refuses it within 2 seconds.
  key prune [--keys <file>]
        Remove the entries whose expiry has passed, such as old `gantry login` keys. Each is removed
        as `DELETE /admin/keys` removes one, safe while Gantry runs; every other line is kept.
  store import --keys <file> [--policy <file>]
        Copy the keys of a keys file, and the kill switches beside it, into the store the policy's store:
        names (default gantry.policy.yaml). Keys already there are left as they are. The file is not changed.
  import litellm <config.yaml> [--keys-from <csv or json export>] [--out <policy file>]
        Write a Gantry policy (default gantry.policy.yaml, never over an existing file) from a LiteLLM proxy
        config, check it, and list what could not be mapped. --keys-from reads an export of LiteLLM virtual
        keys: they become team rules and the `gantry key new` lines to reissue them (keys cannot move).
  prices <model> [--policy <file>]
        Print the price Gantry charges for a model and where it came from: the policy's prices:, Gantry's
        own table, or the table generated from LiteLLM's price map (with its source and date).
  init [--provider <id>] [--models <a,b>] [--out <policy file>]
        Write a starter policy (default gantry.policy.yaml, never over an existing file) for one provider of
        the catalog (default openai, see `gantry providers`) and the models it serves (--models; openai defaults
        to gpt-4o-mini): everyone may use them. Then set
        the provider key it names and run `gantry serve`, which prints a one-time link to make the first admin.
  providers [--markdown]
        List the provider catalog: id, name, kind and URL. A policy provider may say `preset: <id>` in place
        of its url and kind. --markdown prints the reference page of the docs.
  guardrail test <name> (--corpus <file.jsonl> | --since <7d>) [--policy <file>]
        Run a guardrail the policy defines (secrets, pii, regex or keywords; a rule need not use it yet) over
        examples before it goes live: how many requests it would hit, its kinds, up to 20 matched spans with all
        but their first and last two characters masked, and precision and recall when the examples carry
        expect: true or false. The corpus has one JSON object per line: {\"text\": \"...\"} or {\"body\": {...}}.
        --since reads captured request bodies; the audit log holds no text, so without capture it says so.
  serve <policy> [--keys <file>] [--listen <host:port>] [--metrics <host:port>]
        [--tls-cert <pem> --tls-key <pem>]
        Run the gateway: every request is identified, checked against the policy and recorded.
        Listens on 127.0.0.1:8080 unless --listen says otherwise. --metrics serves GET /metrics
        (Prometheus) on an address of its own; it takes no key, so keep it on loopback or a private network.
        --tls-cert and --tls-key (both, PEM) make Gantry serve HTTPS itself.
  audit verify [<file>] [--expect-last <hash>]
        Check that the audit log is one unbroken chain: no record changed, inserted or reordered.
        Prints the count and the last hash, to keep elsewhere. With --expect-last, it also checks
        that a hash kept earlier is still in the chain with nothing before it changed.
  audit repair [<file>] [--yes]
        For a log whose last line was cut short by a write that failed (a full disk): shows that line
        and the chain before it, which must hold. With --yes, removes only that line and appends an
        audit_repaired record that holds what was removed. Run it while Gantry is stopped.
  serve --unchecked
        Forward every request without checking it, on this machine only. For benchmarks.
        GANTRY_ADDR sets the address, GANTRY_UPSTREAM the server to forward to.
  login <gantry url> [--no-browser]
        Sign in through the console's single sign-on and get a personal key, named by your email, that
        expires (30 days unless the policy says otherwise). Saves it in ~/.config/gantry/credentials
        (readable by you only) and prints the lines that point Claude Code, the OpenAI SDKs and Codex at
        Gantry. --no-browser prints the sign-in address instead of opening it.
  logout
        Revoke the key `gantry login` saved, and delete the credentials file.
  kill (--person <name> | --team <team> | --key-prefix <hash> | --model <model> | --all) --reason <text>
        [--force] [--url <gantry url>]
        Turn a kill switch on: Gantry refuses that traffic within 1 second on every node, and the people
        stopped see the reason. Needs an admin key in GANTRY_ADMIN_KEY (or the saved login key, if it is
        an admin's). --url, GANTRY_URL or the saved login name the gateway. A switch that matches no key,
        team or served model is refused with the names it may have meant; --force sets it anyway.
        A switch on a model also stops every alias that can send to it.
  unkill (--person <name> | --team <team> | --key-prefix <hash> | --model <model> | --all) [--url <gantry url>]
        Turn that kill switch off.
  version
        Print the version, the hash of the sources it was built from and the day it was built.

The keys file is gantry.keys.yaml beside the policy file unless --keys names another. When the policy
beside the keys file (or --policy) has a store: section, the key commands change the store instead, and
every gateway on that database applies the change within 2 seconds.";

/// Splits arguments into positional ones and `--name value` options. `None` if an option is unknown or has no value.
fn options<'a>(
    args: &[&'a str],
    allowed: &[&str],
) -> Option<(Vec<&'a str>, HashMap<&'a str, &'a str>)> {
    let (mut positional, mut named) = (Vec::new(), HashMap::new());
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg.starts_with('-') {
            if !allowed.contains(arg) || named.insert(*arg, *rest.next()?).is_some() {
                return None;
            }
        } else {
            positional.push(*arg);
        }
    }
    Some((positional, named))
}

fn fail(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::from(2)
}

/// Runs one `gantry` command, `args` without the program name, as the `gantry` binary does: same output, same exit
/// codes. Call it on a tokio runtime.
pub async fn run(args: &[String]) -> ExitCode {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    // Subcommands are matched by hand until there are enough to justify an argument parser.
    // Every form is matched exactly: an argument Gantry does not know is an error, never ignored.
    let done = match args.as_slice() {
        ["serve", "--unchecked"] => Some(serve_unchecked(true).await),
        ["serve"] => Some(serve_unchecked(false).await),
        ["serve", rest @ ..] => match options(
            rest,
            &["--keys", "--listen", "--metrics", "--tls-cert", "--tls-key"],
        ) {
            // TLS needs both files: one without the other is refused, never served as plain HTTP.
            Some((positional, named))
                if positional.len() == 1
                    && named.contains_key("--tls-cert") == named.contains_key("--tls-key") =>
            {
                let name = format!("gantry {}", gantry_core::VERSION);
                let keys = named.get("--keys").map(Path::new);
                let listen = named.get("--listen").copied();
                let metrics = named.get("--metrics").copied();
                let tls = named
                    .get("--tls-cert")
                    .zip(named.get("--tls-key"))
                    .map(|(cert, key)| (Path::new(*cert), Path::new(*key)));
                let served = gantry_server::serve_policy(
                    &name,
                    Path::new(positional[0]),
                    keys,
                    listen,
                    metrics,
                    tls,
                )
                .await;
                Some(served.map_or_else(fail, |()| ExitCode::SUCCESS))
            }
            _ => None,
        },
        ["explain", rest @ ..] => match options(
            rest,
            &["--keys", "--key", "--model", "--customer", "--tags"],
        ) {
            Some((positional, named))
                if positional.len() == 1
                    && named.contains_key("--key")
                    && named.contains_key("--model") =>
            {
                Some(
                    explain(Path::new(positional[0]), &named)
                        .map_or_else(fail, |()| ExitCode::SUCCESS),
                )
            }
            _ => None,
        },
        ["check", rest @ ..] => match options(rest, &["--keys"]) {
            Some((positional, named)) if positional.len() == 1 => Some(check(
                Path::new(positional[0]),
                named.get("--keys").map(Path::new),
            )),
            _ => None,
        },
        ["key", "new", rest @ ..] => {
            // Flags without a value are taken out first; `options` reads `--name value` pairs.
            let flag = |name: &str| rest.contains(&name);
            let rest: Vec<&str> = rest
                .iter()
                .copied()
                .filter(|a| !matches!(*a, "--admin" | "--quiet"))
                .collect();
            match options(
                &rest,
                &[
                    "--team",
                    "--keys",
                    "--policy",
                    "--expires",
                    "--budget",
                    "--models",
                    "--tpm",
                    "--url",
                    "--org",
                    "--customer",
                    "--tags",
                    "--parallel",
                    "--role",
                ],
            ) {
                Some((positional, named))
                    if positional.len() == 1 && named.contains_key("--team") =>
                {
                    let keys = named
                        .get("--keys")
                        .map_or_else(|| PathBuf::from("gantry.keys.yaml"), PathBuf::from);
                    let made = attributes(flag("--admin"), &named).and_then(|attributes| {
                        let _store = store_for(&keys, named.get("--policy").copied())?;
                        key_new(
                            positional[0],
                            named["--team"],
                            &attributes,
                            named.get("--url").copied(),
                            flag("--quiet"),
                            &keys,
                        )
                    });
                    Some(made.map_or_else(fail, |()| ExitCode::SUCCESS))
                }
                _ => None,
            }
        }
        ["import", "litellm", rest @ ..] => match options(rest, &["--keys-from", "--out"]) {
            Some((positional, named)) if positional.len() == 1 => Some(
                import_litellm(
                    Path::new(positional[0]),
                    named.get("--keys-from").map(Path::new),
                    Path::new(named.get("--out").copied().unwrap_or("gantry.policy.yaml")),
                )
                .unwrap_or_else(fail),
            ),
            _ => None,
        },
        ["guardrail", "test", rest @ ..] => {
            match options(rest, &["--policy", "--corpus", "--since"]) {
                Some((positional, named)) if positional.len() == 1 => Some(
                    guardrail_test(
                        positional[0],
                        Path::new(
                            named
                                .get("--policy")
                                .copied()
                                .unwrap_or("gantry.policy.yaml"),
                        ),
                        named.get("--corpus").map(Path::new),
                        named.get("--since").copied(),
                    )
                    .map_or_else(fail, |()| ExitCode::SUCCESS),
                ),
                _ => None,
            }
        }
        ["prices", rest @ ..] => match options(rest, &["--policy"]) {
            Some((positional, named)) if positional.len() == 1 => Some(
                prices(positional[0], named.get("--policy").map(Path::new))
                    .map_or_else(fail, |()| ExitCode::SUCCESS),
            ),
            _ => None,
        },
        ["key", "prune", rest @ ..] => match options(rest, &["--keys", "--policy"]) {
            Some((positional, named)) if positional.is_empty() => {
                let keys = named
                    .get("--keys")
                    .map_or_else(|| PathBuf::from("gantry.keys.yaml"), PathBuf::from);
                let pruned = store_for(&keys, named.get("--policy").copied())
                    .and_then(|_store| key_prune(&keys));
                Some(pruned.map_or_else(fail, |()| ExitCode::SUCCESS))
            }
            _ => None,
        },
        ["key", "list", rest @ ..] => match options(rest, &["--keys", "--policy"]) {
            Some((positional, named)) if positional.is_empty() => {
                let keys = named
                    .get("--keys")
                    .map_or_else(|| PathBuf::from("gantry.keys.yaml"), PathBuf::from);
                let listed = store_for(&keys, named.get("--policy").copied())
                    .and_then(|_store| key_list(&keys));
                Some(listed.map_or_else(fail, |()| ExitCode::SUCCESS))
            }
            _ => None,
        },
        ["key", "revoke", rest @ ..] => match options(rest, &["--keys", "--policy"]) {
            Some((positional, named)) if positional.len() == 1 => {
                let keys = named
                    .get("--keys")
                    .map_or_else(|| PathBuf::from("gantry.keys.yaml"), PathBuf::from);
                let revoked = store_for(&keys, named.get("--policy").copied())
                    .and_then(|_store| key_revoke(&keys, positional[0]));
                Some(revoked.map_or_else(fail, |()| ExitCode::SUCCESS))
            }
            _ => None,
        },
        ["store", "import", rest @ ..] => match options(rest, &["--keys", "--policy"]) {
            Some((positional, named)) if positional.is_empty() && named.contains_key("--keys") => {
                Some(
                    store_import(
                        Path::new(named["--keys"]),
                        Path::new(
                            named
                                .get("--policy")
                                .copied()
                                .unwrap_or("gantry.policy.yaml"),
                        ),
                    )
                    .map_or_else(fail, |()| ExitCode::SUCCESS),
                )
            }
            _ => None,
        },
        ["audit", "verify", rest @ ..] => match options(rest, &["--expect-last"]) {
            Some((positional, named)) if positional.len() <= 1 => Some(audit_verify(
                Path::new(positional.first().copied().unwrap_or("gantry-audit.jsonl")),
                named.get("--expect-last").copied(),
            )),
            _ => None,
        },
        ["audit", "repair", rest @ ..]
            if rest.iter().filter(|a| **a != "--yes").count() <= 1
                && rest
                    .iter()
                    .filter(|a| a.starts_with('-'))
                    .all(|a| *a == "--yes") =>
        {
            let file = rest
                .iter()
                .find(|a| **a != "--yes")
                .copied()
                .unwrap_or("gantry-audit.jsonl");
            Some(audit_repair(Path::new(file), rest.contains(&"--yes")))
        }
        ["login", rest @ ..] => {
            let rest: Vec<&str> = rest
                .iter()
                .copied()
                .filter(|a| *a != "--no-browser")
                .collect();
            match options(&rest, &[]) {
                Some((positional, _)) if positional.len() == 1 => Some(
                    login(positional[0], args.contains(&"--no-browser"))
                        .await
                        .map_or_else(fail, |()| ExitCode::SUCCESS),
                ),
                _ => None,
            }
        }
        ["logout"] => Some(logout().await.map_or_else(fail, |()| ExitCode::SUCCESS)),
        [verb @ ("kill" | "unkill"), rest @ ..] => {
            let all = rest.contains(&"--all");
            let force = *verb == "kill" && rest.contains(&"--force");
            let rest: Vec<&str> = rest
                .iter()
                .copied()
                .filter(|a| *a != "--all" && !(force && *a == "--force"))
                .collect();
            let allowed: &[&str] = if *verb == "kill" {
                &[
                    "--person",
                    "--team",
                    "--key-prefix",
                    "--model",
                    "--url",
                    "--reason",
                ]
            } else {
                &["--person", "--team", "--key-prefix", "--model", "--url"]
            };
            match options(&rest, allowed) {
                Some((positional, named)) if positional.is_empty() => Some(
                    switch(*verb == "kill", all, force, &named)
                        .await
                        .map_or_else(fail, |()| ExitCode::SUCCESS),
                ),
                _ => None,
            }
        }
        ["init", rest @ ..] => match options(rest, &["--provider", "--models", "--out"]) {
            Some((positional, named)) if positional.is_empty() => Some(init(
                named.get("--provider").copied().unwrap_or("openai"),
                named.get("--models").copied(),
                Path::new(named.get("--out").copied().unwrap_or("gantry.policy.yaml")),
            )),
            _ => None,
        },
        ["providers"] => {
            print!("{}", gantry_core::catalog::table());
            Some(ExitCode::SUCCESS)
        }
        ["providers", "--markdown"] => {
            print!("{}", gantry_core::catalog::page());
            Some(ExitCode::SUCCESS)
        }
        ["version" | "--version" | "-V"] => {
            println!(
                "gantry {} (src {}, built {})",
                gantry_core::VERSION,
                env!("GANTRY_SOURCE_HASH"),
                env!("GANTRY_BUILD_DATE")
            );
            Some(ExitCode::SUCCESS)
        }
        ["help" | "--help" | "-h"] => {
            println!("{USAGE}");
            Some(ExitCode::SUCCESS)
        }
        // No command is a mistake, as an unknown one is: a script that forgot its argument must not pass.
        [] => {
            eprintln!("error: name a command.\n\n{USAGE}");
            Some(ExitCode::from(2))
        }
        _ => None,
    };
    done.unwrap_or_else(|| {
        // A known command with the wrong arguments gets its own usage line, not the whole help.
        let usage = match args.as_slice() {
            ["check", ..] => Some("gantry check <policy> [--keys <file>]"),
            ["explain", ..] => Some(
                "gantry explain <policy> --key <hash prefix or name> --model <model> [--customer <name>] [--tags <a,b>] [--keys <file>]",
            ),
            ["key", "list", ..] => Some("gantry key list [--keys <file>] [--policy <file>]"),
            ["key", "prune", ..] => Some("gantry key prune [--keys <file>] [--policy <file>]"),
            ["key", "revoke", ..] => {
                Some("gantry key revoke <hash prefix> [--keys <file>] [--policy <file>]")
            }
            ["store", ..] => Some("gantry store import --keys <file> [--policy <file>]"),
            ["prices", ..] => Some("gantry prices <model> [--policy <file>]"),
            ["import", ..] => Some(
                "gantry import litellm <config.yaml> [--keys-from <csv or json export>] [--out <policy file>]",
            ),
            ["key", ..] => Some(
                "gantry key new <name> --team <team> [--admin] [--expires <date>] [--budget <usd>/<period>] [--models <a,b>] [--tpm <n>] [--org <org>] [--customer <name>] [--tags <a,b>] [--parallel <n>] [--role <role>] [--url <gateway url>] [--quiet] [--keys <file>] [--policy <file>]",
            ),
            ["serve", ..] => Some(
                "gantry serve <policy> [--keys <file>] [--listen <host:port>] [--metrics <host:port>] [--tls-cert <pem> --tls-key <pem>]",
            ),
            ["audit", "repair", ..] => Some("gantry audit repair [<file>] [--yes]"),
            ["providers", ..] => Some("gantry providers [--markdown]"),
            ["guardrail", ..] => Some(
                "gantry guardrail test <name> (--corpus <file.jsonl> | --since <7d>) [--policy <file>]",
            ),
            ["init", ..] => Some("gantry init [--provider <id>] [--models <a,b>] [--out <policy file>]"),
            ["login", ..] => Some("gantry login <gantry url> [--no-browser]"),
            ["logout", ..] => Some("gantry logout"),
            ["kill", ..] => Some(
                "gantry kill (--person <name> | --team <team> | --key-prefix <hash> | --model <model> | --all) --reason <text> [--force] [--url <gantry url>]",
            ),
            ["unkill", ..] => Some(
                "gantry unkill (--person <name> | --team <team> | --key-prefix <hash> | --model <model> | --all) [--url <gantry url>]",
            ),
            ["audit", ..] => Some("gantry audit verify [<file>] [--expect-last <hash>]"),
            _ => None,
        };
        let help = args.iter().any(|arg| matches!(*arg, "--help" | "-h"));
        match usage {
            Some(usage) if help => {
                println!("Usage: {usage}");
                return ExitCode::SUCCESS;
            }
            Some(usage) => eprintln!(
                "error: `gantry {}` is missing an argument or has one Gantry does not know.\nUsage: {usage}",
                args.join(" ")
            ),
            None => eprintln!(
                "error: `gantry {}` is not a command Gantry knows.\n\n{USAGE}",
                args.join(" ")
            ),
        }
        ExitCode::from(2)
    })
}

async fn serve_unchecked(unchecked: bool) -> ExitCode {
    let name = format!("gantry {}", gantry_core::VERSION);
    match gantry_server::serve_from_env(&name, unchecked).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => fail(err),
    }
}

fn check(policy: &Path, keys: Option<&Path>) -> ExitCode {
    match config::load(policy, keys) {
        Ok(loaded) => {
            // Credential names live in the store: checked there when it can be reached, warned about when not.
            match gantry_server::credential_problems(policy, &loaded, &|v| std::env::var(v).ok()) {
                Ok(problems) if !problems.is_empty() => {
                    return check_failed(policy, &problems);
                }
                Ok(_) => {}
                Err(why) => eprintln!("warning: credential names were not checked: {why}"),
            }
            // UX12-4: keys from `gantry login` lapse on their own, so a past expiry is a warning: the files did not
            // change, and serving refuses such a key (recorded) either way.
            for warning in expired_keys(&loaded)
                .into_iter()
                .chain(config::unserved_models(policy, &loaded))
            {
                eprintln!("{warning}");
            }
            // With a store the keys are in the database, which `check` does not connect to.
            let keys = match &loaded.store {
                Some(store) => format!("keys in the store named by {}", store.postgres_url_env),
                None => gantry_core::count(loaded.policy.keys(), "key"),
            };
            println!(
                "{} is valid: {}, {keys}, {}.",
                policy.display(),
                gantry_core::count(loaded.policy.rules(), "rule"),
                gantry_core::config::describe(&loaded.providers)
            );
            ExitCode::SUCCESS
        }
        Err(errors) => check_failed(policy, &errors),
    }
}

fn check_failed(policy: &Path, errors: &[String]) -> ExitCode {
    for error in errors {
        eprintln!("{error}");
    }
    let problems = match errors.len() {
        1 => "1 problem".to_string(),
        n => format!("{n} problems"),
    };
    eprintln!("{} cannot be used: {problems} above.", policy.display());
    ExitCode::from(1)
}

/// One problem per key in the keys file whose expiry has passed, on the line of its hash.
fn expired_keys(loaded: &config::Loaded) -> Vec<String> {
    let now = gantry_core::audit::timestamp();
    let text = std::fs::read_to_string(&loaded.keys_path).unwrap_or_default();
    let mut problems: Vec<(usize, String)> = loaded
        .policy
        .entries()
        .filter(|(_, who)| who.expired(&now))
        .map(|(hash, who)| {
            let hex = gantry_core::id::hex(hash);
            let line = text.lines().position(|l| l.contains(&hex)).map_or(0, |i| i + 1);
            let problem = format!(
                "{}:{line}: the key of \"{}\" (key hash {}) has expired: expires {} has passed, so every request with it is refused. Remove it with `gantry key prune`, or give it a later date.",
                loaded.keys_path.display(),
                who.name,
                who.key,
                who.expires.as_deref().unwrap_or("")
            );
            (line, problem)
        })
        .collect();
    problems.sort();
    problems.into_iter().map(|(_, p)| p).collect()
}

/// Reads `--expires` and `--budget`, refusing a wrong one before anything is written.
fn attributes(admin: bool, named: &HashMap<&str, &str>) -> Result<keyfile::Attributes, String> {
    let expires = named.get("--expires").map(|e| e.to_string());
    if let Some(Err(problem)) = expires.as_deref().map(config::issuable_expiry) {
        return Err(format!(
            "--{problem}. Nothing was changed and no key was made."
        ));
    }
    let budget = match named.get("--budget") {
        None => None,
        Some(text) => {
            let wrong = || {
                format!(
                    "--budget is \"{text}\". Write US dollars and a period, for example --budget 20/month, --budget 5/day or --budget 100/month@America/New_York."
                )
            };
            let (usd, per) = text.split_once('/').ok_or_else(wrong)?;
            let usd: f64 = usd.trim_start_matches('$').parse().map_err(|_| wrong())?;
            let (per, tz) = match per.split_once('@') {
                Some((per, tz)) => (per, Some(tz)),
                None => (per, None),
            };
            let per = Period::parse(per, tz)
                .map_err(|problem| format!("--budget is \"{text}\": {problem}"))?;
            if !usd.is_finite() || usd <= 0.0 {
                return Err(wrong());
            }
            Some(Budget { usd, per })
        }
    };
    let models = match named.get("--models") {
        None => None,
        Some(text) => {
            let models: Vec<String> = text
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(str::to_string)
                .collect();
            if models.is_empty() {
                return Err(format!(
                    "--models is \"{text}\". List the models the key may use, with commas between, for example --models gpt-4o-mini,o3."
                ));
            }
            Some(models)
        }
    };
    let tpm = match named.get("--tpm") {
        None => None,
        Some(text) => match text.parse::<u32>() {
            Ok(t) if (1..=1_000_000_000).contains(&t) => Some(t),
            _ => {
                return Err(format!(
                    "--tpm is \"{text}\". Give the tokens the key may use per minute, 1 to 1000000000, for example --tpm 200000."
                ));
            }
        },
    };
    let parallel = match named.get("--parallel") {
        None => None,
        Some(text) => match text.parse::<u32>() {
            Ok(n) if (1..=100_000).contains(&n) => Some(n),
            _ => {
                return Err(format!(
                    "--parallel is \"{text}\". Give the most requests the key may have in flight at once, 1 to 100000, for example --parallel 4."
                ));
            }
        },
    };
    Ok(keyfile::Attributes {
        admin,
        expires,
        budget,
        models,
        tpm,
        org: named
            .get("--org")
            .map(|o| o.to_string())
            .unwrap_or_default(),
        customer: named.get("--customer").map(|c| c.to_string()),
        tags: named
            .get("--tags")
            .map(|t| {
                t.split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        parallel,
        role: named.get("--role").map(|r| r.to_string()),
    })
}

/// `gantry explain`: why a request would be allowed or refused, and the limits it would count against.
fn explain(policy: &Path, named: &HashMap<&str, &str>) -> Result<(), String> {
    let loaded = config::load(policy, named.get("--keys").map(Path::new)).map_err(|problems| {
        format!(
            "{}\n{} cannot be used: {} problems above. Fix them with gantry check first.",
            problems.join("\n"),
            policy.display(),
            problems.len()
        )
    })?;
    let key = named["--key"].to_ascii_lowercase();
    let who = loaded
        .policy
        .entries()
        .map(|(_, p)| p)
        .find(|p| (key.len() >= 8 && p.key.starts_with(&key[..8])) || p.name == named["--key"])
        .ok_or_else(|| {
            format!(
                "no key in {} has the hash prefix or name \"{}\". gantry key list shows them.",
                loaded.keys_path.display(),
                named["--key"]
            )
        })?;
    let model = named["--model"];
    let deployed = loaded
        .aliases
        .iter()
        .find(|a| a.name == model)
        .and_then(|a| a.deployments.first())
        .map_or(model.to_string(), |d| d.model.clone());
    let customer = named
        .get("--customer")
        .map(|c| c.to_string())
        .or_else(|| who.customer.clone());
    let mut tags = who.tags.clone();
    for tag in named.get("--tags").copied().unwrap_or_default().split(',') {
        let tag = tag.trim();
        if !tag.is_empty() && !tags.iter().any(|t| t == tag) {
            tags.push(tag.to_string());
        }
    }
    let explained = loaded.policy.explain(
        who,
        gantry_core::policy::Context {
            sent: model,
            model: &deployed,
            customer: customer.as_deref(),
            tags: &tags,
        },
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&explained).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn key_new(
    name: &str,
    team: &str,
    attributes: &keyfile::Attributes,
    url: Option<&str>,
    quiet: bool,
    keys: &Path,
) -> Result<(), String> {
    let issued = keyfile::issue_with(name, team, attributes, keys)?;
    if quiet {
        println!("{}", issued.key);
        return Ok(());
    }
    let what = if attributes.admin { "Admin key" } else { "Key" };
    println!(
        "{what} for {name}, team {team}. It is shown once and is not stored anywhere:\n\n  {}\n",
        issued.key
    );
    let url = url.unwrap_or("http://127.0.0.1:8080").trim_end_matches('/');
    println!(
        "To hand it over, send these lines through your secret manager, never in chat. Claude Code and the OpenAI SDKs read them:\n\nexport ANTHROPIC_BASE_URL={url}\nexport ANTHROPIC_API_KEY={key}\nexport OPENAI_BASE_URL={url}/v1\nexport OPENAI_API_KEY={key}\n\nFor Codex, put the key in GANTRY_KEY and see https://gantry-docs.eliran.me/integrations/codex/ for its provider settings.\n",
        key = issued.key
    );
    if gantry_core::store::attached(keys).is_some() {
        println!(
            "Its hash was added to the store. Every `gantry serve` on that database accepts it within 2 seconds."
        );
    } else {
        println!(
            "Its hash was added to {}. A running `gantry serve` accepts it within 2 seconds. `gantry serve` reads the keys file beside its policy file unless `--keys` names another.",
            std::fs::canonicalize(keys)
                .unwrap_or_else(|_| keys.to_path_buf())
                .display()
        );
    }
    if attributes.admin {
        println!(
            "It may sign in to the console at {url}/console and call the admin API to issue and revoke keys."
        );
    }
    if issued.rotated {
        println!(
            "{name} already had a key. Both work until you remove the old entry from the file."
        );
    }
    Ok(())
}

fn import_litellm(config: &Path, keys: Option<&Path>, out: &Path) -> Result<ExitCode, String> {
    let read = |p: &Path| {
        std::fs::read_to_string(p).map_err(|err| format!("{} cannot be read: {err}.", p.display()))
    };
    let export = keys.map(read).transpose()?;
    let imported = gantry_core::litellm::import(&read(config)?, export.as_deref())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(out).map_err(|err| {
        format!(
            "{} cannot be written: {err}. Name another file with --out; an existing policy is never replaced.",
            out.display()
        )
    })?;
    std::io::Write::write_all(&mut file, imported.policy.as_bytes())
        .map_err(|err| format!("{} cannot be written: {err}.", out.display()))?;
    println!("Wrote {}.", out.display());
    if imported.report.is_empty() {
        println!("Everything in {} was mapped.", config.display());
    } else {
        println!(
            "Not mapped, or needs a hand ({}):",
            gantry_core::count(imported.report.len(), "item")
        );
        for line in &imported.report {
            println!("  - {line}");
        }
    }
    println!("See https://gantry-docs.eliran.me/migrate/from-litellm/. Checking it now:");
    Ok(check(out, None))
}

/// `gantry guardrail test`: a backtest of one defined guardrail, printed for a person.
fn guardrail_test(
    name: &str,
    policy: &Path,
    corpus: Option<&Path>,
    since: Option<&str>,
) -> Result<(), String> {
    let text = std::fs::read_to_string(policy)
        .map_err(|err| format!("{}: cannot be read: {err}", policy.display()))?;
    let defined = gantry_core::guard::defined_in(&text)
        .map_err(|errors| format!("{}: {}", policy.display(), errors.join(" ")))?;
    let guard = defined.iter().find(|g| g.name == name).ok_or_else(|| {
        let names: Vec<&str> = defined.iter().map(|g| g.name.as_str()).collect();
        format!(
            "{} defines no guardrail \"{name}\". It defines: {}.",
            policy.display(),
            if names.is_empty() {
                "none".to_string()
            } else {
                names.join(", ")
            }
        )
    })?;
    if let Some(since) = since {
        gantry_core::guard::since_seconds(since)?;
        if corpus.is_none() {
            return Err(gantry_core::guard::NO_CAPTURE.to_string());
        }
        eprintln!("warning: {}", gantry_core::guard::NO_CAPTURE);
    }
    let Some(corpus) = corpus else {
        return Err("give the examples to test on: --corpus <file.jsonl>, one {\"text\": \"...\"} or {\"body\": {...}} per line.".into());
    };
    let rows = std::fs::read_to_string(corpus)
        .map_err(|err| format!("{}: cannot be read: {err}", corpus.display()))?;
    let samples =
        gantry_core::guard::corpus(&rows).map_err(|err| format!("{}: {err}", corpus.display()))?;
    let report = gantry_core::guard::backtest(guard, &samples)?;
    print!("{}", backtest_text(&report));
    Ok(())
}

fn backtest_text(report: &gantry_core::guard::Backtest) -> String {
    let share = if report.requests == 0 {
        0.0
    } else {
        100.0 * report.hits as f64 / report.requests as f64
    };
    let mut out = format!(
        "guardrail \"{}\" ({}) on {}: would hit {} ({share:.1}%).\n",
        report.guardrail,
        report.detector,
        count(report.requests as u64, "request"),
        report.hits
    );
    for (kind, n) in &report.kinds {
        out.push_str(&format!("  {kind}: {n}\n"));
    }
    if !report.samples.is_empty() {
        out.push_str("samples (masked):\n");
        for s in &report.samples {
            out.push_str(&format!("  #{} {} {} {}\n", s.id, s.path, s.kind, s.masked));
        }
    }
    if let Some(l) = &report.labelled {
        out.push_str(&format!(
            "labelled {}: precision {:.1}% ({} of {} hits expected), recall {:.1}% ({} of {} expected hit)\n",
            count(l.examples as u64, "example"),
            l.precision,
            l.true_positives,
            l.true_positives + l.false_positives,
            l.recall,
            l.true_positives,
            l.true_positives + l.false_negatives
        ));
    }
    out
}

fn prices(model: &str, policy: Option<&Path>) -> Result<(), String> {
    let loaded = policy
        .map(|path| config::load(path, None).map_err(|errors| errors.join("\n")))
        .transpose()?;
    let overrides = loaded
        .as_ref()
        .map(|l| l.policy.prices().clone())
        .unwrap_or_default();
    // An alias has no price of its own: each answer is charged at the price of the deployment that served it.
    if let Some(alias) = loaded
        .as_ref()
        .and_then(|l| l.aliases.iter().find(|a| a.name == model))
    {
        println!(
            "{model} is an alias: each answer is charged at the price of the deployment that served it."
        );
        for d in &alias.deployments {
            let shown = format!("{}/{}", d.provider, d.model);
            match gantry_core::usage::price_for(&d.model, &overrides) {
                Some(price) => print_price(&shown, &price, policy),
                None => println!(
                    "{shown}: no price, so its usage is recorded with cost unknown and a budget refuses it. Add it under prices: in the policy, for example\nprices:\n  {}: {{ input: 3, output: 15 }}",
                    d.model
                ),
            }
        }
        return Ok(());
    }
    let Some(price) = gantry_core::usage::price_for(model, &overrides) else {
        return Err(format!(
            "no price is known for model \"{model}\": its usage is recorded with cost unknown, and a budget cannot reach it. Add it under prices: in the policy, for example\nprices:\n  {model}: {{ input: 3, output: 15 }}"
        ));
    };
    print_price(model, &price, policy);
    Ok(())
}

fn print_price(model: &str, price: &gantry_core::usage::Price, policy: Option<&Path>) {
    let (url, date) = gantry_core::usage::litellm_prices_origin();
    let from = match price.source {
        PriceSource::Policy => format!(
            "the policy's prices: ({})",
            policy.map_or(String::new(), |p| p.display().to_string())
        ),
        PriceSource::Builtin => {
            "Gantry's own table, checked against the provider's price list".into()
        }
        PriceSource::Litellm => format!("the LiteLLM price map (MIT), read {date} from {url}"),
    };
    let dollars = |v: Option<f64>| v.map_or("-".to_string(), |v| format!("{v}"));
    println!("{model}: from {from}.");
    println!(
        "US dollars per million tokens: input {}, output {}, cache read {}, cache write {}, cache write 1h {}.",
        price.input,
        price.output,
        dollars(price.cache_read.or(Some(price.input))),
        dollars(price.cache_write.or(Some(price.input))),
        dollars(
            price
                .cache_write_1h
                .or(price.cache_write)
                .or(Some(price.input))
        )
    );
    if let Some(long) = &price.long_context {
        println!(
            "Above {} prompt tokens: input {}, output {}.",
            long.above_prompt_tokens, long.price.input, long.price.output
        );
    }
    if let Some(each) = price.per_image {
        println!("Per image: {each} US dollars.");
    }
    println!(
        "Most output tokens in one answer: {}. Context window: {}.",
        price.max_output.map_or("unknown".into(), |n| n.to_string()),
        price
            .max_context
            .map_or("unknown".into(), |n| n.to_string())
    );
}

/// Removes every expired entry, one at a time with the same safe rewrite a revoke uses.
fn key_prune(keys: &Path) -> Result<(), String> {
    let now = audit::timestamp();
    let text = config::read_keys(keys)?
        .ok_or_else(|| format!("{} cannot be read: it does not exist.", keys.display()))?;
    let entries = config::key_entries(keys, &text).map_err(|errors| errors.join("\n"))?;
    let mut removed = 0;
    for entry in entries.iter().filter(|e| {
        e.expires
            .as_deref()
            .is_some_and(|at| gantry_core::policy::expiry_passed(at, &now))
    }) {
        if let Some(gone) = keyfile::revoke(keys, &entry.sha256)? {
            println!(
                "Removed the key of \"{}\" (team {}), expired {}.",
                gone.name,
                gone.team,
                entry.expires.as_deref().unwrap_or("")
            );
            removed += 1;
        }
    }
    if removed == 0 {
        println!(
            "No key has expired in {}. Nothing was changed.",
            keys.display()
        );
    }
    Ok(())
}

/// The store the policy names, when it has `store:`, serving `keys` so the key commands change the database.
/// The policy is `--policy`, else gantry.policy.yaml beside the keys file. Held for as long as the command runs.
fn store_for(
    keys: &Path,
    policy: Option<&str>,
) -> Result<Option<std::sync::Arc<dyn gantry_core::store::Store>>, String> {
    let path = match policy {
        Some(path) => {
            let path = PathBuf::from(path);
            std::fs::metadata(&path).map_err(|err| {
                format!(
                    "{} (--policy) cannot be read: {err}. Name the policy file Gantry serves.",
                    path.display()
                )
            })?;
            path
        }
        None => keys.with_file_name("gantry.policy.yaml"),
    };
    gantry_server::open_store(&path, keys, &|variable| std::env::var(variable).ok())
}

fn key_revoke(keys: &Path, prefix: &str) -> Result<(), String> {
    match keyfile::revoke(keys, prefix)? {
        Some(gone) => {
            println!(
                "Revoked the key of \"{}\" (team {}, hash {}). Gantry refuses it within 2 seconds.",
                gone.name,
                gone.team,
                &gone.sha256[..8]
            );
            Ok(())
        }
        None => Err(format!(
            "no key hash starts with {prefix}. `gantry key list` shows the keys and their hash prefixes."
        )),
    }
}

/// Copies a keys file's entries, and the switches beside it, into the store. Both files are read before the store
/// is opened: once it is, their paths read from the store.
fn store_import(keys: &Path, policy: &Path) -> Result<(), String> {
    let text = config::read_keys(keys)?.ok_or_else(|| {
        format!(
            "{} does not exist. Name the keys file to import with --keys.",
            keys.display()
        )
    })?;
    let entries = config::key_entries(keys, &text).map_err(|problems| problems.join("\n"))?;
    let kills = gantry_core::kill::read(&gantry_core::kill::path_beside(keys))?;
    std::fs::metadata(policy).map_err(|err| {
        format!(
            "{} cannot be read: {err}. Name the policy that has the store: section with --policy.",
            policy.display()
        )
    })?;
    let store = gantry_server::open_store(policy, keys, &|variable| std::env::var(variable).ok())?
        .ok_or_else(|| {
            format!(
                "{} has no store: section, so there is no store to import into. Add `store: {{ postgres_url_env: DATABASE_URL }}` to it first.",
                policy.display()
            )
        })?;
    let there =
        config::key_entries(keys, &store.keys_text()).map_err(|problems| problems.join("\n"))?;
    let (mut added, mut skipped) = (0, 0);
    for entry in &entries {
        if there.iter().any(|e| e.sha256 == entry.sha256) {
            skipped += 1;
            continue;
        }
        store.add_key(entry)?;
        added += 1;
    }
    let present = store.kills();
    let mut switched = 0;
    for kill in kills {
        if !present
            .iter()
            .any(|k| k.scope == kill.scope && k.value == kill.value)
        {
            store.set_kill(&kill)?;
            switched += 1;
        }
    }
    println!(
        "Imported {} and {switched} kill switches from {} into the store ({} already there). {} is not read while the policy has store:; keep it as a backup or delete it.",
        count(added, "key"),
        keys.display(),
        count(skipped, "key"),
        keys.display()
    );
    Ok(())
}

fn key_list(keys: &Path) -> Result<(), String> {
    let Some(text) = config::read_keys(keys)? else {
        return Err(format!(
            "{} does not exist. Make the first key with `gantry key new <name> --team <team> --admin`, or name the keys file with --keys.",
            keys.display()
        ));
    };
    let entries = config::key_entries(keys, &text).map_err(|problems| problems.join("\n"))?;
    if entries.is_empty() {
        println!("{}: no keys yet.", keys.display());
        return Ok(());
    }
    println!("name\tteam\tkey\tadmin\texpires\tbudget\tmodels\ttpm");
    let now = gantry_core::audit::timestamp();
    for entry in entries {
        // QA11-6: a key past its date is refused at every request; the list says so.
        let expires = match entry.expires.as_deref() {
            Some(at) if gantry_core::policy::expiry_passed(at, &now) => format!("{at} (expired)"),
            Some(at) => at.to_string(),
            None => "-".to_string(),
        };
        let budget = entry.budget.map_or("-".to_string(), |b| {
            // Under a cent, two places would print $0.00 for a budget that is not zero.
            let places = if b.usd < 0.01 { 4 } else { 2 };
            format!("${:.places$} a {}", b.usd, b.per.word())
        });
        let models = entry.models.map_or("-".to_string(), |m| m.join(","));
        let tpm = entry.tpm.map_or("-".to_string(), |t| t.to_string());
        println!(
            "{}\t{}\t{}\t{}\t{}\t{budget}\t{models}\t{tpm}",
            entry.name,
            entry.team,
            &entry.sha256[..8],
            if entry.admin { "admin" } else { "-" },
            expires,
        );
    }
    Ok(())
}

/// A folder named where a log should be reads as a log whose first record is not text, which sounds like tampering.
fn not_a_folder(path: &Path) -> Option<ExitCode> {
    path.is_dir().then(|| {
        eprintln!(
            "error: {} is a folder, not an audit log. Name the log file, for example {}.",
            path.display(),
            path.join("gantry-audit.jsonl").display()
        );
        ExitCode::from(1)
    })
}

fn audit_verify(path: &Path, expect: Option<&str>) -> ExitCode {
    if let Some(code) = not_a_folder(path) {
        return code;
    }
    match audit::verify_full(path, expect) {
        Ok(summary) if summary.records == 0 => {
            println!("{}: no records yet.", path.display());
            ExitCode::SUCCESS
        }
        Ok(summary) => {
            let records = summary.records;
            let kept = records + 1 - summary.first;
            println!(
                "{}: {kept} {} in an unbroken chain from record {} to record {records}.\n{}, {}, {}, {}{}.\nLast hash: {}",
                path.display(),
                if kept == 1 { "record" } else { "records" },
                summary.first,
                count(summary.requests, "request"),
                count(summary.configuration, "configuration record"),
                count(summary.admin, "admin record"),
                count(summary.usage, "usage record"),
                match summary.attempts {
                    0 => String::new(),
                    n => format!(", {}", count(n, "attempts record")),
                },
                summary.last_hash
            );
            if let Some(retired) = &summary.retired {
                println!(
                    "Records 1 to {} were retired on purpose: record {} (audit_retired, {}) names them, and record {} follows their last hash {}.",
                    retired.through,
                    retired.by,
                    retired.time,
                    retired.through + 1,
                    retired.through_hash
                );
            }
            match summary.found {
                Some(n) => println!(
                    "The kept hash is record {n}, and nothing up to it was changed or removed."
                ),
                None => println!(
                    "Records removed from the end leave the chain unbroken. To rule that out, keep this hash somewhere else and check it later with --expect-last."
                ),
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            if let Ok(Some(_)) = audit::find_cut(path) {
                eprintln!(
                    "Only the last line is cut short, and the chain before it holds: a write that failed part way (for example on a full disk). Run `gantry audit repair {}` to see that line, then add --yes to remove it and record the repair.",
                    path.display()
                );
            }
            ExitCode::from(1)
        }
    }
}

/// Exit 0 when there is nothing to repair or the repair is done, 1 when it only showed the cut line or refused.
fn audit_repair(path: &Path, yes: bool) -> ExitCode {
    if let Some(code) = not_a_folder(path) {
        return code;
    }
    let cut = match audit::find_cut(path) {
        Ok(Some(cut)) => cut,
        Ok(None) => {
            // A whole last line can still follow a broken chain, and "nothing to repair" would read as all clear.
            return match audit::verify(path) {
                Ok((records, _)) => {
                    println!(
                        "{}: its last line is whole and the chain of {} holds, so there is nothing to repair.",
                        path.display(),
                        count(records, "record")
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!(
                        "error: {err}\nRepair cannot fix this: it only removes a last line cut short by a failed write, and this log's last line is whole. A record changed, inserted or removed means the log was altered. Nothing was removed: keep the file as it is, as evidence, and to start a new chain move it aside while Gantry is stopped."
                    );
                    ExitCode::from(1)
                }
            };
        }
        Err(err) => {
            eprintln!("error: {err} Nothing was removed.");
            return ExitCode::from(1);
        }
    };
    if !yes {
        println!(
            "{}: the chain holds up to byte {}, then a last line of {} bytes is cut short:\n{}\nTo remove only that line and record the repair, stop Gantry and run: gantry audit repair {} --yes",
            path.display(),
            cut.keep,
            cut.removed.len(),
            String::from_utf8_lossy(&cut.removed),
            path.display()
        );
        return ExitCode::from(1);
    }
    match audit::repair(path, &cut) {
        Ok(records) => {
            println!(
                "{}: removed the cut last line ({} bytes) and recorded it as record {records}. Gantry can start again.",
                path.display(),
                cut.removed.len()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn count(n: u64, noun: &str) -> String {
    gantry_core::count(usize::try_from(n).unwrap_or(usize::MAX), noun)
}

/// Where `gantry login` keeps its key: `$XDG_CONFIG_HOME/gantry/credentials`, else `~/.config/gantry/credentials`.
fn credentials_path() -> Result<PathBuf, String> {
    let set = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    set("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| set("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|config| config.join("gantry").join("credentials"))
        .ok_or_else(|| "neither HOME nor XDG_CONFIG_HOME is set, so there is no place for the credentials file. Set HOME.".to_string())
}

/// The saved login as `name=value` lines. `None` when there is none.
fn credentials() -> Result<Option<HashMap<String, String>>, String> {
    let path = credentials_path()?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(Some(
            text.lines()
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect(),
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("{} cannot be read: {err}.", path.display())),
    }
}

/// Writes the credentials file readable by its owner only, whole or not at all.
fn save_credentials(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    let cannot = |err: std::io::Error| format!("{} cannot be written: {err}.", path.display());
    let dir = path
        .parent()
        .ok_or_else(|| format!("{} has no folder.", path.display()))?;
    let mut folder = std::fs::DirBuilder::new();
    folder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut folder, 0o700);
    folder.create(dir).map_err(cannot)?;
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
        })
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written.map_err(cannot)
}

async fn login(url: &str, no_browser: bool) -> Result<(), String> {
    let url = gantry_console::cli::gateway(url)?;
    let path = credentials_path()?;
    let open = |address: &str| {
        eprintln!(
            "Sign in at this address. It opens in your browser unless --no-browser was given:\n\n  {address}\n"
        );
        if !no_browser {
            let opener = if cfg!(target_os = "macos") {
                "open"
            } else {
                "xdg-open"
            };
            let _ = std::process::Command::new(opener)
                .arg(address)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
    };
    let got = gantry_console::cli::login(&url, open).await?;
    // A login replaces the one before it: that key is given up, so it does not stay valid on a file nobody reads.
    if let Ok(Some(old)) = credentials() {
        if let (Some(old_url), Some(old_key)) = (old.get("url"), old.get("key")) {
            let _ = gantry_console::cli::call(
                "DELETE",
                &format!("{old_url}/admin/keys/self"),
                old_key,
                None,
            )
            .await;
        }
    }
    save_credentials(
        &path,
        &format!(
            "# Written by gantry login. `gantry logout` revokes this key and deletes this file.\nurl={url}\nkey={}\nname={}\nteam={}\nexpires={}\n",
            got.key, got.name, got.team, got.expires
        ),
    )?;
    println!(
        "Signed in as {} (team {}). Your key works until {} UTC and is saved in {}, readable by you only.\n",
        got.name,
        got.team,
        got.expires,
        path.display()
    );
    // UX12-3: the next login revokes this key, so a profile holding the key itself would break on schedule. The
    // profile reads this file instead, which every login rewrites and logout deletes.
    let env = path.with_file_name("env");
    save_credentials(&env, &env_lines(&url, &got.key))?;
    println!(
        "Point your tools at Gantry: Claude Code and the OpenAI SDKs read these variables, and Codex reads GANTRY_KEY (see https://gantry-docs.eliran.me/integrations/codex/). They are in {env}, which the next `gantry login` rewrites. Add this line to your shell profile, and run it now in this shell:\n\n  . {env}\n\nThe key works within 2 seconds. Every request with it is recorded under {}.",
        got.name,
        env = env.display()
    );
    Ok(())
}

/// The shell lines that point Claude Code, the OpenAI SDKs and Codex at Gantry with `key`.
fn env_lines(url: &str, key: &str) -> String {
    format!(
        "# Written by gantry login. `gantry logout` deletes this file.\nexport ANTHROPIC_BASE_URL={url}\nexport ANTHROPIC_API_KEY={key}\nexport OPENAI_BASE_URL={url}/v1\nexport OPENAI_API_KEY={key}\nexport GANTRY_KEY={key}\n"
    )
}

async fn logout() -> Result<(), String> {
    let path = credentials_path()?;
    let Some(saved) = credentials()? else {
        return Err(format!(
            "you are not signed in: {} does not exist. Nothing was changed.",
            path.display()
        ));
    };
    let (Some(url), Some(key)) = (saved.get("url"), saved.get("key")) else {
        return Err(format!(
            "{} has no url or key line. Delete it by hand, and ask an admin to revoke your key.",
            path.display()
        ));
    };
    // QA14-10: a key from a login seconds ago may not be loaded yet (keys reload every 2 seconds), and then
    // unknown_key means "not yet", not "already gone": asked again for up to 3 seconds, so the key is revoked.
    let young = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < std::time::Duration::from_secs(5));
    let mut tries = 0;
    let (status, answer) = loop {
        let (status, answer) =
            gantry_console::cli::call("DELETE", &format!("{url}/admin/keys/self"), key, None)
                .await?;
        tries += 1;
        if young && answer["error"]["code"] == "unknown_key" && tries < 13 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            continue;
        }
        break (status, answer);
    };
    let code = answer["error"]["code"].as_str().unwrap_or("");
    // A key Gantry no longer knows (revoked or expired and removed) has nothing left to revoke.
    if status != 200 && code != "unknown_key" {
        return Err(format!(
            "Gantry did not revoke the key, so {} was kept: {}",
            path.display(),
            answer["error"]["message"]
                .as_str()
                .unwrap_or("no reason given")
        ));
    }
    // The variables file holds the same key; a profile that reads it then finds nothing to export.
    let _ = std::fs::remove_file(path.with_file_name("env"));
    std::fs::remove_file(&path).map_err(|err| {
        format!(
            "the key was revoked, but {} could not be deleted: {err}. Delete it by hand.",
            path.display()
        )
    })?;
    println!(
        "Signed out: the key of {} is revoked and {} is deleted.",
        saved.get("name").map_or("this login", String::as_str),
        path.display()
    );
    Ok(())
}

/// `gantry kill` (`on`) and `gantry unkill`.
async fn switch(
    on: bool,
    all: bool,
    force: bool,
    named: &HashMap<&str, &str>,
) -> Result<(), String> {
    let scopes = [
        ("--person", "person"),
        ("--team", "team"),
        ("--key-prefix", "key_prefix"),
        ("--model", "model"),
    ];
    let mut chosen: Vec<(&str, &str)> = scopes
        .iter()
        .filter_map(|(flag, scope)| named.get(flag).map(|v| (*scope, *v)))
        .collect();
    if all {
        chosen.push(("all", ""));
    }
    let [(scope, value)] = chosen[..] else {
        return Err("name exactly one of --person, --team, --key-prefix, --model or --all.".into());
    };
    let reason = named.get("--reason").copied().unwrap_or("");
    if on && reason.trim().is_empty() {
        return Err("a kill switch needs --reason: the people stopped see it in their tool, and the audit log keeps it.".into());
    }
    let saved = credentials()?.unwrap_or_default();
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let url = named
        .get("--url")
        .map(|u| u.to_string())
        .or_else(|| env("GANTRY_URL"))
        .or_else(|| saved.get("url").cloned())
        .ok_or("name the gateway with --url, GANTRY_URL or `gantry login`.")?;
    let url = gantry_console::cli::gateway(&url)?;
    let key = env("GANTRY_ADMIN_KEY")
        .or_else(|| saved.get("key").cloned())
        .ok_or("put an admin key in GANTRY_ADMIN_KEY.")?;
    let mut body = serde_json::json!({ "scope": scope, "value": value });
    if on {
        body["reason"] = reason.into();
    }
    if force {
        body["force"] = true.into();
    }
    let method = if on { "POST" } else { "DELETE" };
    let (status, answer) =
        gantry_console::cli::call(method, &format!("{url}/admin/kills"), &key, Some(&body)).await?;
    if !(200..300).contains(&status) {
        return Err(answer["error"]["message"]
            .as_str()
            .map_or_else(|| format!("Gantry answered HTTP {status}."), str::to_string));
    }
    let what = if scope == "all" {
        "everyone".to_string()
    } else {
        format!("{scope} {value}")
    };
    if on {
        println!(
            "Kill switch on for {what}: \"{reason}\". Gantry refuses that traffic now, within 1 second on every node serving the same files. `gantry unkill` turns it off."
        );
    } else {
        println!("Kill switch off for {what}. Traffic flows again within 1 second on every node.");
    }
    Ok(())
}

/// `gantry init`: a starter policy for one catalog provider, and the steps to the first governed call.
fn init(provider: &str, models: Option<&str>, out: &Path) -> ExitCode {
    let Some(preset) = gantry_core::catalog::find(provider) else {
        eprintln!(
            "error: there is no provider \"{provider}\" in the catalog. Run `gantry providers` to see them, then gantry init --provider <id>."
        );
        return ExitCode::from(2);
    };
    let models: Vec<&str> = match (models, preset.id) {
        (Some(list), _) => list
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .collect(),
        (None, "openai") => vec!["gpt-4o-mini"],
        (None, _) => Vec::new(),
    };
    if models.is_empty() || models.contains(&"*") {
        eprintln!(
            "error: name the models {} serves that people may use, for example gantry init --provider {} --models <model>,<model>. A provider lists exact model names.",
            preset.name, preset.id
        );
        return ExitCode::from(2);
    }
    if out.exists() {
        eprintln!(
            "error: {} exists, and gantry init never writes over a policy. Give another file with --out, or edit that one.",
            out.display()
        );
        return ExitCode::from(2);
    }
    let variable = format!(
        "{}_PROVIDER_KEY",
        preset.id.to_ascii_uppercase().replace('-', "_")
    );
    let private = if preset.local {
        "    allow_private: true\n"
    } else {
        ""
    };
    let policy = format!(
        "# Written by gantry init. Reference: https://gantry-docs.eliran.me/governance/policy/\nversion: 1\nproviders:\n  - name: {id}\n    preset: {id}\n{private}    key_env: {variable}\n    models: [{list}]\nrules:\n  - name: everyone\n    principals: {{ any: true }}\n    models: [{list}]\n",
        id = preset.id,
        list = models.join(", ")
    );
    if let Err(err) = std::fs::write(out, policy) {
        eprintln!("error: could not write {}: {err}", out.display());
        return ExitCode::from(1);
    }
    let local = if preset.local {
        ""
    } else {
        "\n  export {variable}=<your {name} API key>"
    };
    println!(
        "Wrote {out} for {name}. Next:\n{local}\n  gantry serve {out}\n  then open the setup link it prints: it makes your admin key and shows how to point Claude Code and the OpenAI SDKs at Gantry.",
        out = out.display(),
        name = preset.name,
        local = local
            .replace("{variable}", &variable)
            .replace("{name}", preset.name),
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn the_credentials_file_is_readable_by_its_owner_only() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("gantry-credentials-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("gantry").join("credentials");
        super::save_credentials(&path, "key=a\n")?;
        super::save_credentials(&path, "key=b\n")?;
        assert_eq!(std::fs::read_to_string(&path)?, "key=b\n");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().ok_or("no folder")?)?
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn the_login_variables_file_sets_every_tool_and_is_sourced_not_pasted() {
        let text = super::env_lines("https://gw.example", "gantry_k");
        for line in [
            "export ANTHROPIC_BASE_URL=https://gw.example\n",
            "export ANTHROPIC_API_KEY=gantry_k\n",
            "export OPENAI_BASE_URL=https://gw.example/v1\n",
            "export OPENAI_API_KEY=gantry_k\n",
            "export GANTRY_KEY=gantry_k\n",
        ] {
            assert!(text.contains(line), "{line}");
        }
    }
}
