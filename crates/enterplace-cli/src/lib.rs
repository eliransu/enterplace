//! The `enterplace` command line as a library: the `enterplace` binary runs it, and so can a binary that adds commands of
//! its own and hands every other one to [`run`].

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::ExitCode,
};

mod start;

use enterplace_core::{
    audit, config, keyfile,
    policy::{Budget, Period},
    usage::PriceSource,
};

pub const USAGE: &str = "\
Usage: enterplace <command>

New here? Run `enterplace start`: it needs no provider key and opens the dashboard, which walks you to a first request.

Commands:
  start [--dir <path>] [--providers <a,b>] [--listen <host:port>] [--no-open] [--force] [--no-serve] [--container]
        Step 1 in one command, no provider key needed. Writes enterplace.policy.yaml in observe mode (nothing is
        blocked) with the free demo model and every provider whose key is in the environment (OPENAI_API_KEY,
        ANTHROPIC_API_KEY, GEMINI_API_KEY or the *_PROVIDER_KEY forms), an admin key (printed once, its hash in
        enterplace.keys.yaml) and enterplace-master.key (0600), which seals the provider keys pasted in the dashboard.
        Then runs the gateway on --listen (default 127.0.0.1:8080) and prints the dashboard link, which signs in
        once from this machine within 10 minutes; on a terminal with a display it opens it unless --no-open.
        Run again in the same folder, it serves the policy it wrote (a new link, no new admin key) unless
        --force. --dir names the folder (default the current one); --providers openai,anthropic picks among the
        keys found; ENTERPLACE_OPENAI_BASE_URL (and the same for ANTHROPIC, GEMINI) points a provider at a proxy.
        --no-serve stops before running the gateway. --container is the image's default command: it serves
        /etc/enterplace/enterplace.policy.yaml when one is mounted, else the policy an earlier start wrote in --dir
        (default /var/lib/enterplace), and only with neither writes one as above, on 0.0.0.0:8080 and opening no
        browser. With DATABASE_URL set it writes a policy kept in that Postgres (store: with policy_from: store)
        and puts the admin key there, made only when the store holds none.
  stop [--dir <path>]
        Stop the gateway that serves from this folder (or --dir), the one enterplace start or enterplace serve runs:
        it finishes the requests in flight and ends. In Docker: docker stop enterplace.
  check <policy> [--keys <file>]
        Check a policy file and its keys file. Prints every problem with its file and line.
  explain <policy> --key <hash prefix or name> --model <model> [--customer <name>] [--tags <a,b>] [--keys <file>]
        Say why a request from that key for that model would be allowed or refused: the rules passed over, the
        rule that decides, and every limit that applies (rule, key, organization, team, person, customer, tag,
        model, global) with where it is written and what it overrides. A running gateway adds what each budget
        has spent: GET /admin/explain.
  key new <name> --team <team> [--admin | --identity-only] [--expires <date>] [--budget <usd>/<period>] [--models <a,b>] [--tpm <n>]
          [--org <org>] [--customer <name>] [--tags <a,b>] [--parallel <n>] [--role <role>]
          [--url <gateway url>] [--quiet] [--keys <file>]
        Make a key for a person or a workload. The key is printed once, with the lines that point
        Claude Code and OpenAI SDKs at Enterplace (--url, default http://127.0.0.1:8080). Only its hash is
        saved. --admin makes a key that may sign in to the console and call the admin API (the first
        admin starts here). --expires 2026-12-31 refuses the key from that UTC day on (or a time:
        2026-12-31T18:00:00Z). --budget 20/month caps what this key alone may spend. --models
        gpt-4o-mini,o3 narrows its rule's models for this key; --tpm 200000 caps its tokens per minute.
        The period of --budget is day, week, month, year, hour, minute or a count such as 6h, with @<zone>
        for a time zone: --budget 100/month@America/New_York. --org puts the key in an organization the
        policy lists; --customer makes every request with it for that end customer; --tags tags them;
        --parallel 4 caps its requests in flight; --role names a console role from the policy.
        --quiet prints the key alone. --identity-only makes a person token (enterplace_u_...) in place of a key:
        it names the person for Claude subscription passthrough (in Claude Code's
        ANTHROPIC_CUSTOM_HEADERS as x-enterplace-user: <token>) and reaches no model on its own.
  key list [--keys <file>]
        List the keys in the keys file: name, team, hash prefix, admin, expiry, budget,
        models and tpm. Never a key.
  key revoke <hash prefix> [--keys <file>]
        Remove the key whose hash starts with the prefix (at least 8 hex characters, as `key list` shows
        it). A running Enterplace refuses it within 2 seconds.
  key info <hash prefix> [--url <enterplace url>]
        Show a key's settings and what it spent today and this month (across every gateway on a store).
  key update <hash prefix> [--expires <date>] [--budget <usd>/<period>[@<tz>]] [--models <a,b>] [--tpm <n>]
          [--rpm <n>] [--parallel <n>] [--customer <name>] [--tags <a,b>] [--routes </v1/...,...>] [--from <cidr,cidr>]
          [--metadata <k=v,k=v>] [--url <enterplace url>]
        Change a key's settings on a running gateway. `none` removes one, for example --rpm none. Each change is
        recorded in the audit log with what the field was and what it became.
  key rotate <hash prefix> [--grace <48h|30m|7d|0>] [--url <enterplace url>]
        Make a new key with the same settings and print it once. The old key keeps working for the grace (24h
        unless given), and every request made with it until then is recorded as made with a rotated key.
        info, update and rotate go through the admin API: an admin key in ENTERPLACE_ADMIN_KEY (or the saved login
        key, if it is an admin's), and --url, ENTERPLACE_URL or the saved login for the gateway.
  budget raise request --usd <n> --until <date> --reason <text> [--scope team|person|key] [--url <enterplace url>]
        Ask for more room on your budget until a UTC date or time. It waits for an admin, and ends by itself.
  budget raise list [--url <enterplace url>]
        The raises an admin may decide, the ones waiting first.
  budget raise approve <id> [--usd <n>] [--until <date>] [--url <enterplace url>]
  budget raise reject <id> [--url <enterplace url>]
        Decide a raise a person asked for. An approval is for what was asked unless --usd or --until say otherwise.
  budget raise add --scope <team:payments> --usd <n> --until <date> --reason <text> [--url <enterplace url>]
        Raise the budgets of a scope at once, as an admin. Every raise and decision is in the audit log.
        The budget commands call a running gateway: --url, ENTERPLACE_URL or the saved login, with the key in
        ENTERPLACE_ADMIN_KEY or the saved login key.
  usage [--since <7d|24h|2026-11-01>] [--group-by <team|person|model|provider|key|tag|org|customer|day|hour>]
        [--csv] [--url <enterplace url>]
        Spend, tokens and requests of a running gateway (every gateway on a store), as tables by team, by person
        and by model, or by the one --group-by names. --since is how far back (30d unless given) or a UTC date.
        --csv prints one CSV in place of the tables. Goes through the admin API (GET /admin/usage), with a key
        whose role may see spend.
  budget status [--model <model>] [--short] [--url <enterplace url>]
        What each budget your own key counts against has left and when it resets (GET /v1/enterplace/me), with the
        key in ENTERPLACE_KEY or the saved login. --model adds the budgets of that model. --short prints one line,
        for a status line: `$9.50 left (resets 2026-12-01 00:00 UTC)`.
  key prune [--keys <file>]
        Remove the entries whose expiry has passed, such as old `enterplace login` keys. Each is removed
        as `DELETE /admin/keys` removes one, safe while Enterplace runs; every other line is kept.
  store import --keys <file> [--policy <file>]
        Copy the keys of a keys file, and the kill switches beside it, into the store the policy's store:
        names (default enterplace.policy.yaml). Keys already there are left as they are. The file is not changed.
  import litellm <config.yaml> [--keys-from <csv or json export>] [--out <policy file>]
        Write a Enterplace policy (default enterplace.policy.yaml, never over an existing file) from a LiteLLM proxy
        config, check it, and list what could not be mapped. --keys-from reads an export of LiteLLM virtual
        keys: they become team rules and the `enterplace key new` lines to reissue them (keys cannot move).
  import litellm --url <proxy> --master-key-env <VAR> [<config.yaml>] [--out <policy file>] [--keys-out <keys file>]
        Read a running LiteLLM proxy's model list, keys and teams through its management API, with the
        master key in VAR. Writes the policy, team budgets as limits:, and a new keys file (default
        enterplace.keys.yaml, never over an existing file) with one Enterplace key per LiteLLM key, printing each
        LiteLLM key next to the Enterplace key that replaces it.
  prices <model> [--policy <file>]
        Print the price Enterplace charges for a model and where it came from: the policy's prices:, Enterplace's
        own table, or the table generated from LiteLLM's price map (with its source and date).
  init [--provider <id>] [--models <a,b>] [--out <policy file>]
        Write a starter policy (default enterplace.policy.yaml, never over an existing file) for one provider of
        the catalog (default openai, see `enterplace providers`) and the models it serves (--models; openai defaults
        to gpt-4o-mini): everyone may use them. Then set
        the provider key it names and run `enterplace serve`, which prints a one-time link to make the first admin.
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
        --tls-cert and --tls-key (both, PEM) make Enterplace serve HTTPS itself.
  audit verify [<file>] [--org <org>] [--expect-last <hash>]
        Check that the audit log is one unbroken chain: no record changed, inserted or reordered.
        Prints the count and the last hash, to keep elsewhere. With --expect-last, it also checks
        that a hash kept earlier is still in the chain with nothing before it changed.
        With audit per_org, each organization's chain beside it is checked too; --org checks one.
  audit repair [<file>] [--yes]
        For a log whose last line was cut short by a write that failed (a full disk): shows that line
        and the chain before it, which must hold. With --yes, removes only that line and appends an
        audit_repaired record that holds what was removed. Run it while Enterplace is stopped.
  audit coverage [<file>] [--keys <file>] [--devices <file>]
        Requests per person and coding tool (from each record's user agent), with refusals and the last
        time seen. With --keys, every key holder who sent nothing is listed with last seen never.
        With --devices (devices.json from the console's Devices page, Enterplace Enterprise), two more
        columns: devices with the tool installed, and how many of them call a provider directly; then
        each device's MCP servers, whether each goes through Enterplace, and the admin's decision.
  serve --unchecked
        Forward every request without checking it, on this machine only. For benchmarks.
        ENTERPLACE_ADDR sets the address, ENTERPLACE_UPSTREAM the server to forward to.
  login <enterplace url> [--no-browser]
        Sign in through the console's single sign-on and get a personal key, named by your email, that
        expires (30 days unless the policy says otherwise). Saves it in ~/.config/enterplace/credentials
        (readable by you only) and prints the lines that point Claude Code, the OpenAI SDKs and Codex at
        Enterplace. --no-browser prints the sign-in address instead of opening it.
  logout
        Revoke the key `enterplace login` saved, and delete the credentials file.
  kill (--person <name> | --team <team> | --key-prefix <hash> | --model <model> | --all) --reason <text>
        [--force] [--url <enterplace url>]
        Turn a kill switch on: Enterplace refuses that traffic within 1 second on every node, and the people
        stopped see the reason. Needs an admin key in ENTERPLACE_ADMIN_KEY (or the saved login key, if it is
        an admin's). --url, ENTERPLACE_URL or the saved login name the gateway. A switch that matches no key,
        team or served model is refused with the names it may have meant; --force sets it anyway.
        A switch on a model also stops every alias that can send to it.
  unkill (--person <name> | --team <team> | --key-prefix <hash> | --model <model> | --all) [--url <enterplace url>]
        Turn that kill switch off.
  version
        Print the version, the hash of the sources it was built from and the day it was built.

The keys file is enterplace.keys.yaml beside the policy file unless --keys names another. When the policy
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

/// Runs one `enterplace` command, `args` without the program name, as the `enterplace` binary does: same output, same exit
/// codes. Call it on a tokio runtime.
pub async fn run(args: &[String]) -> ExitCode {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    // Subcommands are matched by hand until there are enough to justify an argument parser.
    // Every form is matched exactly: an argument Enterplace does not know is an error, never ignored.
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
                let name = format!("enterplace {}", enterplace_core::VERSION);
                let keys = named.get("--keys").map(Path::new);
                let listen = named.get("--listen").copied();
                let metrics = named.get("--metrics").copied();
                let tls = named
                    .get("--tls-cert")
                    .zip(named.get("--tls-key"))
                    .map(|(cert, key)| (Path::new(*cert), Path::new(*key)));
                let served = enterplace_server::serve_policy(
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
                .filter(|a| !matches!(*a, "--admin" | "--quiet" | "--identity-only"))
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
                        .map_or_else(|| PathBuf::from("enterplace.keys.yaml"), PathBuf::from);
                    let made = attributes(flag("--admin"), &named).and_then(|attributes| {
                        let _store = store_for(&keys, named.get("--policy").copied())?;
                        if flag("--identity-only") {
                            return person_token_new(
                                positional[0],
                                named["--team"],
                                &attributes,
                                named.get("--url").copied(),
                                flag("--quiet"),
                                &keys,
                            );
                        }
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
        ["import", "litellm", rest @ ..] => match options(
            rest,
            &[
                "--keys-from",
                "--out",
                "--url",
                "--master-key-env",
                "--keys-out",
            ],
        ) {
            Some((positional, named))
                if positional.len() <= 1
                    && (positional.len() == 1 || named.contains_key("--url"))
                    && named.contains_key("--url") == named.contains_key("--master-key-env") =>
            {
                Some(
                    import_litellm(
                        positional.first().map(Path::new),
                        named.get("--keys-from").map(Path::new),
                        Path::new(
                            named
                                .get("--out")
                                .copied()
                                .unwrap_or("enterplace.policy.yaml"),
                        ),
                        named
                            .get("--url")
                            .copied()
                            .zip(named.get("--master-key-env").copied()),
                        Path::new(
                            named
                                .get("--keys-out")
                                .copied()
                                .unwrap_or("enterplace.keys.yaml"),
                        ),
                    )
                    .await
                    .unwrap_or_else(fail),
                )
            }
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
                                .unwrap_or("enterplace.policy.yaml"),
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
                    .map_or_else(|| PathBuf::from("enterplace.keys.yaml"), PathBuf::from);
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
                    .map_or_else(|| PathBuf::from("enterplace.keys.yaml"), PathBuf::from);
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
                    .map_or_else(|| PathBuf::from("enterplace.keys.yaml"), PathBuf::from);
                let revoked = store_for(&keys, named.get("--policy").copied())
                    .and_then(|_store| key_revoke(&keys, positional[0]));
                Some(revoked.map_or_else(fail, |()| ExitCode::SUCCESS))
            }
            _ => None,
        },
        ["budget", "raise", action, rest @ ..] => {
            match options(rest, &["--usd", "--until", "--reason", "--scope", "--url"]) {
                Some((positional, named)) => match budget_raise_call(action, &positional, &named) {
                    Some(call) => Some(
                        budget_raise(call, &named)
                            .await
                            .map_or_else(fail, |()| ExitCode::SUCCESS),
                    ),
                    None => None,
                },
                None => None,
            }
        }
        ["key", "info", rest @ ..] => match options(rest, &["--url"]) {
            Some((positional, named)) if positional.len() == 1 => Some(
                key_info(positional[0], &named)
                    .await
                    .map_or_else(fail, |()| ExitCode::SUCCESS),
            ),
            _ => None,
        },
        ["key", "update", rest @ ..] => match options(
            rest,
            &[
                "--url",
                "--expires",
                "--budget",
                "--models",
                "--tpm",
                "--rpm",
                "--parallel",
                "--customer",
                "--tags",
                "--routes",
                "--from",
                "--metadata",
            ],
        ) {
            Some((positional, named))
                if positional.len() == 1
                    && named.len() > usize::from(named.contains_key("--url")) =>
            {
                Some(
                    key_update(positional[0], &named)
                        .await
                        .map_or_else(fail, |()| ExitCode::SUCCESS),
                )
            }
            _ => None,
        },
        ["key", "rotate", rest @ ..] => match options(rest, &["--url", "--grace"]) {
            Some((positional, named)) if positional.len() == 1 => Some(
                key_rotate(positional[0], &named)
                    .await
                    .map_or_else(fail, |()| ExitCode::SUCCESS),
            ),
            _ => None,
        },
        ["usage", rest @ ..] => {
            let csv = rest.contains(&"--csv");
            let rest: Vec<&str> = rest.iter().copied().filter(|a| *a != "--csv").collect();
            match options(&rest, &["--since", "--group-by", "--url"]) {
                Some((positional, named)) if positional.is_empty() => Some(
                    usage(&named, csv)
                        .await
                        .map_or_else(fail, |()| ExitCode::SUCCESS),
                ),
                _ => None,
            }
        }
        ["budget", "status", rest @ ..] => {
            let short = rest.contains(&"--short");
            let rest: Vec<&str> = rest.iter().copied().filter(|a| *a != "--short").collect();
            match options(&rest, &["--model", "--url"]) {
                Some((positional, named)) if positional.is_empty() => Some(
                    budget_status(&named, short)
                        .await
                        .map_or_else(fail, |()| ExitCode::SUCCESS),
                ),
                _ => None,
            }
        }
        ["store", "import", rest @ ..] => match options(rest, &["--keys", "--policy"]) {
            Some((positional, named)) if positional.is_empty() && named.contains_key("--keys") => {
                Some(
                    store_import(
                        Path::new(named["--keys"]),
                        Path::new(
                            named
                                .get("--policy")
                                .copied()
                                .unwrap_or("enterplace.policy.yaml"),
                        ),
                    )
                    .map_or_else(fail, |()| ExitCode::SUCCESS),
                )
            }
            _ => None,
        },
        ["audit", "verify", rest @ ..] => match options(rest, &["--expect-last", "--org"]) {
            Some((positional, named)) if positional.len() <= 1 => Some(audit_verify_chains(
                Path::new(
                    positional
                        .first()
                        .copied()
                        .unwrap_or("enterplace-audit.jsonl"),
                ),
                named.get("--org").copied(),
                named.get("--expect-last").copied(),
            )),
            _ => None,
        },
        ["audit", "coverage", rest @ ..] => match options(rest, &["--keys", "--devices"]) {
            Some((positional, named)) if positional.len() <= 1 => Some(
                audit_coverage(
                    Path::new(
                        positional
                            .first()
                            .copied()
                            .unwrap_or("enterplace-audit.jsonl"),
                    ),
                    named.get("--keys").map(Path::new),
                    named.get("--devices").map(Path::new),
                )
                .map_or_else(fail, |()| ExitCode::SUCCESS),
            ),
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
                .unwrap_or("enterplace-audit.jsonl");
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
                Path::new(
                    named
                        .get("--out")
                        .copied()
                        .unwrap_or("enterplace.policy.yaml"),
                ),
            )),
            _ => None,
        },
        ["start", rest @ ..] => {
            // Flags without a value are taken out first; `options` reads `--name value` pairs. --yes and
            // --all-tools are still taken from older scripts: start asks nothing and prints no tool settings now.
            let flag = |name: &str| rest.contains(&name);
            let pairs: Vec<&str> = rest
                .iter()
                .copied()
                .filter(|a| {
                    !matches!(
                        *a,
                        "--yes"
                            | "--force"
                            | "--no-serve"
                            | "--no-open"
                            | "--all-tools"
                            | "--container"
                    )
                })
                .collect();
            match options(&pairs, &["--dir", "--providers", "--listen"]) {
                Some((positional, named)) if positional.is_empty() => {
                    // In the image nobody opens a browser, and the port is published.
                    let container = flag("--container");
                    let (dir, listen) = if container {
                        (start::CONTAINER_DIR, start::CONTAINER_LISTEN)
                    } else {
                        (".", start::DEFAULT_LISTEN)
                    };
                    let options = start::Options {
                        dir: Path::new(named.get("--dir").copied().unwrap_or(dir)),
                        providers: named.get("--providers").copied(),
                        force: flag("--force"),
                        serve: !flag("--no-serve"),
                        listen: named.get("--listen").copied().unwrap_or(listen),
                        open: !flag("--no-open"),
                        container,
                    };
                    Some(
                        start::run(&options)
                            .await
                            .map_or_else(fail, |()| ExitCode::SUCCESS),
                    )
                }
                _ => None,
            }
        }
        ["stop", rest @ ..] => match options(rest, &["--dir"]) {
            Some((positional, named)) if positional.is_empty() => Some(
                start::stop(Path::new(named.get("--dir").copied().unwrap_or("."))).map_or_else(
                    fail,
                    |said| {
                        println!("{said}");
                        ExitCode::SUCCESS
                    },
                ),
            ),
            _ => None,
        },
        ["providers"] => {
            print!("{}", enterplace_core::catalog::table());
            Some(ExitCode::SUCCESS)
        }
        ["providers", "--markdown"] => {
            print!("{}", enterplace_core::catalog::page());
            Some(ExitCode::SUCCESS)
        }
        ["version" | "--version" | "-V"] => {
            println!(
                "enterplace {} (src {}, built {})",
                enterplace_core::VERSION,
                env!("ENTERPLACE_SOURCE_HASH"),
                env!("ENTERPLACE_BUILD_DATE")
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
            ["check", ..] => Some("enterplace check <policy> [--keys <file>]"),
            ["explain", ..] => Some(
                "enterplace explain <policy> --key <hash prefix or name> --model <model> [--customer <name>] [--tags <a,b>] [--keys <file>]",
            ),
            ["budget", "status", ..] => {
                Some("enterplace budget status [--model <model>] [--short] [--url <enterplace url>]")
            }
            ["budget", ..] => Some(
                "enterplace budget raise request --usd <n> --until <date> --reason <text> [--scope team|person|key] | list | approve <id> [--usd <n>] [--until <date>] | reject <id> | add --scope <team:payments> --usd <n> --until <date> --reason <text>, each with [--url <enterplace url>]",
            ),
            ["key", "list", ..] => Some("enterplace key list [--keys <file>] [--policy <file>]"),
            ["key", "prune", ..] => Some("enterplace key prune [--keys <file>] [--policy <file>]"),
            ["key", "info", ..] => Some("enterplace key info <hash prefix> [--url <enterplace url>]"),
            ["key", "update", ..] => Some(
                "enterplace key update <hash prefix> [--expires <date>] [--budget <usd>/<period>[@<tz>]] [--models <a,b>] [--tpm <n>] [--rpm <n>] [--parallel <n>] [--customer <name>] [--tags <a,b>] [--routes <a,b>] [--from <cidr,cidr>] [--metadata <k=v,k=v>] [--url <enterplace url>] (at least one change; none removes a setting)",
            ),
            ["key", "rotate", ..] => {
                Some("enterplace key rotate <hash prefix> [--grace <48h|30m|7d|0>] [--url <enterplace url>]")
            }
            ["key", "revoke", ..] => {
                Some("enterplace key revoke <hash prefix> [--keys <file>] [--policy <file>]")
            }
            ["usage", ..] => Some(
                "enterplace usage [--since <7d|24h|2026-11-01>] [--group-by <team|person|model|provider|key|tag|org|customer|day|hour>] [--csv] [--url <enterplace url>]",
            ),
            ["store", ..] => Some("enterplace store import --keys <file> [--policy <file>]"),
            ["prices", ..] => Some("enterplace prices <model> [--policy <file>]"),
            ["import", ..] => Some(
                "enterplace import litellm <config.yaml> [--keys-from <csv or json export>] [--out <policy file>], or enterplace import litellm --url <proxy> --master-key-env <VAR> [--out <policy file>] [--keys-out <keys file>]",
            ),
            ["key", ..] => Some(
                "enterplace key new <name> --team <team> [--admin | --identity-only] [--expires <date>] [--budget <usd>/<period>] [--models <a,b>] [--tpm <n>] [--org <org>] [--customer <name>] [--tags <a,b>] [--parallel <n>] [--role <role>] [--url <gateway url>] [--quiet] [--keys <file>] [--policy <file>]",
            ),
            ["serve", ..] => Some(
                "enterplace serve <policy> [--keys <file>] [--listen <host:port>] [--metrics <host:port>] [--tls-cert <pem> --tls-key <pem>]",
            ),
            ["audit", "repair", ..] => Some("enterplace audit repair [<file>] [--yes]"),
            ["audit", "coverage", ..] => Some("enterplace audit coverage [<file>] [--keys <file>] [--devices <file>]"),
            ["providers", ..] => Some("enterplace providers [--markdown]"),
            ["guardrail", ..] => Some(
                "enterplace guardrail test <name> (--corpus <file.jsonl> | --since <7d>) [--policy <file>]",
            ),
            ["start", ..] => Some(
                "enterplace start [--dir <path>] [--providers <a,b>] [--listen <host:port>] [--no-open] [--force] [--no-serve] [--container]",
            ),
            ["stop", ..] => Some("enterplace stop [--dir <path>]"),
            ["init", ..] => Some("enterplace init [--provider <id>] [--models <a,b>] [--out <policy file>]"),
            ["login", ..] => Some("enterplace login <enterplace url> [--no-browser]"),
            ["logout", ..] => Some("enterplace logout"),
            ["kill", ..] => Some(
                "enterplace kill (--person <name> | --team <team> | --key-prefix <hash> | --model <model> | --all) --reason <text> [--force] [--url <enterplace url>]",
            ),
            ["unkill", ..] => Some(
                "enterplace unkill (--person <name> | --team <team> | --key-prefix <hash> | --model <model> | --all) [--url <enterplace url>]",
            ),
            ["audit", ..] => Some("enterplace audit verify [<file>] [--org <org>] [--expect-last <hash>]"),
            _ => None,
        };
        let help = args.iter().any(|arg| matches!(*arg, "--help" | "-h"));
        match usage {
            Some(usage) if help => {
                println!("Usage: {usage}");
                return ExitCode::SUCCESS;
            }
            Some(usage) => eprintln!(
                "error: `enterplace {}` is missing an argument or has one Enterplace does not know.\nUsage: {usage}",
                args.join(" ")
            ),
            None => eprintln!(
                "error: `enterplace {}` is not a command Enterplace knows.\n\n{USAGE}",
                args.join(" ")
            ),
        }
        ExitCode::from(2)
    })
}

async fn serve_unchecked(unchecked: bool) -> ExitCode {
    let name = format!("enterplace {}", enterplace_core::VERSION);
    match enterplace_server::serve_from_env(&name, unchecked).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => fail(err),
    }
}

fn check(policy: &Path, keys: Option<&Path>) -> ExitCode {
    match config::load(policy, keys) {
        Ok(loaded) => {
            // Credential names live in the store: checked there when it can be reached, warned about when not.
            match enterplace_server::credential_problems(policy, &loaded, &|v| {
                std::env::var(v).ok()
            }) {
                Ok(problems) if !problems.is_empty() => {
                    return check_failed(policy, &problems);
                }
                Ok(_) => {}
                Err(why) => eprintln!("warning: credential names were not checked: {why}"),
            }
            // UX12-4: keys from `enterplace login` lapse on their own, so a past expiry is a warning: the files did not
            // change, and serving refuses such a key (recorded) either way.
            for warning in expired_keys(&loaded)
                .into_iter()
                .chain(config::warnings(policy, &loaded))
            {
                eprintln!("{warning}");
            }
            // With a store the keys are in the database, which `check` does not connect to.
            let keys = match &loaded.store {
                Some(store) => format!("keys in the store named by {}", store.postgres_url_env),
                None => enterplace_core::count(loaded.policy.keys(), "key"),
            };
            println!(
                "{} is valid: {}, {keys}, {}.",
                policy.display(),
                enterplace_core::count(loaded.policy.rules(), "rule"),
                enterplace_core::config::describe(&loaded.providers)
            );
            for line in worst_waits(&loaded) {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(errors) => check_failed(policy, &errors),
    }
}

/// For each alias, the longest a caller can wait before the first byte of an answer or the error: every deployment
/// tried with its provider's retries (and their pauses), each up to its first-byte limit, then each fallback in turn,
/// and after that the answer's total limit.
fn worst_waits(loaded: &config::Loaded) -> Vec<String> {
    let defaults = enterplace_server::Timeouts::default();
    // (wait before the first byte, attempts, the longest total limit of a deployment that may answer)
    fn walk(
        loaded: &config::Loaded,
        target: &str,
        defaults: &enterplace_server::Timeouts,
        seen: &mut Vec<String>,
    ) -> (std::time::Duration, u32, std::time::Duration) {
        use std::time::Duration;
        if seen.iter().any(|s| s == target) {
            return (Duration::ZERO, 0, Duration::ZERO);
        }
        seen.push(target.to_string());
        let ms = |v: Option<u64>, d: Duration| v.map_or(d, Duration::from_millis);
        let hop = |provider: &config::Provider, set: config::Timeouts| {
            let set = set.or(provider.timeouts);
            let total = ms(set.total_ms, defaults.total);
            let first = ms(set.first_byte_ms, defaults.first_byte).min(total);
            let pauses: u64 = (1..=provider.retries).map(|r| 100u64 << r.min(5)).sum();
            (
                first * (provider.retries + 1) + Duration::from_millis(pauses),
                provider.retries + 1,
                total,
            )
        };
        let (mut wait, mut tries, mut total) = (Duration::ZERO, 0, Duration::ZERO);
        let mut add = |(w, t, tot): (Duration, u32, Duration)| {
            wait += w;
            tries += t;
            total = total.max(tot);
        };
        match loaded.aliases.iter().find(|a| a.name == target) {
            Some(alias) => {
                for d in &alias.deployments {
                    if let Some(p) = loaded.providers.iter().find(|p| p.name == d.provider) {
                        add(hop(p, d.timeouts.or(alias.timeouts)));
                    }
                }
                for next in alias
                    .fallbacks
                    .iter()
                    .chain(&alias.context_window_fallback)
                    .chain(&alias.content_policy_fallback)
                {
                    add(walk(loaded, next, defaults, seen));
                }
            }
            None => {
                // A model of a provider: that provider, then its fallback providers hop by hop.
                let mut next = loaded
                    .providers
                    .iter()
                    .find(|p| p.models.iter().any(|m| config::model_matches(m, target)));
                let mut hops = Vec::new();
                while let Some(p) = next.filter(|p| !hops.contains(&p.name)) {
                    hops.push(p.name.clone());
                    add(hop(p, config::Timeouts::default()));
                    next = p
                        .fallback
                        .as_ref()
                        .and_then(|f| loaded.providers.iter().find(|q| q.name == *f));
                }
            }
        }
        (wait, tries, total)
    }
    let secs = |d: std::time::Duration| {
        if d.subsec_millis() == 0 {
            format!("{} s", d.as_secs())
        } else {
            format!("{:.1} s", d.as_secs_f64())
        }
    };
    loaded
        .aliases
        .iter()
        .map(|alias| {
            let (wait, tries, total) = walk(loaded, &alias.name, &defaults, &mut Vec::new());
            format!(
                "alias {}: a caller waits at most {} for the first byte ({tries} attempts across deployments, retries and fallbacks, each to its first-byte limit), then at most {} for the answer.",
                alias.name,
                secs(wait),
                secs(total)
            )
        })
        .collect()
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
    let now = enterplace_core::audit::timestamp();
    let text = std::fs::read_to_string(&loaded.keys_path).unwrap_or_default();
    let mut problems: Vec<(usize, String)> = loaded
        .policy
        .entries()
        .filter(|(_, who)| who.expired(&now))
        .map(|(hash, who)| {
            let hex = enterplace_core::id::hex(hash);
            let line = text.lines().position(|l| l.contains(&hex)).map_or(0, |i| i + 1);
            let problem = format!(
                "{}:{line}: the key of \"{}\" (key hash {}) has expired: expires {} has passed, so every request with it is refused. Remove it with `enterplace key prune`, or give it a later date.",
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
        options: Default::default(),
    })
}

/// `enterplace explain`: why a request would be allowed or refused, and the limits it would count against.
fn explain(policy: &Path, named: &HashMap<&str, &str>) -> Result<(), String> {
    let loaded = config::load(policy, named.get("--keys").map(Path::new)).map_err(|problems| {
        format!(
            "{}\n{} cannot be used: {} problems above. Fix them with enterplace check first.",
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
                "no key in {} has the hash prefix or name \"{}\". enterplace key list shows them.",
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
        enterplace_core::policy::Context {
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

/// `enterplace key new --identity-only`: a person token for Claude subscription passthrough. It names the person and
/// reaches no model on its own, so it costs nothing and holds no limits of a key's.
fn person_token_new(
    name: &str,
    team: &str,
    attributes: &keyfile::Attributes,
    url: Option<&str>,
    quiet: bool,
    keys: &Path,
) -> Result<(), String> {
    if attributes.admin
        || attributes.budget.is_some()
        || attributes.models.is_some()
        || attributes.tpm.is_some()
    {
        return Err("--identity-only makes a person token, which names a person and reaches no model, so it takes no --admin, --budget, --models or --tpm. Set limits on the person's rule, or leave out --identity-only for a key.".into());
    }
    let issued = keyfile::issue_person_token(name, team, keys)?;
    if quiet {
        println!("{}", issued.key);
        return Ok(());
    }
    let url = url.unwrap_or("http://127.0.0.1:8080").trim_end_matches('/');
    println!(
        "Person token for {name}, team {team}. It names {name} to Enterplace and reaches no model on its own; it is shown once:\n\n  {key}\n\nClaude Code keeps its normal Claude login (Pro, Max, Team or Enterprise). Add these two lines to the shell profile, with ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN unset:\n\nexport ANTHROPIC_BASE_URL={url}\nexport ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: {key}\"\n\nThe gateway needs a provider with auth: passthrough (enterplace start writes one). Docs: https://docs.enterplace.dev/integrations/claude-code/\n",
        key = issued.key
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
        "To hand it over, send these lines through your secret manager, never in chat. Claude Code and the OpenAI SDKs read them:\n\nexport ANTHROPIC_BASE_URL={url}\nexport ANTHROPIC_API_KEY={key}\nexport OPENAI_BASE_URL={url}/v1\nexport OPENAI_API_KEY={key}\n\nFor Codex, put the key in ENTERPLACE_KEY and see https://docs.enterplace.dev/integrations/codex/ for its provider settings.\n",
        key = issued.key
    );
    if enterplace_core::store::attached(keys).is_some() {
        println!(
            "Its hash was added to the store. Every `enterplace serve` on that database accepts it within 2 seconds."
        );
    } else {
        println!(
            "Its hash was added to {}. A running `enterplace serve` accepts it within 2 seconds. `enterplace serve` reads the keys file beside its policy file unless `--keys` names another.",
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

/// What a running LiteLLM proxy's management API answers, read with its master key: the model list, every key
/// (page by page), every team. A route the proxy does not serve is reported, not fatal.
async fn read_proxy(
    url: &str,
    master: &str,
    report: &mut Vec<String>,
) -> Result<enterplace_core::litellm::FromProxy, String> {
    use enterplace_core::litellm::listed;
    let url = enterplace_console::cli::gateway(url).map_err(|_| {
        format!("{url} is not an address the master key may be sent to. Give the proxy's https address, or http://127.0.0.1 or localhost through a port forward.")
    })?;
    let get = |path: String| {
        let (url, master) = (url.clone(), master.to_string());
        async move { enterplace_console::cli::call("GET", &format!("{url}{path}"), &master, None).await }
    };
    let (status, models) = get("/model/info".into()).await?;
    if status != 200 {
        return Err(format!(
            "the proxy answered GET /model/info with HTTP {status}{}. Check the URL and that the variable holds its master key.",
            models["error"]["message"]
                .as_str()
                .map(|m| format!(" ({m})"))
                .unwrap_or_default()
        ));
    }
    let mut keys = Vec::new();
    for page in 1u64..=1000 {
        let (status, answer) = get(format!(
            "/key/list?return_full_object=true&page={page}&size=100"
        ))
        .await?;
        if status != 200 {
            report.push(format!("the proxy answered GET /key/list with HTTP {status}: no keys were read. Export them and pass --keys-from instead."));
            break;
        }
        let listed = listed(&answer, &["keys", "data"]);
        let count = listed.len();
        for key in listed {
            // Without full objects a proxy lists token hashes: each is read with /key/info.
            match key.as_str() {
                Some(token) => {
                    let (status, info) = get(format!("/key/info?key={token}")).await?;
                    if status == 200 {
                        let mut info = info["info"].clone();
                        info["token"] = token.into();
                        keys.push(info);
                    } else {
                        report.push(format!(
                            "key {}...: GET /key/info answered HTTP {status}; not imported.",
                            token.get(..12).unwrap_or(token)
                        ));
                    }
                }
                None => keys.push(key),
            }
        }
        let pages = answer["total_pages"].as_u64().unwrap_or(0);
        if count < 100 || (pages > 0 && page >= pages) {
            break;
        }
    }
    let (status, answer) = get("/team/list".into()).await?;
    let teams = if status == 200 {
        listed(&answer, &["teams", "data"])
    } else {
        report.push(format!(
            "the proxy answered GET /team/list with HTTP {status}: team budgets were not read."
        ));
        Vec::new()
    };
    println!(
        "Read {} from the proxy, {} and {}.",
        enterplace_core::count(listed(&models, &["data"]).len(), "model"),
        enterplace_core::count(keys.len(), "key"),
        enterplace_core::count(teams.len(), "team")
    );
    Ok(enterplace_core::litellm::from_proxy(&models, &keys, &teams))
}

async fn import_litellm(
    config: Option<&Path>,
    keys: Option<&Path>,
    out: &Path,
    proxy: Option<(&str, &str)>,
    keys_out: &Path,
) -> Result<ExitCode, String> {
    let read = |p: &Path| {
        std::fs::read_to_string(p).map_err(|err| format!("{} cannot be read: {err}.", p.display()))
    };
    let mut report = Vec::new();
    let live = match proxy {
        Some((url, variable)) => {
            let master = std::env::var(variable)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| format!("{variable} is not set. Set it to the LiteLLM proxy's master key; it is read from the environment so it stays out of your shell history."))?;
            Some(read_proxy(url, master.trim(), &mut report).await?)
        }
        None => None,
    };
    let config_text =
        match (config, &live) {
            (Some(path), _) => read(path)?,
            (None, Some(live)) => live.config.clone(),
            (None, None) => return Err(
                "name a LiteLLM config.yaml, or a running proxy with --url and --master-key-env."
                    .into(),
            ),
        };
    let export = match (keys, &live) {
        (Some(path), _) => Some(read(path)?),
        (None, Some(live)) => Some(live.export.clone()),
        (None, None) => None,
    };
    let imported = enterplace_core::litellm::import(&config_text, export.as_deref())?;
    let mut policy = imported.policy.clone();
    if let Some(live) = &live {
        report.extend(live.report.iter().cloned());
        if !live.limits.is_empty() {
            let mut limits = match enterplace_core::versions::section(&policy, "limits")? {
                serde_json::Value::Array(list) => list,
                _ => Vec::new(),
            };
            limits.extend(live.limits.iter().cloned());
            policy =
                enterplace_core::versions::set_section(&policy, "limits", Some(limits.into()))?;
        }
    }
    let write_new = |path: &Path, text: &str| -> Result<(), String> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options.open(path).map_err(|err| {
            format!(
                "{} cannot be written: {err}. Name another file; an existing one is never replaced.",
                path.display()
            )
        })?;
        std::io::Write::write_all(&mut file, text.as_bytes())
            .map_err(|err| format!("{} cannot be written: {err}.", path.display()))
    };
    // The keys of a running proxy are issued again here, into a keys file of their own.
    let reissued = match &live {
        Some(_) if keys_out.exists() => {
            return Err(format!(
                "{} exists. Name a new keys file with --keys-out; an existing one is never changed by an import.",
                keys_out.display()
            ));
        }
        Some(live) => {
            let served: Vec<String> = enterplace_core::litellm::listed(
                &serde_json::from_str(&config_text).unwrap_or(serde_json::Value::Null),
                &["model_list"],
            )
            .iter()
            .filter_map(|m| m["model_name"].as_str().map(str::to_string))
            .chain(
                enterplace_core::litellm::listed(
                    &serde_json::from_str(&live.config).unwrap_or_default(),
                    &["model_list"],
                )
                .iter()
                .filter_map(|m| m["model_name"].as_str().map(str::to_string)),
            )
            .collect();
            let (keys, more) =
                enterplace_core::litellm::reissue(export.as_deref().unwrap_or("[]"), &served)?;
            report.extend(more);
            Some(keys)
        }
        None => None,
    };
    write_new(out, &policy)?;
    println!("Wrote {}.", out.display());
    if let Some(keys) = &reissued {
        if keys.is_empty() {
            write_new(keys_out, "keys: []\n")?;
        }
        println!(
            "Issued {} in {} for the LiteLLM keys. Each is shown once: hand it to its owner.",
            enterplace_core::count(keys.len(), "key"),
            keys_out.display()
        );
        for key in keys {
            let issued = enterplace_core::keyfile::issue_with(
                &key.name,
                &key.team,
                &key.attributes,
                keys_out,
            )?;
            println!(
                "  {} -> {} (team {}): {}",
                key.was, key.name, key.team, issued.key
            );
        }
    }
    let report: Vec<&String> = imported
        .report
        .iter()
        .filter(|line| reissued.is_none() || !line.contains("reissue with `enterplace key new"))
        .chain(report.iter())
        .collect();
    let source = config.map_or_else(|| "the proxy".to_string(), |c| c.display().to_string());
    if report.is_empty() {
        println!("Everything in {source} was mapped.");
    } else {
        println!(
            "Not mapped, or needs a hand ({}):",
            enterplace_core::count(report.len(), "item")
        );
        for line in &report {
            println!("  - {line}");
        }
    }
    println!("See https://docs.enterplace.dev/migrate/from-litellm/. Checking it now:");
    Ok(check(out, reissued.is_some().then_some(keys_out)))
}

/// `enterplace guardrail test`: a backtest of one defined guardrail, printed for a person.
fn guardrail_test(
    name: &str,
    policy: &Path,
    corpus: Option<&Path>,
    since: Option<&str>,
) -> Result<(), String> {
    // The policy in force: the store's live version when it is kept there.
    let text = config::policy_text(policy)?;
    let defined = enterplace_core::guard::defined_in(&text)
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
        enterplace_core::guard::since_seconds(since)?;
        if corpus.is_none() {
            return Err(enterplace_core::guard::NO_CAPTURE.to_string());
        }
        eprintln!("warning: {}", enterplace_core::guard::NO_CAPTURE);
    }
    let Some(corpus) = corpus else {
        return Err("give the examples to test on: --corpus <file.jsonl>, one {\"text\": \"...\"} or {\"body\": {...}} per line.".into());
    };
    let rows = std::fs::read_to_string(corpus)
        .map_err(|err| format!("{}: cannot be read: {err}", corpus.display()))?;
    let samples = enterplace_core::guard::corpus(&rows)
        .map_err(|err| format!("{}: {err}", corpus.display()))?;
    let report = enterplace_core::guard::backtest(guard, &samples)?;
    print!("{}", backtest_text(&report));
    Ok(())
}

fn backtest_text(report: &enterplace_core::guard::Backtest) -> String {
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
            match enterplace_core::usage::price_for(&d.model, &overrides) {
                Some(price) => print_price(&shown, &price, policy),
                None => println!(
                    "{shown}: no price, so its usage is recorded with cost unknown and a budget refuses it. Add it under prices: in the policy, for example\nprices:\n  {}: {{ input: 3, output: 15 }}",
                    d.model
                ),
            }
        }
        return Ok(());
    }
    let Some(price) = enterplace_core::usage::price_for(model, &overrides) else {
        return Err(format!(
            "no price is known for model \"{model}\": its usage is recorded with cost unknown, and a budget cannot reach it. Add it under prices: in the policy, for example\nprices:\n  {model}: {{ input: 3, output: 15 }}"
        ));
    };
    print_price(model, &price, policy);
    Ok(())
}

fn print_price(model: &str, price: &enterplace_core::usage::Price, policy: Option<&Path>) {
    let (url, date) = enterplace_core::usage::litellm_prices_origin();
    let from = match price.source {
        PriceSource::Policy => format!(
            "the policy's prices: ({})",
            policy.map_or(String::new(), |p| p.display().to_string())
        ),
        PriceSource::Builtin => {
            "Enterplace's own table, checked against the provider's price list".into()
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
            .is_some_and(|at| enterplace_core::policy::expiry_passed(at, &now))
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
/// The policy is `--policy`, else enterplace.policy.yaml beside the keys file. Held for as long as the command runs.
fn store_for(
    keys: &Path,
    policy: Option<&str>,
) -> Result<Option<std::sync::Arc<dyn enterplace_core::store::Store>>, String> {
    let path = match policy {
        Some(path) => {
            let path = PathBuf::from(path);
            std::fs::metadata(&path).map_err(|err| {
                format!(
                    "{} (--policy) cannot be read: {err}. Name the policy file Enterplace serves.",
                    path.display()
                )
            })?;
            path
        }
        None => keys.with_file_name("enterplace.policy.yaml"),
    };
    enterplace_server::open_store(&path, keys, &|variable| std::env::var(variable).ok())
}

fn key_revoke(keys: &Path, prefix: &str) -> Result<(), String> {
    match keyfile::revoke(keys, prefix)? {
        Some(gone) => {
            println!(
                "Revoked the key of \"{}\" (team {}, hash {}). Enterplace refuses it within 2 seconds.",
                gone.name,
                gone.team,
                &gone.sha256[..8]
            );
            Ok(())
        }
        None => Err(format!(
            "no key hash starts with {prefix}. `enterplace key list` shows the keys and their hash prefixes."
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
    let kills = enterplace_core::kill::read(&enterplace_core::kill::path_beside(keys))?;
    std::fs::metadata(policy).map_err(|err| {
        format!(
            "{} cannot be read: {err}. Name the policy that has the store: section with --policy.",
            policy.display()
        )
    })?;
    let store = enterplace_server::open_store(policy, keys, &|variable| std::env::var(variable).ok())?
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
            "{} does not exist. Make the first key with `enterplace key new <name> --team <team> --admin`, or name the keys file with --keys.",
            keys.display()
        ));
    };
    let entries = config::key_entries(keys, &text).map_err(|problems| problems.join("\n"))?;
    if entries.is_empty() {
        println!("{}: no keys yet.", keys.display());
        return Ok(());
    }
    println!("name\tteam\tkey\tadmin\texpires\tbudget\tmodels\ttpm");
    let now = enterplace_core::audit::timestamp();
    for entry in entries {
        // QA11-6: a key past its date is refused at every request; the list says so.
        let expires = match entry.expires.as_deref() {
            Some(at) if enterplace_core::policy::expiry_passed(at, &now) => {
                format!("{at} (expired)")
            }
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
            path.join("enterplace-audit.jsonl").display()
        );
        ExitCode::from(1)
    })
}

/// Requests per person and coding tool, from the audit log's request records and their `user_agent`; with
/// `--keys`, every key holder who sent nothing; with `--devices`, each tool's enrolled devices and how many of them
/// call a provider directly, then per person the tools set to go through Enterplace, those going direct, denied apps and
/// blocked MCP servers still configured. Tab-separated, like `key list`.
fn audit_coverage(path: &Path, keys: Option<&Path>, devices: Option<&Path>) -> Result<(), String> {
    use enterplace_core::coverage;
    let mut rows = coverage::traffic(path)?;
    if let Some(keys) = keys {
        let text = config::read_keys(keys)?.ok_or_else(|| {
            format!(
                "{} does not exist. Name the keys file the gateway serves with.",
                keys.display()
            )
        })?;
        let entries = config::key_entries(keys, &text).map_err(|problems| problems.join("\n"))?;
        coverage::add_people(&mut rows, entries.into_iter().map(|e| (e.name, e.team)));
    }
    let devices = devices.map(coverage::read_devices).transpose()?;
    if let Some(devices) = &devices {
        coverage::add_devices(&mut rows, devices);
    }
    let more = if devices.is_some() {
        "\tdevices\tdirect"
    } else {
        ""
    };
    println!("person\tteam\ttool\trequests\trefused\tlast_seen{more}");
    for ((person, tool), r) in rows {
        let more = if devices.is_some() {
            format!("\t{}\t{}", r.devices, r.direct)
        } else {
            String::new()
        };
        println!(
            "{person}\t{}\t{tool}\t{}\t{}\t{}{more}",
            r.team, r.requests, r.refused, r.last_seen
        );
    }
    // Then each person's devices summed: what goes through Enterplace, and what is there that should not be.
    if let Some(devices) = &devices {
        let list = |set: &std::collections::BTreeSet<String>| {
            if set.is_empty() {
                "-".to_string()
            } else {
                set.iter().cloned().collect::<Vec<_>>().join(", ")
            }
        };
        println!("\nperson\tteam\tvia_enterplace\tdirect\tdenied_apps\tblocked_mcp");
        for (person, p) in coverage::people(devices) {
            println!(
                "{person}\t{}\t{}\t{}\t{}\t{}",
                if p.team.is_empty() { "-" } else { &p.team },
                list(&p.enterplace),
                list(&p.direct),
                list(&p.denied_apps),
                list(&p.blocked_mcp)
            );
        }
    }
    // Then each device's MCP servers, and whether each goes through Enterplace's MCP gateway.
    let servers: Vec<_> = devices
        .iter()
        .flatten()
        .flat_map(|d| d.mcp.iter().map(move |m| (d, m)))
        .collect();
    if !servers.is_empty() {
        println!("\ndevice\tperson\tos\ttool\tserver\ttransport\ttarget\tvia_enterplace\tdecision");
        for (d, m) in servers {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                d.device_id,
                d.person,
                if d.os.is_empty() { "-" } else { &d.os },
                m.tool,
                m.server,
                m.transport,
                m.target,
                if m.via_enterplace { "yes" } else { "no" },
                if m.decision.is_empty() {
                    "pending"
                } else {
                    &m.decision
                }
            );
        }
    }
    Ok(())
}

/// `enterplace audit verify`: the install's chain, then each organization's beside it (`audit: { per_org: true }`).
/// With `--org`, that organization's chain alone, which `--expect-last` then applies to.
fn audit_verify_chains(path: &Path, org: Option<&str>, expect: Option<&str>) -> ExitCode {
    if let Some(org) = org {
        let own = audit::org_path(path, org);
        if !own.exists() {
            eprintln!(
                "error: organization \"{org}\" has no audit chain at {}. Chains of their own are kept with `audit: {{ per_org: true }}` in the policy, from the organization's first record; check the name, and the install's log path given first.",
                own.display()
            );
            return ExitCode::from(1);
        }
        return audit_verify(&own, expect);
    }
    let mut code = audit_verify(path, expect);
    for (org, own) in audit::org_chains(path).unwrap_or_default() {
        println!("\nOrganization {org}:");
        if audit_verify(&own, None) != ExitCode::SUCCESS {
            code = ExitCode::from(1);
        }
    }
    code
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
                    "Only the last line is cut short, and the chain before it holds: a write that failed part way (for example on a full disk). Run `enterplace audit repair {}` to see that line, then add --yes to remove it and record the repair.",
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
                        "error: {err}\nRepair cannot fix this: it only removes a last line cut short by a failed write, and this log's last line is whole. A record changed, inserted or removed means the log was altered. Nothing was removed: keep the file as it is, as evidence, and to start a new chain move it aside while Enterplace is stopped."
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
            "{}: the chain holds up to byte {}, then a last line of {} bytes is cut short:\n{}\nTo remove only that line and record the repair, stop Enterplace and run: enterplace audit repair {} --yes",
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
                "{}: removed the cut last line ({} bytes) and recorded it as record {records}. Enterplace can start again.",
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
    enterplace_core::count(usize::try_from(n).unwrap_or(usize::MAX), noun)
}

/// Where `enterplace login` keeps its key: `$XDG_CONFIG_HOME/enterplace/credentials`, else `~/.config/enterplace/credentials`.
fn credentials_path() -> Result<PathBuf, String> {
    let set = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    set("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| set("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|config| config.join("enterplace").join("credentials"))
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
    let url = enterplace_console::cli::gateway(url)?;
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
    let got = enterplace_console::cli::login(&url, open).await?;
    // A login replaces the one before it: that key is given up, so it does not stay valid on a file nobody reads.
    if let Ok(Some(old)) = credentials() {
        if let (Some(old_url), Some(old_key)) = (old.get("url"), old.get("key")) {
            let _ = enterplace_console::cli::call(
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
            "# Written by enterplace login. `enterplace logout` revokes this key and deletes this file.\nurl={url}\nkey={}\nname={}\nteam={}\nexpires={}\n",
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
    // Claude Code reads the key from its own settings, so nothing is pasted into a shell for it.
    let settings = write_claude_settings(&url, &got.key, got.subscriptions)?;
    // UX12-3: the next login revokes this key, so a profile holding the key itself would break on schedule. The
    // profile reads this file instead, which every login rewrites and logout deletes.
    let env = path.with_file_name("env");
    save_credentials(&env, &env_lines(&url, &got.key, got.subscriptions))?;
    println!(
        "Claude Code is pointed at Enterplace: ANTHROPIC_BASE_URL and ANTHROPIC_CUSTOM_HEADERS are in the env block of {}, and its other settings are unchanged. Restart Claude Code to pick them up.\n\nFor the OpenAI SDKs and Codex (which reads ENTERPLACE_KEY, see https://docs.enterplace.dev/integrations/codex/), and as a fallback for Claude Code, the same variables are in {env}, which the next `enterplace login` rewrites. To use them, add this line to your shell profile, and run it now in this shell:\n\n  . {env}\n\nThe key works within 2 seconds. Every request with it is recorded under {}.",
        settings.display(),
        got.name,
        env = env.display()
    );
    Ok(())
}

/// The shell lines that point Claude Code, the OpenAI SDKs and Codex at Enterplace with `key`. On a gateway with Claude
/// subscription passthrough, Claude Code keeps its own Claude login and the key only names the person.
fn env_lines(url: &str, key: &str, subscriptions: bool) -> String {
    let claude = if subscriptions {
        format!(
            "# Claude Code keeps your Claude subscription login; the key names you to Enterplace.\nunset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN\nexport ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: {key}\"\n"
        )
    } else {
        format!("export ANTHROPIC_API_KEY={key}\n")
    };
    format!(
        "# Written by enterplace login. `enterplace logout` deletes this file.\nexport ANTHROPIC_BASE_URL={url}\n{claude}export OPENAI_BASE_URL={url}/v1\nexport OPENAI_API_KEY={key}\nexport ENTERPLACE_KEY={key}\n"
    )
}

/// `~/.claude/settings.json`, where Claude Code reads its `env` block.
fn claude_settings_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            "HOME is not set, so ~/.claude/settings.json cannot be found. Set HOME and run `enterplace login` again."
                .to_string()
        })?;
    Ok(PathBuf::from(home).join(".claude").join("settings.json"))
}

/// Claude Code's settings with Enterplace's variables in `env`. Every other key stays, and a file that is not a JSON
/// object is refused rather than overwritten, because it holds the person's own settings.
fn claude_settings(
    existing: Option<&str>,
    url: &str,
    key: &str,
    subscriptions: bool,
) -> Result<String, String> {
    let refuse = |why: &str| {
        format!(
            "~/.claude/settings.json {why}. Nothing was changed. Fix or move the file, then run `enterplace login` again."
        )
    };
    let mut root = match existing.map(str::trim).filter(|t| !t.is_empty()) {
        None => serde_json::Map::new(),
        Some(text) => match serde_json::from_str::<serde_json::Value>(text) {
            Ok(serde_json::Value::Object(map)) => map,
            Ok(_) => return Err(refuse("is not a JSON object")),
            Err(err) => return Err(refuse(&format!("is not valid JSON ({err})"))),
        },
    };
    let env = root
        .entry("env")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let serde_json::Value::Object(env) = env else {
        return Err(refuse("has an \"env\" that is not an object"));
    };
    env.insert("ANTHROPIC_BASE_URL".into(), url.into());
    env.insert(
        "ANTHROPIC_CUSTOM_HEADERS".into(),
        format!("x-enterplace-user: {key}").into(),
    );
    // Without subscription passthrough the key is Claude Code's API key. With it, the person's own Claude login
    // stays and no key is set.
    if !subscriptions {
        env.insert("ANTHROPIC_API_KEY".into(), key.into());
    }
    let mut text = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    text.push('\n');
    Ok(text)
}

/// Writes the Enterplace variables into `~/.claude/settings.json`, keeping its other keys. Returns the path.
fn write_claude_settings(url: &str, key: &str, subscriptions: bool) -> Result<PathBuf, String> {
    let path = claude_settings_path()?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(format!("{} cannot be read: {err}.", path.display())),
    };
    let text = claude_settings(existing.as_deref(), url, key, subscriptions)?;
    save_credentials(&path, &text)?;
    Ok(path)
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
            enterplace_console::cli::call("DELETE", &format!("{url}/admin/keys/self"), key, None)
                .await?;
        tries += 1;
        if young && answer["error"]["code"] == "unknown_key" && tries < 13 {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            continue;
        }
        break (status, answer);
    };
    let code = answer["error"]["code"].as_str().unwrap_or("");
    // A key Enterplace no longer knows (revoked or expired and removed) has nothing left to revoke.
    if status != 200 && code != "unknown_key" {
        return Err(format!(
            "Enterplace did not revoke the key, so {} was kept: {}",
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

/// `enterplace kill` (`on`) and `enterplace unkill`.
/// The gateway and the admin key an admin command calls it with: --url, ENTERPLACE_URL or the saved login, and
/// ENTERPLACE_ADMIN_KEY or the saved login key.
fn admin_target(named: &HashMap<&str, &str>) -> Result<(String, String), String> {
    let saved = credentials()?.unwrap_or_default();
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let url = named
        .get("--url")
        .map(|u| u.to_string())
        .or_else(|| env("ENTERPLACE_URL"))
        .or_else(|| saved.get("url").cloned())
        .ok_or("name the gateway with --url, ENTERPLACE_URL or `enterplace login`.")?;
    let url = enterplace_console::cli::gateway(&url)?;
    // ENTERPLACE_KEY too: it is the name `enterplace start` prints the admin key under.
    let key = env("ENTERPLACE_ADMIN_KEY")
        .or_else(|| env("ENTERPLACE_KEY"))
        .or_else(|| saved.get("key").cloned())
        .ok_or(
            "put an admin key in ENTERPLACE_ADMIN_KEY (or ENTERPLACE_KEY, as `enterplace start` prints it).",
        )?;
    Ok((url, key))
}

/// Calls the admin API and returns its answer, or the gateway's refusal as the error.
async fn admin_call(
    method: &str,
    path: &str,
    named: &HashMap<&str, &str>,
    body: Option<&serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let (url, key) = admin_target(named)?;
    let (status, answer) =
        enterplace_console::cli::call(method, &format!("{url}{path}"), &key, body).await?;
    if !(200..300).contains(&status) {
        return Err(answer["error"]["message"].as_str().map_or_else(
            || format!("Enterplace answered HTTP {status}."),
            str::to_string,
        ));
    }
    Ok(answer)
}

/// `enterplace budget raise <action>`: the method, path and body of the call it makes, or `None` when its arguments
/// do not fit.
fn budget_raise_call(
    action: &str,
    positional: &[&str],
    named: &HashMap<&str, &str>,
) -> Option<(&'static str, String, serde_json::Value)> {
    let mut body = serde_json::Map::new();
    for (option, field) in [
        ("--until", "until"),
        ("--reason", "reason"),
        ("--scope", "scope"),
    ] {
        if let Some(value) = named.get(option) {
            body.insert(field.into(), (*value).into());
        }
    }
    if let Some(usd) = named.get("--usd") {
        body.insert("usd".into(), usd.parse::<f64>().ok()?.into());
    }
    let has = |options: &[&str]| options.iter().all(|o| named.contains_key(o));
    let (method, path) = match (action, positional) {
        ("request", []) if has(&["--usd", "--until", "--reason"]) => {
            ("POST", "/v1/budget/raises".to_string())
        }
        ("add", []) if has(&["--scope", "--usd", "--until", "--reason"]) => {
            ("POST", "/admin/budget/raises".to_string())
        }
        ("list", []) => ("GET", "/admin/budget/raises".to_string()),
        ("approve" | "reject", [id]) => ("POST", format!("/admin/budget/raises/{id}/{action}")),
        _ => return None,
    };
    Some((method, path, serde_json::Value::Object(body)))
}

/// Makes a budget raise call and prints each raise it answers with on a line.
async fn budget_raise(
    (method, path, body): (&str, String, serde_json::Value),
    named: &HashMap<&str, &str>,
) -> Result<(), String> {
    let sent = (method == "POST").then_some(&body);
    let answer = admin_call(method, &path, named, sent).await?;
    let line = |raise: &serde_json::Value| {
        let text = |field: &str| raise[field].as_str().unwrap_or("").to_string();
        println!(
            "{}  {}  {}  ${} until {}  asked by {}: {}",
            text("id"),
            text("state"),
            text("scope"),
            raise["usd"].as_f64().unwrap_or(0.0),
            text("until"),
            text("requested_by"),
            text("reason")
        );
    };
    match answer["raises"].as_array() {
        Some(list) if list.is_empty() => println!("No budget raises."),
        Some(list) => list.iter().for_each(line),
        None => line(&answer),
    }
    Ok(())
}

/// `--since` as the `from` of a usage query: a UTC date as given, or now less a span such as `7d`, `24h` or `30m`.
fn since(text: &str, now: std::time::SystemTime) -> Result<String, String> {
    let wrong = || {
        format!(
            "--since is \"{text}\". Write how far back, such as 7d, 24h or 30m, or a UTC date such as 2026-11-01."
        )
    };
    let date = text.len() == 10
        && text.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            _ => b.is_ascii_digit(),
        });
    if date {
        return Ok(text.to_string());
    }
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let n: u64 = number.parse().map_err(|_| wrong())?;
    let seconds = match unit {
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        "d" => n.saturating_mul(86_400),
        _ => return Err(wrong()),
    };
    let from = now
        .checked_sub(std::time::Duration::from_secs(seconds))
        .ok_or_else(wrong)?;
    Ok(audit::rfc3339(from))
}

/// A CSV field, quoted, and kept from reading as a formula in a spreadsheet, as the admin API writes one.
fn csv_field(text: &str) -> String {
    let text = if text.starts_with(['=', '+', '-', '@']) {
        format!("'{text}")
    } else {
        text.to_string()
    };
    format!("\"{}\"", text.replace('"', "\"\""))
}

/// The columns of a usage table: the field of the admin API's answer, and its heading.
const USAGE_COLUMNS: [(&str, &str); 9] = [
    ("requests", "requests"),
    ("refused", "refused"),
    ("errors", "errors"),
    ("input_tokens", "tokens in"),
    ("output_tokens", "tokens out"),
    ("total_tokens", "tokens"),
    ("spend_usd", "spend USD"),
    ("latency_p50_ms", "p50 ms"),
    ("latency_p95_ms", "p95 ms"),
];

/// One table of a usage answer, columns aligned: the group, then its numbers.
fn usage_table(group: &str, answer: &serde_json::Value) -> String {
    let cell = |row: &serde_json::Value, field: &str| match &row[field] {
        serde_json::Value::Null => "-".to_string(),
        serde_json::Value::String(text) => text.clone(),
        value if field == "spend_usd" => format!("{:.4}", value.as_f64().unwrap_or(0.0)),
        value => value.to_string(),
    };
    let mut rows: Vec<Vec<String>> = vec![
        std::iter::once(group.to_string())
            .chain(
                USAGE_COLUMNS
                    .iter()
                    .map(|(_, heading)| (*heading).to_string()),
            )
            .collect(),
    ];
    let line = |name: String, row: &serde_json::Value| -> Vec<String> {
        std::iter::once(name)
            .chain(USAGE_COLUMNS.iter().map(|(field, _)| cell(row, field)))
            .collect()
    };
    for row in answer["groups"].as_array().into_iter().flatten() {
        let name = match row[group].as_str() {
            Some("") | None => "(none)".to_string(),
            Some(name) => name.to_string(),
        };
        rows.push(line(name, row));
    }
    rows.push(line("total".to_string(), &answer["totals"]));
    let widths: Vec<usize> = (0..rows[0].len())
        .map(|i| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for row in &rows {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                // The group reads from the left, numbers line up on the right.
                if i == 0 {
                    format!("{cell:<width$}", width = widths[i])
                } else {
                    format!("{cell:>width$}", width = widths[i])
                }
            })
            .collect();
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
    }
    out
}

/// `enterplace usage`: `GET /admin/usage` once per group, as tables or one CSV.
async fn usage(named: &HashMap<&str, &str>, csv: bool) -> Result<(), String> {
    let from = since(
        named.get("--since").copied().unwrap_or("30d"),
        std::time::SystemTime::now(),
    )?;
    let groups: Vec<&str> = match named.get("--group-by") {
        Some(group) => vec![*group],
        None => vec!["team", "person", "model"],
    };
    let mut answers = Vec::new();
    for group in &groups {
        let path = format!("/admin/usage?group_by={group}&from={from}");
        answers.push(admin_call("GET", &path, named, None).await?);
    }
    if csv {
        let fields: Vec<&str> = USAGE_COLUMNS.iter().map(|(field, _)| *field).collect();
        println!("group_by,value,{}", fields.join(","));
        for (group, answer) in groups.iter().zip(&answers) {
            for row in answer["groups"].as_array().into_iter().flatten() {
                let cells: Vec<String> = fields
                    .iter()
                    .map(|field| match &row[*field] {
                        serde_json::Value::Null => String::new(),
                        value => value.to_string(),
                    })
                    .collect();
                println!(
                    "{group},{},{}",
                    csv_field(row[*group].as_str().unwrap_or_default()),
                    cells.join(",")
                );
            }
        }
        return Ok(());
    }
    println!(
        "Usage since {from} (UTC), counted by {}.",
        answers
            .first()
            .and_then(|a| a["counted_by"].as_str())
            .unwrap_or("the gateway")
    );
    for (group, answer) in groups.iter().zip(&answers) {
        println!("\nBy {group}:\n{}", usage_table(group, answer).trim_end());
    }
    Ok(())
}

/// Dollars as a status line shows them: cents, or four places under a dollar.
fn dollars(usd: f64) -> String {
    if usd >= 1.0 || usd == 0.0 {
        format!("${usd:.2}")
    } else {
        format!("${usd:.4}")
    }
}

/// `enterplace budget status`: what the caller's own key has left, from `GET /v1/enterplace/me`.
async fn budget_status(named: &HashMap<&str, &str>, short: bool) -> Result<(), String> {
    let saved = credentials()?.unwrap_or_default();
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let url = named
        .get("--url")
        .map(|u| u.to_string())
        .or_else(|| env("ENTERPLACE_URL"))
        .or_else(|| saved.get("url").cloned())
        .ok_or("name the gateway with --url, ENTERPLACE_URL or `enterplace login`.")?;
    let url = enterplace_console::cli::gateway(&url)?;
    let key = env("ENTERPLACE_KEY")
        .or_else(|| saved.get("key").cloned())
        .ok_or("put your Enterplace key in ENTERPLACE_KEY, or run `enterplace login`.")?;
    let model = named
        .get("--model")
        .map(|m| format!("?model={m}"))
        .unwrap_or_default();
    let (status, answer) =
        enterplace_console::cli::call("GET", &format!("{url}/v1/enterplace/me{model}"), &key, None)
            .await?;
    if !(200..300).contains(&status) {
        return Err(answer["error"]["message"].as_str().map_or_else(
            || format!("Enterplace answered HTTP {status}."),
            str::to_string,
        ));
    }
    let resets = |value: &serde_json::Value| {
        value.as_str().map_or_else(
            || "a sliding window".to_string(),
            |at| format!("resets {at}"),
        )
    };
    if short {
        match answer["remaining_usd"].as_f64() {
            Some(left) => println!("{} left ({})", dollars(left), resets(&answer["resets"])),
            None => println!("no budget"),
        }
        return Ok(());
    }
    println!(
        "{} (team {}), rule {}",
        answer["name"].as_str().unwrap_or(""),
        answer["team"].as_str().unwrap_or(""),
        answer["rule"].as_str().unwrap_or("")
    );
    let budgets = answer["budgets"].as_array().cloned().unwrap_or_default();
    if budgets.is_empty() {
        println!("No budget applies to this key.");
        return Ok(());
    }
    for b in &budgets {
        let usd = |field: &str| dollars(b[field].as_f64().unwrap_or(0.0));
        println!(
            "  {}: {} left of {} a {}, {} spent, {} held by requests in flight, {}{}",
            b["whose"].as_str().unwrap_or(""),
            usd("remaining_usd"),
            usd("usd"),
            b["per"].as_str().unwrap_or(""),
            usd("spent_usd"),
            usd("reserved_usd"),
            resets(&b["resets"]),
            if b["shadow"] == true {
                " (recorded only, refuses nothing)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

async fn key_info(prefix: &str, named: &HashMap<&str, &str>) -> Result<(), String> {
    let answer = admin_call("GET", &format!("/admin/keys/{prefix}"), named, None).await?;
    let key = &answer["key"];
    println!(
        "{} (team {}), key {}",
        key["name"].as_str().unwrap_or(""),
        key["team"].as_str().unwrap_or(""),
        key["sha256_prefix"].as_str().unwrap_or("")
    );
    if let Some(fields) = key.as_object() {
        for (name, value) in fields {
            let shown = match value {
                serde_json::Value::Null => continue,
                serde_json::Value::Array(list) if list.is_empty() => continue,
                serde_json::Value::Object(map) if map.is_empty() => continue,
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            if !matches!(name.as_str(), "name" | "team" | "sha256_prefix") {
                println!("  {name}: {shown}");
            }
        }
    }
    println!(
        "Spend (counted by {}):",
        answer["spend_counted_by"].as_str().unwrap_or("the gateway")
    );
    for row in answer["spend"].as_array().into_iter().flatten() {
        println!(
            "  {} {}: ${:.4} spent, ${:.4} held by requests in flight",
            row["per"].as_str().unwrap_or(""),
            row["period"].as_str().unwrap_or(""),
            row["spent_usd"].as_f64().unwrap_or(0.0),
            row["reserved_usd"].as_f64().unwrap_or(0.0)
        );
    }
    Ok(())
}

async fn key_update(prefix: &str, named: &HashMap<&str, &str>) -> Result<(), String> {
    let mut body = serde_json::Map::new();
    let list = |text: &str| -> serde_json::Value {
        text.split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
            .into()
    };
    for (flag, value) in named {
        let field = flag.trim_start_matches("--");
        if field == "url" {
            continue;
        }
        let value = if *value == "none" {
            serde_json::Value::Null
        } else {
            match field {
                "tpm" | "rpm" | "parallel" => value
                    .parse::<u64>()
                    .map(serde_json::Value::from)
                    .map_err(|_| {
                        format!(
                            "--{field} is \"{value}\". Write a whole number, or none to remove it."
                        )
                    })?,
                "budget" => {
                    let wrong = || {
                        format!(
                            "--budget is \"{value}\". Write US dollars and a period, for example --budget 20/month, or none to remove it."
                        )
                    };
                    let (usd, per) = value.split_once('/').ok_or_else(wrong)?;
                    let usd: f64 = usd.trim_start_matches('$').parse().map_err(|_| wrong())?;
                    // A time zone after the period, as `enterplace key new` takes it: 20/week@Europe/Berlin.
                    match per.split_once('@') {
                        Some((per, tz)) => serde_json::json!({ "usd": usd, "per": per, "tz": tz }),
                        None => serde_json::json!({ "usd": usd, "per": per }),
                    }
                }
                "models" | "tags" | "routes" | "from" => list(value),
                "metadata" => {
                    let mut map = serde_json::Map::new();
                    for pair in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        let (k, v) = pair.split_once('=').ok_or_else(|| {
                            format!("--metadata is \"{value}\". Write name=value pairs with commas between, for example --metadata owner=maya,ticket=OPS-12.")
                        })?;
                        map.insert(k.trim().to_string(), v.trim().into());
                    }
                    map.into()
                }
                _ => (*value).into(),
            }
        };
        body.insert(field.to_string(), value);
    }
    let answer = admin_call(
        "PATCH",
        &format!("/admin/keys/{prefix}"),
        named,
        Some(&body.into()),
    )
    .await?;
    let key = &answer["key"];
    println!(
        "Changed the key {} of \"{}\". The change is recorded in the audit log and in force within 2 seconds on every gateway serving the same keys.",
        key["sha256_prefix"].as_str().unwrap_or(prefix),
        key["name"].as_str().unwrap_or("")
    );
    Ok(())
}

async fn key_rotate(prefix: &str, named: &HashMap<&str, &str>) -> Result<(), String> {
    let mut body = serde_json::Map::new();
    if let Some(grace) = named.get("--grace") {
        body.insert("grace".into(), (*grace).into());
    }
    let answer = admin_call(
        "POST",
        &format!("/admin/keys/{prefix}/rotate"),
        named,
        Some(&body.into()),
    )
    .await?;
    println!(
        "New key for {} (team {}). It is shown once and is not stored anywhere:\n\n  {}\n",
        answer["name"].as_str().unwrap_or(""),
        answer["team"].as_str().unwrap_or(""),
        answer["key"].as_str().unwrap_or("")
    );
    println!(
        "The old key {} keeps working until {} (UTC). Every request made with it until then is recorded with key_rotated, so you can find who still uses it.",
        answer["replaces"].as_str().unwrap_or(prefix),
        answer["old_key_until"].as_str().unwrap_or("")
    );
    Ok(())
}

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
        .or_else(|| env("ENTERPLACE_URL"))
        .or_else(|| saved.get("url").cloned())
        .ok_or("name the gateway with --url, ENTERPLACE_URL or `enterplace login`.")?;
    let url = enterplace_console::cli::gateway(&url)?;
    // ENTERPLACE_KEY too: it is the name `enterplace start` prints the admin key under.
    let key = env("ENTERPLACE_ADMIN_KEY")
        .or_else(|| env("ENTERPLACE_KEY"))
        .or_else(|| saved.get("key").cloned())
        .ok_or(
            "put an admin key in ENTERPLACE_ADMIN_KEY (or ENTERPLACE_KEY, as `enterplace start` prints it).",
        )?;
    let mut body = serde_json::json!({ "scope": scope, "value": value });
    if on {
        body["reason"] = reason.into();
    }
    if force {
        body["force"] = true.into();
    }
    let method = if on { "POST" } else { "DELETE" };
    let (status, answer) =
        enterplace_console::cli::call(method, &format!("{url}/admin/kills"), &key, Some(&body))
            .await?;
    if !(200..300).contains(&status) {
        return Err(answer["error"]["message"].as_str().map_or_else(
            || format!("Enterplace answered HTTP {status}."),
            str::to_string,
        ));
    }
    let what = if scope == "all" {
        "everyone".to_string()
    } else {
        format!("{scope} {value}")
    };
    if on {
        println!(
            "Kill switch on for {what}: \"{reason}\". Enterplace refuses that traffic now, within 1 second on every node serving the same files. `enterplace unkill` turns it off."
        );
    } else {
        println!("Kill switch off for {what}. Traffic flows again within 1 second on every node.");
    }
    Ok(())
}

/// `enterplace init`: a starter policy for one catalog provider, and the steps to the first governed call.
fn init(provider: &str, models: Option<&str>, out: &Path) -> ExitCode {
    let Some(preset) = enterplace_core::catalog::find(provider) else {
        eprintln!(
            "error: there is no provider \"{provider}\" in the catalog. Run `enterplace providers` to see them, then enterplace init --provider <id>."
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
            "error: name the models {} serves that people may use, for example enterplace init --provider {} --models <model>,<model>. A provider lists exact model names.",
            preset.name, preset.id
        );
        return ExitCode::from(2);
    }
    if out.exists() {
        eprintln!(
            "error: {} exists, and enterplace init never writes over a policy. Give another file with --out, or edit that one.",
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
        "# Written by enterplace init. Reference: https://docs.enterplace.dev/governance/policy/\nversion: 1\nproviders:\n  - name: {id}\n    preset: {id}\n{private}    key_env: {variable}\n    models: [{list}]\nrules:\n  - name: everyone\n    principals: {{ any: true }}\n    models: [{list}]\n",
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
        "Wrote {out} for {name}. Next:\n{local}\n  enterplace serve {out}\n  then open the setup link it prints: it makes your admin key and shows how to point Claude Code and the OpenAI SDKs at Enterplace.",
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
        let dir =
            std::env::temp_dir().join(format!("enterplace-credentials-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("enterplace").join("credentials");
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
        let text = super::env_lines("https://gw.example", "enterplace_k", false);
        for line in [
            "export ANTHROPIC_BASE_URL=https://gw.example\n",
            "export ANTHROPIC_API_KEY=enterplace_k\n",
            "export OPENAI_BASE_URL=https://gw.example/v1\n",
            "export OPENAI_API_KEY=enterplace_k\n",
            "export ENTERPLACE_KEY=enterplace_k\n",
        ] {
            assert!(text.contains(line), "{line}");
        }
        let text = super::env_lines("https://gw.example", "enterplace_k", true);
        assert!(
            text.contains("export ANTHROPIC_CUSTOM_HEADERS=\"x-enterplace-user: enterplace_k\"\n")
        );
        assert!(text.contains("unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN\n"));
        assert!(!text.contains("export ANTHROPIC_API_KEY"));
    }

    #[test]
    fn the_login_writes_claude_codes_settings_and_keeps_its_other_keys() -> Result<(), String> {
        let existing = r#"{"theme":"dark","env":{"FOO":"1","ANTHROPIC_BASE_URL":"old"},"permissions":{"allow":["Bash"]}}"#;
        let text =
            super::claude_settings(Some(existing), "https://gw.example", "enterplace_k", true)?;
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["permissions"]["allow"][0], "Bash");
        assert_eq!(v["env"]["FOO"], "1");
        assert_eq!(v["env"]["ANTHROPIC_BASE_URL"], "https://gw.example");
        assert_eq!(
            v["env"]["ANTHROPIC_CUSTOM_HEADERS"],
            "x-enterplace-user: enterplace_k"
        );
        assert!(v["env"].get("ANTHROPIC_API_KEY").is_none());
        // No file yet: one is made with just the env block.
        let fresh = super::claude_settings(None, "https://gw.example", "enterplace_k", false)?;
        let v: serde_json::Value = serde_json::from_str(&fresh).map_err(|e| e.to_string())?;
        assert_eq!(v["env"]["ANTHROPIC_API_KEY"], "enterplace_k");
        // A file that is not a JSON object is never overwritten.
        for bad in ["not json", "[1]", "{\"env\":3}"] {
            let err = super::claude_settings(Some(bad), "https://gw.example", "k", true)
                .err()
                .ok_or("accepted a bad file")?;
            assert!(err.contains("Nothing was changed"), "{err}");
        }
        Ok(())
    }
}
