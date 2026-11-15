//! Editing the policy and the keys in the console: Models, Teams, a key's fields, and the policy's versions (the
//! editor, its diff, approval, a dry run, rollback, export and import).
//!
//! The policy changes only when it is kept in the store (`store.policy_from: store`): each save is a new version,
//! checked as `gantry check` checks a file, recorded in the audit chain first, and live on every gateway within
//! 2 seconds, or waiting for a second admin when the live version sets `store.approval: true`. When the policy is
//! kept in the file, these pages show it and say how to change it there.
//!
//! No Claude Design design exists for these pages yet. They are built only from the console's existing components
//! (head, panel, table, tag, dialog, field, code, banner, toast) and its tokens, and need a design pass.

use std::fmt::Write as _;

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gantry_core::{
    config::{self, Loaded},
    keyfile,
    policy::{Budget, Period, Permission, Who},
    store::{self, PolicyVersion},
    usage,
    versions::{self, DryRun, Refused},
};
use serde_json::json;

use crate::{
    Act, Admin, Console, Form, NOT_RECORDED, foreign,
    html::{
        Field, button, close_link, code, dialog, empty, enc, esc, facts, field, head, icon, link,
        motif, tag,
    },
    page,
    pages::{self, PolicySource, alert, long_time, money, tool_page},
    read_only, record, redirect, same_origin,
};

pub(crate) fn routes() -> Router<Console> {
    Router::new()
        .route("/models", get(models_page))
        .route("/models/{action}", post(models_change))
        .route("/teams", get(teams_page))
        .route("/people/edit", get(key_page).post(key_change))
        .route("/policy/versions", get(versions_page))
        .route("/policy/versions/{id}/{action}", post(version_action))
        .route("/policy/edit", get(editor_page))
        .route("/policy/save", post(save))
        .route("/policy/dry-run", post(dry_run))
        .route("/policy/export", get(export))
}

/// A message from the core, written as a sentence for a page.
fn sentence(text: &str) -> String {
    let mut text = text.trim().to_string();
    if let Some(first) = text.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    text
}

/// The live version, when the policy is kept in the store.
pub(crate) fn live(console: &Console) -> Option<PolicyVersion> {
    store::policy_store(&console.config().policy).and_then(|s| s.live_policy())
}

/// The version number a form says it started from.
fn base_of(form: &Form) -> Option<i64> {
    form.get("base").parse().ok()
}

fn base_field(live: Option<&PolicyVersion>) -> String {
    format!(
        r#"<input type="hidden" name="base" value="{}">"#,
        live.map_or_else(|| "none".to_string(), |v| v.id.to_string())
    )
}

/// What the policy page shows in its head and above the policy.
pub(crate) fn policy_source(console: &Console, admin: &Admin) -> PolicySource {
    let path = &console.config().policy;
    let live = live(console);
    let mut actions = String::new();
    if live.is_some() && edits_policy(admin) {
        actions.push_str(&link("Edit", "", "/console/policy/edit", false));
    }
    if live.is_some() {
        actions.push_str(&link(
            "Versions",
            "quiet",
            "/console/policy/versions",
            false,
        ));
    }
    actions.push_str(&link(
        "Export YAML",
        "quiet",
        "/console/policy/export",
        false,
    ));
    let banner = match versions::file_differs(path) {
        Some(v) => format!(
            r#"<div class="g-banner" role="status"><span class="t-body">{} differs from live version {v}, and only its store: section is read: the store decides. Export the live version to update the file, or paste the file in the editor to make it a new version.</span></div>"#,
            esc(&path.display().to_string())
        ),
        None => String::new(),
    };
    PolicySource {
        version: live.map(|v| v.id),
        actions,
        banner,
    }
}

/// Records a change, then makes it as a new policy version. `Err` holds what to tell the person.
async fn save_version(
    console: &Console,
    admin: &Admin,
    action: &'static str,
    text: String,
    base: Option<i64>,
    note: String,
) -> Result<PolicyVersion, Refused> {
    let act = Act {
        action,
        by: Some((&admin.name, &admin.team)),
        key: None,
        // The policy holds no secrets: the chain keeps every draft whole, saved, pending or refused.
        target: json!({ "base": base, "note": note, "sha256": gantry_core::id::sha256_hex(text.as_bytes()), "policy": text }),
    };
    run(
        console,
        &act,
        move |policy, keys, by| versions::propose(&policy, &keys, &text, base, &note, &by),
        &admin.name,
    )
    .await
}

/// Records `act`, runs `work` off the request threads, and records its failure if it fails.
async fn run(
    console: &Console,
    act: &Act<'_>,
    work: impl FnOnce(std::path::PathBuf, std::path::PathBuf, String) -> Result<PolicyVersion, Refused>
    + Send
    + 'static,
    by: &str,
) -> Result<PolicyVersion, Refused> {
    if record(console, act, None, None).await.is_err() {
        return Err(Refused::Store(NOT_RECORDED.into()));
    }
    let c = console.config();
    let (policy, keys, by) = (c.policy.clone(), c.keys.clone(), by.to_string());
    let done = tokio::task::spawn_blocking(move || work(policy, keys, by))
        .await
        .unwrap_or_else(|err| {
            Err(Refused::Store(format!(
                "nothing was changed: {err}. Try again."
            )))
        });
    if let Err(err) = &done {
        let code = match err {
            Refused::Invalid(_) => "invalid_policy",
            Refused::ReadOnly(_) => "policy_in_file",
            Refused::Forbidden(_) => "own_version",
            Refused::Conflict(_) => "version_conflict",
            Refused::Unknown(_) => "no_such_version",
            Refused::Store(_) => "store_unavailable",
        };
        let _ = record(console, act, Some(code), Some(&err.message())).await;
    }
    done
}

fn toast(text: &str) -> String {
    format!(
        r#"<div class="g-toasts"><div class="g-toast" role="status" tabindex="-1" data-focus><span class="g-toast__text t-body">{}</span></div></div>"#,
        esc(text)
    )
}

/// Where a saved version is shown, with a toast that says what happened.
fn saved(v: &PolicyVersion) -> Response {
    redirect(&format!(
        "/console/policy/versions?version={}&done={}",
        v.id, v.state
    ))
}

fn problems(err: &Refused) -> String {
    let lines: Vec<String> = match err {
        Refused::Invalid(problems) => problems.iter().map(|p| esc(p)).collect(),
        other => vec![esc(&sentence(&other.message()))],
    };
    alert(&lines.join("<br>"))
}

// ---------------------------------------------------------------- models

async fn models_page(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let query = Form::of(&uri);
    page(StatusCode::OK, models_body(&console, &admin, &query, ""))
}

fn models_body(console: &Console, admin: &Admin, query: &Form, error: &str) -> String {
    let title = "Models";
    let here = "/console/models";
    let c = console.config();
    let lead = "The models each provider serves, what they cost per million tokens, and the other names callers may send for them.";
    let loaded = match config::load(&c.policy, Some(&c.keys)) {
        Ok(loaded) => loaded,
        Err(problems) => {
            let failed = empty(
                &motif(&["", "flame"], &["empty"], (2, 1), true, true),
                "The policy did not load",
                &esc(&problems.join(" ")),
                &link("Open the policy", "", "/console/policy", false),
            );
            return tool_page(
                title,
                &admin.label(),
                here,
                query,
                &format!("{}\n{failed}", head(title, lead, "")),
                "",
            );
        }
    };
    let live = live(console);
    let editable = live.is_some() && edits_policy(admin);
    let add = if editable {
        link("Add a model", "", "/console/models?add=1", false)
    } else {
        String::new()
    };
    let banner = if live.is_none() {
        format!(
            r#"<div class="g-banner" role="status"><span class="t-body">{}</span></div>"#,
            esc(&sentence(&versions::read_only_message(&c.policy)))
        )
    } else {
        String::new()
    };
    let prices = loaded.policy.prices();
    let mut rows = String::new();
    for provider in &loaded.providers {
        for model in &provider.models {
            let (price, source) = match (prices.get(model), usage::price_for(model, prices)) {
                (Some(p), _) => (
                    format!("{} / {}", money(p.input), money(p.output)),
                    "policy",
                ),
                (None, Some(p)) => (
                    format!("{} / {}", money(p.input), money(p.output)),
                    "built in",
                ),
                (None, None) => ("no price".into(), "spend is not counted"),
            };
            let aliases: Vec<&str> = loaded
                .aliases
                .iter()
                .filter(|a| {
                    a.deployments
                        .iter()
                        .any(|d| d.provider == provider.name && d.model == *model)
                })
                .map(|a| a.name.as_str())
                .collect();
            let action = if editable {
                link(
                    "Price",
                    "quiet",
                    &format!("{here}?price={}", enc(model)),
                    true,
                )
            } else {
                String::new()
            };
            let _ = write!(
                rows,
                r#"<tr><td>{}<span class="g-table__sub">{}</span></td><td class="g-table__num">{price}<span class="g-table__sub">{source}</span></td><td class="g-table__wide">{}</td><td><span class="g-head__actions">{action}</span></td></tr>"#,
                esc(model),
                esc(&format!("{} ({})", provider.name, provider.kind.word())),
                if aliases.is_empty() {
                    "none".to_string()
                } else {
                    esc(&aliases.join(", "))
                },
            );
        }
    }
    let table = if rows.is_empty() {
        empty(
            &motif(&["", ""], &["empty"], (2, 1), true, true),
            "No models yet",
            "Add a provider in the policy editor, then add its models here.",
            &add,
        )
    } else {
        format!(
            r#"<div class="g-panel g-stack"><div class="g-table-wrap"><table class="g-table g-table--stack g-table--prose t-mono-sm">
<thead class="t-tag"><tr><th>Model</th><th>USD per 1M tokens, in / out</th><th>Aliases</th><th>Change</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<p class="t-small g-muted" style="margin: 0">A price set in the policy is used over the built-in one. A form edit saves the policy without its comments: the editor keeps them.</p></div>"#
        )
    };
    let overlay = if editable {
        model_dialog(query, &loaded, live.as_ref(), error)
    } else {
        String::new()
    };
    let main = format!("{}\n{banner}\n{table}", head(title, lead, &add));
    tool_page(title, &admin.label(), here, query, &main, &overlay)
}

fn number_field(id: &str, name: &str, label: &str, value: &str, hint: &str) -> String {
    field(&Field {
        id,
        name,
        label,
        value,
        mono: true,
        extra: r#" type="number" min="0" step="any" inputmode="decimal" required aria-required="true""#,
        hint,
        error: "",
    })
}

fn model_dialog(
    query: &Form,
    loaded: &Loaded,
    live: Option<&PolicyVersion>,
    error: &str,
) -> String {
    let cancel = close_link("Cancel", "quiet", "/console/models");
    let error = if error.is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="g-field__error t-small" role="alert" style="margin: 0">{}</p>"#,
            esc(error)
        )
    };
    let base = base_field(live);
    if query.get("add") == "1" {
        let options: String = loaded
            .providers
            .iter()
            .map(|p| {
                let selected = if query.get("provider") == p.name {
                    " selected"
                } else {
                    ""
                };
                format!(
                    r#"<option value="{0}"{selected}>{0}</option>"#,
                    esc(&p.name)
                )
            })
            .collect();
        let fields = format!(
            r#"<div class="g-field"><label class="g-field__label t-tag g-caps" for="model-provider">Provider</label><div class="g-select-wrap"><select class="g-input g-select t-body" id="model-provider" name="provider">{options}</select>{}</div></div>"#,
            icon("down")
        ) + &field(&Field {
            id: "model-name",
            name: "model",
            label: "Model",
            value: query.get("model"),
            mono: true,
            extra: r#" required aria-required="true" autocomplete="off" autofocus placeholder="gpt-4o-mini""#,
            hint: "The name callers send, as the provider knows it.",
            error: "",
        }) + &number_field(
            "model-input",
            "input",
            "Input, USD per 1M tokens",
            query.get("input"),
            "",
        ) + &number_field(
            "model-output",
            "output",
            "Output, USD per 1M tokens",
            query.get("output"),
            "",
        ) + &field(&Field {
            id: "model-aliases",
            name: "aliases",
            label: "Aliases, optional",
            value: query.get("aliases"),
            mono: true,
            extra: r#" autocomplete="off" placeholder="fast, default""#,
            hint: "Other names callers may send for this model, separated by commas.",
            error: "",
        });
        return dialog(
            "add-model-title",
            "Add a model",
            "Saved as a new policy version. It is checked as gantry check checks a file and every gateway serves it within 2 seconds, or after a second admin approves it.",
            &format!(
                r#"<form class="g-stack" style="gap: var(--space-6)" method="post" action="/console/models/add">{base}{fields}{error}<div class="g-dialog__actions">{cancel}{}</div></form>"#,
                button("Save version", "", "submit", "")
            ),
        );
    }
    let model = query.get("price");
    if model.is_empty() {
        return String::new();
    }
    let price = loaded
        .policy
        .prices()
        .get(model)
        .cloned()
        .or_else(|| usage::price_for(model, loaded.policy.prices()));
    let (input, output) = price.map_or((String::new(), String::new()), |p| {
        (p.input.to_string(), p.output.to_string())
    });
    dialog(
        "price-title",
        "Change the price",
        &format!(
            "What <span class=\"t-mono\">{}</span> costs, for budgets and the spend page. Saved as a new policy version.",
            esc(model)
        ),
        &format!(
            r#"<form class="g-stack" style="gap: var(--space-6)" method="post" action="/console/models/price">{base}<input type="hidden" name="model" value="{}">{}{}{error}<div class="g-dialog__actions">{cancel}{}</div></form>"#,
            esc(model),
            number_field(
                "price-input",
                "input",
                "Input, USD per 1M tokens",
                &input,
                ""
            ),
            number_field(
                "price-output",
                "output",
                "Output, USD per 1M tokens",
                &output,
                ""
            ),
            button("Save version", "", "submit", "")
        ),
    )
}

async fn models_change(
    State(console): State<Console>,
    Path(action): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    let (act, back): (&'static str, String) = match action.as_str() {
        "add" => ("add_model", format!("add=1&{body}")),
        "price" => ("price_model", format!("price={}", enc(form.get("model")))),
        _ => return redirect("/console/models"),
    };
    let refuse = |error: String| {
        page(
            StatusCode::BAD_REQUEST,
            models_body(&console, &admin, &Form::parse(&back), &error),
        )
    };
    if !edits_policy(&admin) {
        read_only(&console, &admin, act).await;
        return refuse("You are signed in read only: ask an admin to change models.".into());
    }
    let Some(live) = live(&console) else {
        return refuse(sentence(&versions::read_only_message(
            &console.config().policy,
        )));
    };
    let price = |input: &str, output: &str| -> Result<(f64, f64), String> {
        match (input.trim().parse::<f64>(), output.trim().parse::<f64>()) {
            (Ok(i), Ok(o)) if i.is_finite() && o.is_finite() && i >= 0.0 && o >= 0.0 => Ok((i, o)),
            _ => Err("A price is a number of US dollars per million tokens, 0 or more, for example 0.15 and 0.60.".into()),
        }
    };
    let model = form.get("model").trim().to_string();
    let edited = price(form.get("input"), form.get("output")).and_then(|p| {
        if !config::valid_name(&model) {
            return Err("A model name uses letters, digits, '.', '-', '_' and '@', for example gpt-4o-mini.".into());
        }
        if act == "add_model" {
            let aliases: Vec<String> = form
                .get("aliases")
                .split(',')
                .map(|a| a.trim().to_string())
                .filter(|a| !a.is_empty())
                .collect();
            if let Some(bad) = aliases.iter().find(|a| !config::valid_name(a)) {
                return Err(format!("The alias \"{bad}\" uses a character a model name cannot. Use letters, digits, '.', '-', '_' and '@'."));
            }
            versions::add_model(&live.text, form.get("provider"), &model, Some(p), &aliases).map_err(|e| sentence(&e))
        } else {
            versions::set_price(&live.text, &model, p).map_err(|e| sentence(&e))
        }
    });
    let text = match edited {
        Ok(text) => text,
        Err(error) => {
            let _ = record(
                &console,
                &Act {
                    action: act,
                    by: Some((&admin.name, &admin.team)),
                    key: None,
                    target: json!({ "model": model }),
                },
                Some("invalid_request"),
                None,
            )
            .await;
            return refuse(error);
        }
    };
    let note = if act == "add_model" {
        format!("Add model {model} to provider {}", form.get("provider"))
    } else {
        format!("Change the price of {model}")
    };
    match save_version(&console, &admin, act, text, base_of(&form), note).await {
        Ok(v) => saved(&v),
        Err(err) => refuse(sentence(&err.message())),
    }
}

// ---------------------------------------------------------------- teams

async fn teams_page(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let query = Form::of(&uri);
    let title = "Teams";
    let here = "/console/teams";
    let lead = "Each key names a person or a workload and its team. Admin keys may sign in to this console and use the admin API; members send requests. A binary with a members feature adds its own roles on its pages.";
    let c = console.config();
    let loaded = match config::load(&c.policy, Some(&c.keys)) {
        Ok(loaded) => loaded,
        Err(problems) => {
            let failed = empty(
                &motif(&["", "flame"], &["empty"], (2, 1), true, true),
                "The policy did not load",
                &esc(&problems.join(" ")),
                "",
            );
            return page(
                StatusCode::OK,
                tool_page(
                    title,
                    &admin.label(),
                    here,
                    &query,
                    &format!("{}\n{failed}", head(title, lead, "")),
                    "",
                ),
            );
        }
    };
    let mut teams: std::collections::BTreeMap<&str, Vec<(&str, bool)>> =
        std::collections::BTreeMap::new();
    for (_, who) in loaded
        .policy
        .entries()
        .filter(|(_, w)| admin.covers(&w.org, &w.team, w.customer.as_deref()))
    {
        teams
            .entry(who.team.as_str())
            .or_default()
            .push((who.name.as_str(), who.admin));
    }
    // Teams the policy lists show even before their first key, to those who see every team or this one.
    for team in loaded.policy.teams() {
        if !admin.confined() || admin.teams.contains(&team.name) {
            teams.entry(team.name.as_str()).or_default();
        }
    }
    let mut rows = String::new();
    for (team, people) in &mut teams {
        people.sort_unstable();
        people.dedup();
        let names: Vec<String> = people
            .iter()
            .map(|(name, admin)| {
                format!(
                    "{} {}",
                    esc(name),
                    tag(
                        if *admin { "product" } else { "" },
                        if *admin { "Admin" } else { "Member" },
                        ""
                    )
                )
            })
            .collect();
        // The rule that decides for the team's members, as the policy reads it: the first that names the team or
        // everyone. A rule naming one person may come before it for that person.
        let probe = gantry_core::policy::Principal {
            team: (*team).to_string(),
            ..Default::default()
        };
        let rule = loaded.policy.rule_for(&probe);
        let budget = rule.and_then(|r| r.limits.budget()).map_or_else(
            || "none".to_string(),
            |b| format!("${} a {}", money(b.usd), b.per.describe()),
        );
        let rule = rule.map_or_else(
            || "none: refused".to_string(),
            |r| match &r.who {
                Who::Team(_) => esc(&r.name),
                _ => format!("{} (everyone)", esc(&r.name)),
            },
        );
        let listed = loaded.policy.teams().iter().find(|t| t.name == *team);
        let owner = listed
            .and_then(|t| t.owner.as_deref())
            .map(|o| format!(", owner {}", esc(o)))
            .unwrap_or_default();
        let _ = write!(
            rows,
            r#"<tr><td>{}<span class="g-table__sub">{}{owner}</span></td><td class="g-table__wide">{}</td><td>{rule}</td><td class="g-table__num">{budget}</td></tr>"#,
            esc(team),
            gantry_core::count(people.len(), "key"),
            names.join("<br>"),
        );
    }
    let actions = if !admin.may(Permission::IssueKeys) {
        String::new()
    } else {
        link("Issue a key", "", "/console/people?issue=1", false)
    };
    let table = if rows.is_empty() {
        crate::empty_page("Teams", &crate::base(), admin.may(Permission::IssueKeys))
    } else {
        format!(
            r#"<div class="g-panel g-stack"><div class="g-table-wrap"><table class="g-table g-table--stack g-table--prose t-mono-sm">
<thead class="t-tag"><tr><th>Team</th><th>People and workloads</th><th>Rule</th><th>Budget</th></tr></thead>
<tbody>{rows}</tbody></table></div></div>"#
        )
    };
    let main = format!("{}\n{table}", head(title, lead, &actions));
    page(
        StatusCode::OK,
        tool_page(title, &admin.label(), here, &query, &main, ""),
    )
}

// ---------------------------------------------------------------- permissions

/// Whether the person may change the policy: `edit_policy`, and not kept to one organization, since the policy
/// governs every one.
pub(crate) fn edits_policy(admin: &Admin) -> bool {
    admin.may(Permission::EditPolicy) && !admin.confined()
}

/// Whether the person may change this key: `issue_keys`, in the key's organization when kept to one.
fn edits_key(admin: &Admin, entry: &config::KeyEntry) -> bool {
    admin.may(Permission::IssueKeys) && admin.covers_entry(entry)
}

/// Whether the person holds every right an admin key gives, so may make one or change one.
fn full_admin(admin: &Admin) -> bool {
    !admin.confined() && Permission::ALL.iter().all(|p| admin.may(*p))
}

// ---------------------------------------------------------------- key fields

fn entry_of(console: &Console, sha256: &str) -> Option<config::KeyEntry> {
    let keys = &console.config().keys;
    let text = store::attached(keys)
        .map(|s| s.keys_text())
        .or_else(|| config::read_keys(keys).ok().flatten())?;
    config::key_entries(keys, &text)
        .ok()?
        .into_iter()
        .find(|e| e.sha256 == sha256)
}

async fn key_page(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let query = Form::of(&uri);
    match entry_of(&console, query.get("sha256")) {
        Some(entry) if edits_key(&admin, &entry) => {
            page(StatusCode::OK, key_body(&admin, &query, &entry, None, ""))
        }
        _ => redirect("/console/people"),
    }
}

/// The form of a key's fields. `typed` is what a refused form sent, to show it again as it was.
fn key_body(
    admin: &Admin,
    query: &Form,
    entry: &config::KeyEntry,
    typed: Option<&Form>,
    error: &str,
) -> String {
    let title = "People and workloads";
    let value = |name: &str, now: String| typed.map_or(now, |f| f.get(name).to_string());
    let (budget, per) = entry
        .budget
        .map_or((String::new(), "month".to_string()), |b| {
            (b.usd.to_string(), b.per.word())
        });
    let per = value("per", per);
    // A period the policy reads but this form does not offer (a week, 6h, a time zone) is kept as its own choice.
    let other = if per == "day" || per == "month" {
        String::new()
    } else {
        format!(
            r#"<option value="{}" selected>a {}</option>"#,
            esc(&per),
            esc(&Period::from_word(&per).map_or_else(|| per.clone(), |p| p.describe()))
        )
    };
    let admin_box = typed.map_or(entry.admin, |f| f.get("admin") == "1");
    let fields = field(&Field {
        id: "key-expires",
        name: "expires",
        label: "Expires, optional",
        value: &value("expires", entry.expires.clone().unwrap_or_default()),
        mono: true,
        extra: "",
        hint: "UTC, for example 2026-12-31 or 2026-12-31T18:00:00Z. Empty never expires.",
        error: "",
    }) + &format!(
        r#"<div class="g-field"><label class="g-field__label t-tag g-caps" for="key-budget">Budget, USD, optional</label><div class="g-toolbar" style="flex-wrap: nowrap"><input class="g-input t-mono" style="flex: 1; min-width: 0" id="key-budget" name="budget" type="number" min="0" step="any" inputmode="decimal" value="{}"><div class="g-select-wrap"><select class="g-input g-select t-body" name="per" aria-label="Budget period"><option value="day"{}>a day</option><option value="month"{}>a month</option>{other}</select>{}</div></div><span class="g-field__hint t-small">Most the key may spend, on top of its rule's budget. Empty for none.</span></div>"#,
        esc(&value("budget", budget)),
        if per == "day" { " selected" } else { "" },
        if per == "month" { " selected" } else { "" },
        icon("down")
    ) + &field(&Field {
        id: "key-models",
        name: "models",
        label: "Models, optional",
        value: &value(
            "models",
            entry.models.clone().unwrap_or_default().join(", "),
        ),
        mono: true,
        extra: r#" autocomplete="off" placeholder="gpt-4o-mini, o3""#,
        hint: "Narrows the rule's models for this key, separated by commas. Empty uses the rule's.",
        error: "",
    }) + &field(&Field {
        id: "key-tpm",
        name: "tpm",
        label: "Tokens per minute, optional",
        value: &value("tpm", entry.tpm.map(|t| t.to_string()).unwrap_or_default()),
        mono: true,
        extra: r#" type="number" min="1" step="1" inputmode="numeric""#,
        hint: "On top of the rule's limit. Empty for none.",
        error: "",
    }) + &format!(
        r#"<label class="g-choice t-body"><input type="checkbox" name="admin" value="1"{}>Admin: may sign in to this console and use the admin API</label>"#,
        if admin_box { " checked" } else { "" }
    );
    let error = if error.is_empty() {
        String::new()
    } else {
        alert(&esc(error))
    };
    let main = format!(
        r#"{}
{error}
<div class="g-panel g-stack" style="max-width: 40rem">
{}
<form class="g-stack" style="gap: var(--space-6)" method="post" action="/console/people/edit"><input type="hidden" name="sha256" value="{}">{fields}<div class="g-dialog__actions">{}{}</div></form>
</div>"#,
        head(
            &format!("Edit the key of {}", esc(&entry.name)),
            "The key itself does not change and is never shown again: only what it may do. Every gateway uses the new fields within 2 seconds.",
            ""
        ),
        facts(&[
            ("Name", esc(&entry.name)),
            ("Team", esc(&entry.team)),
            ("Key hash", esc(&entry.sha256[..8])),
        ]),
        esc(&entry.sha256),
        link("Cancel", "quiet", "/console/people", false),
        button("Save", "", "submit", "")
    );
    tool_page(
        title,
        &admin.label(),
        "/console/people/edit",
        query,
        &main,
        "",
    )
}

async fn key_change(State(console): State<Console>, headers: HeaderMap, body: String) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    let Some(entry) = entry_of(&console, form.get("sha256")) else {
        return redirect("/console/people");
    };
    let refuse = |error: &str| {
        page(
            StatusCode::BAD_REQUEST,
            key_body(&admin, &Form(Vec::new()), &entry, Some(&form), error),
        )
    };
    if !edits_key(&admin, &entry) {
        read_only(&console, &admin, "edit_key").await;
        return refuse("You are signed in read only: ask an admin to change keys.");
    }
    let text = |name: &str| Some(form.get(name).trim().to_string()).filter(|v| !v.is_empty());
    let attributes = keyfile::Attributes {
        admin: form.get("admin") == "1",
        expires: text("expires"),
        // Text that is not a number becomes NaN, which the edit refuses with the budget's own message.
        budget: text("budget").map(|b| Budget {
            usd: b.parse().unwrap_or(f64::NAN),
            per: Period::from_word(form.get("per")).unwrap_or(Period::Month),
        }),
        models: text("models").map(|m| {
            m.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }),
        tpm: match text("tpm").map(|t| t.parse::<u32>()) {
            None => None,
            Some(Ok(t)) => Some(t),
            Some(Err(_)) => Some(0),
        },
        ..keyfile::Attributes::default()
    };
    // An admin key gives every right: only someone who holds them all may make one or change one.
    if (entry.admin || attributes.admin) && !full_admin(&admin) {
        read_only(&console, &admin, "edit_key").await;
        return refuse(
            "Only an admin of the whole install may change an admin key or make a key an admin.",
        );
    }
    let act = Act {
        action: "edit_key",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({
            "name": entry.name, "team": entry.team, "sha256_prefix": &entry.sha256[..8],
            "admin": attributes.admin, "expires": attributes.expires,
            "budget": attributes.budget.map(|b| json!({ "usd": b.usd, "per": b.per.word() })),
            "models": attributes.models, "tpm": attributes.tpm,
        }),
    };
    // The last admin key keeps its admin: nobody could sign in again.
    if entry.admin && !attributes.admin {
        let keys = &console.config().keys;
        let admins = store::attached(keys)
            .map(|s| s.keys_text())
            .or_else(|| config::read_keys(keys).ok().flatten())
            .and_then(|t| config::key_entries(keys, &t).ok())
            .map_or(0, |e| e.iter().filter(|e| e.admin).count());
        if admins <= 1 {
            let _ = record(&console, &act, Some("last_admin"), None).await;
            return refuse(
                "This is the only admin key. Make another key an admin first, so someone can still sign in.",
            );
        }
    }
    if record(&console, &act, None, None).await.is_err() {
        return refuse(NOT_RECORDED);
    }
    let (keys, sha256) = (console.config().keys.clone(), entry.sha256.clone());
    let done = tokio::task::spawn_blocking(move || keyfile::edit(&keys, &sha256, &attributes))
        .await
        .unwrap_or_else(|err| Err(format!("nothing was changed: {err}. Try again.")));
    let error = match done {
        Ok(Some(_)) => return redirect(&format!("/console/people?edited={}", enc(&entry.name))),
        Ok(None) => {
            "The key is no longer there: someone revoked it. Nothing was changed.".to_string()
        }
        Err(err) => sentence(&err),
    };
    let _ = record(&console, &act, Some("keys_file"), Some(&error)).await;
    refuse(&error)
}

// ---------------------------------------------------------------- versions

fn state_tag(state: &str) -> String {
    match state {
        store::LIVE => tag("allow", "Live", ""),
        store::PENDING => tag("warn", "Waiting for approval", ""),
        store::REJECTED => tag("refused", "Rejected", ""),
        _ => tag("", "Earlier", ""),
    }
}

async fn versions_page(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    page(
        StatusCode::OK,
        versions_body(&console, &admin, &Form::of(&uri), ""),
    )
}

fn versions_body(console: &Console, admin: &Admin, query: &Form, error: &str) -> String {
    let title = "Policy";
    let here = "/console/policy/versions";
    let lead = "Each save of the policy is a version. The live one decides every request; an earlier one can be put back in one click, as a new version.";
    let path = &console.config().policy;
    let store = match versions::store_for(path) {
        Ok(store) => store,
        Err(err) => {
            let off = empty(
                &motif(&["", "flame"], &["empty"], (2, 1), true, true),
                "The policy is kept in the file",
                &esc(&sentence(&err.message())),
                &link("Open the policy", "", "/console/policy", false),
            );
            return tool_page(
                title,
                &admin.label(),
                here,
                query,
                &format!("{}\n{off}", head("Policy versions", lead, "")),
                "",
            );
        }
    };
    let all = store.policy_versions().unwrap_or_default();
    let selected: Option<i64> = query.get("version").parse().ok();
    let mut rows = String::new();
    for v in all.iter() {
        let decided = match (&v.decided_by, &v.decided_at) {
            (Some(by), Some(at)) => format!("{} by {}", long_time(at), esc(by)),
            _ => String::new(),
        };
        let _ = write!(
            rows,
            r#"<tr><td><a href="{here}?version={0}">Version {0}</a></td><td>{1}</td><td class="g-table__wide">{2}<span class="g-table__sub">{3}</span></td><td class="g-table__wide">{4}</td><td class="g-table__wide">{decided}</td></tr>"#,
            v.id,
            state_tag(&v.state),
            esc(&v.created_by),
            long_time(&v.created_at),
            esc(&v.note),
        );
    }
    let detail = selected
        .and_then(|id| all.iter().find(|v| v.id == id))
        .map(|v| version_detail(&store, admin, v))
        .unwrap_or_default();
    let done = match query.get("done") {
        "live" => toast("The version is live. Every gateway uses it within 2 seconds."),
        "pending" => toast("The version is saved and waits for a second admin to approve it."),
        "rejected" => toast("The version is rejected. The live version stays in force."),
        _ => String::new(),
    };
    let error = if error.is_empty() {
        String::new()
    } else {
        alert(&error.replace('\n', "<br>"))
    };
    let actions = if !edits_policy(admin) {
        link("Export YAML", "quiet", "/console/policy/export", false)
    } else {
        link("Edit the policy", "", "/console/policy/edit", false)
            + &link("Export YAML", "quiet", "/console/policy/export", false)
    };
    let main = format!(
        r#"{}
{error}
{detail}
<div class="g-panel g-stack"><div class="g-table-wrap"><table class="g-table g-table--stack g-table--prose t-mono-sm">
<thead class="t-tag"><tr><th>Version</th><th>State</th><th>Saved</th><th>Note</th><th>Approved or rejected</th></tr></thead>
<tbody>{rows}</tbody></table></div></div>"#,
        head("Policy versions", lead, &actions)
    );
    tool_page(title, &admin.label(), here, query, &main, &done)
}

fn version_detail(
    store: &std::sync::Arc<dyn store::Store>,
    admin: &Admin,
    v: &PolicyVersion,
) -> String {
    let base = versions::base_text(store, v);
    let lines = pages::diff(&base, &v.text);
    let diff = if lines.is_empty() {
        r#"<p class="t-small g-muted" style="margin: 0">The same text as the version it was drafted on.</p>"#.to_string()
    } else {
        code(&lines)
    };
    let form = |action: &str, label: &str, kind: &str| {
        format!(
            r#"<form method="post" action="/console/policy/versions/{}/{action}" style="margin: 0">{}</form>"#,
            v.id,
            button(label, kind, "submit", "")
        )
    };
    let mut actions = String::new();
    if edits_policy(admin) {
        if v.state == store::PENDING {
            if v.created_by != admin.name {
                actions.push_str(&form("approve", "Approve and put live", ""));
            }
            actions.push_str(&form("reject", "Reject", "quiet"));
        } else if v.state != store::LIVE {
            actions.push_str(&form("rollback", "Roll back to this version", "flame"));
        }
        actions.push_str(&format!(
            r#"<form method="post" action="/console/policy/dry-run" style="margin: 0"><input type="hidden" name="text" value="{}"><input type="hidden" name="hours" value="24">{}</form>"#,
            esc(&v.text),
            button("Dry run, last 24 hours", "quiet", "submit", "")
        ));
    }
    let own = if v.state == store::PENDING && v.created_by == admin.name {
        r#"<p class="t-small g-muted" style="margin: 0">You saved this version, so another admin approves it.</p>"#
    } else {
        ""
    };
    format!(
        r#"<div class="g-panel g-stack"><div class="g-pager"><h2 class="t-md" style="margin: 0">Version {}</h2>{}</div>
{}
<h3 class="t-tag g-caps" style="margin: 0">Changes from {}</h3>
{diff}
{own}
<div class="g-head__actions">{actions}</div></div>"#,
        v.id,
        state_tag(&v.state),
        facts(&[
            ("Saved by", esc(&v.created_by)),
            ("Saved at", long_time(&v.created_at)),
            ("Note", esc(&v.note)),
            ("SHA-256", esc(&v.sha256[..16])),
        ]),
        v.base.map_or_else(
            || "nothing: the first version".to_string(),
            |b| format!("version {b}")
        ),
    )
}

async fn version_action(
    State(console): State<Console>,
    Path((id, action)): Path<(i64, String)>,
    headers: HeaderMap,
) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let act_name: &'static str = match action.as_str() {
        "approve" => "approve_policy",
        "reject" => "reject_policy",
        "rollback" => "rollback_policy",
        _ => return redirect("/console/policy/versions"),
    };
    let back = Form::parse(&format!("version={id}"));
    if !edits_policy(&admin) {
        read_only(&console, &admin, act_name).await;
        return page(
            StatusCode::BAD_REQUEST,
            versions_body(
                &console,
                &admin,
                &back,
                "You are signed in read only: ask an admin.",
            ),
        );
    }
    let act = Act {
        action: act_name,
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "version": id }),
    };
    let done = run(
        &console,
        &act,
        move |policy, keys, by| match act_name {
            "rollback_policy" => versions::rollback(&policy, &keys, id, &by),
            name => versions::decide(&policy, &keys, id, name == "approve_policy", &by),
        },
        &admin.name,
    )
    .await;
    match done {
        Ok(v) => saved(&v),
        Err(err) => {
            let status = match err {
                Refused::Forbidden(_) => StatusCode::FORBIDDEN,
                Refused::Conflict(_) => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            };
            page(
                status,
                versions_body(&console, &admin, &back, &esc(&sentence(&err.message()))),
            )
        }
    }
}

// ---------------------------------------------------------------- the editor and the dry run

async fn editor_page(State(console): State<Console>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let Some(live) = live(&console) else {
        return redirect("/console/policy/versions");
    };
    if !edits_policy(&admin) {
        return redirect("/console/policy");
    }
    let query = Form::of(&uri);
    // A Start here step opens the editor with its lines already in: a draft, saved only as any edit is.
    let (text, note) = match crate::start::change(query.get("add")) {
        Some(change) => (
            crate::start::apply(&live.text, &change).0,
            "Added from Start here",
        ),
        None => (live.text.clone(), ""),
    };
    page(
        StatusCode::OK,
        editor_body(
            &console,
            &admin,
            &query,
            &text,
            Some(live.id),
            note,
            "",
            None,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn editor_body(
    console: &Console,
    admin: &Admin,
    query: &Form,
    text: &str,
    base: Option<i64>,
    note: &str,
    error: &str,
    run: Option<&DryRun>,
) -> String {
    let approval = config::load(&console.config().policy, Some(&console.config().keys))
        .is_ok_and(|l| versions::approval_needed(&l));
    let lead = if approval {
        "Edit the YAML, or load a file to import it. A save is checked as gantry check checks a file, then waits for a second admin to approve it."
    } else {
        "Edit the YAML, or load a file to import it. A save is checked as gantry check checks a file, then every gateway uses it within 2 seconds."
    };
    let report = run.map(dry_run_report).unwrap_or_default();
    let main = format!(
        r#"{}
{error}
{report}
<form class="g-panel g-stack" method="post" action="/console/policy/save">
<input type="hidden" name="base" value="{}">
<div class="g-field"><label class="g-field__label t-tag g-caps" for="policy-file">Import a YAML file, optional</label><input class="g-input t-body" id="policy-file" type="file" accept=".yaml,.yml,text/yaml" data-load-into="policy-text"><span class="g-field__hint t-small">Its text replaces the editor's. Nothing is saved until you save.</span></div>
<div class="g-field"><label class="g-field__label t-tag g-caps" for="policy-text">Policy</label><textarea class="g-input g-textarea t-mono" id="policy-text" name="text" rows="28" spellcheck="false" autocomplete="off">{}</textarea></div>
{}
<div class="g-field"><label class="g-field__label t-tag g-caps" for="dry-hours">Dry run over the last hours</label><input class="g-input t-mono" id="dry-hours" name="hours" type="number" min="1" max="720" value="{}" style="max-width: 10rem"></div>
<div class="g-dialog__actions">{}{}{}</div>
</form>"#,
        head("Edit the policy", lead, ""),
        base.map_or_else(|| "none".to_string(), |b| b.to_string()),
        esc(text),
        field(&Field {
            id: "policy-note",
            name: "note",
            label: "What changed, for the history",
            value: note,
            mono: false,
            extra: r#" autocomplete="off" maxlength="500""#,
            hint: "",
            error: "",
        }),
        query
            .get("hours")
            .parse::<u64>()
            .unwrap_or(24)
            .clamp(1, 720),
        link("Cancel", "quiet", "/console/policy", false),
        button(
            "Dry run",
            "quiet",
            "submit",
            r#" formaction="/console/policy/dry-run""#
        ),
        button(
            if approval {
                "Save for approval"
            } else {
                "Save version"
            },
            "",
            "submit",
            ""
        )
    );
    tool_page(
        "Policy",
        &admin.label(),
        "/console/policy/edit",
        query,
        &main,
        "",
    )
}

fn dry_run_report(run: &DryRun) -> String {
    let table = |title: &str, list: &[versions::Replayed]| {
        if list.is_empty() {
            return format!(r#"<p class="t-small g-muted" style="margin: 0">{title}: none.</p>"#);
        }
        let rows: String = list
            .iter()
            .take(200)
            .map(|r| {
                format!(
                    "<tr><td>{}</td><td>{}<span class=\"g-table__sub\">{}</span></td><td>{}</td><td>{} to {}</td><td class=\"g-table__wide\">{} to {}</td></tr>",
                    long_time(&r.time),
                    esc(&r.person),
                    esc(&r.team),
                    esc(&r.model),
                    esc(&r.was),
                    esc(&r.now),
                    esc(if r.rule_was.is_empty() { "none" } else { &r.rule_was }),
                    esc(if r.rule_now.is_empty() { "none" } else { &r.rule_now }),
                )
            })
            .collect();
        format!(
            r#"<h3 class="t-tag g-caps" style="margin: 0">{title}: {}</h3><div class="g-table-wrap"><table class="g-table g-table--stack g-table--prose t-mono-sm"><thead class="t-tag"><tr><th>Time</th><th>Who</th><th>Model</th><th>Decision</th><th>Rule</th></tr></thead><tbody>{rows}</tbody></table></div>"#,
            list.len()
        )
    };
    let changed = run.now_refused.len() + run.now_allowed.len() + run.other_rule.len();
    format!(
        r#"<div class="g-panel g-stack"><div class="g-pager"><h2 class="t-md" style="margin: 0">Dry run</h2>{}</div>
<p class="t-body" style="margin: 0">{} replayed since {}, {} changed. {} refused before the policy decided (a key, a budget, a guardrail, a kill switch) and not replayed.</p>
<p class="t-small g-muted" style="margin: 0">{}</p>
{}{}{}</div>"#,
        if changed == 0 {
            tag("allow", "No change", "")
        } else {
            tag("warn", "Changes", "")
        },
        gantry_core::count(run.replayed, "request"),
        long_time(&run.since),
        changed,
        gantry_core::count(run.skipped, "request"),
        esc(&run.note),
        table("Now refused", &run.now_refused),
        table("Now allowed", &run.now_allowed),
        table("Allowed by another rule", &run.other_rule),
    )
}

async fn save(State(console): State<Console>, headers: HeaderMap, body: String) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    // A browser sends a textarea's line breaks as CRLF.
    let text = form.get("text").replace("\r\n", "\n");
    let (base, note) = (base_of(&form), form.get("note").trim().to_string());
    let back = |err: &Refused| {
        page(
            StatusCode::BAD_REQUEST,
            editor_body(
                &console,
                &admin,
                &form,
                &text,
                base,
                &note,
                &problems(err),
                None,
            ),
        )
    };
    if !edits_policy(&admin) {
        read_only(&console, &admin, "propose_policy").await;
        return back(&Refused::Forbidden(
            "you are signed in read only: ask an admin to change the policy.".into(),
        ));
    }
    match save_version(
        &console,
        &admin,
        "propose_policy",
        text.clone(),
        base,
        note.clone(),
    )
    .await
    {
        Ok(v) => saved(&v),
        Err(err) => back(&err),
    }
}

async fn dry_run(State(console): State<Console>, headers: HeaderMap, body: String) -> Response {
    if !same_origin(&headers) {
        return foreign();
    }
    let Some(admin) = console.admin(&headers).await else {
        return redirect("/console/sign-in");
    };
    let form = Form::parse(&body);
    let text = form.get("text").replace("\r\n", "\n");
    let base = base_of(&form).or_else(|| live(&console).map(|v| v.id));
    let note = form.get("note").trim().to_string();
    let hours = form.get("hours").parse::<u64>().unwrap_or(24).clamp(1, 720);
    let act = Act {
        action: "dry_run_policy",
        by: Some((&admin.name, &admin.team)),
        key: None,
        target: json!({ "hours": hours, "sha256": gantry_core::id::sha256_hex(text.as_bytes()) }),
    };
    if record(&console, &act, None, None).await.is_err() {
        return page(
            StatusCode::SERVICE_UNAVAILABLE,
            editor_body(
                &console,
                &admin,
                &form,
                &text,
                base,
                &note,
                &alert(NOT_RECORDED),
                None,
            ),
        );
    }
    let c = console.config();
    let (policy, keys, draft) = (c.policy.clone(), c.keys.clone(), text.clone());
    let stopped = |err: tokio::task::JoinError| {
        Refused::Store(format!("the dry run stopped: {err}. Try again."))
    };
    let checked = tokio::task::spawn_blocking(move || {
        let loaded = config::load(&policy, Some(&keys)).map_err(Refused::Invalid)?;
        let checked = versions::check(&policy, &keys, &draft, &loaded).map_err(Refused::Invalid)?;
        Ok((loaded, checked))
    })
    .await
    .unwrap_or_else(|err| Err(stopped(err)));
    // With a store every gateway's requests are in its index; without, only this gateway's log has them.
    let run = match checked {
        Err(err) => Err(err),
        Ok((loaded, checked)) => match gantry_core::insights::attached(&loaded.audit_path).index {
            Some(index) => match versions::shared_lines(index.as_ref(), hours).await {
                Err(err) => Err(Refused::Store(err)),
                Ok(lines) => tokio::task::spawn_blocking(move || {
                    versions::dry_run_shared(
                        lines,
                        &loaded.audit_path,
                        hours,
                        &checked,
                        &loaded.policy,
                    )
                    .map_err(Refused::Store)
                })
                .await
                .unwrap_or_else(|err| Err(stopped(err))),
            },
            None => tokio::task::spawn_blocking(move || {
                versions::dry_run_log(&loaded.audit_path, hours, &checked, &loaded.policy)
                    .map_err(Refused::Store)
            })
            .await
            .unwrap_or_else(|err| Err(stopped(err))),
        },
    };
    match run {
        Ok(run) => page(
            StatusCode::OK,
            editor_body(&console, &admin, &form, &text, base, &note, "", Some(&run)),
        ),
        Err(err) => page(
            StatusCode::BAD_REQUEST,
            editor_body(
                &console,
                &admin,
                &form,
                &text,
                base,
                &note,
                &problems(&err),
                None,
            ),
        ),
    }
}

async fn export(State(console): State<Console>, headers: HeaderMap) -> Response {
    if console.admin(&headers).await.is_none() {
        return redirect("/console/sign-in");
    }
    match config::policy_text(&console.config().policy) {
        Ok(text) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/yaml; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"gantry.policy.yaml\"",
                ),
                (header::CACHE_CONTROL, "no-store"),
            ],
            text,
        )
            .into_response(),
        Err(err) => page(
            StatusCode::SERVICE_UNAVAILABLE,
            pages::notice(
                "The policy could not be read",
                &esc(&err),
                "/console/policy",
                "Open the policy",
            ),
        ),
    }
}
