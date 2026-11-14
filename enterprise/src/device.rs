//! Device agent (plan 6.4, levels 1 and 2). Every interval it reads the org's device profile from the control plane,
//! points the installed coding tools of the signed-in OS user at the gateway, puts them back when someone changes
//! them (drift), and reports each tool's state for the coverage report.

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct Options {
    pub control_plane: String,
    pub token: String,
    pub interval: Duration,
    pub dry_run: bool,
    pub once: bool,
    /// Set by `--home` (tests): only that folder is inspected and written, never system paths.
    pub home: Option<PathBuf>,
}

/// Where each managed file lives for one user.
struct Paths {
    home: PathBuf,
    claude_settings: PathBuf,
    /// The agent runs as root under the LaunchDaemon: files it writes in the user's home go back to the user.
    owner: Option<(u32, u32)>,
    system: bool,
}

const MANAGED_SETTINGS: &str = "/Library/Application Support/ClaudeCode/managed-settings.json";

fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn paths(home: Option<&Path>) -> Result<Paths, String> {
    if let Some(home) = home {
        return Ok(Paths {
            home: home.to_path_buf(),
            claude_settings: home.join(".claude/settings.json"),
            owner: None,
            system: false,
        });
    }
    if is_root() {
        // The person at the screen owns /dev/console on macOS.
        use std::os::unix::fs::MetadataExt;
        let out = std::process::Command::new("stat")
            .args(["-f", "%Su", "/dev/console"])
            .output()
            .map_err(|e| format!("stat /dev/console: {e}"))?;
        let user = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if user.is_empty() || user == "root" {
            return Err("no one is signed in at the screen; trying again next interval.".into());
        }
        let home = PathBuf::from("/Users").join(&user);
        let meta = std::fs::metadata(&home).map_err(|e| format!("{}: {e}", home.display()))?;
        return Ok(Paths {
            home,
            claude_settings: PathBuf::from(MANAGED_SETTINGS),
            owner: Some((meta.uid(), meta.gid())),
            system: true,
        });
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set. Set it or pass --home.")?;
    Ok(Paths {
        claude_settings: home.join(".claude/settings.json"),
        home,
        owner: None,
        system: true,
    })
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

/// Every tool the agent looks for, by the name the coverage report gives it (`gantry_core::audit::tool_of`).
pub const TOOLS: [&str; 11] = [
    "claude-code",
    "codex",
    "cursor",
    "github-copilot",
    "zed",
    "jetbrains-ai",
    "qwen-code",
    "gemini-cli",
    "kilo-code",
    "roo-code",
    "claude-desktop",
];

/// The tools the agent can point at the gateway itself; the others it only inspects.
pub const MANAGEABLE: [&str; 2] = ["claude-code", "codex"];

/// Whether `dir` holds an entry whose name starts with `prefix`: VS Code keeps extensions as `<id>-<version>`.
fn has_entry(dir: &Path, prefix: &str) -> bool {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with(prefix))
        })
        .unwrap_or(false)
}

/// Which tools are installed. With `--home` only that folder counts, so tests do not depend on the machine.
fn installed(p: &Paths, tool: &str) -> bool {
    let h = &p.home;
    let app = |name: &str| {
        Path::new("/Applications").join(name).exists() && p.system
            || h.join("Applications").join(name).exists()
    };
    let bin = |name: &str| p.system && on_path(name);
    let extension = |id: &str| has_entry(&h.join(".vscode/extensions"), id);
    match tool {
        "claude-code" => {
            h.join(".claude").is_dir() || h.join(".local/bin/claude").exists() || bin("claude")
        }
        "codex" => h.join(".codex").is_dir() || bin("codex"),
        "cursor" => h.join(".cursor").is_dir() || app("Cursor.app"),
        "github-copilot" => extension("github.copilot") || h.join(".copilot").is_dir(),
        "zed" => h.join(".config/zed").is_dir() || app("Zed.app"),
        "jetbrains-ai" => {
            h.join("Library/Application Support/JetBrains").is_dir()
                || h.join(".config/JetBrains").is_dir()
        }
        "qwen-code" => h.join(".qwen").is_dir() || bin("qwen"),
        "gemini-cli" => h.join(".gemini").is_dir() || bin("gemini"),
        "kilo-code" => h.join(".config/kilo").is_dir() || extension("kilocode.kilo-code"),
        "roo-code" => extension("rooveterinaryinc.roo-cline"),
        "claude-desktop" => {
            app("Claude.app") || h.join("Library/Application Support/Claude").is_dir()
        }
        _ => false,
    }
}

// ---- Where each tool sends. Read from the files and settings each tool documents, nothing else. ----

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Every string value of `"key": "value"` in a JSON or JSON-with-comments file (VS Code's and Zed's settings allow
/// comments, which a JSON parser refuses).
// ponytail: a scan, not a parser; a key named inside a string value would count too. A JSONC parser if that bites.
fn string_values(text: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(&needle) {
        rest = &rest[at + needle.len()..];
        let Some(after) = rest.trim_start().strip_prefix(':') else {
            continue;
        };
        let Some(value) = after.trim_start().strip_prefix('"') else {
            continue;
        };
        if let Some(end) = value.find('"') {
            out.push(value[..end].to_string());
        }
    }
    out
}

/// A value of an XML property list: `<key>name</key><string>value</string>`.
fn plist_value(text: &str, key: &str) -> Option<String> {
    let after = text.split(&format!("<key>{key}</key>")).nth(1)?;
    let value = after.trim_start().strip_prefix("<string>")?;
    Some(value.split("</string>").next()?.trim().to_string())
}

/// A property list as XML text. Profiles an MDM installs are often binary; `plutil` (macOS) turns them into XML.
fn plist_text(path: &Path, system: bool) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    if !bytes.starts_with(b"bplist") {
        return String::from_utf8_lossy(&bytes).into_owned();
    }
    if !system {
        return String::new();
    }
    std::process::Command::new("plutil")
        .args(["-convert", "xml1", "-o", "-"])
        .arg(path)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// `NAME=value` from a dotenv file, with or without `export`.
fn dotenv(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let l = l.trim();
        let l = l.strip_prefix("export ").unwrap_or(l);
        let value = l.strip_prefix(name)?.strip_prefix('=')?;
        Some(
            value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string(),
        )
    })
}

/// Codex: the active `model_provider` (default `openai`) and its `[model_providers.<id>]` `base_url`; the built-in
/// OpenAI provider with a saved login (`auth.json`) goes to OpenAI.
fn codex_endpoints(config: &str, logged_in: bool) -> Vec<String> {
    let mut provider = "openai".to_string();
    let mut table = String::new();
    let mut urls: Vec<(String, String)> = Vec::new();
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            table = t.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        let v = v
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_string();
        match (table.as_str(), k.trim()) {
            ("", "model_provider") => provider = v,
            (t, "base_url") if t.starts_with("model_providers.") => {
                urls.push((t["model_providers.".len()..].to_string(), v));
            }
            _ => {}
        }
    }
    if let Some((_, url)) = urls.into_iter().find(|(id, _)| *id == provider) {
        return vec![url];
    }
    if provider == "openai" && logged_in {
        return vec!["https://api.openai.com/v1".into()];
    }
    Vec::new()
}

/// Where a tool's configuration sends its model requests: base URLs, or a provider's own address when only a
/// provider key or provider login is configured. Empty when the configuration names none, or keeps it where no
/// documented file holds it (Cursor, JetBrains AI Assistant, Roo Code keep theirs in the app's own storage).
fn endpoints(p: &Paths, tool: &str) -> Vec<String> {
    let h = &p.home;
    match tool {
        "claude-code" => {
            // Managed settings win over the user's, so the first file that names an endpoint decides.
            let mut files = vec![p.claude_settings.clone()];
            if p.claude_settings != h.join(".claude/settings.json") {
                files.push(h.join(".claude/settings.json"));
            }
            for file in files {
                let v: Value = serde_json::from_str(&read(&file)).unwrap_or(Value::Null);
                let env = &v["env"];
                let set = |name: &str| env[name].as_str().is_some_and(|s| !s.is_empty());
                if let Some(url) = env["ANTHROPIC_BASE_URL"].as_str().filter(|s| !s.is_empty()) {
                    return vec![url.to_string()];
                }
                if set("CLAUDE_CODE_USE_BEDROCK") {
                    return vec!["bedrock".into()];
                }
                if set("CLAUDE_CODE_USE_VERTEX") {
                    return vec!["vertex".into()];
                }
                if set("ANTHROPIC_API_KEY")
                    || set("ANTHROPIC_AUTH_TOKEN")
                    || v["apiKeyHelper"].is_string()
                {
                    return vec!["https://api.anthropic.com".into()];
                }
            }
            Vec::new()
        }
        "codex" => codex_endpoints(
            &read(&h.join(".codex/config.toml")),
            h.join(".codex/auth.json").exists(),
        ),
        "github-copilot" => {
            let mut out = Vec::new();
            for dir in ["Library/Application Support/Code/User", ".config/Code/User"] {
                out.extend(string_values(
                    &read(&h.join(dir).join("chatLanguageModels.json")),
                    "url",
                ));
            }
            out.extend(string_values(
                &read(&h.join(".copilot/providers.json")),
                "baseUrl",
            ));
            out
        }
        "zed" => string_values(&read(&h.join(".config/zed/settings.json")), "api_url"),
        "qwen-code" => string_values(&read(&h.join(".qwen/settings.json")), "baseUrl"),
        "gemini-cli" => {
            if let Some(url) = dotenv(&read(&h.join(".gemini/.env")), "GOOGLE_GEMINI_BASE_URL") {
                return vec![url];
            }
            match string_values(&read(&h.join(".gemini/settings.json")), "selectedType")
                .first()
                .map(String::as_str)
            {
                Some("vertex-ai") => vec!["vertex".into()],
                Some(_) => vec!["https://generativelanguage.googleapis.com".into()],
                None => Vec::new(),
            }
        }
        "kilo-code" => string_values(&read(&h.join(".config/kilo/kilo.json")), "baseURL"),
        "claude-desktop" => {
            const DOMAIN: &str = "com.anthropic.claudefordesktop.plist";
            let files = if p.system {
                let user = h
                    .file_name()
                    .map(|u| u.to_string_lossy().into_owned())
                    .unwrap_or_default();
                vec![
                    PathBuf::from("/Library/Managed Preferences")
                        .join(user)
                        .join(DOMAIN),
                    PathBuf::from("/Library/Managed Preferences").join(DOMAIN),
                ]
            } else {
                vec![h.join("Library/Managed Preferences").join(DOMAIN)]
            };
            for file in files {
                let text = plist_text(&file, p.system);
                if let Some(url) = plist_value(&text, "inferenceGatewayBaseUrl") {
                    return vec![url];
                }
                if let Some(provider) = plist_value(&text, "inferenceProvider") {
                    return vec![provider];
                }
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// The tool's state for the report, and the endpoints that are not the gateway.
fn classify(found: Vec<String>, gateway: &str) -> (&'static str, Vec<String>) {
    let gateway = gateway.trim_end_matches('/');
    let at_gateway = |url: &str| {
        url.strip_prefix(gateway)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    // A placeholder such as `${input:key}` or `{env:X}` is not an address.
    let found: Vec<String> = found.into_iter().filter(|e| !e.contains('{')).collect();
    if found.is_empty() {
        return ("installed", Vec::new());
    }
    let direct: Vec<String> = found.into_iter().filter(|e| !at_gateway(e)).collect();
    if direct.is_empty() {
        ("gantry", direct)
    } else {
        ("direct", direct)
    }
}

// ---- Desired file contents. Each takes the current text and returns the text it should be. ----

/// Claude Code settings with env.ANTHROPIC_BASE_URL set to the gateway, other keys kept.
fn claude_settings(current: &str, gateway: &str) -> Result<String, String> {
    let mut v: Value = if current.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(current).map_err(|e| format!("is not JSON ({e}); fix or delete it"))?
    };
    let obj = v.as_object_mut().ok_or("is not a JSON object")?;
    let env = obj.entry("env").or_insert_with(|| json!({}));
    if !env.is_object() {
        *env = json!({});
    }
    if let Some(env) = env.as_object_mut() {
        env.insert("ANTHROPIC_BASE_URL".into(), json!(gateway));
    }
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
    ))
}

/// Codex config.toml with `model_provider = "gantry"` and a `[model_providers.gantry]` table at the gateway.
/// ponytail: line-based TOML edit (no toml crate); it owns only those two places and keeps every other line.
fn codex_config(current: &str, gateway: &str) -> String {
    let section = format!(
        "[model_providers.gantry]\nname = \"Gantry\"\nbase_url = \"{gateway}/v1\"\nenv_key = \"GANTRY_KEY\"\nwire_api = \"responses\"\nstream_max_retries = 0\n"
    );
    let mut top = Vec::new();
    let mut rest = Vec::new();
    let mut in_table = false;
    let mut skipping = false;
    for line in current.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_table = true;
            skipping = t == "[model_providers.gantry]";
        }
        if skipping {
            continue;
        }
        if !in_table {
            if t.starts_with("model_provider") && t[14..].trim_start().starts_with('=') {
                continue;
            }
            top.push(line);
        } else {
            rest.push(line);
        }
    }
    while top.last().is_some_and(|l| l.trim().is_empty()) {
        top.pop();
    }
    let mut out = String::from("model_provider = \"gantry\"\n");
    for l in top {
        out.push_str(l);
        out.push('\n');
    }
    for l in rest {
        out.push_str(l);
        out.push('\n');
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out.push('\n');
    out.push_str(&section);
    out
}

/// The shell env file `gantry login` also writes: our two base URL lines replace any old ones, key lines stay.
fn env_file(current: &str, gateway: &str) -> String {
    let mut out = String::new();
    if current.is_empty() {
        out.push_str(
            "# Base URLs managed by the Gantry device agent. Load with: . ~/.config/gantry/env\n",
        );
    }
    for l in current.lines() {
        if !l.starts_with("export OPENAI_BASE_URL=") && !l.starts_with("export ANTHROPIC_BASE_URL=")
        {
            out.push_str(l);
            out.push('\n');
        }
    }
    out.push_str(&format!(
        "export ANTHROPIC_BASE_URL={gateway}\nexport OPENAI_BASE_URL={gateway}/v1\n"
    ));
    out
}

/// One managed file: whether it already matches, and writing it when not.
struct Change {
    path: PathBuf,
    desired: String,
    matches: bool,
}

fn plan(path: PathBuf, f: impl FnOnce(&str) -> Result<String, String>) -> Result<Change, String> {
    let current = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let desired = f(&current).map_err(|e| format!("{} {e}", path.display()))?;
    Ok(Change {
        matches: current == desired,
        path,
        desired,
    })
}

fn write(c: &Change, owner: Option<(u32, u32)>) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{} cannot be written: {e}", c.path.display());
    if let Some(dir) = c.path.parent() {
        std::fs::create_dir_all(dir).map_err(err)?;
    }
    let tmp = c.path.with_extension("gantry-tmp");
    std::fs::write(&tmp, &c.desired).map_err(err)?;
    std::fs::rename(&tmp, &c.path).map_err(err)?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(&c.path, Some(uid), Some(gid)).map_err(err)?;
    }
    Ok(())
}

/// Tools this agent has configured before, kept so a later mismatch counts as drift, not first setup.
fn applied_path(p: &Paths) -> PathBuf {
    p.home.join(".config/gantry/device-applied")
}

/// Applies the profile once and returns the report for the control plane.
fn cycle(p: &Paths, gateway: &str, manage: &[String], dry_run: bool) -> Result<Value, String> {
    let applied_file = applied_path(p);
    let mut applied: Vec<String> = std::fs::read_to_string(&applied_file)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect();
    let mut tools = Vec::new();
    let mut env_needed = false;
    for tool in TOOLS {
        let inst = installed(p, tool);
        let managed = inst && manage.iter().any(|m| m == tool);
        let change = match (managed, tool) {
            (true, "claude-code") => Some(plan(p.claude_settings.clone(), |c| {
                claude_settings(c, gateway)
            })?),
            (true, "codex") => Some(plan(p.home.join(".codex/config.toml"), |c| {
                Ok(codex_config(c, gateway))
            })?),
            _ => None,
        };
        env_needed |= managed;
        let mut drift = false;
        if let Some(c) = change {
            drift = !c.matches && applied.iter().any(|a| a == tool);
            if c.matches {
                // Nothing to write.
            } else if dry_run {
                println!("would write {} ({tool})", c.path.display());
            } else {
                write(
                    &c,
                    if c.path.starts_with(&p.home) {
                        p.owner
                    } else {
                        None
                    },
                )?;
                println!(
                    "{} {} ({tool})",
                    if drift { "re-applied" } else { "wrote" },
                    c.path.display()
                );
                if !applied.iter().any(|a| a == tool) {
                    applied.push(tool.to_owned());
                }
            }
        }
        // Read back after writing, so the report says what the tool will do now.
        let (state, direct) = if inst {
            classify(endpoints(p, tool), gateway)
        } else {
            ("not_installed", Vec::new())
        };
        tools.push(json!({
            "tool": tool,
            "state": state,
            "installed": inst,
            "configured": state == "gantry",
            "drift": drift,
            "endpoints": direct,
        }));
    }
    if env_needed {
        let c = plan(p.home.join(".config/gantry/env"), |c| {
            Ok(env_file(c, gateway))
        })?;
        if !c.matches {
            if dry_run {
                println!("would write {}", c.path.display());
            } else {
                write(&c, p.owner)?;
                println!("wrote {}", c.path.display());
            }
        }
    }
    if !dry_run {
        let c = Change {
            path: applied_file,
            desired: applied.join("\n"),
            matches: false,
        };
        write(&c, p.owner)?;
    }
    let os_user = p
        .home
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let host = hostname();
    let email = person(&p.home);
    Ok(json!({
        "device_id": format!("{host}:{os_user}"),
        "hostname": host,
        "os_user": os_user,
        "email": email,
        "agent_version": env!("CARGO_PKG_VERSION"),
        "tools": tools,
    }))
}

/// The person at this device: the name (their email) `gantry login` saved in the credentials file.
fn person(home: &Path) -> Option<String> {
    std::fs::read_to_string(home.join(".config/gantry/credentials"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("name=").map(|v| v.trim().to_owned()))
        .filter(|v| !v.is_empty())
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn once(agent: &ureq::Agent, opts: &Options) -> Result<(), String> {
    let cp = opts.control_plane.trim_end_matches('/');
    let auth = format!("Bearer {}", opts.token);
    let call_err = |e: ureq::Error| match e {
        ureq::Error::Status(code, res) => format!(
            "the control plane answered {code}: {}",
            res.into_string().unwrap_or_default()
        ),
        other => format!("the control plane is unreachable: {other}"),
    };
    let p = paths(opts.home.as_deref())?;
    // The gateway answers with the profile of this person's team.
    let mut ask = agent
        .get(&format!("{cp}/device/profile"))
        .set("authorization", &auth);
    if let Some(person) = person(&p.home) {
        ask = ask.query("person", &person);
    }
    let profile: Value = ask
        .call()
        .map_err(call_err)?
        .into_json()
        .map_err(|e| e.to_string())?;
    let gateway = profile["gateway_url"]
        .as_str()
        .ok_or("the profile has no gateway_url")?
        .trim_end_matches('/');
    let manage: Vec<String> = profile["tools"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let report = cycle(&p, gateway, &manage, opts.dry_run)?;
    if opts.dry_run {
        println!("would report {report}");
        return Ok(());
    }
    agent
        .post(&format!("{cp}/device/report"))
        .set("authorization", &auth)
        .send_json(report)
        .map_err(call_err)?;
    Ok(())
}

pub fn run(opts: Options) -> Result<(), String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .build();
    loop {
        let result = once(&agent, &opts);
        if opts.once || opts.dry_run {
            return result;
        }
        if let Err(e) = result {
            eprintln!("device agent: {e}");
        }
        std::thread::sleep(opts.interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GW: &str = "https://gw.example.com";

    #[test]
    fn claude_settings_keep_other_keys() -> Result<(), String> {
        let out = claude_settings(r#"{"model":"opus","env":{"FOO":"1"}}"#, GW)?;
        let v: Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
        assert_eq!(v["model"], "opus");
        assert_eq!(v["env"]["FOO"], "1");
        assert_eq!(v["env"]["ANTHROPIC_BASE_URL"], GW);
        assert_eq!(claude_settings(&out, GW)?, out, "idempotent");
        assert!(claude_settings("not json", GW).is_err());
        Ok(())
    }

    #[test]
    fn codex_config_replaces_only_its_parts() {
        let cur = "model = \"o3\"\nmodel_provider = \"openai\"\n\n[model_providers.gantry]\nbase_url = \"old\"\n\n[profiles.x]\nmodel = \"y\"\n";
        let out = codex_config(cur, GW);
        assert!(out.starts_with("model_provider = \"gantry\"\nmodel = \"o3\"\n"));
        assert!(!out.contains("openai\""));
        assert!(!out.contains("old"));
        assert!(out.contains("[profiles.x]\nmodel = \"y\"\n"));
        assert!(out.contains("base_url = \"https://gw.example.com/v1\"\nenv_key = \"GANTRY_KEY\"\nwire_api = \"responses\""));
        assert_eq!(codex_config(&out, GW), out, "idempotent");
    }

    #[test]
    fn env_file_keeps_key_lines() {
        let out = env_file(
            "# login\nexport OPENAI_BASE_URL=x\nexport GANTRY_KEY=gantry_1\n",
            GW,
        );
        assert!(out.contains("export GANTRY_KEY=gantry_1\n"));
        assert!(!out.contains("=x\n"));
        assert!(out.ends_with("export OPENAI_BASE_URL=https://gw.example.com/v1\n"));
        assert_eq!(env_file(&out, GW), out);
    }

    #[test]
    fn cycle_applies_then_reports_drift() -> Result<(), String> {
        let home = std::env::temp_dir().join(format!("gantry-device-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".claude")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(home.join(".cursor")).map_err(|e| e.to_string())?;
        let p = paths(Some(&home))?;
        let manage = vec!["claude-code".to_owned(), "codex".to_owned()];
        let tool = |r: &Value, t: &str| {
            r["tools"]
                .as_array()
                .and_then(|a| a.iter().find(|x| x["tool"] == t).cloned())
                .unwrap_or_default()
        };

        let dry = cycle(&p, GW, &manage, true)?;
        assert_eq!(tool(&dry, "claude-code")["configured"], false);
        assert!(!p.claude_settings.exists(), "dry run writes nothing");

        let r = cycle(&p, GW, &manage, false)?;
        assert_eq!(
            tool(&r, "claude-code"),
            json!({"tool":"claude-code","state":"gantry","installed":true,"configured":true,"drift":false,"endpoints":[]})
        );
        assert_eq!(tool(&r, "codex")["state"], "not_installed");
        assert_eq!(
            tool(&r, "cursor"),
            json!({"tool":"cursor","state":"installed","installed":true,"configured":false,"drift":false,"endpoints":[]})
        );
        assert_eq!(r["tools"].as_array().map(Vec::len), Some(TOOLS.len()));
        assert!(home.join(".config/gantry/env").exists());

        std::fs::write(&p.claude_settings, "{}").map_err(|e| e.to_string())?;
        let r = cycle(&p, GW, &manage, false)?;
        assert_eq!(tool(&r, "claude-code")["drift"], true);
        assert!(
            std::fs::read_to_string(&p.claude_settings)
                .map_err(|e| e.to_string())?
                .contains(GW)
        );
        let r = cycle(&p, GW, &manage, false)?;
        assert_eq!(tool(&r, "claude-code")["drift"], false);
        let _ = std::fs::remove_dir_all(&home);
        Ok(())
    }

    fn put(home: &Path, file: &str, text: &str) -> Result<(), String> {
        let path = home.join(file);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, text).map_err(|e| e.to_string())
    }

    /// Each tool's documented configuration, pointed at a provider, reads as `direct`; at the gateway, as `gantry`.
    #[test]
    fn tools_configured_for_a_provider_report_direct() -> Result<(), String> {
        let home =
            std::env::temp_dir().join(format!("gantry-device-direct-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let h = &home;
        put(
            h,
            ".claude/settings.json",
            r#"{"env":{"ANTHROPIC_API_KEY":"sk-ant-x"}}"#,
        )?;
        put(h, ".codex/config.toml", "model = \"o3\"\n")?;
        put(h, ".codex/auth.json", "{}")?;
        put(
            h,
            ".vscode/extensions/github.copilot-chat-0.30.0/package.json",
            "{}",
        )?;
        put(
            h,
            "Library/Application Support/Code/User/chatLanguageModels.json",
            r#"[{"vendor":"customendpoint","apiKey":"${input:k}","url":"https://gw.example.com/v1"}]"#,
        )?;
        put(
            h,
            ".config/zed/settings.json",
            "// Zed settings\n{ \"language_models\": { \"openai\": { \"api_url\": \"https://api.openai.com/v1\" } } }",
        )?;
        put(
            h,
            ".qwen/settings.json",
            r#"{"modelProviders":{"openai":[{"baseUrl":"https://dashscope.aliyuncs.com/compatible-mode/v1","envKey":"K"}]}}"#,
        )?;
        put(
            h,
            ".gemini/settings.json",
            r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
        )?;
        put(
            h,
            ".config/kilo/kilo.json",
            r#"{"provider":{"gantry":{"options":{"baseURL":"https://gw.example.com/v1","apiKey":"{env:GANTRY_KEY}"}}}}"#,
        )?;
        put(
            h,
            ".vscode/extensions/rooveterinaryinc.roo-cline-3.0.0/package.json",
            "{}",
        )?;
        put(
            h,
            "Library/Application Support/JetBrains/IntelliJIdea2026.3/options/x.xml",
            "",
        )?;
        put(h, "Library/Application Support/Claude/config.json", "{}")?;
        put(
            h,
            "Library/Managed Preferences/com.anthropic.claudefordesktop.plist",
            "<plist><dict><key>inferenceProvider</key><string>gateway</string><key>inferenceGatewayBaseUrl</key>\n<string>https://other-gateway.example.net</string></dict></plist>",
        )?;
        let p = paths(Some(h))?;
        // Inspect only: nothing is managed.
        let r = cycle(&p, GW, &[], true)?;
        let state = |t: &str| {
            r["tools"]
                .as_array()
                .and_then(|a| a.iter().find(|x| x["tool"] == t))
                .map(|x| {
                    (
                        x["state"].as_str().unwrap_or("").to_string(),
                        x["endpoints"].clone(),
                    )
                })
                .unwrap_or_default()
        };
        assert_eq!(
            state("claude-code"),
            ("direct".into(), json!(["https://api.anthropic.com"]))
        );
        assert_eq!(
            state("codex"),
            ("direct".into(), json!(["https://api.openai.com/v1"]))
        );
        assert_eq!(state("github-copilot").0, "gantry");
        assert_eq!(
            state("zed"),
            ("direct".into(), json!(["https://api.openai.com/v1"]))
        );
        assert_eq!(state("qwen-code").0, "direct");
        assert_eq!(
            state("gemini-cli"),
            (
                "direct".into(),
                json!(["https://generativelanguage.googleapis.com"])
            )
        );
        assert_eq!(state("kilo-code").0, "gantry");
        assert_eq!(state("roo-code").0, "installed");
        assert_eq!(state("jetbrains-ai").0, "installed");
        assert_eq!(
            state("claude-desktop"),
            (
                "direct".into(),
                json!(["https://other-gateway.example.net"])
            )
        );
        assert_eq!(state("cursor").0, "not_installed");

        // Managing Claude Code and Codex turns both to the gateway.
        let manage = vec!["claude-code".to_owned(), "codex".to_owned()];
        let r = cycle(&p, GW, &manage, false)?;
        for t in ["claude-code", "codex"] {
            let x = r["tools"]
                .as_array()
                .and_then(|a| a.iter().find(|x| x["tool"] == t))
                .cloned()
                .unwrap_or_default();
            assert_eq!(x["state"], "gantry", "{t}: {x}");
        }
        let _ = std::fs::remove_dir_all(&home);
        Ok(())
    }

    #[test]
    fn a_lookalike_host_is_not_the_gateway() {
        assert_eq!(
            classify(vec!["https://gw.example.com.evil.io/v1".into()], GW).0,
            "direct"
        );
        assert_eq!(
            classify(vec!["https://gw.example.com".into()], GW).0,
            "gantry"
        );
        assert_eq!(classify(vec!["${input:key}".into()], GW).0, "installed");
    }
}
