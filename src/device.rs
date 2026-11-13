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

/// Which tools are installed. With `--home` only that folder counts, so tests do not depend on the machine.
fn installed(p: &Paths, tool: &str) -> bool {
    let h = &p.home;
    let app = |name: &str| {
        p.system
            && (Path::new("/Applications").join(name).exists()
                || h.join("Applications").join(name).exists())
    };
    match tool {
        "claude-code" => {
            h.join(".claude").is_dir()
                || h.join(".local/bin/claude").exists()
                || (p.system && on_path("claude"))
        }
        "codex" => h.join(".codex").is_dir() || (p.system && on_path("codex")),
        "cursor" => h.join(".cursor").is_dir() || app("Cursor.app"),
        "vscode" => h.join(".vscode").is_dir() || app("Visual Studio Code.app"),
        _ => false,
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
    for tool in ["claude-code", "codex", "cursor", "vscode"] {
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
        let mut configured = false;
        if let Some(c) = change {
            drift = !c.matches && applied.iter().any(|a| a == tool);
            if c.matches {
                configured = true;
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
                configured = true;
                if !applied.iter().any(|a| a == tool) {
                    applied.push(tool.to_owned());
                }
            }
        }
        tools.push(
            json!({ "tool": tool, "installed": inst, "configured": configured, "drift": drift }),
        );
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
    // `gantry login` saves the person's name (their email) in the credentials file.
    let email = std::fs::read_to_string(p.home.join(".config/gantry/credentials"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("name=").map(|v| v.trim().to_owned()))
        .filter(|v| !v.is_empty());
    Ok(json!({
        "device_id": format!("{host}:{os_user}"),
        "hostname": host,
        "os_user": os_user,
        "email": email,
        "agent_version": env!("CARGO_PKG_VERSION"),
        "tools": tools,
    }))
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
    let profile: Value = agent
        .get(&format!("{cp}/device/profile"))
        .set("authorization", &auth)
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
    let p = paths(opts.home.as_deref())?;
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
            json!({"tool":"claude-code","installed":true,"configured":true,"drift":false})
        );
        assert_eq!(tool(&r, "codex")["installed"], false);
        assert_eq!(
            tool(&r, "cursor"),
            json!({"tool":"cursor","installed":true,"configured":false,"drift":false})
        );
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
}
