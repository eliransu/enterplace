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

/// The operating system whose paths the agent uses: the one it was built for, or another in tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Os {
    Macos,
    Linux,
    Windows,
}

impl Os {
    fn this() -> Os {
        if cfg!(target_os = "windows") {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            Os::Linux
        }
    }

    /// Where Claude Code reads managed settings and managed MCP servers on this OS (code.claude.com/docs, settings).
    fn managed_dir(self) -> PathBuf {
        match self {
            Os::Macos => PathBuf::from("/Library/Application Support/ClaudeCode"),
            Os::Linux => PathBuf::from("/etc/claude-code"),
            Os::Windows => PathBuf::from(r"C:\Program Files\ClaudeCode"),
        }
    }
}

/// Where each managed file lives for one user.
struct Paths {
    os: Os,
    home: PathBuf,
    /// The per-user application settings folder: ~/Library/Application Support, %APPDATA%, or ~/.config.
    config: PathBuf,
    claude_settings: PathBuf,
    /// The agent runs as root under the LaunchDaemon or a systemd unit: files it writes in the user's home go back to
    /// the user.
    owner: Option<(u32, u32)>,
    system: bool,
}

#[cfg(unix)]
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

/// The per-user settings folder of `home` on `os`, from the environment unless a test fixed the home.
fn config_dir(os: Os, home: &Path, from_env: bool) -> PathBuf {
    let env = |name: &str| {
        from_env
            .then(|| std::env::var_os(name))
            .flatten()
            .map(PathBuf::from)
    };
    match os {
        Os::Macos => home.join("Library/Application Support"),
        Os::Windows => env("APPDATA").unwrap_or_else(|| home.join("AppData").join("Roaming")),
        Os::Linux => env("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")),
    }
}

fn user_paths(os: Os, home: PathBuf, from_env: bool) -> Paths {
    Paths {
        os,
        config: config_dir(os, &home, from_env),
        claude_settings: home.join(".claude").join("settings.json"),
        home,
        owner: None,
        system: from_env,
    }
}

/// The person signed in at the screen, when the agent runs as root: the owner of /dev/console on macOS, the first
/// user `who` lists on Linux.
#[cfg(unix)]
fn console_user(os: Os) -> Result<PathBuf, String> {
    let (cmd, args): (&str, &[&str]) = match os {
        Os::Macos => ("stat", &["-f", "%Su", "/dev/console"]),
        _ => ("who", &[]),
    };
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    let user = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if user.is_empty() || user == "root" {
        return Err("no one is signed in at the screen; trying again next interval.".into());
    }
    let base = if os == Os::Macos { "/Users" } else { "/home" };
    Ok(PathBuf::from(base).join(user))
}

fn paths(home: Option<&Path>) -> Result<Paths, String> {
    let os = Os::this();
    if let Some(home) = home {
        return Ok(user_paths(os, home.to_path_buf(), false));
    }
    #[cfg(unix)]
    if is_root() {
        use std::os::unix::fs::MetadataExt;
        let home = console_user(os)?;
        let meta = std::fs::metadata(&home).map_err(|e| format!("{}: {e}", home.display()))?;
        let mut p = user_paths(os, home, false);
        p.claude_settings = os.managed_dir().join("managed-settings.json");
        p.owner = Some((meta.uid(), meta.gid()));
        p.system = true;
        return Ok(p);
    }
    // On Windows the agent runs as the signed-in user, a scheduled task at logon, so its own profile is the one.
    let var = if os == Os::Windows {
        "USERPROFILE"
    } else {
        "HOME"
    };
    let home = std::env::var_os(var)
        .map(PathBuf::from)
        .ok_or(format!("{var} is not set. Set it or pass --home."))?;
    Ok(user_paths(os, home, true))
}

fn on_path(bin: &str) -> bool {
    let exe = format!("{bin}.exe");
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file() || d.join(&exe).is_file()))
        .unwrap_or(false)
}

/// Which tools are installed. With `--home` only that folder counts, so tests do not depend on the machine.
fn installed(p: &Paths, tool: &str) -> bool {
    let h = &p.home;
    // Where each OS's installer puts the app: /Applications, %LOCALAPPDATA%\Programs, or a command on PATH.
    let app = |mac: &str, windows: &str, linux_bin: &str| {
        p.system
            && match p.os {
                Os::Macos => {
                    Path::new("/Applications").join(mac).exists()
                        || h.join("Applications").join(mac).exists()
                }
                Os::Windows => std::env::var_os("LOCALAPPDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| h.join("AppData").join("Local"))
                    .join("Programs")
                    .join(windows)
                    .exists(),
                Os::Linux => on_path(linux_bin),
            }
    };
    match tool {
        "claude-code" => {
            h.join(".claude").is_dir()
                || h.join(".local/bin/claude").exists()
                || (p.system && on_path("claude"))
        }
        "codex" => h.join(".codex").is_dir() || (p.system && on_path("codex")),
        "cursor" => h.join(".cursor").is_dir() || app("Cursor.app", "cursor", "cursor"),
        "vscode" => {
            h.join(".vscode").is_dir() || app("Visual Studio Code.app", "Microsoft VS Code", "code")
        }
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
    #[cfg(unix)]
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(&c.path, Some(uid), Some(gid)).map_err(err)?;
    }
    #[cfg(not(unix))]
    let _ = owner;
    Ok(())
}

// ---- MCP inventory: the MCP servers each tool is configured with, and whether they go through the gateway. ----

/// Each MCP config file of each tool for this user: (tool, file, the key that holds the servers). Paths from each
/// tool's docs: Claude Desktop (modelcontextprotocol.io quickstart), Claude Code (code.claude.com/docs, mcp and
/// managed-mcp), Cursor (cursor.com/docs/context/mcp), VS Code (code.visualstudio.com, MCP configuration) and Zed
/// (zed.dev/docs/ai/mcp).
fn mcp_files(p: &Paths) -> Vec<(&'static str, PathBuf, &'static str)> {
    let zed = match p.os {
        Os::Windows => p.config.join("Zed").join("settings.json"),
        Os::Linux => p.config.join("zed").join("settings.json"),
        Os::Macos => p.home.join(".config").join("zed").join("settings.json"),
    };
    let mut files = vec![
        (
            "claude-desktop",
            p.config.join("Claude").join("claude_desktop_config.json"),
            "mcpServers",
        ),
        ("claude-code", p.home.join(".claude.json"), "mcpServers"),
        (
            "cursor",
            p.home.join(".cursor").join("mcp.json"),
            "mcpServers",
        ),
        (
            "vscode",
            p.config.join("Code").join("User").join("mcp.json"),
            "servers",
        ),
        ("zed", zed, "context_servers"),
    ];
    if p.system {
        files.push((
            "claude-code",
            p.os.managed_dir().join("managed-mcp.json"),
            "mcpServers",
        ));
    }
    files
}

/// JSON with comments and trailing commas (VS Code's and Zed's settings) as plain JSON.
fn jsonc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                '\\' => {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                }
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match (c, chars.peek()) {
            ('"', _) => {
                in_string = true;
                out.push(c);
            }
            ('/', Some('/')) => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut last = ' ';
                for n in chars.by_ref() {
                    if last == '*' && n == '/' {
                        break;
                    }
                    last = n;
                }
            }
            (',', _) => {
                // A comma whose next non-space character closes a list or object is dropped.
                let rest: String = chars.clone().take_while(|n| n.is_whitespace()).collect();
                let after = chars.clone().nth(rest.chars().count());
                if !matches!(after, Some('}' | ']')) {
                    out.push(c);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// A URL without its login, query or fragment, which may hold credentials: scheme, host and path only.
fn bare_url(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let rest = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    let rest = rest.trim_end_matches('/');
    if scheme.is_empty() {
        rest.to_owned()
    } else {
        format!("{scheme}://{rest}")
    }
}

/// One server entry as reported: its name, transport and target (a bare URL, or the command's file name only, never
/// its arguments, environment or headers), and whether it is Gantry's MCP gateway (`<gateway>/mcp` or a bundle under
/// it).
fn mcp_entry(tool: &str, file: &Path, name: &str, entry: &Value, gateway: &str) -> Value {
    let url = ["url", "serverUrl", "httpUrl"]
        .iter()
        .find_map(|k| entry[*k].as_str());
    let (transport, target, via) = match url {
        Some(url) => {
            let bare = bare_url(url);
            let mcp = format!("{}/mcp", gateway.trim_end_matches('/'));
            let via = bare == mcp || bare.starts_with(&format!("{mcp}/"));
            ("http", bare, via)
        }
        None => {
            let command = entry["command"]
                .as_str()
                .or_else(|| entry["command"]["path"].as_str())
                .unwrap_or_default();
            let file_name = command
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or_default()
                .to_owned();
            ("stdio", file_name, false)
        }
    };
    json!({
        "tool": tool,
        "file": file.display().to_string(),
        "server": name,
        "transport": transport,
        "target": target,
        "via_gantry": via,
    })
}

/// Every MCP server configured in each tool this user has, and a line for each file that could not be read.
fn mcp_inventory(p: &Paths, gateway: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (tool, file, key) in mcp_files(p) {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let Ok(config) = serde_json::from_str::<Value>(&jsonc(&text)) else {
            out.push(json!({"tool": tool, "file": file.display().to_string(), "error": "the file is not JSON"}));
            continue;
        };
        let mut lists = vec![&config[key]];
        // Claude Code keeps servers added in one project under projects.<path>.mcpServers.
        if file.ends_with(".claude.json") {
            lists.extend(
                config["projects"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .map(|(_, project)| &project[key]),
            );
        }
        for list in lists {
            for (name, entry) in list.as_object().into_iter().flatten() {
                out.push(mcp_entry(tool, &file, name, entry, gateway));
            }
        }
    }
    out
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
        "os": format!("{:?}", p.os).to_lowercase(),
        "tools": tools,
        "mcp": mcp_inventory(p, gateway),
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

    #[test]
    fn windows_and_linux_paths_follow_each_tools_docs() {
        let home = PathBuf::from("/h");
        let win = user_paths(Os::Windows, home.clone(), false);
        let files: Vec<PathBuf> = mcp_files(&win).into_iter().map(|(_, f, _)| f).collect();
        assert!(files.contains(&home.join("AppData/Roaming/Claude/claude_desktop_config.json")));
        assert!(files.contains(&home.join("AppData/Roaming/Code/User/mcp.json")));
        assert!(files.contains(&home.join("AppData/Roaming/Zed/settings.json")));
        assert_eq!(win.claude_settings, home.join(".claude/settings.json"));
        assert_eq!(
            Os::Windows.managed_dir(),
            PathBuf::from(r"C:\Program Files\ClaudeCode")
        );
        let linux = user_paths(Os::Linux, home.clone(), false);
        let files: Vec<PathBuf> = mcp_files(&linux).into_iter().map(|(_, f, _)| f).collect();
        assert!(files.contains(&home.join(".config/Claude/claude_desktop_config.json")));
        assert!(files.contains(&home.join(".config/Code/User/mcp.json")));
        assert!(files.contains(&home.join(".config/zed/settings.json")));
        assert!(files.contains(&home.join(".cursor/mcp.json")));
        assert_eq!(Os::Linux.managed_dir(), PathBuf::from("/etc/claude-code"));
        let mac = user_paths(Os::Macos, home.clone(), false);
        let files: Vec<PathBuf> = mcp_files(&mac).into_iter().map(|(_, f, _)| f).collect();
        assert!(
            files.contains(
                &home.join("Library/Application Support/Claude/claude_desktop_config.json")
            )
        );
    }

    #[test]
    fn the_mcp_inventory_lists_each_tools_servers_and_which_go_through_gantry() -> Result<(), String>
    {
        let home = std::env::temp_dir().join(format!("gantry-device-mcp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let p = user_paths(Os::Linux, home.clone(), false);
        let put = |rel: &str, text: &str| -> Result<(), String> {
            let path = home.join(rel);
            std::fs::create_dir_all(path.parent().ok_or("no parent")?)
                .map_err(|e| e.to_string())?;
            std::fs::write(path, text).map_err(|e| e.to_string())
        };
        put(
            ".config/Claude/claude_desktop_config.json",
            r#"{"mcpServers":{"files":{"command":"/usr/bin/npx","args":["-y","@x/fs","/secret/path"],"env":{"TOKEN":"t0ps3cret"}}}}"#,
        )?;
        put(
            ".claude.json",
            r#"{"mcpServers":{"gantry":{"type":"http","url":"https://gw.example.com/mcp"}},"projects":{"/repo":{"mcpServers":{"bundle":{"type":"http","url":"https://gw.example.com/mcp/eng?key=abc"}}}}}"#,
        )?;
        put(
            ".cursor/mcp.json",
            r#"{"mcpServers":{"github":{"url":"https://user:pw@api.githubcopilot.com/mcp/","headers":{"Authorization":"Bearer x"}}}}"#,
        )?;
        put(
            ".config/Code/User/mcp.json",
            "{\n  // my servers\n  \"servers\": {\"docs\": {\"type\": \"http\", \"url\": \"https://gw.example.com/mcp\",},},\n}",
        )?;
        put(
            ".config/zed/settings.json",
            r#"{"theme":"One","context_servers":{"local":{"command":{"path":"C:\\tools\\srv.exe","args":[]}}}}"#,
        )?;
        let found = mcp_inventory(&p, GW);
        let row = |server: &str| {
            found
                .iter()
                .find(|r| r["server"] == server)
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(found.len(), 6, "{found:?}");
        assert_eq!(row("files")["tool"], "claude-desktop");
        assert_eq!(
            (
                row("files")["transport"].clone(),
                row("files")["target"].clone()
            ),
            (json!("stdio"), json!("npx"))
        );
        assert_eq!(row("gantry")["via_gantry"], true);
        assert_eq!(row("bundle")["via_gantry"], true);
        assert_eq!(row("bundle")["target"], "https://gw.example.com/mcp/eng");
        assert_eq!(row("github")["via_gantry"], false);
        assert_eq!(row("github")["target"], "https://api.githubcopilot.com/mcp");
        assert_eq!(row("docs")["tool"], "vscode");
        assert_eq!(row("docs")["via_gantry"], true);
        assert_eq!(row("local")["target"], "srv.exe");
        let text = serde_json::to_string(&found).map_err(|e| e.to_string())?;
        for secret in ["t0ps3cret", "/secret/path", "key=abc", "pw@", "Bearer x"] {
            assert!(!text.contains(secret), "{secret} reported: {text}");
        }
        let _ = std::fs::remove_dir_all(&home);
        Ok(())
    }
}
