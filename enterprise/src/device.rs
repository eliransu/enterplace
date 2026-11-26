//! Device agent (plan 6.4, levels 1 and 2). Every interval it reads the org's device profile from the control plane,
//! points the installed coding tools of the signed-in OS user at the gateway, puts them back when someone changes
//! them (drift), reports blocked MCP servers (or takes them out of the tools' MCP files when the profile says
//! `remove`), and reports each tool's state, the MCP servers and the AI apps it finds for the coverage report. It
//! writes only files each tool documents, and stops no process.

use enterplace_core::coding_agents::CodingAgents;
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

impl Paths {
    /// Zed's settings file (zed.dev/docs/configuring-zed): `~/.config/zed` on macOS and Linux, `%APPDATA%\Zed` on
    /// Windows.
    fn zed_settings(&self) -> PathBuf {
        match self.os {
            Os::Windows => self.config.join("Zed"),
            Os::Linux => self.config.join("zed"),
            Os::Macos => self.home.join(".config").join("zed"),
        }
        .join("settings.json")
    }

    /// OpenCode's global configuration (opencode.ai/docs/config): `~/.config/opencode/opencode.json` on every OS,
    /// or `opencode.jsonc` there when that is the one the person keeps.
    fn opencode_config(&self) -> PathBuf {
        let dir = self.home.join(".config").join("opencode");
        if dir.join("opencode.jsonc").exists() && !dir.join("opencode.json").exists() {
            return dir.join("opencode.jsonc");
        }
        dir.join("opencode.json")
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

/// Whether a command is on PATH: the file itself, or on Windows its `.exe`, or the `.cmd` npm writes for a command
/// line tool installed with `npm install -g`.
fn on_path(bin: &str) -> bool {
    let names = [bin.to_string(), format!("{bin}.exe"), format!("{bin}.cmd")];
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| names.iter().any(|n| d.join(n).is_file())))
        .unwrap_or(false)
}

/// Every tool the agent looks for, by the name the coverage report gives it (`enterplace_core::audit::tool_of`).
pub const TOOLS: [&str; 15] = [
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
    "opencode",
    "continue",
    "cline",
    "aider",
];

/// The tools the agent can point at the gateway itself, each through a file the tool documents; the others it only
/// inspects (`why_not`).
pub const MANAGEABLE: [&str; 9] = [
    "claude-code",
    "codex",
    "opencode",
    "kilo-code",
    "continue",
    "zed",
    "gemini-cli",
    "qwen-code",
    "aider",
];

/// The tools a device manages when no profile was saved: the two the agent managed before it learned the others,
/// so an upgrade alone starts writing no new file.
pub const DEFAULT_MANAGED: [&str; 2] = ["claude-code", "codex"];

/// Why the agent cannot point `tool` at the gateway: no file the tool documents holds its endpoint. `None` for a
/// tool it can configure.
pub fn why_not(tool: &str) -> Option<&'static str> {
    Some(match tool {
        "cursor" => {
            "Cursor keeps its OpenAI base URL override in the app's own settings storage, which no documented file sets. Set it in Cursor Settings, Models."
        }
        "cline" => {
            "Cline keeps its provider and base URL in VS Code's extension storage, which no documented file sets. Set them in Cline's settings panel."
        }
        "roo-code" => {
            "Roo Code keeps its provider and base URL in VS Code's extension storage, which no documented file sets. Set them in Roo Code's settings panel."
        }
        "github-copilot" => {
            "GitHub Copilot's own models are served by GitHub; only a custom endpoint a person adds in VS Code is read."
        }
        "jetbrains-ai" => {
            "JetBrains AI Assistant keeps its providers in the IDE's settings storage, which no documented file sets."
        }
        "claude-desktop" => {
            "Claude Desktop takes its gateway from the managed preference inferenceGatewayBaseUrl, which your device management tool delivers, not a file the agent may write."
        }
        _ => return None,
    })
}

/// AI desktop apps the agent looks for besides `TOOLS`, each by where its vendor's installer puts it: (name, macOS
/// bundle in /Applications, folder under %LOCALAPPDATA%\Programs, command on PATH, folder it keeps in the home).
const OTHER_APPS: [(&str, &str, &str, &str, &str); 5] = [
    ("chatgpt", "ChatGPT.app", "ChatGPT", "", ""),
    (
        "windsurf",
        "Windsurf.app",
        "Windsurf",
        "windsurf",
        ".codeium/windsurf",
    ),
    ("ollama", "Ollama.app", "Ollama", "ollama", ".ollama"),
    (
        "lm-studio",
        "LM Studio.app",
        "LM Studio",
        "lms",
        ".lmstudio",
    ),
    ("perplexity", "Perplexity.app", "Perplexity", "", ""),
];

/// The process each app runs as, for the apps whose process name is their own (a command line tool's is often
/// `node`): (name, process).
const PROCESSES: [(&str, &str); 7] = [
    ("chatgpt", "ChatGPT"),
    ("windsurf", "Windsurf"),
    ("ollama", "ollama"),
    ("lm-studio", "LM Studio"),
    ("perplexity", "Perplexity"),
    ("cursor", "Cursor"),
    ("claude-desktop", "Claude"),
];

/// Every app a device profile can allow or deny: the coding tools and the desktop apps.
pub fn app_names() -> Vec<&'static str> {
    TOOLS
        .into_iter()
        .chain(OTHER_APPS.into_iter().map(|a| a.0))
        .collect()
}

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

/// Whether a desktop app is where each OS's installer puts it: /Applications (or ~/Applications),
/// %LOCALAPPDATA%\Programs, or a command on PATH.
fn app_installed(p: &Paths, mac: &str, windows: &str, linux_bin: &str) -> bool {
    let h = &p.home;
    match p.os {
        Os::Macos => {
            Path::new("/Applications").join(mac).exists() && p.system
                || h.join("Applications").join(mac).exists()
        }
        Os::Windows => {
            let programs = if p.system {
                std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
            } else {
                None
            }
            .unwrap_or_else(|| h.join("AppData").join("Local"))
            .join("Programs");
            !windows.is_empty() && programs.join(windows).exists()
        }
        Os::Linux => p.system && !linux_bin.is_empty() && on_path(linux_bin),
    }
}

/// Which tools are installed. With `--home` only that folder counts, so tests do not depend on the machine.
fn installed(p: &Paths, tool: &str) -> bool {
    let h = &p.home;
    let app = |mac: &str, windows: &str, linux_bin: &str| app_installed(p, mac, windows, linux_bin);
    let bin = |name: &str| p.system && on_path(name);
    let extension = |id: &str| has_entry(&h.join(".vscode/extensions"), id);
    match tool {
        "claude-code" => {
            h.join(".claude").is_dir() || h.join(".local/bin/claude").exists() || bin("claude")
        }
        "codex" => h.join(".codex").is_dir() || bin("codex"),
        "cursor" => h.join(".cursor").is_dir() || app("Cursor.app", "cursor", "cursor"),
        "github-copilot" => extension("github.copilot") || h.join(".copilot").is_dir(),
        "zed" => {
            p.zed_settings().parent().is_some_and(Path::is_dir) || app("Zed.app", "Zed", "zed")
        }
        "jetbrains-ai" => {
            h.join("Library/Application Support/JetBrains").is_dir()
                || h.join(".config/JetBrains").is_dir()
                || h.join("AppData/Roaming/JetBrains").is_dir()
        }
        "qwen-code" => h.join(".qwen").is_dir() || bin("qwen"),
        "gemini-cli" => h.join(".gemini").is_dir() || bin("gemini"),
        "kilo-code" => h.join(".config/kilo").is_dir() || extension("kilocode.kilo-code"),
        "roo-code" => extension("rooveterinaryinc.roo-cline"),
        "claude-desktop" => {
            app("Claude.app", "Claude", "claude-desktop")
                || h.join("Library/Application Support/Claude").is_dir()
                || h.join(".config/Claude").is_dir()
                || h.join("AppData/Roaming/Claude").is_dir()
        }
        "opencode" => {
            h.join(".config/opencode").is_dir() || h.join(".opencode").is_dir() || bin("opencode")
        }
        "continue" => h.join(".continue").is_dir() || extension("continue.continue"),
        "cline" => extension("saoudrizwan.claude-dev"),
        "aider" => h.join(".aider.conf.yml").exists() || bin("aider"),
        other => OTHER_APPS.iter().find(|a| a.0 == other).is_some_and(
            |(_, mac, windows, command, folder)| {
                app(mac, windows, command)
                    || !command.is_empty() && bin(command)
                    || !folder.is_empty() && h.join(folder).is_dir()
            },
        ),
    }
}

/// The names of the processes running now: the file name of each, without `.exe`. Read from `ps` or `tasklist`;
/// nothing is stopped.
fn running(os: Os) -> Vec<String> {
    let (command, args): (&str, &[&str]) = match os {
        Os::Windows => ("tasklist", &["/FO", "CSV", "/NH"]),
        _ => ("ps", &["-axo", "comm="]),
    };
    let Ok(out) = std::process::Command::new(command).args(args).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| {
            let name = match os {
                // "Image Name","PID",...
                Os::Windows => line.split("\",").next().unwrap_or("").trim_matches('"'),
                _ => line.trim().rsplit('/').next().unwrap_or(""),
            };
            name.strip_suffix(".exe").unwrap_or(name).to_string()
        })
        .filter(|n| !n.is_empty())
        .collect()
}

/// Every app of `app_names` that is installed or running, with what the profile's lists say of it: `denied` when
/// the deny list names it, or an allow list is set and does not; `allowed` when the allow list names it; else
/// `unlisted`.
fn apps(p: &Paths, allowed: &[String], denied: &[String], processes: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    for app in app_names() {
        let is_installed = installed(p, app);
        let is_running = PROCESSES.iter().any(|(name, process)| {
            *name == app
                && processes.iter().any(|r| match p.os {
                    // `claude` is Claude Code and `Claude` the desktop app.
                    Os::Macos => r == process,
                    _ => r.eq_ignore_ascii_case(process),
                })
        });
        if !is_installed && !is_running {
            continue;
        }
        let named = |list: &[String]| list.iter().any(|a| a == app);
        let status = if named(denied) || !allowed.is_empty() && !named(allowed) {
            "denied"
        } else if named(allowed) {
            "allowed"
        } else {
            "unlisted"
        };
        out.push(json!({ "app": app, "status": status, "installed": is_installed, "running": is_running }));
    }
    out
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
/// documented file holds it (Cursor, JetBrains AI Assistant, Cline and Roo Code keep theirs in the app's own
/// storage: `why_not`).
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
            let mut out = string_values(
                &read(&p.config.join("Code/User/chatLanguageModels.json")),
                "url",
            );
            out.extend(string_values(
                &read(&h.join(".copilot/providers.json")),
                "baseUrl",
            ));
            out
        }
        "zed" => string_values(&read(&p.zed_settings()), "api_url"),
        "qwen-code" => {
            let settings = read(&h.join(".qwen/settings.json"));
            let mut out = string_values(&settings, "baseUrl");
            out.extend(dotenv(&read(&h.join(".qwen/.env")), "OPENAI_BASE_URL"));
            // A sign-in other than the OpenAI-compatible one (Qwen's own, say) does not use the base URL.
            out.extend(
                string_values(&settings, "selectedType")
                    .into_iter()
                    .filter(|t| t != "openai"),
            );
            out
        }
        "opencode" => string_values(&read(&p.opencode_config()), "baseURL"),
        "continue" => {
            let text = read(&h.join(".continue/config.yaml"));
            let lines: Vec<&str> = text.lines().collect();
            continue_models(&lines)
                .into_iter()
                .filter_map(|item| {
                    let value = |key: &str| item_key(&lines, &item, key).map(|(_, v)| v);
                    // A model with no apiBase goes to its provider's own address: named by the provider.
                    value("apiBase").or(value("provider"))
                })
                .collect()
        }
        "aider" => {
            let text = read(&h.join(".aider.conf.yml"));
            let top = |key: &str| {
                text.lines().find_map(|l| {
                    let value = l.strip_prefix(key)?.strip_prefix(':')?;
                    let value = value.split(" #").next().unwrap_or("").trim();
                    Some(value.trim_matches(['"', '\'']).to_string()).filter(|v| !v.is_empty())
                })
            };
            let mut out = Vec::new();
            match top("openai-api-base") {
                Some(url) => out.push(url),
                None if top("openai-api-key").is_some() => {
                    out.push("https://api.openai.com/v1".into());
                }
                None => {}
            }
            if top("anthropic-api-key").is_some() {
                out.push("https://api.anthropic.com".into());
            }
            out
        }
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
        ("enterplace", direct)
    } else {
        ("direct", direct)
    }
}

// ---- Desired file contents. Each takes the current text and returns the text it should be. ----

/// Claude Code settings with env.ANTHROPIC_BASE_URL set to the gateway, other keys kept. With the person's Enterplace key
/// from `enterplace login`, ANTHROPIC_CUSTOM_HEADERS names them in x-enterplace-user, so a Claude subscription login sent
/// through the gateway's passthrough provider is recorded under them. Claude Code's own login stays as it is.
fn claude_settings(
    current: &str,
    gateway: &str,
    person: Option<&str>,
    controls: CodingAgents,
) -> Result<String, String> {
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
        if let Some(person) = person {
            env.insert(
                "ANTHROPIC_CUSTOM_HEADERS".into(),
                json!(format!("x-enterplace-user: {person}")),
            );
        }
    }
    claude_controls(obj, controls);
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
    ))
}

/// The policy's coding agent controls as the keys Claude Code documents for them (code.claude.com/docs/en/settings-reference):
/// `permissions.disableBypassPermissionsMode` rejects `--dangerously-skip-permissions`, `disableAutoMode` takes auto
/// mode out, and `deniedMcpServers` refuses the browser servers, Claude in Chrome included. Blocked writes the key,
/// allowed takes out what blocked writes (and only that), unset leaves the file as it is.
fn claude_controls(obj: &mut serde_json::Map<String, Value>, controls: CodingAgents) {
    use enterplace_core::coding_agents::{BROWSER_SERVERS, Control};
    match controls.bypass_permissions {
        Control::Block => {
            let permissions = obj.entry("permissions").or_insert_with(|| json!({}));
            if !permissions.is_object() {
                *permissions = json!({});
            }
            permissions["disableBypassPermissionsMode"] = json!("disable");
        }
        Control::Allow => {
            if let Some(permissions) = obj.get_mut("permissions").and_then(Value::as_object_mut) {
                permissions.remove("disableBypassPermissionsMode");
                if permissions.is_empty() {
                    obj.remove("permissions");
                }
            }
        }
        Control::Unset => {}
    }
    match controls.auto_mode {
        Control::Block => {
            obj.insert("disableAutoMode".into(), json!("disable"));
        }
        Control::Allow => {
            obj.remove("disableAutoMode");
        }
        Control::Unset => {}
    }
    let ours = |s: &Value| {
        s["serverName"]
            .as_str()
            .is_some_and(|n| BROWSER_SERVERS.contains(&n))
    };
    match controls.browser {
        Control::Block => {
            let denied = obj.entry("deniedMcpServers").or_insert_with(|| json!([]));
            if !denied.is_array() {
                *denied = json!([]);
            }
            if let Some(list) = denied.as_array_mut() {
                for server in BROWSER_SERVERS {
                    if !list.iter().any(|s| s["serverName"] == *server) {
                        list.push(json!({ "serverName": server }));
                    }
                }
            }
        }
        Control::Allow => {
            if let Some(list) = obj
                .get_mut("deniedMcpServers")
                .and_then(Value::as_array_mut)
            {
                list.retain(|s| !ours(s));
                if list.is_empty() {
                    obj.remove("deniedMcpServers");
                }
            }
        }
        Control::Unset => {}
    }
}

/// Codex config.toml with `model_provider = "enterplace"` and a `[model_providers.enterplace]` table at the gateway.
/// ponytail: line-based TOML edit (no toml crate); it owns only those two places and keeps every other line.
fn codex_config(current: &str, gateway: &str) -> String {
    let section = format!(
        "[model_providers.enterplace]\nname = \"Enterplace\"\nbase_url = \"{gateway}/v1\"\nenv_key = \"ENTERPLACE_KEY\"\nwire_api = \"responses\"\nstream_max_retries = 0\n"
    );
    let mut top = Vec::new();
    let mut rest = Vec::new();
    let mut in_table = false;
    let mut skipping = false;
    for line in current.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_table = true;
            skipping = t == "[model_providers.enterplace]";
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
    let mut out = String::from("model_provider = \"enterplace\"\n");
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

/// The shell env file `enterplace login` also writes: our two base URL lines replace any old ones, key lines stay.
fn env_file(current: &str, gateway: &str) -> String {
    let mut out = String::new();
    if current.is_empty() {
        out.push_str(
            "# Base URLs managed by the Enterplace device agent. Load with: . ~/.config/enterplace/env\n",
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

/// A JSON settings file, comments and trailing commas allowed, with `edit` applied and every other key kept. Text
/// the edit leaves as it was comes back untouched, comments and all; a changed file is written as plain JSON, so its
/// comments go (the agent keeps the file as it was beside it, `backup`).
fn json_edit(current: &str, edit: impl FnOnce(&mut Value)) -> Result<String, String> {
    let before: Value = if current.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&jsonc(current))
            .map_err(|e| format!("is not JSON ({e}); fix or delete it"))?
    };
    if !before.is_object() {
        return Err("is not a JSON object; fix or delete it".into());
    }
    let mut after = before.clone();
    edit(&mut after);
    if after == before {
        return Ok(current.to_owned());
    }
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&after).map_err(|e| e.to_string())?
    ))
}

/// Sets the string at `path`, keys from the root, making the objects on the way.
fn set_at(v: &mut Value, path: &[&str], value: &str) {
    let mut at = v;
    for key in path {
        if !at.is_object() {
            *at = json!({});
        }
        at = &mut at[*key];
    }
    *at = json!(value);
}

/// OpenCode's and Kilo CLI's configuration (opencode.ai/docs/providers, kilo.ai/docs: the same `provider` table)
/// with the built-in `openai` and `anthropic` providers sent to the gateway: `options.baseURL`, and the Enterplace key
/// read from ENTERPLACE_KEY unless the person set a key there.
fn opencode_config(current: &str, gateway: &str) -> Result<String, String> {
    json_edit(current, |v| {
        for provider in ["openai", "anthropic"] {
            let options = ["provider", provider, "options"];
            set_at(
                v,
                &[options.as_slice(), &["baseURL"]].concat(),
                &format!("{gateway}/v1"),
            );
            if !v["provider"][provider]["options"]["apiKey"].is_string() {
                set_at(
                    v,
                    &[options.as_slice(), &["apiKey"]].concat(),
                    "{env:ENTERPLACE_KEY}",
                );
            }
        }
    })
}

/// Zed's settings (zed.dev/docs/ai/llm-providers) with the OpenAI and Anthropic providers' `api_url` at the gateway.
/// The key stays where Zed keeps it, the system keychain.
fn zed_config(current: &str, gateway: &str) -> Result<String, String> {
    json_edit(current, |v| {
        set_at(
            v,
            &["language_models", "openai", "api_url"],
            &format!("{gateway}/v1"),
        );
        set_at(v, &["language_models", "anthropic", "api_url"], gateway);
    })
}

/// Qwen Code's settings (qwenlm.github.io/qwen-code-docs, model providers) with every `modelProviders.openai` entry's
/// `baseUrl` at the gateway. A file with no such entry is left as it is: `OPENAI_BASE_URL` in `~/.qwen/.env` decides.
fn qwen_settings(current: &str, gateway: &str) -> Result<String, String> {
    json_edit(current, |v| {
        for entry in v["modelProviders"]["openai"]
            .as_array_mut()
            .into_iter()
            .flatten()
            .filter_map(Value::as_object_mut)
        {
            entry.insert("baseUrl".into(), json!(format!("{gateway}/v1")));
        }
    })
}

/// A flat settings file with its `name` line replaced by `line`, or `line` added at the end: a dotenv file
/// (`sep` `=`, with or without `export`), or the top-level keys of a YAML file (`sep` `:`).
fn set_line(current: &str, name: &str, sep: char, line: &str) -> String {
    let mut out = String::new();
    let mut done = false;
    for l in current.lines() {
        let key = if sep == '=' {
            let t = l.trim();
            t.strip_prefix("export ").unwrap_or(t)
        } else {
            l
        };
        let ours = key
            .strip_prefix(name)
            .is_some_and(|rest| rest.trim_start().starts_with(sep));
        if !ours {
            out.push_str(l);
            out.push('\n');
        } else if !done {
            out.push_str(line);
            out.push('\n');
            done = true;
        }
    }
    if !done {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// One item of a YAML list: its first line, the line after its last, and the column its keys start at.
struct Item {
    start: usize,
    end: usize,
    column: usize,
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The items of the top-level `models:` list of Continue's config.yaml (docs.continue.dev/reference).
// ponytail: reads block-style YAML by its indentation, as Continue writes it; a flow-style list (`models: [{...}]`)
// is not seen. A YAML parser that keeps comments if that bites.
fn continue_models(lines: &[&str]) -> Vec<Item> {
    let mut out = Vec::new();
    let mut section = "";
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let text = line.trim_start();
        if indent(line) == 0 && !text.starts_with(['-', '#']) && !text.is_empty() {
            section = text.split(':').next().unwrap_or("");
        }
        if section != "models" || !text.starts_with("- ") {
            i += 1;
            continue;
        }
        let at = indent(line);
        let mut end = i + 1;
        while end < lines.len() && (lines[end].trim().is_empty() || indent(lines[end]) > at) {
            end += 1;
        }
        out.push(Item {
            start: i,
            end,
            column: at + 1 + indent(&text[1..]),
        });
        i = end;
    }
    out
}

/// The line and value of one of an item's own keys.
fn item_key(lines: &[&str], item: &Item, key: &str) -> Option<(usize, String)> {
    (item.start..item.end).find_map(|n| {
        let line = lines[n];
        let text = line.get(item.column..)?;
        // The item's own keys start at its column: after the dash on its first line, after spaces on the others.
        let before = line.get(..item.column)?.trim();
        if !(before.is_empty() || n == item.start && before == "-") {
            return None;
        }
        let value = text.strip_prefix(key)?.strip_prefix(':')?;
        let value = value.split(" #").next().unwrap_or("").trim();
        Some((n, value.trim_matches(['"', '\'']).to_string()))
    })
}

/// Continue's config.yaml with `apiBase` at the gateway's `/v1` on every model of `provider: openai`, the one
/// provider Continue documents `apiBase` for. Other models and every other line stay.
fn continue_config(current: &str, base: &str) -> String {
    let lines: Vec<&str> = current.lines().collect();
    let mut out: Vec<String> = lines.iter().map(|l| (*l).to_string()).collect();
    // From the last item up, so a line added does not move the items still to do.
    for item in continue_models(&lines).into_iter().rev() {
        let Some((provider_line, provider)) = item_key(&lines, &item, "provider") else {
            continue;
        };
        if provider != "openai" {
            continue;
        }
        match item_key(&lines, &item, "apiBase") {
            Some((n, _)) => out[n] = format!("{}apiBase: {base}", &lines[n][..item.column]),
            None => out.insert(
                provider_line + 1,
                format!("{}apiBase: {base}", " ".repeat(item.column)),
            ),
        }
    }
    if out.is_empty() {
        return String::new();
    }
    out.join("\n") + "\n"
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
    let tmp = c.path.with_extension("enterplace-tmp");
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

/// Keeps the file as it is now beside it, as `<name>.enterplace-backup`, before the agent changes it. `None` when there
/// is no file yet.
fn backup(path: &Path, owner: Option<(u32, u32)>) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let mut name = path.as_os_str().to_owned();
    name.push(".enterplace-backup");
    let kept = PathBuf::from(name);
    let err = |e: std::io::Error| format!("{} cannot be written: {e}", kept.display());
    std::fs::copy(path, &kept).map_err(err)?;
    #[cfg(unix)]
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(&kept, Some(uid), Some(gid)).map_err(err)?;
    }
    #[cfg(not(unix))]
    let _ = owner;
    Ok(Some(kept))
}

/// The files that point `tool` at the gateway, each as it is and as it should be. Every path and key is one the
/// tool's own documentation names; the key or sign-in stays the person's.
fn changes(p: &Paths, tool: &str, profile: &Profile) -> Result<Vec<Change>, String> {
    let gateway = profile.gateway.as_str();
    let h = &p.home;
    let v1 = format!("{gateway}/v1");
    Ok(match tool {
        "claude-code" => {
            // Only into the person's own settings: a managed file outside the home may be readable by others.
            let person = saved(h, "key=").filter(|_| p.claude_settings.starts_with(h));
            vec![plan(p.claude_settings.clone(), |c| {
                claude_settings(c, gateway, person.as_deref(), profile.coding_agents)
            })?]
        }
        "codex" => vec![plan(h.join(".codex/config.toml"), |c| {
            Ok(codex_config(c, gateway))
        })?],
        "opencode" => vec![plan(p.opencode_config(), |c| opencode_config(c, gateway))?],
        "kilo-code" => vec![plan(h.join(".config/kilo/kilo.json"), |c| {
            opencode_config(c, gateway)
        })?],
        "continue" => vec![plan(h.join(".continue/config.yaml"), |c| {
            Ok(continue_config(c, &v1))
        })?],
        "zed" => vec![plan(p.zed_settings(), |c| zed_config(c, gateway))?],
        // Gemini CLI and Qwen Code read `.env` in their own folder of the home (their docs, "Environment variables
        // and .env files").
        "gemini-cli" => vec![plan(h.join(".gemini/.env"), |c| {
            Ok(set_line(
                c,
                "GOOGLE_GEMINI_BASE_URL",
                '=',
                &format!("GOOGLE_GEMINI_BASE_URL={gateway}"),
            ))
        })?],
        "qwen-code" => vec![
            plan(h.join(".qwen/.env"), |c| {
                Ok(set_line(
                    c,
                    "OPENAI_BASE_URL",
                    '=',
                    &format!("OPENAI_BASE_URL={v1}"),
                ))
            })?,
            plan(h.join(".qwen/settings.json"), |c| qwen_settings(c, gateway))?,
        ],
        // aider.chat/docs/config/aider_conf.html: `openai-api-base` in `.aider.conf.yml` in the home.
        "aider" => vec![plan(h.join(".aider.conf.yml"), |c| {
            Ok(set_line(
                c,
                "openai-api-base",
                ':',
                &format!("openai-api-base: {v1}"),
            ))
        })?],
        _ => Vec::new(),
    })
}

// ---- MCP inventory: the MCP servers each tool is configured with, and whether they go through the gateway. ----

/// Each MCP config file of each tool for this user: (tool, file, the key that holds the servers). Paths from each
/// tool's docs: Claude Desktop (modelcontextprotocol.io quickstart), Claude Code (code.claude.com/docs, mcp and
/// managed-mcp), Cursor (cursor.com/docs/context/mcp), VS Code (code.visualstudio.com, MCP configuration) and Zed
/// (zed.dev/docs/ai/mcp).
fn mcp_files(p: &Paths) -> Vec<(&'static str, PathBuf, &'static str)> {
    let zed = p.zed_settings();
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
/// its arguments, environment or headers), and whether it is Enterplace's MCP gateway (`<gateway>/mcp` or a bundle under
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
        "via_enterplace": via,
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

/// Whether the profile's decisions list `row`'s server, by transport and target, under `kind` (`approved` or
/// `blocked`).
fn decided(decisions: &Value, kind: &str, row: &Value) -> bool {
    decisions[kind].as_array().is_some_and(|list| {
        list.iter()
            .any(|d| d["transport"] == row["transport"] && d["target"] == row["target"])
    })
}

/// Applies the decisions to one list of servers: with `enforcement` `remove`, a blocked server is taken out (with
/// `report`, the default, it stays and the report marks it); with `via_gateway`, an approved
/// HTTP server is pointed at Enterplace's MCP gateway, without the headers that held its own credential, or taken out
/// when the list already has the gateway. Returns what was done, each as its inventory row with an `action`.
fn enforce_list(
    list: &mut Value,
    tool: &str,
    file: &Path,
    gateway: &str,
    decisions: &Value,
) -> Vec<Value> {
    let Some(servers) = list.as_object_mut() else {
        return Vec::new();
    };
    let gateway_mcp = format!("{}/mcp", gateway.trim_end_matches('/'));
    let mut has_gateway = servers
        .iter()
        .any(|(name, entry)| mcp_entry(tool, file, name, entry, gateway)["via_enterplace"] == true);
    let mut done = Vec::new();
    for name in servers.keys().cloned().collect::<Vec<_>>() {
        let Some(entry) = servers.get_mut(&name) else {
            continue;
        };
        let mut row = mcp_entry(tool, file, &name, entry, gateway);
        let blocked = decided(decisions, "blocked", &row);
        let action = if blocked && decisions["enforcement"] == "remove" {
            servers.remove(&name);
            "removed"
        } else if !blocked
            && decisions["via_gateway"] == true
            && row["transport"] == "http"
            && row["via_enterplace"] == false
            && decided(decisions, "approved", &row)
        {
            match entry.as_object_mut() {
                Some(entry) if !has_gateway => {
                    for key in ["url", "serverUrl", "httpUrl"] {
                        if entry.contains_key(key) {
                            entry.insert(key.into(), json!(gateway_mcp));
                        }
                    }
                    entry.remove("headers");
                    has_gateway = true;
                }
                _ => {
                    servers.remove(&name);
                }
            }
            "rewritten"
        } else {
            continue;
        };
        row["action"] = action.into();
        done.push(row);
    }
    done
}

/// Enforces the admin's MCP decisions in each tool's MCP file of this user, keeping the file as it was beside it
/// (`<name>.enterplace-backup`). Returns what was done, for the report. Files outside the home (Claude Code's managed
/// MCP file) are the device management tool's, and stay.
fn mcp_enforce(
    p: &Paths,
    gateway: &str,
    decisions: &Value,
    dry_run: bool,
) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for (tool, file, key) in mcp_files(p) {
        if !file.starts_with(&p.home) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let Ok(mut config) = serde_json::from_str::<Value>(&jsonc(&text)) else {
            continue;
        };
        let mut done = Vec::new();
        if let Some(list) = config.get_mut(key) {
            done.extend(enforce_list(list, tool, &file, gateway, decisions));
        }
        // Claude Code keeps servers added in one project under projects.<path>.mcpServers.
        if file.ends_with(".claude.json")
            && let Some(projects) = config.get_mut("projects").and_then(Value::as_object_mut)
        {
            for (_, project) in projects.iter_mut() {
                if let Some(list) = project.get_mut(key) {
                    done.extend(enforce_list(list, tool, &file, gateway, decisions));
                }
            }
        }
        if done.is_empty() {
            continue;
        }
        for row in &done {
            println!(
                "{} MCP server \"{}\" ({}) in {} ({tool}): {}",
                if dry_run { "would change" } else { "changed" },
                row["server"].as_str().unwrap_or(""),
                row["target"].as_str().unwrap_or(""),
                file.display(),
                row["action"].as_str().unwrap_or("")
            );
        }
        if dry_run {
            continue;
        }
        let kept = backup(&file, p.owner)?;
        let change = Change {
            desired: format!(
                "{}\n",
                serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?
            ),
            path: file,
            matches: false,
        };
        write(&change, p.owner)?;
        for mut row in done {
            row["backup"] = kept
                .as_ref()
                .map(|k| k.display().to_string())
                .unwrap_or_default()
                .into();
            out.push(row);
        }
    }
    Ok(out)
}

/// The device profile, as `GET /device/profile` answers it.
struct Profile {
    gateway: String,
    /// The tools to point at the gateway.
    manage: Vec<String>,
    /// The admin's MCP decisions: `approved`, `blocked`, `via_gateway`, and `enforcement` (`report` or `remove`).
    mcp: Value,
    apps_allowed: Vec<String>,
    apps_denied: Vec<String>,
    /// What people may do in their coding agents, as Claude Code settings.
    coding_agents: CodingAgents,
}

impl Profile {
    fn parse(profile: &Value) -> Result<Self, String> {
        let list = |v: &Value| -> Vec<String> {
            v.as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect()
        };
        Ok(Self {
            gateway: profile["gateway_url"]
                .as_str()
                .ok_or("the profile has no gateway_url")?
                .trim_end_matches('/')
                .to_owned(),
            manage: list(&profile["tools"]),
            mcp: profile["mcp"].clone(),
            apps_allowed: list(&profile["apps"]["allowed"]),
            apps_denied: list(&profile["apps"]["denied"]),
            coding_agents: CodingAgents::from_json(&profile["coding_agents"]).map_err(|e| {
                format!("the profile says {e}. Update this agent to the gateway's version")
            })?,
        })
    }
}

/// Tools this agent has configured before, kept so a later mismatch counts as drift, not first setup.
fn applied_path(p: &Paths) -> PathBuf {
    p.home.join(".config/enterplace/device-applied")
}

/// Applies the profile once and returns the report for the control plane.
fn cycle(p: &Paths, profile: &Profile, dry_run: bool) -> Result<Value, String> {
    let (gateway, manage) = (profile.gateway.as_str(), &profile.manage);
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
        let managed = managed && MANAGEABLE.contains(&tool);
        let wanted = if managed {
            changes(p, tool, profile)?
        } else {
            Vec::new()
        };
        env_needed |= managed;
        let was_applied = applied.iter().any(|a| a == tool);
        let mut drift = false;
        for c in wanted.iter().filter(|c| !c.matches) {
            drift = was_applied;
            if dry_run {
                println!("would write {} ({tool})", c.path.display());
                continue;
            }
            let owner = if c.path.starts_with(&p.home) {
                p.owner
            } else {
                None
            };
            backup(&c.path, owner)?;
            write(c, owner)?;
            println!(
                "{} {} ({tool})",
                if drift { "re-applied" } else { "wrote" },
                c.path.display()
            );
        }
        if managed && !dry_run && !was_applied {
            applied.push(tool.to_owned());
        }
        // Read back after writing, so the report says what the tool will do now.
        let (state, direct) = if inst {
            classify(endpoints(p, tool), gateway)
        } else {
            ("not_installed", Vec::new())
        };
        let mut row = json!({
            "tool": tool,
            "state": state,
            "installed": inst,
            "configured": state == "enterplace",
            "drift": drift,
            "endpoints": direct,
        });
        // A tool no documented file configures stays `installed`, and the report says why.
        if let (true, Some(why)) = (state == "installed", why_not(tool)) {
            row["note"] = why.into();
        }
        tools.push(row);
    }
    if env_needed {
        let c = plan(p.home.join(".config/enterplace/env"), |c| {
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
    // Blocked servers go before the inventory is read, so the report lists what the tools have now.
    let mcp_actions = mcp_enforce(p, gateway, &profile.mcp, dry_run)?;
    let mut mcp = json!(mcp_inventory(p, gateway));
    for warning in mcp_decided(&mut mcp, &profile.mcp) {
        eprintln!("device agent: {warning}");
    }
    let processes = if p.system { running(p.os) } else { Vec::new() };
    Ok(json!({
        "device_id": format!("{host}:{os_user}"),
        "hostname": host,
        "os_user": os_user,
        "email": email,
        "agent_version": env!("CARGO_PKG_VERSION"),
        "os": format!("{:?}", p.os).to_lowercase(),
        "tools": tools,
        "mcp": mcp,
        "mcp_actions": mcp_actions,
        "apps": apps(p, &profile.apps_allowed, &profile.apps_denied, &processes),
    }))
}

/// The person at this device: the name (their email) `enterplace login` saved in the credentials file.
fn person(home: &Path) -> Option<String> {
    saved(home, "name=")
}

/// A line of the credentials file `enterplace login` wrote: `name=` or `key=`.
fn saved(home: &Path, prefix: &str) -> Option<String> {
    std::fs::read_to_string(home.join(".config/enterplace/credentials"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(prefix).map(|v| v.trim().to_owned()))
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

/// Marks each MCP server of the inventory with the admin's decision from the profile (`approved`, `blocked`, or
/// `pending` when there is none), and says which blocked ones this user still has: those of a dry run, and those in
/// a file outside the home, which the agent leaves to the device management tool.
fn mcp_decided(inventory: &mut Value, decisions: &Value) -> Vec<String> {
    let listed = |kind: &str, row: &Value| decided(decisions, kind, row);
    let mut warnings = Vec::new();
    for row in inventory.as_array_mut().into_iter().flatten() {
        if row.get("server").is_none() {
            continue;
        }
        let decision = if listed("blocked", row) {
            warnings.push(format!(
                "MCP server \"{}\" ({}) in {} is blocked by your Enterplace admin. Remove it from {}.",
                row["server"].as_str().unwrap_or(""),
                row["target"].as_str().unwrap_or(""),
                row["tool"].as_str().unwrap_or(""),
                row["file"].as_str().unwrap_or("")
            ));
            "blocked"
        } else if listed("approved", row) {
            "approved"
        } else {
            "pending"
        };
        row["decision"] = decision.into();
    }
    warnings
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
    // The person's Enterplace key from `enterplace login`: the gateway takes the person from it, never from the report,
    // and answers with the profile of their team.
    let key = saved(&p.home, "key=").unwrap_or_default();
    let ask = agent
        .get(&format!("{cp}/device/profile"))
        .set("authorization", &auth)
        .set(crate::enterprise::devices::PERSON_HEADER, &key);
    let profile: Value = ask
        .call()
        .map_err(call_err)?
        .into_json()
        .map_err(|e| e.to_string())?;
    let report = cycle(&p, &Profile::parse(&profile)?, opts.dry_run)?;
    if opts.dry_run {
        println!("would report {report}");
        return Ok(());
    }
    agent
        .post(&format!("{cp}/device/report"))
        .set("authorization", &auth)
        .set(crate::enterprise::devices::PERSON_HEADER, &key)
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

    /// A profile that manages `manage` at `GW`, with no MCP decision and no app list.
    fn profile(manage: &[&str]) -> Profile {
        Profile {
            gateway: GW.into(),
            manage: manage.iter().map(|t| (*t).to_string()).collect(),
            mcp: Value::Null,
            apps_allowed: Vec::new(),
            apps_denied: Vec::new(),
            coding_agents: CodingAgents::default(),
        }
    }

    /// An empty home folder of this test, with one OS's paths whatever machine runs the test.
    fn home_of(test: &str, os: Os) -> Paths {
        let home =
            std::env::temp_dir().join(format!("enterplace-device-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        user_paths(os, home, false)
    }

    fn tool_of(report: &Value, tool: &str) -> Value {
        report["tools"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["tool"] == tool).cloned())
            .unwrap_or_default()
    }

    #[test]
    fn claude_settings_keep_other_keys() -> Result<(), String> {
        let out = claude_settings(
            r#"{"model":"opus","env":{"FOO":"1"}}"#,
            GW,
            None,
            CodingAgents::default(),
        )?;
        let v: Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
        assert_eq!(v["model"], "opus");
        assert_eq!(v["env"]["FOO"], "1");
        assert_eq!(v["env"]["ANTHROPIC_BASE_URL"], GW);
        assert_eq!(
            claude_settings(&out, GW, None, CodingAgents::default())?,
            out,
            "idempotent"
        );
        assert!(claude_settings("not json", GW, None, CodingAgents::default()).is_err());
        let named = claude_settings(&out, GW, Some("enterplace_maya"), CodingAgents::default())?;
        let v: Value = serde_json::from_str(&named).map_err(|e| e.to_string())?;
        assert_eq!(
            v["env"]["ANTHROPIC_CUSTOM_HEADERS"],
            "x-enterplace-user: enterplace_maya"
        );
        assert!(
            v["env"].get("ANTHROPIC_API_KEY").is_none(),
            "the login stays Claude Code's own"
        );
        Ok(())
    }

    #[test]
    fn codex_config_replaces_only_its_parts() {
        let cur = "model = \"o3\"\nmodel_provider = \"openai\"\n\n[model_providers.enterplace]\nbase_url = \"old\"\n\n[profiles.x]\nmodel = \"y\"\n";
        let out = codex_config(cur, GW);
        assert!(out.starts_with("model_provider = \"enterplace\"\nmodel = \"o3\"\n"));
        assert!(!out.contains("openai\""));
        assert!(!out.contains("old"));
        assert!(out.contains("[profiles.x]\nmodel = \"y\"\n"));
        assert!(out.contains("base_url = \"https://gw.example.com/v1\"\nenv_key = \"ENTERPLACE_KEY\"\nwire_api = \"responses\""));
        assert_eq!(codex_config(&out, GW), out, "idempotent");
    }

    #[test]
    fn env_file_keeps_key_lines() {
        let out = env_file(
            "# login\nexport OPENAI_BASE_URL=x\nexport ENTERPLACE_KEY=enterplace_1\n",
            GW,
        );
        assert!(out.contains("export ENTERPLACE_KEY=enterplace_1\n"));
        assert!(!out.contains("=x\n"));
        assert!(out.ends_with("export OPENAI_BASE_URL=https://gw.example.com/v1\n"));
        assert_eq!(env_file(&out, GW), out);
    }

    #[test]
    fn cycle_applies_then_reports_drift() -> Result<(), String> {
        let home = std::env::temp_dir().join(format!("enterplace-device-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".claude")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(home.join(".cursor")).map_err(|e| e.to_string())?;
        let p = paths(Some(&home))?;
        let manage = profile(&["claude-code", "codex"]);
        let tool = tool_of;

        let dry = cycle(&p, &manage, true)?;
        assert_eq!(tool(&dry, "claude-code")["configured"], false);
        assert!(!p.claude_settings.exists(), "dry run writes nothing");

        let r = cycle(&p, &manage, false)?;
        assert_eq!(
            tool(&r, "claude-code"),
            json!({"tool":"claude-code","state":"enterplace","installed":true,"configured":true,"drift":false,"endpoints":[]})
        );
        assert_eq!(tool(&r, "codex")["state"], "not_installed");
        assert_eq!(
            tool(&r, "cursor"),
            json!({"tool":"cursor","state":"installed","installed":true,"configured":false,"drift":false,"endpoints":[],"note":why_not("cursor")})
        );
        assert!(
            tool(&r, "cursor")["note"]
                .as_str()
                .is_some_and(|n| n.contains("Cursor Settings"))
        );
        assert_eq!(r["tools"].as_array().map(Vec::len), Some(TOOLS.len()));
        assert!(home.join(".config/enterplace/env").exists());

        std::fs::write(&p.claude_settings, "{}").map_err(|e| e.to_string())?;
        let r = cycle(&p, &manage, false)?;
        assert_eq!(tool(&r, "claude-code")["drift"], true);
        assert!(
            std::fs::read_to_string(&p.claude_settings)
                .map_err(|e| e.to_string())?
                .contains(GW)
        );
        let r = cycle(&p, &manage, false)?;
        assert_eq!(tool(&r, "claude-code")["drift"], false);
        let _ = std::fs::remove_dir_all(&home);
        Ok(())
    }

    /// The profile's coding agent controls become Claude Code's own settings: blocked is written, allowed is taken
    /// out, and a control the policy does not set leaves the file as it is.
    #[test]
    fn coding_agent_controls_become_claude_code_settings() -> Result<(), String> {
        use enterplace_core::coding_agents::CodingAgents;
        let parse = |v: Value| CodingAgents::from_json(&v);
        let mine = r#"{"permissions":{"deny":["Bash(rm *)"]},"deniedMcpServers":[{"serverName":"filesystem"}]}"#;
        let block =
            parse(json!({"bypass_permissions":"block","auto_mode":"block","browser":"block"}))?;
        let out = claude_settings(mine, GW, None, block)?;
        let v: Value = serde_json::from_str(&out).map_err(|e| e.to_string())?;
        assert_eq!(v["permissions"]["disableBypassPermissionsMode"], "disable");
        assert_eq!(v["permissions"]["deny"], json!(["Bash(rm *)"]));
        assert_eq!(v["disableAutoMode"], "disable");
        let denied: Vec<&str> = v["deniedMcpServers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s["serverName"].as_str())
            .collect();
        assert!(denied.contains(&"filesystem") && denied.contains(&"claude-in-chrome"));
        assert_eq!(claude_settings(&out, GW, None, block)?, out, "idempotent");

        // Unset leaves what is there; allow takes out what block wrote and nothing else.
        assert_eq!(
            claude_settings(&out, GW, None, CodingAgents::default())?,
            out
        );
        let allow =
            parse(json!({"bypass_permissions":"allow","auto_mode":"allow","browser":"allow"}))?;
        let v: Value = serde_json::from_str(&claude_settings(&out, GW, None, allow)?)
            .map_err(|e| e.to_string())?;
        assert!(
            v["permissions"]
                .get("disableBypassPermissionsMode")
                .is_none()
        );
        assert!(v.get("disableAutoMode").is_none());
        assert_eq!(v["deniedMcpServers"], json!([{"serverName": "filesystem"}]));
        assert_eq!(v["permissions"]["deny"], json!(["Bash(rm *)"]));
        Ok(())
    }

    #[test]
    fn cycle_writes_the_controls_and_puts_them_back() -> Result<(), String> {
        let p = home_of("controls", Os::Linux);
        std::fs::create_dir_all(p.home.join(".claude")).map_err(|e| e.to_string())?;
        let mut manage = profile(&["claude-code"]);
        manage.coding_agents = enterplace_core::coding_agents::CodingAgents::from_json(
            &json!({"bypass_permissions": "block"}),
        )?;
        cycle(&p, &manage, false)?;
        let read = || -> Result<Value, String> {
            let text = std::fs::read_to_string(&p.claude_settings).map_err(|e| e.to_string())?;
            serde_json::from_str(&text).map_err(|e| e.to_string())
        };
        assert_eq!(
            read()?["permissions"]["disableBypassPermissionsMode"],
            "disable"
        );
        // Someone takes it out: the next run puts it back and reports the drift.
        std::fs::write(
            &p.claude_settings,
            format!(r#"{{"env":{{"ANTHROPIC_BASE_URL":"{GW}"}}}}"#),
        )
        .map_err(|e| e.to_string())?;
        let r = cycle(&p, &manage, false)?;
        assert_eq!(tool_of(&r, "claude-code")["drift"], true);
        assert_eq!(
            read()?["permissions"]["disableBypassPermissionsMode"],
            "disable"
        );
        let _ = std::fs::remove_dir_all(&p.home);
        Ok(())
    }

    #[test]
    fn a_profile_with_controls_the_agent_does_not_know_is_refused() {
        let bad =
            Profile::parse(&json!({"gateway_url": GW, "coding_agents": {"browser": "maybe"}}));
        assert!(bad.err().is_some_and(|e| e.contains("allow or block")));
    }

    fn put(home: &Path, file: &str, text: &str) -> Result<(), String> {
        let path = home.join(file);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, text).map_err(|e| e.to_string())
    }

    /// Each tool's documented configuration, pointed at a provider, reads as `direct`; at the gateway, as `enterplace`.
    #[test]
    fn tools_configured_for_a_provider_report_direct() -> Result<(), String> {
        // macOS paths: VS Code's and Claude Desktop's files are under Library.
        let p = home_of("direct", Os::Macos);
        let home = p.home.clone();
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
            r#"{"provider":{"enterplace":{"options":{"baseURL":"https://gw.example.com/v1","apiKey":"{env:ENTERPLACE_KEY}"}}}}"#,
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
        // Inspect only: nothing is managed.
        let r = cycle(&p, &profile(&[]), true)?;
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
        assert_eq!(state("github-copilot").0, "enterplace");
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
        assert_eq!(state("kilo-code").0, "enterplace");
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
        let manage = profile(&["claude-code", "codex"]);
        let r = cycle(&p, &manage, false)?;
        for t in ["claude-code", "codex"] {
            let x = r["tools"]
                .as_array()
                .and_then(|a| a.iter().find(|x| x["tool"] == t))
                .cloned()
                .unwrap_or_default();
            assert_eq!(x["state"], "enterplace", "{t}: {x}");
        }
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
            win.zed_settings(),
            home.join("AppData/Roaming/Zed/settings.json")
        );
        assert_eq!(
            win.opencode_config(),
            home.join(".config/opencode/opencode.json")
        );
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
    fn the_mcp_inventory_lists_each_tools_servers_and_which_go_through_enterplace()
    -> Result<(), String> {
        let home =
            std::env::temp_dir().join(format!("enterplace-device-mcp-{}", std::process::id()));
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
            r#"{"mcpServers":{"enterplace":{"type":"http","url":"https://gw.example.com/mcp"}},"projects":{"/repo":{"mcpServers":{"bundle":{"type":"http","url":"https://gw.example.com/mcp/eng?key=abc"}}}}}"#,
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
        assert_eq!(row("enterplace")["via_enterplace"], true);
        assert_eq!(row("bundle")["via_enterplace"], true);
        assert_eq!(row("bundle")["target"], "https://gw.example.com/mcp/eng");
        assert_eq!(row("github")["via_enterplace"], false);
        assert_eq!(row("github")["target"], "https://api.githubcopilot.com/mcp");
        assert_eq!(row("docs")["tool"], "vscode");
        assert_eq!(row("docs")["via_enterplace"], true);
        assert_eq!(row("local")["target"], "srv.exe");
        let text = serde_json::to_string(&found).map_err(|e| e.to_string())?;
        for secret in ["t0ps3cret", "/secret/path", "key=abc", "pw@", "Bearer x"] {
            assert!(!text.contains(secret), "{secret} reported: {text}");
        }
        let _ = std::fs::remove_dir_all(&home);
        Ok(())
    }

    #[test]
    fn the_profile_marks_each_mcp_server_approved_blocked_or_pending() {
        let mut report = json!({"mcp": [
            {"tool": "cursor", "file": "/h/.cursor/mcp.json", "server": "github", "transport": "http", "target": "https://api.githubcopilot.com/mcp"},
            {"tool": "claude-code", "file": "/h/.claude.json", "server": "enterplace", "transport": "http", "target": "https://gw.example.com/mcp"},
            {"tool": "zed", "file": "/h/.config/zed/settings.json", "server": "local", "transport": "stdio", "target": "srv"},
            {"tool": "vscode", "file": "/h/mcp.json", "error": "the file is not JSON"}
        ]});
        let decisions = json!({
            "approved": [{"transport": "http", "target": "https://gw.example.com/mcp"}],
            "blocked": [{"transport": "http", "target": "https://api.githubcopilot.com/mcp"}]
        });
        let warnings = mcp_decided(&mut report["mcp"], &decisions);
        let decision = |i: usize| report["mcp"][i]["decision"].clone();
        assert_eq!(
            (decision(0), decision(1), decision(2), decision(3)),
            (
                json!("blocked"),
                json!("approved"),
                json!("pending"),
                Value::Null
            )
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("github") && warnings[0].contains("/h/.cursor/mcp.json"));
    }

    /// Every tool the agent can configure, each from a provider's address or none to the gateway, through the file
    /// its docs name; then changed back by hand, which is drift, and repaired.
    #[test]
    fn each_manageable_tool_is_pointed_at_the_gateway_and_repaired() -> Result<(), String> {
        let p = home_of("manage", Os::Linux);
        let h = &p.home;
        put(
            h,
            ".claude/settings.json",
            r#"{"env":{"ANTHROPIC_API_KEY":"sk-ant-x"}}"#,
        )?;
        put(h, ".codex/config.toml", "model = \"o3\"\n")?;
        put(h, ".codex/auth.json", "{}")?;
        put(
            h,
            ".config/opencode/opencode.json",
            "// mine\n{\"theme\": \"dark\"}\n",
        )?;
        put(h, ".config/kilo/kilo.json", "{}")?;
        put(
            h,
            ".continue/config.yaml",
            "name: Mine\nmodels:\n  - name: four\n    provider: openai\n    model: gpt-4o\n    apiBase: https://api.openai.com/v1\n    roles:\n      - chat\n  - provider: openai\n    model: gpt-4o-mini\ncontext:\n  - provider: code\n",
        )?;
        put(
            h,
            ".config/zed/settings.json",
            "// Zed settings\n{ \"theme\": \"One\", \"language_models\": { \"openai\": { \"api_url\": \"https://api.openai.com/v1\" } }, }",
        )?;
        put(
            h,
            ".gemini/settings.json",
            r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
        )?;
        put(
            h,
            ".qwen/settings.json",
            r#"{"modelProviders":{"openai":[{"id":"q","envKey":"K","baseUrl":"https://dashscope.aliyuncs.com/compatible-mode/v1"}]},"security":{"auth":{"selectedType":"openai"}}}"#,
        )?;
        put(
            h,
            ".aider.conf.yml",
            "openai-api-key: sk-x\nmodel: gpt-4o\n",
        )?;
        put(h, ".cursor/mcp.json", "{}")?;
        put(
            h,
            ".vscode/extensions/saoudrizwan.claude-dev-3.0.0/package.json",
            "{}",
        )?;
        put(
            h,
            ".vscode/extensions/rooveterinaryinc.roo-cline-3.0.0/package.json",
            "{}",
        )?;

        let before = cycle(&p, &profile(&[]), true)?;
        for t in [
            "claude-code",
            "codex",
            "continue",
            "zed",
            "gemini-cli",
            "qwen-code",
            "aider",
        ] {
            assert_eq!(tool_of(&before, t)["state"], "direct", "{t}");
        }

        let all = profile(&MANAGEABLE);
        let r = cycle(&p, &all, false)?;
        for t in MANAGEABLE {
            let x = tool_of(&r, t);
            assert_eq!(x["state"], "enterplace", "{t}: {x}");
            assert_eq!(x["drift"], false, "{t}: first setup is not drift");
        }
        // What no documented file configures stays `installed`, with the reason.
        for t in ["cursor", "cline", "roo-code"] {
            let x = tool_of(&r, t);
            assert_eq!(x["state"], "installed", "{t}: {x}");
            assert!(
                x["note"]
                    .as_str()
                    .is_some_and(|n| n.contains("no documented file")),
                "{x}"
            );
        }
        // Each file holds the gateway where the tool's docs say, and keeps what else was there.
        let text = |file: &str| read(&h.join(file));
        let json_of = |file: &str| serde_json::from_str::<Value>(&text(file)).unwrap_or_default();
        let opencode = json_of(".config/opencode/opencode.json");
        assert_eq!(opencode["theme"], "dark");
        assert_eq!(
            opencode["provider"]["openai"]["options"]["baseURL"],
            format!("{GW}/v1")
        );
        assert_eq!(
            opencode["provider"]["anthropic"]["options"]["apiKey"],
            "{env:ENTERPLACE_KEY}"
        );
        assert_eq!(
            text(".config/opencode/opencode.json.enterplace-backup"),
            "// mine\n{\"theme\": \"dark\"}\n",
            "the file as it was is kept"
        );
        assert_eq!(
            json_of(".config/kilo/kilo.json")["provider"]["openai"]["options"]["baseURL"],
            format!("{GW}/v1")
        );
        assert_eq!(
            text(".continue/config.yaml"),
            format!(
                "name: Mine\nmodels:\n  - name: four\n    provider: openai\n    model: gpt-4o\n    apiBase: {GW}/v1\n    roles:\n      - chat\n  - provider: openai\n    apiBase: {GW}/v1\n    model: gpt-4o-mini\ncontext:\n  - provider: code\n"
            )
        );
        let zed = json_of(".config/zed/settings.json");
        assert_eq!(zed["theme"], "One");
        assert_eq!(
            zed["language_models"]["openai"]["api_url"],
            format!("{GW}/v1")
        );
        assert_eq!(zed["language_models"]["anthropic"]["api_url"], GW);
        assert_eq!(
            text(".gemini/.env"),
            format!("GOOGLE_GEMINI_BASE_URL={GW}\n")
        );
        assert_eq!(text(".qwen/.env"), format!("OPENAI_BASE_URL={GW}/v1\n"));
        let qwen = json_of(".qwen/settings.json");
        assert_eq!(
            qwen["modelProviders"]["openai"][0]["baseUrl"],
            format!("{GW}/v1")
        );
        assert_eq!(qwen["modelProviders"]["openai"][0]["envKey"], "K");
        assert_eq!(
            text(".aider.conf.yml"),
            format!("openai-api-key: sk-x\nmodel: gpt-4o\nopenai-api-base: {GW}/v1\n")
        );

        // A second pass changes nothing.
        let zed_text = text(".config/zed/settings.json");
        let r = cycle(&p, &all, false)?;
        assert!(MANAGEABLE.iter().all(|t| tool_of(&r, t)["drift"] == false));
        assert_eq!(text(".config/zed/settings.json"), zed_text);

        // Someone points each back at a provider: drift, repaired in the same pass.
        put(h, ".claude/settings.json", "{}")?;
        put(h, ".codex/config.toml", "model = \"o3\"\n")?;
        put(
            h,
            ".config/opencode/opencode.json",
            r#"{"provider":{"openai":{"options":{"baseURL":"https://api.openai.com/v1"}}}}"#,
        )?;
        put(h, ".config/kilo/kilo.json", "{}")?;
        put(
            h,
            ".continue/config.yaml",
            "models:\n  - provider: openai\n    apiBase: https://api.openai.com/v1\n",
        )?;
        put(
            h,
            ".config/zed/settings.json",
            r#"{"language_models":{"anthropic":{"api_url":"https://api.anthropic.com"}}}"#,
        )?;
        put(
            h,
            ".gemini/.env",
            "export GOOGLE_GEMINI_BASE_URL=https://generativelanguage.googleapis.com\nGEMINI_API_KEY=k\n",
        )?;
        put(h, ".qwen/.env", "")?;
        put(
            h,
            ".aider.conf.yml",
            "openai-api-base: https://api.openai.com/v1\n",
        )?;
        let r = cycle(&p, &all, false)?;
        for t in MANAGEABLE {
            let x = tool_of(&r, t);
            assert_eq!(
                (x["state"].clone(), x["drift"].clone()),
                (json!("enterplace"), json!(true)),
                "{t}: {x}"
            );
        }
        assert_eq!(
            text(".gemini/.env"),
            format!("GOOGLE_GEMINI_BASE_URL={GW}\nGEMINI_API_KEY=k\n")
        );
        let r = cycle(&p, &all, false)?;
        assert!(MANAGEABLE.iter().all(|t| tool_of(&r, t)["drift"] == false));

        // A tool the profile does not name is left alone.
        put(
            h,
            ".aider.conf.yml",
            "openai-api-base: https://api.openai.com/v1\n",
        )?;
        let r = cycle(&p, &profile(&["codex"]), false)?;
        assert_eq!(tool_of(&r, "aider")["state"], "direct");
        let _ = std::fs::remove_dir_all(h);
        Ok(())
    }

    #[test]
    fn continue_models_of_another_provider_stay_and_read_direct() {
        let config = "models:\n- name: claude\n  provider: anthropic\n  model: claude-sonnet-4-5\n- name: \"local\"\n  provider: 'openai'   # ours\n  apiBase: \"http://localhost:1234/v1\"\nmcpServers:\n  - name: x\n    provider: openai\n";
        let out = continue_config(config, "https://gw.example.com/v1");
        assert_eq!(
            out,
            "models:\n- name: claude\n  provider: anthropic\n  model: claude-sonnet-4-5\n- name: \"local\"\n  provider: 'openai'   # ours\n  apiBase: https://gw.example.com/v1\nmcpServers:\n  - name: x\n    provider: openai\n"
        );
        assert_eq!(continue_config(&out, "https://gw.example.com/v1"), out);
        assert_eq!(continue_config("", "x"), "", "no file is made for no model");
        let lines: Vec<&str> = out.lines().collect();
        let models = continue_models(&lines);
        assert_eq!(models.len(), 2);
        assert_eq!(item_key(&lines, &models[0], "apiBase"), None);
        assert_eq!(
            item_key(&lines, &models[0], "provider").map(|(_, v)| v),
            Some("anthropic".into())
        );
    }

    #[test]
    fn a_settings_file_that_is_not_json_is_named_and_left() -> Result<(), String> {
        let p = home_of("badjson", Os::Linux);
        put(&p.home, ".config/zed/settings.json", "{ not json")?;
        let Err(e) = cycle(&p, &profile(&["zed"]), false) else {
            return Err("a broken settings file was rewritten".into());
        };
        assert!(
            e.contains("settings.json") && e.contains("fix or delete it"),
            "{e}"
        );
        assert_eq!(
            read(&p.home.join(".config/zed/settings.json")),
            "{ not json"
        );
        let _ = std::fs::remove_dir_all(&p.home);
        Ok(())
    }

    /// By default a blocked server is only reported. With `enforcement` `remove`, it leaves each tool's MCP file,
    /// the file as it was is kept beside it, and the report says what was done. With `via_gateway`, an approved HTTP
    /// server is pointed at Enterplace's MCP gateway.
    #[test]
    fn blocked_mcp_servers_are_reported_or_removed_with_a_backup_and_approved_ones_go_through_the_gateway()
    -> Result<(), String> {
        let p = home_of("enforce", Os::Linux);
        let h = &p.home;
        let desktop = r#"{"mcpServers":{"files":{"command":"/usr/bin/npx","args":["-y","@x/fs"]},"shady":{"command":"shady-mcp"}},"theme":"dark"}"#;
        put(h, ".config/Claude/claude_desktop_config.json", desktop)?;
        put(
            h,
            ".claude.json",
            r#"{"numStartups":7,"mcpServers":{"github":{"type":"http","url":"https://api.githubcopilot.com/mcp/","headers":{"Authorization":"Bearer x"}}},"projects":{"/repo":{"mcpServers":{"shady":{"command":"/opt/shady-mcp"},"docs":{"type":"http","url":"https://docs.example.com/mcp"}}}}}"#,
        )?;
        put(
            h,
            ".cursor/mcp.json",
            r#"{"mcpServers":{"gh":{"url":"https://api.githubcopilot.com/mcp"},"docs":{"url":"https://docs.example.com/mcp?token=abc"}}}"#,
        )?;
        put(
            h,
            ".config/Code/User/mcp.json",
            "{\n  // mine\n  \"servers\": {\"shady\": {\"type\": \"stdio\", \"command\": \"shady-mcp\"}, \"ok\": {\"type\": \"http\", \"url\": \"https://gw.example.com/mcp\"},},\n}",
        )?;
        put(
            h,
            ".config/zed/settings.json",
            r#"{"theme":"One","context_servers":{"shady":{"command":{"path":"shady-mcp","args":[]}},"pending":{"command":"other"}}}"#,
        )?;
        let mut all = profile(&[]);
        all.mcp = json!({
            "blocked": [{"transport": "stdio", "target": "shady-mcp"}],
            "approved": [
                {"transport": "http", "target": "https://api.githubcopilot.com/mcp"},
                {"transport": "http", "target": "https://docs.example.com/mcp"}
            ],
        });

        // A dry run changes no file and says what is blocked.
        let dry = cycle(&p, &all, true)?;
        assert_eq!(dry["mcp_actions"], json!([]));
        assert_eq!(
            read(&h.join(".config/Claude/claude_desktop_config.json")),
            desktop
        );
        assert!(
            dry["mcp"].as_array().is_some_and(|m| m
                .iter()
                .filter(|r| r["decision"] == "blocked")
                .count()
                == 4),
            "{dry}"
        );

        // Report mode, the default: each blocked server is marked in the report and no file changes.
        let reported = cycle(&p, &all, false)?;
        assert_eq!(reported["mcp_actions"], json!([]));
        assert!(
            reported["mcp"].as_array().is_some_and(|m| m
                .iter()
                .filter(|r| r["decision"] == "blocked")
                .count()
                == 4),
            "{reported}"
        );
        assert_eq!(
            read(&h.join(".config/Claude/claude_desktop_config.json")),
            desktop
        );
        assert!(
            !h.join(".config/Claude/claude_desktop_config.json.enterplace-backup")
                .exists()
        );

        all.mcp["enforcement"] = json!("remove");
        let r = cycle(&p, &all, false)?;
        let actions = r["mcp_actions"].as_array().cloned().unwrap_or_default();
        assert_eq!(actions.len(), 4, "{actions:?}");
        assert!(
            actions
                .iter()
                .all(|a| a["action"] == "removed" && a["server"] == "shady")
        );
        let tools: Vec<&str> = actions.iter().filter_map(|a| a["tool"].as_str()).collect();
        assert_eq!(tools, ["claude-desktop", "claude-code", "vscode", "zed"]);
        // As paths, so Windows' separators compare equal.
        assert_eq!(
            actions[0]["backup"].as_str().map(PathBuf::from),
            Some(h.join(".config/Claude/claude_desktop_config.json.enterplace-backup"))
        );
        assert_eq!(
            read(&h.join(".config/Claude/claude_desktop_config.json.enterplace-backup")),
            desktop
        );
        let json_of =
            |file: &str| serde_json::from_str::<Value>(&read(&h.join(file))).unwrap_or_default();
        let desktop_now = json_of(".config/Claude/claude_desktop_config.json");
        assert_eq!(desktop_now["theme"], "dark");
        assert!(
            desktop_now["mcpServers"]["shady"].is_null()
                && desktop_now["mcpServers"]["files"].is_object()
        );
        let claude = json_of(".claude.json");
        assert_eq!(claude["numStartups"], 7);
        assert!(claude["projects"]["/repo"]["mcpServers"]["shady"].is_null());
        assert!(claude["projects"]["/repo"]["mcpServers"]["docs"].is_object());
        assert!(json_of(".config/Code/User/mcp.json")["servers"]["shady"].is_null());
        let zed = json_of(".config/zed/settings.json");
        assert!(
            zed["context_servers"]["shady"].is_null()
                && zed["context_servers"]["pending"].is_object()
        );
        // Nothing blocked is left, an approved server stays where it points, and a second pass does nothing.
        assert!(
            r["mcp"]
                .as_array()
                .is_some_and(|m| m.iter().all(|x| x["decision"] != "blocked")),
            "{r}"
        );
        assert_eq!(
            claude["mcpServers"]["github"]["url"],
            "https://api.githubcopilot.com/mcp/"
        );
        assert_eq!(cycle(&p, &all, false)?["mcp_actions"], json!([]));

        // The profile sends approved HTTP servers through the gateway: one entry per file becomes the gateway,
        // without the header that held the server's own credential; another approved one beside it goes.
        all.mcp["via_gateway"] = json!(true);
        let r = cycle(&p, &all, false)?;
        let actions = r["mcp_actions"].as_array().cloned().unwrap_or_default();
        assert_eq!(actions.len(), 4, "{actions:?}");
        assert!(actions.iter().all(|a| a["action"] == "rewritten"));
        let claude = json_of(".claude.json");
        assert_eq!(
            claude["mcpServers"]["github"],
            json!({"type": "http", "url": "https://gw.example.com/mcp"})
        );
        assert_eq!(
            claude["projects"]["/repo"]["mcpServers"]["docs"]["url"],
            "https://gw.example.com/mcp"
        );
        let cursor = json_of(".cursor/mcp.json");
        assert_eq!(
            cursor["mcpServers"],
            json!({"gh": {"url": "https://gw.example.com/mcp"}})
        );
        assert!(!read(&h.join(".cursor/mcp.json")).contains("token=abc"));
        assert!(
            r["mcp"].as_array().is_some_and(|m| m
                .iter()
                .filter(|x| x["transport"] == "http")
                .all(|x| x["via_enterplace"] == true)),
            "{r}"
        );
        assert_eq!(cycle(&p, &all, false)?["mcp_actions"], json!([]));
        let _ = std::fs::remove_dir_all(h);
        Ok(())
    }

    #[test]
    fn installed_apps_are_reported_as_the_profile_allows_or_denies_them() -> Result<(), String> {
        let p = home_of("apps", Os::Macos);
        let h = &p.home;
        put(h, "Applications/ChatGPT.app/Contents/Info.plist", "")?;
        put(h, ".ollama/history", "")?;
        put(h, ".cursor/mcp.json", "{}")?;
        let status = |r: &Value, app: &str| {
            r["apps"]
                .as_array()
                .and_then(|a| a.iter().find(|x| x["app"] == app))
                .map(|x| x["status"].clone())
                .unwrap_or_default()
        };
        let mut lists = profile(&[]);
        let r = cycle(&p, &lists, true)?;
        assert_eq!(r["apps"].as_array().map(Vec::len), Some(3), "{}", r["apps"]);
        assert_eq!(status(&r, "chatgpt"), "unlisted");
        assert_eq!(
            r["apps"][0],
            json!({"app": "cursor", "status": "unlisted", "installed": true, "running": false})
        );

        lists.apps_denied = vec!["chatgpt".into()];
        let r = cycle(&p, &lists, true)?;
        assert_eq!(
            (status(&r, "chatgpt"), status(&r, "ollama")),
            (json!("denied"), json!("unlisted"))
        );

        // With an allow list, what it does not name is denied.
        lists.apps_denied.clear();
        lists.apps_allowed = vec!["cursor".into()];
        let r = cycle(&p, &lists, true)?;
        assert_eq!(
            (
                status(&r, "cursor"),
                status(&r, "chatgpt"),
                status(&r, "ollama")
            ),
            (json!("allowed"), json!("denied"), json!("denied"))
        );

        // A running app counts though no install was found; `claude` (Claude Code) is not the desktop app on macOS.
        let found = apps(
            &p,
            &[],
            &["perplexity".into()],
            &["Perplexity".into(), "claude".into()],
        );
        assert!(found.contains(&json!({"app": "perplexity", "status": "denied", "installed": false, "running": true})), "{found:?}");
        assert!(!found.iter().any(|a| a["app"] == "claude-desktop"));
        assert!(
            app_names().contains(&"lm-studio")
                && app_names().len() == TOOLS.len() + OTHER_APPS.len()
        );
        let _ = std::fs::remove_dir_all(h);
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
            "enterplace"
        );
        assert_eq!(classify(vec!["${input:key}".into()], GW).0, "installed");
    }
}
