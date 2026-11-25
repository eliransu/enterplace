//! `enterplace diagnose`: one file an operator can attach to a support ticket. It holds what support asks for first
//! (version, configuration, store and audit health, recent refusals, a metrics snapshot) and never a secret: the
//! policy is redacted, the keys file is counted and not copied, and environment variables are named, never shown.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use enterplace_core::config;
use serde_json::{Value, json};

/// What replaces a value that may be a secret.
const REDACTED: &str = "[redacted]";
/// How much of the end of the audit log is read for recent refusals: enough for a busy day, bounded for a big log.
const TAIL_BYTES: u64 = 32 * 1024 * 1024;

/// Writes the bundle to `out`. `metrics` is the address of a running gateway's `/metrics` (`--metrics`, else the
/// policy's `admin_listen`). `more` are files a binary that embeds Enterplace adds (the enterprise license status),
/// as (name, text); they must hold no secret either.
pub fn diagnose(
    policy: &Path,
    keys: Option<&Path>,
    out: &Path,
    metrics: Option<&str>,
    more: &[(String, String)],
) -> Result<(), String> {
    let text = std::fs::read_to_string(policy).map_err(|err| {
        format!(
            "{} cannot be read: {err}. Name the policy the gateway runs with --policy.",
            policy.display()
        )
    })?;
    let loaded = config::load(policy, keys);
    let mut files: Vec<(String, String)> = Vec::new();
    files.push((
        "version.json".into(),
        pretty(&json!({
            "enterplace": enterplace_core::VERSION,
            "source": env!("ENTERPLACE_SOURCE_HASH"),
            "built": env!("ENTERPLACE_BUILD_DATE"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "collected_at": enterplace_core::audit::timestamp(),
        })),
    ));
    files.push(("config.json".into(), pretty(&configuration(&text, &loaded))));
    let store = store_health(policy, keys, &loaded);
    files.push(("store.json".into(), pretty(&store)));
    if let Ok(loaded) = &loaded {
        files.push((
            "audit.json".into(),
            pretty(&audit_health(&loaded.audit_path)),
        ));
        files.push((
            "errors.json".into(),
            pretty(&recent_errors(&loaded.audit_path)),
        ));
    }
    let address = metrics.map(str::to_string).or_else(|| {
        loaded
            .as_ref()
            .ok()
            .and_then(|l| l.admin_listen)
            .map(|a| a.to_string())
    });
    files.push(("metrics.txt".into(), metrics_snapshot(address.as_deref())));
    files.extend(more.iter().cloned());
    let bundle = tar_gz(&files)?;
    std::fs::write(out, bundle).map_err(|err| {
        format!(
            "{} could not be written: {err}. Name a file in a directory you can write with --out.",
            out.display()
        )
    })?;
    println!(
        "Wrote {} ({} files). It holds no key, password or token: the policy is redacted and the keys file is counted, not copied. Look it over, then attach it to your support request.",
        out.display(),
        files.len()
    );
    Ok(())
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default() + "\n"
}

/// The policy as JSON with anything that may be a secret replaced, what it loads to, the keys counted and the
/// environment variables it reads named with whether each is set.
fn configuration(text: &str, loaded: &Result<config::Loaded, Vec<String>>) -> Value {
    let policy = serde_saphyr::from_str::<Value>(text)
        .map(|v| redact(&v))
        .unwrap_or_else(|err| json!(format!("the policy is not YAML Enterplace reads: {err}")));
    let mut variables: BTreeMap<String, &str> = BTreeMap::new();
    collect_env(&policy, &mut variables);
    for (name, _) in std::env::vars() {
        if name.starts_with("ENTERPLACE_") {
            variables.insert(name, "set");
        }
    }
    let loaded = match loaded {
        Ok(l) => {
            let now = enterplace_core::audit::timestamp();
            let keys = if l.store.is_some() {
                json!("kept in the store")
            } else {
                let entries = config::read_keys(&l.keys_path)
                    .ok()
                    .flatten()
                    .and_then(|t| config::key_entries(&l.keys_path, &t).ok())
                    .unwrap_or_default();
                json!({
                    "file_found": l.keys_file_found,
                    "count": entries.len(),
                    "admin": entries.iter().filter(|e| e.admin).count(),
                    "expired": entries.iter().filter(|e| e.expires.as_deref().is_some_and(|x| *x < *now)).count(),
                })
            };
            json!({
                "valid": true,
                "policy_sha256": l.policy_sha256,
                "keys_sha256": l.keys_sha256,
                "providers": l.providers.iter().map(|p| json!({ "name": p.name, "kind": p.kind.word(), "url": strip_userinfo(&p.url) })).collect::<Vec<_>>(),
                "aliases": l.aliases.len(),
                "mcp_servers": l.mcp.len(),
                "store": l.store.is_some(),
                "admin_listen": l.admin_listen.map(|a| a.to_string()),
                "tls_client_certificates": l.tls.client_ca_file.is_some(),
                "keys": keys,
            })
        }
        Err(problems) => json!({ "valid": false, "problems": problems }),
    };
    json!({ "loaded": loaded, "environment": variables, "policy": policy })
}

/// Every `<name>_env: VARIABLE` in the policy, as whether VARIABLE is set.
fn collect_env(value: &Value, out: &mut BTreeMap<String, &'static str>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if let (true, Some(name)) = (k.ends_with("_env"), v.as_str()) {
                    let set = std::env::var_os(name).is_some_and(|v| !v.is_empty());
                    out.insert(name.to_string(), if set { "set" } else { "not set" });
                }
                collect_env(v, out);
            }
        }
        Value::Array(list) => list.iter().for_each(|v| collect_env(v, out)),
        _ => {}
    }
}

/// Whether a field of this name holds a secret when it holds text. `*_env`, `*_file` and `*_path` name where a
/// secret is, not the secret, and are kept.
fn secret_field(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if ["_env", "_file", "_path"].iter().any(|s| name.ends_with(s)) {
        return false;
    }
    [
        "key",
        "secret",
        "token",
        "password",
        "passwd",
        "credential",
        "authorization",
        "cookie",
        "signature",
        "private",
        "dsn",
    ]
    .iter()
    .any(|word| name.contains(word))
}

/// Text that looks like a secret wherever it stands: a known key prefix or a bearer token.
fn secret_text(text: &str) -> bool {
    let lower = text.trim().to_ascii_lowercase();
    [
        "enterplace_",
        "sk-",
        "sk_",
        "akia",
        "asia",
        "ghp_",
        "gho_",
        "xox",
        "bearer ",
        "basic ",
        "eyj",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

/// `https://user:pass@host/x` as `https://[redacted]@host/x`, and a Postgres `password=...` as
/// `password=[redacted]`.
fn strip_userinfo(text: &str) -> String {
    let text = match text.split_once("://") {
        Some((scheme, rest)) => {
            let end = rest.find(['/', '?', '#', ' ']).unwrap_or(rest.len());
            match rest[..end].rfind('@') {
                Some(at) => format!("{scheme}://{REDACTED}{}", &rest[at..]),
                None => text.to_string(),
            }
        }
        None => text.to_string(),
    };
    match text.find("password=") {
        Some(at) => {
            let value = &text[at + "password=".len()..];
            // Quoted ('...' with \' inside) or up to the next space.
            let len = if let Some(quoted) = value.strip_prefix('\'') {
                let mut escaped = false;
                quoted
                    .char_indices()
                    .find(|&(_, c)| {
                        let end = c == '\'' && !escaped;
                        escaped = c == '\\' && !escaped;
                        end
                    })
                    .map_or(value.len(), |(i, _)| i + 2)
            } else {
                value.find(' ').unwrap_or(value.len())
            };
            format!(
                "{}password={REDACTED}{}",
                &text[..at],
                strip_userinfo(&value[len..])
            )
        }
        None => text,
    }
}

/// The policy with every value that may be a secret replaced: fields named like one, every value under `headers`,
/// text that looks like a key, and the login part of URLs.
pub fn redact(value: &Value) -> Value {
    redact_in(value, false)
}

fn redact_in(value: &Value, all: bool) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let hidden = all || k.eq_ignore_ascii_case("headers");
                    let v = match v {
                        Value::String(_) | Value::Number(_) if hidden || secret_field(k) => {
                            json!(REDACTED)
                        }
                        _ => redact_in(v, hidden),
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(list) => Value::Array(list.iter().map(|v| redact_in(v, all)).collect()),
        Value::String(_) if all => json!(REDACTED),
        Value::String(s) if secret_text(s) => json!(REDACTED),
        Value::String(s) => json!(strip_userinfo(s)),
        other => other.clone(),
    }
}

/// Whether the store can be reached and its schema is current, without changing a table.
fn store_health(
    policy: &Path,
    keys: Option<&Path>,
    loaded: &Result<config::Loaded, Vec<String>>,
) -> Value {
    let Ok(loaded) = loaded else {
        return json!({ "checked": false, "why": "the policy does not load; see config.json" });
    };
    if loaded.store.is_none() {
        return json!({ "configured": false });
    }
    let keys = keys.map_or_else(|| loaded.keys_path.clone(), Path::to_path_buf);
    // A diagnosis changes nothing: a schema that is behind is reported, not migrated.
    enterplace_server::store::set_no_migrate(true);
    let opened = enterplace_server::open_store(policy, &keys, &|v| std::env::var(v).ok());
    enterplace_server::store::set_no_migrate(false);
    match opened {
        Ok(Some(store)) => {
            let entries = config::key_entries(&keys, &store.keys_text()).unwrap_or_default();
            json!({
                "configured": true, "reachable": true, "schema": "current",
                "keys": entries.len(), "admin_keys": entries.iter().filter(|e| e.admin).count(),
                "kill_switches": store.kills().len(),
            })
        }
        Ok(None) => {
            json!({ "configured": true, "reachable": false, "error": "the store section could not be read" })
        }
        Err(err) => {
            json!({ "configured": true, "reachable": false, "error": strip_userinfo(&err) })
        }
    }
}

fn audit_health(path: &Path) -> Value {
    let size = std::fs::metadata(path).map(|m| m.len()).ok();
    let chain = match enterplace_core::audit::verify_full(path, None) {
        Ok(s) => json!({
            "intact": true, "records": s.records, "first": s.first,
            "requests": s.requests, "configuration": s.configuration, "admin": s.admin,
        }),
        Err(err) => json!({ "intact": false, "error": err }),
    };
    json!({ "path": path.display().to_string(), "bytes": size, "chain": chain })
}

/// Refusals and failures in the last 24 hours of the audit log, counted by code: no record, person or key.
fn recent_errors(path: &Path) -> Value {
    let Ok(mut file) = std::fs::File::open(path) else {
        return json!({ "read": false, "why": "the audit log cannot be opened" });
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(TAIL_BYTES);
    let mut tail = Vec::new();
    if file.seek(SeekFrom::Start(start)).is_err() || file.read_to_end(&mut tail).is_err() {
        return json!({ "read": false, "why": "the audit log cannot be read" });
    }
    let since = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24);
    let (mut by_code, mut by_status) = (
        BTreeMap::<String, u64>::new(),
        BTreeMap::<String, u64>::new(),
    );
    let mut requests = 0u64;
    // The first line may be cut where the read began: it does not parse and is skipped.
    for line in String::from_utf8_lossy(&tail).lines() {
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let recent = record["time"]
            .as_str()
            .and_then(|t| t.parse::<jiff::Timestamp>().ok())
            .is_some_and(|t| t >= since);
        if !recent {
            continue;
        }
        // A request record carries no `event`; follow-ups (an upstream error) and admin records name theirs.
        if record.get("event").is_none() {
            requests += 1;
        }
        if let Some(code) = record["code"].as_str() {
            *by_code.entry(code.to_string()).or_default() += 1;
        }
        if let Some(status) = record["status"].as_u64().filter(|s| *s >= 400) {
            *by_status.entry(status.to_string()).or_default() += 1;
        }
    }
    json!({
        "window_hours": 24, "partial": start > 0, "requests": requests,
        "by_code": by_code, "by_status": by_status,
    })
}

/// The text of `http://<address>/metrics`, or why there is none. The metrics address serves plain HTTP inside
/// the cluster, so this needs no client beyond a socket.
fn metrics_snapshot(address: Option<&str>) -> String {
    let Some(address) = address else {
        return "Not collected: pass --metrics <host:port>, the address the gateway serves /metrics on (serve --metrics, or admin_listen).\n".into();
    };
    let fetched = (|| -> Result<String, String> {
        use std::net::ToSocketAddrs;
        let addr = address
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("no address")?;
        let timeout = std::time::Duration::from_secs(5);
        let mut stream =
            std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        write!(
            stream,
            "GET /metrics HTTP/1.0\r\nHost: {address}\r\nConnection: close\r\n\r\n"
        )
        .map_err(|e| e.to_string())?;
        let mut reply = String::new();
        stream
            .read_to_string(&mut reply)
            .map_err(|e| e.to_string())?;
        let (head, body) = reply.split_once("\r\n\r\n").ok_or("no HTTP reply")?;
        if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
            return Err(head.lines().next().unwrap_or("").to_string());
        }
        Ok(body.to_string())
    })();
    fetched.unwrap_or_else(|err| {
        format!("Not collected: http://{address}/metrics answered {err}. Check the address and that the gateway is running.\n")
    })
}

/// A gzipped tar of `files` under `enterplace-diagnose/`, in the ustar format every `tar` reads.
fn tar_gz(files: &[(String, String)]) -> Result<Vec<u8>, String> {
    let mtime = jiff::Timestamp::now().as_second().max(0);
    let mut tar = Vec::new();
    for (name, text) in files {
        let mut header = [0u8; 512];
        let path = format!("enterplace-diagnose/{name}");
        if path.len() > 99 {
            return Err(format!("{path} is too long a name for the bundle"));
        }
        let mut put = |at: usize, value: &[u8]| header[at..at + value.len()].copy_from_slice(value);
        put(0, path.as_bytes());
        put(100, b"0000644\0");
        put(108, b"0000000\0");
        put(116, b"0000000\0");
        put(124, format!("{:011o}\0", text.len()).as_bytes());
        put(136, format!("{mtime:011o}\0").as_bytes());
        put(148, b"        ");
        put(156, b"0");
        put(257, b"ustar\0");
        put(263, b"00");
        let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        tar.extend_from_slice(&header);
        tar.extend_from_slice(text.as_bytes());
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar)
        .and_then(|()| gz.finish())
        .map_err(|err| format!("the bundle could not be compressed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_hides_secret_fields_headers_key_text_and_url_logins() {
        let policy = json!({
            "providers": [{ "name": "openai", "url": "https://u:hunter2@api.example.com/v1", "api_key_env": "OPENAI_KEY", "api_key": "plain-secret-1" }],
            "guardrails": [{ "url": "https://g.example.com", "headers": { "X-Team": "abc-secret-2" } }],
            "note": "sk-live-secret-3",
            "console": { "sso": { "client_secret": "secret-4", "client_id": "enterplace" } },
        });
        let text = redact(&policy).to_string();
        for secret in [
            "hunter2",
            "plain-secret-1",
            "abc-secret-2",
            "sk-live-secret-3",
            "secret-4",
        ] {
            assert!(!text.contains(secret), "{secret} in {text}");
        }
        for kept in [
            "OPENAI_KEY",
            "api.example.com",
            "enterplace",
            "g.example.com",
        ] {
            assert!(text.contains(kept), "{kept} missing from {text}");
        }
        let error = strip_userinfo("host='h' password='p\\'w d' dbname='x' failed");
        assert_eq!(error, "host='h' password=[redacted] dbname='x' failed");
    }
}
