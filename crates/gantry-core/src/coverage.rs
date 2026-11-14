//! Coverage: which people's coding tools reach Gantry, from the audit log's request records, and, when device
//! reports are given (the device agent's, as the enterprise console's Devices page downloads them), which tools are
//! installed on each person's devices and which of those call a provider directly.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::path::Path;

use serde::Deserialize;

use crate::audit;

/// One person's use of one tool.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub team: String,
    pub requests: u64,
    pub refused: u64,
    /// The last request's time, or `never`.
    pub last_seen: String,
    /// The person's enrolled devices with the tool installed (for tool `-`, every enrolled device of theirs).
    pub devices: u64,
    /// Of those, the devices where the tool is configured to call a provider directly.
    pub direct: u64,
}

/// Rows by (person, tool). Tool `-` is a person with nothing else to show.
pub type Coverage = BTreeMap<(String, String), Row>;

/// One device as the device agent last reported it.
#[derive(Clone, Debug, Deserialize)]
pub struct Device {
    pub person: String,
    #[serde(default)]
    pub team: String,
    pub device_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub last_seen: String,
    #[serde(default)]
    pub tools: Vec<DeviceTool>,
    /// `macos`, `linux` or `windows`; empty from an agent that does not say.
    #[serde(default)]
    pub os: String,
    /// The MCP servers its tools are configured with.
    #[serde(default)]
    pub mcp: Vec<DeviceMcp>,
}

/// One MCP server a tool on a device is configured with, and the admin's decision on it.
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceMcp {
    pub tool: String,
    pub server: String,
    /// `http` or `stdio`.
    pub transport: String,
    /// The URL without query or login, or the command's file name.
    pub target: String,
    /// Whether it is Gantry's MCP gateway.
    #[serde(default)]
    pub via_gantry: bool,
    /// `approved`, `blocked` or `pending`.
    #[serde(default)]
    pub decision: String,
}

/// One tool on a device. `state` is `not_installed`, `installed` (found, its endpoint not set or not readable),
/// `gantry` (pointed at the gateway) or `direct` (pointed at a provider, or holding a provider key).
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceTool {
    pub tool: String,
    pub state: String,
    /// Where a `direct` tool sends, as its configuration names it.
    #[serde(default)]
    pub endpoints: Vec<String>,
}

/// Requests per person and tool from the request records of the log at `path` and its sealed segments.
pub fn traffic(path: &Path) -> Result<Coverage, String> {
    let mut rows = Coverage::new();
    // Every organization's chain too (`audit: { per_org: true }`).
    let reader = audit::chains_reader(path).map_err(|e| format!("{}: {e}", path.display()))?;
    for line in reader.lines() {
        let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
        let Ok(record) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        // A request's decision record has a verdict and no event; admin records have both, usage and
        // configuration records have no verdict.
        let (Some(verdict), None) = (record["verdict"].as_str(), record.get("event")) else {
            continue;
        };
        let text = |field: &str| record[field].as_str().unwrap_or("-").to_string();
        let row = rows
            .entry((
                text("person"),
                audit::tool_of(record["user_agent"].as_str()),
            ))
            .or_insert_with(|| Row {
                team: text("team"),
                ..Row::default()
            });
        row.requests += 1;
        row.refused += u64::from(verdict != "allow");
        row.last_seen = text("time");
    }
    Ok(rows)
}

/// Adds a row with tool `-` for each (person, team) that has no row yet.
pub fn add_people(rows: &mut Coverage, people: impl IntoIterator<Item = (String, String)>) {
    for (person, team) in people {
        if !rows.keys().any(|(p, _)| *p == person) {
            rows.insert(
                (person, "-".into()),
                Row {
                    team,
                    last_seen: "never".into(),
                    ..Row::default()
                },
            );
        }
    }
}

/// Counts each device's installed tools into `rows`, adding rows for tools that never reached Gantry.
pub fn add_devices(rows: &mut Coverage, devices: &[Device]) {
    for device in devices {
        // By name, so a report listing a tool twice counts it once.
        let installed: BTreeMap<&str, &DeviceTool> = device
            .tools
            .iter()
            .filter(|t| t.state != "not_installed")
            .map(|t| (t.tool.as_str(), t))
            .collect();
        for tool in installed.values() {
            let row = rows
                .entry((device.person.clone(), tool.tool.clone()))
                .or_insert_with(|| Row {
                    team: device.team.clone(),
                    last_seen: "never".into(),
                    ..Row::default()
                });
            row.devices += 1;
            row.direct += u64::from(tool.state == "direct");
        }
        if installed.is_empty() {
            let row = rows
                .entry((device.person.clone(), "-".into()))
                .or_insert_with(|| Row {
                    team: device.team.clone(),
                    last_seen: "never".into(),
                    ..Row::default()
                });
            row.devices += 1;
        }
    }
    // A person first known as a key holder who sent nothing keeps a `-` row only while it is all there is.
    let people: BTreeSet<String> = rows
        .keys()
        .filter(|(_, tool)| tool != "-")
        .map(|(person, _)| person.clone())
        .collect();
    rows.retain(|(person, tool), row| tool != "-" || row.devices > 0 || !people.contains(person));
}

/// Reads device reports as the console's `devices.json` holds them.
pub fn read_devices(path: &Path) -> Result<Vec<Device>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| {
        format!(
            "{} is not a device report list ({e}). Download it from the console's Devices page (devices.json).",
            path.display()
        )
    })
}
