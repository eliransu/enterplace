# MDM packaging for the Gantry device agent (plan 6.4, levels 1 and 2)

On macOS the agent (`gantry device`) runs as a root LaunchDaemon; Linux and Windows are below. Every 5 minutes it reads the org's device
profile from the control plane and, for the person signed in at the screen, points Claude Code (managed settings in
`/Library/Application Support/ClaudeCode/managed-settings.json`), Codex (`~/.codex/config.toml`) and the shell
(`~/.config/gantry/env`) at the gateway. It puts them back if someone changes them and reports coverage, which owners
read at `/o/<org>/devices/coverage` in the app.

| File | What it is |
|---|---|
| `me.gantry.device.plist` | The LaunchDaemon. `CONTROL_PLANE_URL` is filled in by `build-pkg.sh`. |
| `build-pkg.sh` | Builds a signed-ready `.pkg` with `pkgbuild`: binary in `/usr/local/bin`, daemon loaded on install. |
| `gantry-device-token.mobileconfig` | Delivers the enrolment token as a managed preference (`me.gantry.device`, key `EnrolmentToken`). |
| `level3-block-providers.mobileconfig.template` | **UNTESTED** sketch for level 3. Do not deploy before the device spike (plan 0.5) passes. |

## Steps

1. In the app, open Devices (linked from Gateways), create an enrolment token, and set the device profile
   (gateway URL, which tools to manage).
2. Build the package on a Mac:
   ```sh
   cargo build --release
   deploy/mdm/build-pkg.sh https://gantry-control.eliran.me
   productsign --sign "Developer ID Installer: <your org>" deploy/mdm/gantry-device-0.0.1.pkg gantry-device-signed.pkg
   ```
3. In Jamf or Intune, upload `gantry-device-token.mobileconfig` with `PASTE_ENROLMENT_TOKEN` replaced by the token.
4. The agent reads a file, not the preference domain, so it never has to parse plists. Deploy this script with the
   package (Jamf policy script, Intune shell script, run as root) so the token lands where the agent looks:
   ```sh
   mkdir -p "/Library/Application Support/Gantry" && umask 077 && \
   /usr/bin/defaults read "/Library/Managed Preferences/me.gantry.device" EnrolmentToken \
     > "/Library/Application Support/Gantry/device-token"
   ```
   The agent's token order: `GANTRY_DEVICE_TOKEN`, then the file named by `GANTRY_DEVICE_TOKEN_FILE`, then
   `/Library/Application Support/Gantry/device-token`.
5. Deploy the package. The agent's log is `/var/log/gantry-device.log`. Devices show up in the coverage report after
   the first run; one not seen in 24 hours is flagged.

Try it by hand first: `GANTRY_DEVICE_TOKEN=gantry_dev_... gantry device --control-plane <url> --dry-run`
prints what it would change and the report it would send, and writes nothing.

## Linux

`gantry-device.service` runs the agent as root under systemd. Replace `CONTROL_PLANE_URL`, put the token in
`/etc/gantry/device-token` (mode 0600), and `systemctl enable --now gantry-device`. As root it finds the signed-in
person with `who` and works in `/home/<user>`; Claude Code's managed settings go to
`/etc/claude-code/managed-settings.json`. Run as a user (a user unit, or by hand) it writes that user's own
`~/.claude/settings.json`. Cursor and VS Code count as installed when `cursor` or `code` is on `PATH`.

## Windows

The agent runs as the signed-in user, from a scheduled task at logon, so it writes `%USERPROFILE%\.claude\settings.json`,
`%USERPROFILE%\.codex\config.toml` and `%USERPROFILE%\.config\gantry\env`. The token is read from
`C:\ProgramData\Gantry\device-token`, which Intune or Group Policy can deliver. Create the task with:

```bat
schtasks /Create /TN "Gantry device agent" /SC ONLOGON /RL LIMITED ^
  /TR "\"C:\Program Files\Gantry\gantry.exe\" device --control-plane https://gantry-control.example.com"
```

Cursor and VS Code count as installed when `%LOCALAPPDATA%\Programs\cursor` or `%LOCALAPPDATA%\Programs\Microsoft VS Code`
exists. The shell env file is not read by Windows shells: set `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` with your
device management tool there. Not run on a Windows machine yet: the paths follow each tool's documentation.

## MCP inventory

Every report also lists the MCP servers configured in each tool, with `tool`, `file`, `server`, `transport` (`http` or
`stdio`), `target` (the URL without its query or login, or the command's file name) and `via_gantry` (whether the URL is
the gateway's `/mcp` or a bundle under it). Arguments, environment variables and headers are never reported.

| Tool | macOS | Linux | Windows | Key |
|---|---|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` | `mcpServers` |
| Claude Code | `~/.claude.json` (and each project under `projects`), managed `managed-mcp.json` | same | same (`C:\Program Files\ClaudeCode\managed-mcp.json`) | `mcpServers` |
| Cursor | `~/.cursor/mcp.json` | same | `%USERPROFILE%\.cursor\mcp.json` | `mcpServers` |
| VS Code | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` | `%APPDATA%\Code\User\mcp.json` | `servers` |
| Zed | `~/.config/zed/settings.json` | `~/.config/zed/settings.json` | `%APPDATA%\Zed\settings.json` | `context_servers` |

VS Code's and Zed's files may hold comments and trailing commas; they are read as such. Project files (`.mcp.json`,
`.cursor/mcp.json`, `.vscode/mcp.json`) are not read: the agent does not walk the disk for repositories.

## Levels

0 not seen, 1 installed only, 2 configured through Gantry. Cursor and VS Code are detected (level 1) but not
configured by the agent. Level 3 (enforced) needs the device spike, plan item 0.5, on a real Mac with admin rights.
