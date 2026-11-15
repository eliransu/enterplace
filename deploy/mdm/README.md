# MDM packaging for the Gantry device agent (plan 6.4, levels 1 and 2)

On macOS the agent (`gantry device`) runs as a root LaunchDaemon; Linux and Windows are below. Every 5 minutes it reads the device profile from your
Gantry gateway (license feature `devices`) and, for the person signed in at the screen, points the tools the profile
names at the gateway: Claude Code (managed settings in `/Library/Application Support/ClaudeCode/managed-settings.json`),
Codex (`~/.codex/config.toml`), OpenCode, Kilo CLI, Continue, Zed, Gemini CLI, Qwen Code and Aider, each through the
file it documents, and the shell (`~/.config/gantry/env`). It puts them back if someone changes them, takes MCP servers
an admin blocked out of the tools' MCP files (keeping each file as it was beside it, `<name>.gantry-backup`), and
reports every coding tool, MCP server and AI app it finds. Owners read it on the console's Devices page. Docs:
https://gantry-docs.eliran.me/operations/devices/ and, for Intune, Jamf, Kandji and Linux step by step,
https://gantry-docs.eliran.me/operations/device-deployment/

| File | What it is |
|---|---|
| `me.gantry.device.plist` | The LaunchDaemon. `CONTROL_PLANE_URL` (your gateway's address) is filled in by `build-pkg.sh`. |
| `build-pkg.sh` | Builds a signed-ready `.pkg` with `pkgbuild`: binary in `/usr/local/bin`, daemon loaded on install. |
| `gantry-device-token.mobileconfig` | Delivers the enrolment token as a managed preference (`me.gantry.device`, key `EnrolmentToken`). |
| `gantry-device.service`, `install-linux.sh` | The systemd unit, and the script that installs the binary, the token and the unit on Linux. |
| `windows/install.ps1` | The Windows installer: binary, token file and the scheduled task at sign-in. Deployed by Intune as a Win32 app. |
| `level3-block-providers.mobileconfig.template` | **UNTESTED** sketch for level 3. Do not deploy before the device spike (plan 0.5) passes. |

## Steps

1. On the console's Devices page, create an enrolment token (a label, a team or none, days valid) and, if the
   default does not fit, set the device profile (gateway URL, which tools to manage). Or with an admin key:
   `curl -X POST https://gantry.example.com/console/devices/tokens -H "Authorization: Bearer $GANTRY_ADMIN_KEY" -d '{"label": "jamf"}'`.
2. Build the package on a Mac:
   ```sh
   cargo build --release
   deploy/mdm/build-pkg.sh https://gantry.example.com
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
5. Each person runs `gantry login <gateway url>` once on their machine. The agent sends the key that saves
   (`~/.config/gantry/credentials`) with every report, and the gateway takes the person from it; a machine where
   nobody has signed in is refused with `person_key_required` until someone does. A device stays bound to the first
   person and token scope that reported it.
6. Deploy the package. The agent's log is `/var/log/gantry-device.log`. Devices show up on the Devices page after the
   first run; one not seen in 24 hours is flagged. A token expires after the days it was made for: deliver a new one
   before then.

Try it by hand first: `GANTRY_DEVICE_TOKEN=gantry_dev_... gantry device --control-plane <gateway url> --dry-run`
prints what it would change and the report it would send, and writes nothing.

## Watch mode: Claude Code telemetry for Claude Team and Enterprise seats

People on Claude subscriptions cannot be routed through the gateway; watch mode (license feature `watch`) receives
Claude Code's own telemetry instead. Docs: https://gantry-docs.eliran.me/integrations/claude-team/

1. `GANTRY_ADMIN_KEY=gantry_... gantry watch setup --gateway https://gantry.example.com --team engineering` creates
   a watch token and prints the settings (`--org <org>` for one organization's token). `claude-code-watch.managed-settings.json` here is the same block with
   placeholders.
2. Claude Team and Enterprise: paste the block at claude.ai, Organization settings, Claude Code, Managed settings.
   Nothing is deployed to machines.
3. Otherwise deliver it as Claude Code's managed settings file: `/Library/Application Support/ClaudeCode/managed-settings.json`
   on macOS, `/etc/claude-code/managed-settings.json` on Linux, `C:\Program Files\ClaudeCode\managed-settings.json` on
   Windows. Where the device agent runs it writes the same file and keeps the `env` keys it does not manage, so merge
   the block's `env` into the file instead of replacing it:
   ```sh
   f="/Library/Application Support/ClaudeCode/managed-settings.json"; mkdir -p "$(dirname "$f")"; [ -s "$f" ] || echo '{}' > "$f"
   python3 - "$f" claude-code-watch.managed-settings.json <<'PY'
   import json, sys
   have, add = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
   have.setdefault("env", {}).update(add["env"])
   json.dump(have, open(sys.argv[1], "w"), indent=2)
   PY
   ```
4. A watch token expires after the days it was made for (90 unless `--days`): deliver a new block before then.

## Linux

```sh
sudo GANTRY_DEVICE_TOKEN=gantry_dev_... deploy/mdm/install-linux.sh https://gantry.example.com ./gantry
sudo deploy/mdm/install-linux.sh --uninstall
```

The script installs the binary in `/usr/local/bin/gantry`, the token in `/etc/gantry/device-token` (mode 0600) and
`gantry-device.service` with the control plane URL filled in, then enables and starts it. Its log is
`journalctl -u gantry-device`. As root the agent finds the signed-in person with `who` and works in `/home/<user>`;
Claude Code's managed settings go to `/etc/claude-code/managed-settings.json`. Run as a user (a user unit, or by hand)
it writes that user's own `~/.claude/settings.json`. Cursor and VS Code count as installed when `cursor` or `code` is
on `PATH`.

## Windows

The agent runs as the signed-in person, from a scheduled task at sign-in, so it writes that person's own files
(`%USERPROFILE%\.claude\settings.json`, `%USERPROFILE%\.codex\config.toml`, `%APPDATA%\Zed\settings.json` and so
on). `windows/install.ps1`, run as administrator or as SYSTEM, copies `gantry.exe` to `C:\Program Files\Gantry`,
writes the token to `C:\ProgramData\Gantry\device-token` and registers the task `Gantry device agent`:

```bat
powershell.exe -ExecutionPolicy Bypass -File install.ps1 -ControlPlane https://gantry.example.com -Token gantry_dev_...
powershell.exe -ExecutionPolicy Bypass -File install.ps1 -Uninstall
```

With Intune: wrap the folder holding `gantry.exe` and `install.ps1` with `IntuneWinAppUtil.exe -c <folder> -s install.ps1 -o out`,
add it as a Windows app (Win32) with the two commands above as install and uninstall commands, install behavior
System, and the detection rule "file `C:\Program Files\Gantry\gantry.exe` exists". Leave `-Token` out when a platform
script delivers the token file first. The script is not signed: sign it with your own certificate if your execution
policy asks for it. An MSI was left out on purpose: the install is one file and one task, which a script Intune already
deploys does without a WiX toolchain.

Build the binary on Windows (`cargo build --release -p gantry-enterprise`, `--target aarch64-pc-windows-msvc` for
arm64), or take the `gantry-enterprise-windows-x86_64` artifact of the `device-agent` CI job on `main`.

Cursor and VS Code count as installed when `%LOCALAPPDATA%\Programs\cursor` or `%LOCALAPPDATA%\Programs\Microsoft VS Code`
exists; a command line tool installed with npm is found by its `.cmd` on `PATH`. The shell env file is not read by
Windows shells: set `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` with your device management tool there. Built and
unit-tested in CI on Windows, not run on a Windows fleet yet: the paths follow each tool's documentation.

## Jamf and Kandji

Both take the three macOS pieces above as they are. Jamf Pro: upload the `.mobileconfig` under Configuration Profiles,
the token script under Settings, Scripts and the signed package under Settings, Packages, then one Policy that runs the
script and installs the package, scoped like the profile. Kandji: a Custom Profile for the `.mobileconfig`, a Custom
App (install type Package) for the package with the token script as its preinstall script, both assigned to one
Blueprint.

## MCP inventory and enforcement

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

The same files are where the agent enforces an admin's decisions: a blocked server is taken out, and with the
profile's "Approved MCP servers through Gantry" an approved HTTP server is pointed at `<gateway>/mcp`. The file as it
was is kept beside it as `<name>.gantry-backup`. `managed-mcp.json` is never edited: it is yours to deliver.

## Apps

A profile lists denied and allowed apps. The agent reports which of the coding tools and of ChatGPT, Windsurf, Ollama,
LM Studio and Perplexity are installed (by their installer's documented location) or running (by process name, from
`ps` or `tasklist`), each as `allowed`, `denied` or `unlisted`. It stops no process and removes nothing: remove or
block a denied app with your device management tool.

## States

Each tool is reported as `not_installed`, `installed` (found, no endpoint readable), `gantry` (pointed at the gateway)
or `direct` (pointed at a provider, or holding a provider key or login). The agent configures Claude Code, Codex,
OpenCode, Kilo CLI, Continue, Zed, Gemini CLI, Qwen Code and Aider; Cursor, Cline, Roo Code, JetBrains AI, GitHub
Copilot and Claude Desktop keep their endpoint where no documented file sets it, stay `installed`, and the report says
why. Blocking direct provider traffic (level 3) needs the device spike, plan item 0.5, on a real Mac with admin rights.
