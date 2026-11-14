# MDM packaging for the Gantry device agent (plan 6.4, levels 1 and 2)

The agent (`gantry device`) runs as a root LaunchDaemon. Every 5 minutes it reads the device profile from your
Gantry gateway (license feature `devices`) and, for the person signed in at the screen, points Claude Code (managed
settings in `/Library/Application Support/ClaudeCode/managed-settings.json`), Codex (`~/.codex/config.toml`) and the
shell (`~/.config/gantry/env`) at the gateway. It puts them back if someone changes them, and reports every coding tool
it finds (Claude Code, Codex, Cursor, GitHub Copilot, Zed, JetBrains AI, Qwen Code, Gemini CLI, Kilo Code, Roo Code,
Claude Desktop) with whether it goes through Gantry or calls a provider directly. Owners read it on the console's
Devices page. Docs: https://gantry-docs.eliran.me/operations/devices/

| File | What it is |
|---|---|
| `me.gantry.device.plist` | The LaunchDaemon. `CONTROL_PLANE_URL` (your gateway's address) is filled in by `build-pkg.sh`. |
| `build-pkg.sh` | Builds a signed-ready `.pkg` with `pkgbuild`: binary in `/usr/local/bin`, daemon loaded on install. |
| `gantry-device-token.mobileconfig` | Delivers the enrolment token as a managed preference (`me.gantry.device`, key `EnrolmentToken`). |
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

## States

Each tool is reported as `not_installed`, `installed` (found, no endpoint readable), `gantry` (pointed at the gateway)
or `direct` (pointed at a provider, or holding a provider key or login). Claude Code and Codex are configured by the
agent; the others are only inspected. Blocking direct provider traffic (level 3) needs the device spike, plan item 0.5,
on a real Mac with admin rights.
