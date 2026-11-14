#!/bin/sh
# Builds gantry-device-<version>.pkg: the agent binary in /usr/local/bin and the LaunchDaemon, loaded on install.
# Usage: deploy/mdm/build-pkg.sh <control plane URL> [path to the enterprise gantry binary]
# Needs macOS (pkgbuild). Sign the result with productsign before distributing it through an MDM.
set -eu
CP="${1:?usage: build-pkg.sh <control plane URL> [binary]}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${2:-$HERE/../../target/release/gantry-enterprise}"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$HERE/../../Cargo.toml" | head -1)"
[ -x "$BIN" ] || { echo "no binary at $BIN: run cargo build --release first, or pass its path." >&2; exit 2; }
command -v pkgbuild >/dev/null || { echo "pkgbuild not found: build the package on macOS." >&2; exit 2; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/root/usr/local/bin" "$WORK/root/Library/LaunchDaemons" "$WORK/scripts"
cp "$BIN" "$WORK/root/usr/local/bin/gantry"
sed "s|CONTROL_PLANE_URL|$CP|" "$HERE/me.gantry.device.plist" > "$WORK/root/Library/LaunchDaemons/me.gantry.device.plist"
chmod 755 "$WORK/root/usr/local/bin/gantry"; chmod 644 "$WORK/root/Library/LaunchDaemons/me.gantry.device.plist"
cat > "$WORK/scripts/postinstall" <<'POST'
#!/bin/sh
launchctl bootout system/me.gantry.device 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/me.gantry.device.plist
POST
chmod 755 "$WORK/scripts/postinstall"
OUT="${OUT:-$HERE/gantry-device-$VERSION.pkg}"
pkgbuild --root "$WORK/root" --scripts "$WORK/scripts" --identifier me.gantry.device --version "$VERSION" --install-location / "$OUT"
echo "built $OUT"
