#!/bin/sh
# Installs the gantry CLI from the GitHub Releases of eliransu/gantry.
#
#   curl -fsSL https://gantry.eliran.me/install.sh | sh
#
# It picks the latest stable release, or the rolling `edge` pre-release (built from main) when there is none yet,
# checks the release signature (ssh-keygen, the release key below) and the tarball's SHA256 against SHA256SUMS, and
# puts the binary in ~/.local/bin. The binary is the single Gantry build: without a license key it is the open source
# gateway.
#
# Environment:
#   GANTRY_VERSION       edge, or a tag such as v0.1.0 (default: the latest stable release, else edge)
#   GANTRY_INSTALL_DIR   where to put gantry (default ~/.local/bin); a folder you cannot write, such as
#                        /usr/local/bin, is written with sudo
#   GANTRY_REPO_URL      the repository to download from (default https://github.com/eliransu/gantry); for tests
#   GANTRY_ALLOWED_SIGNERS  an ssh allowed_signers file to verify with in place of the release key; for tests
set -eu

REPO_URL=${GANTRY_REPO_URL:-https://github.com/eliransu/gantry}
VERSION=${GANTRY_VERSION:-}
INSTALL_DIR=${GANTRY_INSTALL_DIR:-${HOME:?HOME is not set; set GANTRY_INSTALL_DIR}/.local/bin}
# The release public key, also in release/allowed_signers of the repository. Public by definition.
RELEASE_KEY='release@gantry ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK9+t0WEkM/799u9M6gxLDZY8KlA50qMWHCwqkRdVNeu'

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
fail() { printf 'gantry install failed: %s\n' "$*" >&2; exit 1; }

# fetch URL FILE: downloads, following redirects. Fails on an HTTP error. Only https unless the repository URL is
# plain http (a local test server).
fetch() {
  if command -v curl > /dev/null 2>&1; then
    case $REPO_URL in
      https://*) curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1" ;;
      *) curl -fsSL -o "$2" "$1" ;;
    esac
  elif command -v wget > /dev/null 2>&1; then
    case $REPO_URL in
      https://*) wget -q --https-only -O "$2" "$1" ;;
      *) wget -q -O "$2" "$1" ;;
    esac
  else
    fail "neither curl nor wget is installed. Install one of them and run this again."
  fi
}

sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum > /dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl > /dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else fail "no sha256sum, shasum or openssl to check the download. Install one of them and run this again."
  fi
}

# The release target of this machine, as in the tarball names.
case $(uname -s) in
  Darwin) os=apple-darwin ;;
  Linux) os=unknown-linux-musl ;;
  *) fail "$(uname -s) is not supported: Gantry ships for macOS and Linux. On Windows use WSL or the container image ghcr.io/eliransu/gantry." ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) fail "the $(uname -m) processor is not supported: Gantry ships for x86_64 and arm64. Use the container image ghcr.io/eliransu/gantry or build from source." ;;
esac
# A shell under Rosetta on Apple silicon reports x86_64: the native binary is the right one.
if [ "$os" = apple-darwin ] && [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2> /dev/null || echo 0)" = 1 ]; then
  arch=aarch64
fi
target=$arch-$os

tmp=$(mktemp -d 2> /dev/null || mktemp -d -t gantry)
trap 'rm -rf "$tmp"' EXIT INT TERM

# The release: the latest stable one, else edge.
if [ -z "$VERSION" ]; then
  if fetch "$REPO_URL/releases/latest/download/SHA256SUMS" "$tmp/SHA256SUMS" 2> /dev/null; then
    base=$REPO_URL/releases/latest/download
    VERSION=latest
  else
    say "No stable release yet: installing edge, the pre-release built from main."
    VERSION=edge
  fi
fi
case $VERSION in
  */* | *..*) fail "GANTRY_VERSION=$VERSION is not a release. Use edge or a tag such as v0.1.0." ;;
  latest) ;;
  edge | v[0-9]*) base=$REPO_URL/releases/download/$VERSION ;;
  *) fail "GANTRY_VERSION=$VERSION is not a release. Use edge or a tag such as v0.1.0." ;;
esac
if [ ! -s "$tmp/SHA256SUMS" ]; then
  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" \
    || fail "could not download SHA256SUMS of release $VERSION from $base. Check the version and your network."
fi
fetch "$base/SHA256SUMS.sig" "$tmp/SHA256SUMS.sig" \
  || fail "could not download SHA256SUMS.sig of release $VERSION from $base."

# The signature first: nothing in SHA256SUMS is used before it verifies.
if [ -n "${GANTRY_ALLOWED_SIGNERS:-}" ]; then
  cp "$GANTRY_ALLOWED_SIGNERS" "$tmp/allowed_signers"
else
  say "$RELEASE_KEY" > "$tmp/allowed_signers"
fi
if command -v ssh-keygen > /dev/null 2>&1; then
  if out=$(ssh-keygen -Y verify -f "$tmp/allowed_signers" -I release@gantry -n gantry-release \
    -s "$tmp/SHA256SUMS.sig" < "$tmp/SHA256SUMS" 2>&1); then
    say "Signature verified: release@gantry"
  else
    case $out in
      *"illegal option"* | *"unknown option"* | *"invalid option"*)
        warn "this ssh-keygen is older than OpenSSH 8.1 and cannot check the release signature; relying on the SHA256 over HTTPS." ;;
      *) fail "the release signature does not verify ($out). Do not use this download; report it at $REPO_URL/issues." ;;
    esac
  fi
else
  warn "ssh-keygen (OpenSSH) is not installed, so the release signature is not checked; relying on the SHA256 over HTTPS."
fi

name=$(awk -v t="-$target.tar.gz" '{ n = $2; if (length(n) > length(t) && substr(n, length(n) - length(t) + 1) == t) print n }' "$tmp/SHA256SUMS" | head -n 1)
[ -n "$name" ] || fail "release $VERSION has no build for $target. See $REPO_URL/releases for what it ships."
case $name in
  */* | .*) fail "unexpected file name in SHA256SUMS: $name" ;;
esac
expected=$(awk -v n="$name" '$2 == n { print $1 }' "$tmp/SHA256SUMS")

say "Downloading $name"
fetch "$base/$name" "$tmp/$name" || fail "could not download $base/$name."
actual=$(sha256_of "$tmp/$name")
[ "$actual" = "$expected" ] \
  || fail "$name does not match its SHA256 in SHA256SUMS (expected $expected, got $actual). Do not use this download."
say "SHA256 verified"

mkdir "$tmp/x"
tar -xzf "$tmp/$name" -C "$tmp/x"
binary=$tmp/x/${name%.tar.gz}/gantry
[ -f "$binary" ] || fail "$name holds no gantry binary."
chmod 755 "$binary"

# Write the folder ourselves when we can, else with sudo.
sudo=
if ! mkdir -p "$INSTALL_DIR" 2> /dev/null || [ ! -w "$INSTALL_DIR" ]; then
  command -v sudo > /dev/null 2>&1 || fail "cannot write $INSTALL_DIR and sudo is not installed. Pick a folder you own: GANTRY_INSTALL_DIR=\$HOME/.local/bin"
  say "Writing $INSTALL_DIR needs sudo."
  sudo=sudo
  $sudo mkdir -p "$INSTALL_DIR"
fi
# Copy then rename, so a running gantry is replaced in one step.
$sudo cp "$binary" "$INSTALL_DIR/.gantry.new"
$sudo chmod 755 "$INSTALL_DIR/.gantry.new"
$sudo mv -f "$INSTALL_DIR/.gantry.new" "$INSTALL_DIR/gantry"

say "Installed $("$INSTALL_DIR/gantry" version 2> /dev/null || echo gantry) to $INSTALL_DIR/gantry"
case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    gantry=gantry
    # An older gantry earlier on the PATH would run instead of the one just installed.
    found=$(command -v gantry 2> /dev/null || true)
    if [ -n "$found" ] && [ "$found" != "$INSTALL_DIR/gantry" ]; then
      gantry=$INSTALL_DIR/gantry
      say ""
      say "Another gantry at $found comes first on your PATH and would run instead of this one."
      say "Remove it ($found), or put $INSTALL_DIR first on your PATH. Until then, run $INSTALL_DIR/gantry."
    fi
    ;;
  *)
    gantry=$INSTALL_DIR/gantry
    say ""
    say "$INSTALL_DIR is not on your PATH. Add it, then open a new terminal:"
    case ${SHELL:-} in
      */zsh) say "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.zshrc" ;;
      */fish) say "  fish_add_path $INSTALL_DIR" ;;
      *) say "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.profile" ;;
    esac
    ;;
esac
say ""
say "Next: $gantry start"
say "(If your shell still runs an old gantry, run: hash -r)"
