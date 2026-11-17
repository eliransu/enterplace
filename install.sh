#!/bin/sh
# Installs the enterplace CLI from the GitHub Releases of eliransu/enterplace.
#
#   curl -fsSL https://enterplace.dev/install.sh | sh
#
# It picks the latest stable release, or the rolling `edge` pre-release (built from main) when there is none yet,
# checks the release signature (ssh-keygen, the release key below) and the tarball's SHA256 against SHA256SUMS, and
# puts the binary in ~/.local/bin. The binary is the single Enterplace build: without a license key it is the open source
# gateway.
#
# Environment:
#   ENTERPLACE_VERSION       edge, or a tag such as v0.1.0 (default: the latest stable release, else edge)
#   ENTERPLACE_INSTALL_DIR   where to put enterplace (default ~/.local/bin); a folder you cannot write, such as
#                        /usr/local/bin, is written with sudo
#   ENTERPLACE_NO_MODIFY_PATH=1  leave the shell's startup file alone (by default the install folder is added to the
#                        PATH in ~/.zshrc, ~/.bashrc or ~/.bash_profile on macOS, fish's conf.d, or ~/.profile, once)
#   ENTERPLACE_REPO_URL      the repository to download from (default https://github.com/eliransu/enterplace); for tests
#   ENTERPLACE_ALLOWED_SIGNERS  an ssh allowed_signers file to verify with in place of the release key; for tests
set -eu

REPO_URL=${ENTERPLACE_REPO_URL:-https://github.com/eliransu/enterplace}
VERSION=${ENTERPLACE_VERSION:-}
INSTALL_DIR=${ENTERPLACE_INSTALL_DIR:-${HOME:?HOME is not set; set ENTERPLACE_INSTALL_DIR}/.local/bin}
# The release public key, also in release/allowed_signers of the repository. Public by definition.
RELEASE_KEY='release@enterplace ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK9+t0WEkM/799u9M6gxLDZY8KlA50qMWHCwqkRdVNeu'

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
fail() { printf 'enterplace install failed: %s\n' "$*" >&2; exit 1; }

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
  *) fail "$(uname -s) is not supported: Enterplace ships for macOS and Linux. On Windows use WSL or the container image ghcr.io/eliransu/enterplace." ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) fail "the $(uname -m) processor is not supported: Enterplace ships for x86_64 and arm64. Use the container image ghcr.io/eliransu/enterplace or build from source." ;;
esac
# A shell under Rosetta on Apple silicon reports x86_64: the native binary is the right one.
if [ "$os" = apple-darwin ] && [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2> /dev/null || echo 0)" = 1 ]; then
  arch=aarch64
fi
target=$arch-$os

tmp=$(mktemp -d 2> /dev/null || mktemp -d -t enterplace)
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
  */* | *..*) fail "ENTERPLACE_VERSION=$VERSION is not a release. Use edge or a tag such as v0.1.0." ;;
  latest) ;;
  edge | v[0-9]*) base=$REPO_URL/releases/download/$VERSION ;;
  *) fail "ENTERPLACE_VERSION=$VERSION is not a release. Use edge or a tag such as v0.1.0." ;;
esac
if [ ! -s "$tmp/SHA256SUMS" ]; then
  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" \
    || fail "could not download SHA256SUMS of release $VERSION from $base. Check the version and your network."
fi
fetch "$base/SHA256SUMS.sig" "$tmp/SHA256SUMS.sig" \
  || fail "could not download SHA256SUMS.sig of release $VERSION from $base."

# The signature first: nothing in SHA256SUMS is used before it verifies.
if [ -n "${ENTERPLACE_ALLOWED_SIGNERS:-}" ]; then
  cp "$ENTERPLACE_ALLOWED_SIGNERS" "$tmp/allowed_signers"
else
  say "$RELEASE_KEY" > "$tmp/allowed_signers"
fi
if command -v ssh-keygen > /dev/null 2>&1; then
  if out=$(ssh-keygen -Y verify -f "$tmp/allowed_signers" -I release@enterplace -n enterplace-release \
    -s "$tmp/SHA256SUMS.sig" < "$tmp/SHA256SUMS" 2>&1); then
    say "Signature verified: release@enterplace"
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
binary=$tmp/x/${name%.tar.gz}/enterplace
[ -f "$binary" ] || fail "$name holds no enterplace binary."
chmod 755 "$binary"

# Write the folder ourselves when we can, else with sudo.
sudo=
if ! mkdir -p "$INSTALL_DIR" 2> /dev/null || [ ! -w "$INSTALL_DIR" ]; then
  command -v sudo > /dev/null 2>&1 || fail "cannot write $INSTALL_DIR and sudo is not installed. Pick a folder you own: ENTERPLACE_INSTALL_DIR=\$HOME/.local/bin"
  say "Writing $INSTALL_DIR needs sudo."
  sudo=sudo
  $sudo mkdir -p "$INSTALL_DIR"
fi
# Copy then rename, so a running enterplace is replaced in one step.
$sudo cp "$binary" "$INSTALL_DIR/.enterplace.new"
$sudo chmod 755 "$INSTALL_DIR/.enterplace.new"
$sudo mv -f "$INSTALL_DIR/.enterplace.new" "$INSTALL_DIR/enterplace"

# add_to_path: puts INSTALL_DIR on the PATH of new terminals through the shell's startup file, once, as rustup and
# bun do, then says the one line that does it in this terminal.
add_to_path() {
  line="export PATH=\"$INSTALL_DIR:\$PATH\""
  now=$line
  case ${SHELL##*/} in
    zsh) rc=${ZDOTDIR:-$HOME}/.zshrc ;;
    bash) if [ "$os" = apple-darwin ]; then rc=$HOME/.bash_profile; else rc=$HOME/.bashrc; fi ;;
    fish)
      rc=${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/enterplace.fish
      line="fish_add_path $INSTALL_DIR"
      now=$line
      ;;
    *) rc=$HOME/.profile ;;
  esac
  say ""
  if [ "${ENTERPLACE_NO_MODIFY_PATH:-}" = 1 ]; then
    say "$INSTALL_DIR is not on your PATH, and ENTERPLACE_NO_MODIFY_PATH=1 leaves $rc as it is. Add this line to it:"
  elif [ -f "$rc" ] && grep -qF "$INSTALL_DIR" "$rc"; then
    say "$rc already adds $INSTALL_DIR to the PATH: new terminals have enterplace. To use it in this terminal now, run:"
  elif mkdir -p "$(dirname "$rc")" 2> /dev/null && printf '\n# Added by the Enterplace installer (https://enterplace.dev)\n%s\n' "$line" >> "$rc" 2> /dev/null; then
    say "Added $INSTALL_DIR to your PATH in $rc: new terminals have enterplace. To use it in this terminal now, run:"
  else
    say "$rc could not be written. Add this line to your shell's startup file, and run it in this terminal:"
  fi
  say ""
  say "  $now"
}

say "Installed $("$INSTALL_DIR/enterplace" version 2> /dev/null || echo enterplace) to $INSTALL_DIR/enterplace"
case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    enterplace=enterplace
    # An older enterplace earlier on the PATH would run instead of the one just installed.
    found=$(command -v enterplace 2> /dev/null || true)
    if [ -n "$found" ] && [ "$found" != "$INSTALL_DIR/enterplace" ]; then
      enterplace=$INSTALL_DIR/enterplace
      say ""
      say "Another enterplace at $found comes first on your PATH and would run instead of this one."
      say "Remove it ($found), or put $INSTALL_DIR first on your PATH. Until then, run $INSTALL_DIR/enterplace."
    fi
    ;;
  *)
    enterplace=enterplace
    add_to_path
    ;;
esac
say ""
say "Next: $enterplace start"
say "(If your shell still runs an old enterplace, run: hash -r)"
