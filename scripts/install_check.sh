#!/bin/sh
# Tests install.sh against a fake release served on localhost: a stable release, an edge-only repository,
# GANTRY_VERSION, and a tampered tarball and a bad signature, which must both fail. The fake release is signed by
# scripts/signing.py with a throwaway key, so SHA256SUMS has the real format. Runs on macOS and Linux (CI: ci.yml).
#
#   scripts/install_check.sh            (INSTALL_SH=dash to run install.sh under another shell)
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
work=$(mktemp -d)
pid=
cleanup() { [ -n "$pid" ] && kill "$pid" 2> /dev/null; rm -rf "$work"; }
trap cleanup EXIT INT TERM

case $(uname -s) in Darwin) os=apple-darwin ;; *) os=unknown-linux-musl ;; esac
case $(uname -m) in x86_64 | amd64) arch=x86_64 ;; *) arch=aarch64 ;; esac
if [ "$os" = apple-darwin ] && [ "$(sysctl -n sysctl.proc_translated 2> /dev/null || echo 0)" = 1 ]; then arch=aarch64; fi

ssh-keygen -q -t ed25519 -N '' -C test -f "$work/key"
printf 'release@gantry %s\n' "$(cut -d' ' -f1,2 "$work/key.pub")" > "$work/allowed_signers"

# release DIR VERSION: a signed fake release with tarballs for this machine and one other target.
release() {
  mkdir -p "$1"
  for target in "$arch-$os" riscv64-unknown-linux-musl; do
    name=gantry-$2-abc123-$target
    mkdir -p "$work/pack/$name"
    printf '#!/bin/sh\necho "gantry %s (src abc123, built 2026-11-15)"\n' "$2" > "$work/pack/$name/gantry"
    chmod 755 "$work/pack/$name/gantry"
    tar -czf "$1/$name.tar.gz" -C "$work/pack" "$name"
  done
  GANTRY_SIGNING_KEY_FILE=$work/key RELEASE_SIGNING_KEY='' python3 scripts/signing.py sign "$1" > /dev/null
}

srv=$work/srv
release "$srv/stable/releases/download/v0.1.0" 0.1.0
mkdir -p "$srv/stable/releases/latest"
cp -R "$srv/stable/releases/download/v0.1.0" "$srv/stable/releases/latest/download"
release "$srv/stable/releases/download/edge" 0.2.0-edge
release "$srv/edgeonly/releases/download/edge" 0.2.0-edge

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$srv" > "$work/http.log" 2>&1 &
pid=$!
i=0
until curl -fs "http://127.0.0.1:$port/" > /dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 50 ] || { echo "FAIL: the test server did not start"; cat "$work/http.log"; exit 1; }
  sleep 0.1
done

failures=0
# run NAME REPO EXPECT [VAR=VALUE...]: EXPECT is a version the installed binary prints, or "fail".
run() {
  case_name=$1 repo=$2 expect=$3; shift 3
  dir=$work/bin-$case_name
  if env "$@" GANTRY_REPO_URL="http://127.0.0.1:$port/$repo" GANTRY_INSTALL_DIR="$dir" \
    GANTRY_ALLOWED_SIGNERS="$work/allowed_signers" "${INSTALL_SH:-sh}" "$root/install.sh" > "$work/$case_name.log" 2>&1; then
    if [ "$expect" != fail ] && "$dir/gantry" version | grep -q "gantry $expect " && grep -q 'Next: .*gantry start' "$work/$case_name.log"; then
      echo "ok   $case_name"; return
    fi
  elif [ "$expect" = fail ] && [ ! -e "$dir/gantry" ]; then
    echo "ok   $case_name ($(grep 'install failed' "$work/$case_name.log" | head -n 1 | cut -c1-110))"; return
  fi
  echo "FAIL $case_name"; sed 's/^/     /' "$work/$case_name.log"; failures=$((failures + 1))
}

run latest-stable stable 0.1.0
run edge-when-no-stable edgeonly 0.2.0-edge
run version-edge stable 0.2.0-edge GANTRY_VERSION=edge
run version-tag stable 0.1.0 GANTRY_VERSION=v0.1.0
run version-missing stable fail GANTRY_VERSION=v9.9.9
run version-invalid stable fail GANTRY_VERSION=v1/../../x

# A tarball changed after signing.
cp -R "$srv/stable" "$srv/tampered"
t=$(ls "$srv/tampered/releases/latest/download/"*"-$arch-$os.tar.gz")
printf 'x' >> "$t"
run tampered-tarball tampered fail

# SHA256SUMS changed after signing (pointing at the tampered tarball): the signature must catch it.
cp -R "$srv/tampered" "$srv/resigned"
d=$srv/resigned/releases/latest/download
sum=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$d/$(basename "$t")")
awk -v n="$(basename "$t")" -v s="$sum" '$2 == n { $1 = s; print $1 "  " $2; next } { print }' "$d/SHA256SUMS" > "$work/sums"
cp "$work/sums" "$d/SHA256SUMS"
run bad-signature resigned fail

[ "$failures" -eq 0 ] || { echo "$failures install.sh check(s) failed"; exit 1; }
echo "install.sh: all checks passed"
