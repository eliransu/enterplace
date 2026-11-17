#!/usr/bin/env bash
# Builds what a release ships, on this machine. Publishing is a separate step and waits for the product name.
#
#   scripts/release.sh tarball   the binary for this machine as dist/enterplace-<version>-<src>-<target>.tar.gz
#   scripts/release.sh image     the container image for this machine's platform, tagged enterplace:<version>
#   scripts/release.sh images    the container image for linux/amd64 and linux/arm64 (needs docker buildx)
#   scripts/release.sh linux     dist tarballs for x86_64 and aarch64 linux, taken from the images
#   scripts/release.sh smoke     runs the image and times its first governed request against a local mock
#   scripts/release.sh reproduce builds the linux tarballs twice from scratch and fails unless both are the same bytes
#   scripts/release.sh sign      writes SHA256SUMS and provenance.json in dist/ and signs both (scripts/signing.py)
#   scripts/release.sh verify    checks dist/ against the signatures and the public key in release/allowed_signers
#   scripts/release.sh bump X.Y.Z sets the version in Cargo.toml, Cargo.lock and the Helm chart and dates its CHANGELOG
#                                section today; see RELEASING.md
# The binary in every tarball and image is the enterprise build (enterprise/): without a license key it is the open
# source gateway. Each tarball carries both licenses: LICENSE (Apache 2.0) and LICENSE-enterprise.
# Builds use the last commit's time as SOURCE_DATE_EPOCH unless it is set, so a rebuild of a commit is identical.
# <src> is the source hash `enterplace version` prints. Each tarball gets a .sha256 and a .BUILD file (the version line),
# and the tarballs of the targets a run builds are deleted first, so a stale one cannot survive a partial run.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
mkdir -p dist
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"

# The source hash from a `enterplace version` line: enterplace 0.0.1 (src 3f9a1c2b4d5e, built 2026-11-13).
src_of() { sed -n 's/.*(src \([0-9a-f]*\),.*/\1/p' <<< "$1"; }

# Deletes every earlier tarball, checksum and BUILD file of one target, whatever build it came from.
clear_target() { rm -f dist/enterplace-*-"$1".tar.gz dist/enterplace-*-"$1".tar.gz.sha256 dist/enterplace-*-"$1".BUILD; }

tarball() {
  local target=$1 binary=$2 line=$3
  local src
  src=$(src_of "$line")
  [ -n "$src" ] || { echo "error: no source hash in \"$line\"" >&2; exit 1; }
  local name="enterplace-$version-$src-$target"
  rm -rf "dist/$name" && mkdir -p "dist/$name"
  cp "$binary" "dist/$name/enterplace"
  cp LICENSE README.md "dist/$name/"
  cp enterprise/LICENSE "dist/$name/LICENSE-enterprise"
  python3 scripts/pack.py "dist/$name.tar.gz" "$name" "dist/$name/enterplace" "dist/$name/LICENSE" "dist/$name/LICENSE-enterprise" "dist/$name/README.md"
  rm -rf "dist/$name"
  (cd dist && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
  echo "$line" > "dist/enterplace-$version-$src-$target.BUILD"
  echo "dist/$name.tar.gz"
}

case "${1:-}" in
  tarball)
    host=$(rustc -vV | sed -n 's/^host: //p')
    clear_target "$host"
    cargo build --release --locked -p enterplace-enterprise
    tarball "$host" target/release/enterplace-enterprise "$(target/release/enterplace-enterprise version)"
    ;;
  image)
    docker build -t "enterplace:$version" -t enterplace:local .
    docker run --rm "enterplace:$version" version
    docker image inspect "enterplace:$version" --format '{{index .RepoTags 0}}: {{.Size}} bytes, user {{.Config.User}}'
    bytes=$(docker image inspect "enterplace:$version" --format '{{.Size}}')
    awk -v b="$bytes" 'BEGIN { printf "%.1f MB\n%s\n", b / 1e6, b }' > dist/image-size.txt
    ;;
  images)
    docker buildx build --platform linux/amd64,linux/arm64 -t "enterplace:$version" .
    ;;
  linux)
    case " ${PLATFORMS:-amd64 arm64} " in *" amd64 "*) clear_target x86_64-unknown-linux-musl ;; esac
    case " ${PLATFORMS:-amd64 arm64} " in *" arm64 "*) clear_target aarch64-unknown-linux-musl ;; esac
    for platform in ${PLATFORMS:-amd64 arm64}; do
      docker buildx build --platform "linux/$platform" --build-arg SOURCE_DATE_EPOCH --load -t "enterplace:$version-$platform" ${NO_CACHE:+--no-cache} .
      line=$(docker run --rm --platform "linux/$platform" "enterplace:$version-$platform" version)
      id=$(docker create "enterplace:$version-$platform")
      docker cp "$id:/enterplace" "dist/enterplace-linux-$platform"
      docker rm "$id" > /dev/null
      # The per-platform tag only carried the binary out. enterplace:<version> stays the image of this machine.
      docker rmi "enterplace:$version-$platform" > /dev/null
      case $platform in amd64) target=x86_64-unknown-linux-musl ;; arm64) target=aarch64-unknown-linux-musl ;; esac
      tarball "$target" "dist/enterplace-linux-$platform" "$line"
      rm "dist/enterplace-linux-$platform"
    done
    ;;
  smoke)
    exec python3 scripts/smoke_image.py "enterplace:$version"
    ;;
  reproduce)
    # Two builds with no cache. Any difference is a build that depends on where or when it ran.
    NO_CACHE=1 "$0" linux > /dev/null
    first=$(cd dist && shasum -a 256 enterplace-*-linux-musl.tar.gz)
    NO_CACHE=1 "$0" linux > /dev/null
    second=$(cd dist && shasum -a 256 enterplace-*-linux-musl.tar.gz)
    echo "$second"
    if [ "$first" != "$second" ]; then
      echo "NOT REPRODUCIBLE: the first build was" >&2
      echo "$first" >&2
      exit 1
    fi
    echo "reproducible: two builds from scratch gave the same bytes"
    ;;
  sign)
    exec python3 scripts/signing.py sign dist
    ;;
  verify)
    exec python3 scripts/signing.py verify dist
    ;;
  bump)
    [ -n "${2:-}" ] || { echo "usage: scripts/release.sh bump X.Y.Z" >&2; exit 2; }
    repo=.
    python3 scripts/version.py --root "$repo" --bump "$2"
    # Only the workspace's own entries change in Cargo.lock; no dependency moves.
    (cd "$repo" && { cargo update --workspace --offline -q 2>/dev/null || cargo update --workspace -q; })
    python3 scripts/version.py --root "$repo"
    ;;
  *)
    sed -n '2,20p' "$0"
    exit 2
    ;;
esac
