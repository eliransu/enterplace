#!/usr/bin/env bash
# Builds what a release ships, on this machine. Publishing is a separate step and waits for the product name.
#
#   scripts/release.sh tarball   the binary for this machine as dist/gantry-<version>-<src>-<target>.tar.gz
#   scripts/release.sh image     the container image for this machine's platform, tagged gantry:<version>
#   scripts/release.sh images    the container image for linux/amd64 and linux/arm64 (needs docker buildx)
#   scripts/release.sh linux     dist tarballs for x86_64 and aarch64 linux, taken from the images
#   scripts/release.sh smoke     runs the image and times its first governed request against a local mock
# <src> is the source hash `gantry version` prints. Each tarball gets a .sha256 and a .BUILD file (the version line),
# and the tarballs of the targets a run builds are deleted first, so a stale one cannot survive a partial run.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
mkdir -p dist

# The source hash from a `gantry version` line: gantry 0.0.1 (src 3f9a1c2b4d5e, built 2026-11-13).
src_of() { sed -n 's/.*(src \([0-9a-f]*\),.*/\1/p' <<< "$1"; }

# Deletes every earlier tarball, checksum and BUILD file of one target, whatever build it came from.
clear_target() { rm -f dist/gantry-*-"$1".tar.gz dist/gantry-*-"$1".tar.gz.sha256 dist/gantry-*-"$1".BUILD; }

tarball() {
  local target=$1 binary=$2 line=$3
  local src
  src=$(src_of "$line")
  [ -n "$src" ] || { echo "error: no source hash in \"$line\"" >&2; exit 1; }
  local name="gantry-$version-$src-$target"
  rm -rf "dist/$name" && mkdir -p "dist/$name"
  cp "$binary" "dist/$name/gantry"
  cp LICENSE README.md "dist/$name/"
  tar -C dist -czf "dist/$name.tar.gz" "$name"
  rm -rf "dist/$name"
  (cd dist && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256")
  echo "$line" > "dist/gantry-$version-$src-$target.BUILD"
  echo "dist/$name.tar.gz"
}

case "${1:-}" in
  tarball)
    host=$(rustc -vV | sed -n 's/^host: //p')
    clear_target "$host"
    cargo build --release --locked -p gantry-cli
    tarball "$host" target/release/gantry "$(target/release/gantry version)"
    ;;
  image)
    docker build -t "gantry:$version" -t gantry:local .
    docker run --rm "gantry:$version" version
    docker image inspect "gantry:$version" --format '{{index .RepoTags 0}}: {{.Size}} bytes, user {{.Config.User}}'
    # The docs site and website take the size from here (scripts/docs.py, scripts/site.py), so it is never stale.
    bytes=$(docker image inspect "gantry:$version" --format '{{.Size}}')
    awk -v b="$bytes" 'BEGIN { printf "%.1f MB\n%s\n", b / 1e6, b }' > dist/image-size.txt
    ;;
  images)
    docker buildx build --platform linux/amd64,linux/arm64 -t "gantry:$version" .
    ;;
  linux)
    clear_target x86_64-unknown-linux-musl
    clear_target aarch64-unknown-linux-musl
    for platform in amd64 arm64; do
      docker buildx build --platform "linux/$platform" --load -t "gantry:$version-$platform" .
      line=$(docker run --rm --platform "linux/$platform" "gantry:$version-$platform" version)
      id=$(docker create "gantry:$version-$platform")
      docker cp "$id:/gantry" "dist/gantry-linux-$platform"
      docker rm "$id" > /dev/null
      # The per-platform tag only carried the binary out. gantry:<version> stays the image of this machine.
      docker rmi "gantry:$version-$platform" > /dev/null
      case $platform in amd64) target=x86_64-unknown-linux-musl ;; arm64) target=aarch64-unknown-linux-musl ;; esac
      tarball "$target" "dist/gantry-linux-$platform" "$line"
      rm "dist/gantry-linux-$platform"
    done
    ;;
  smoke)
    exec python3 scripts/smoke_image.py "gantry:$version"
    ;;
  *)
    sed -n '2,11p' "$0"
    exit 2
    ;;
esac
