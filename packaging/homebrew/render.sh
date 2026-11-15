#!/bin/sh
# Prints the Homebrew formula of one release: packaging/homebrew/gantry.rb with the version, and the download URL and
# SHA256 of each platform's tarball, read from the release's SHA256SUMS. Fails if a platform is missing.
#
#   packaging/homebrew/render.sh <dist folder with SHA256SUMS> vX.Y.Z
set -eu
dist=${1:?usage: render.sh <dist folder> vX.Y.Z}
tag=${2:?usage: render.sh <dist folder> vX.Y.Z}
base=${GANTRY_REPO_URL:-https://github.com/eliransu/gantry}/releases/download/$tag
formula=$(cat "$(dirname "$0")/gantry.rb")
formula=$(printf '%s\n' "$formula" | sed "s|@VERSION@|${tag#v}|")
for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
  line=$(awk -v t="-$target.tar.gz" '{ n = $2; if (length(n) > length(t) && substr(n, length(n) - length(t) + 1) == t) print }' "$dist/SHA256SUMS" | head -n 1)
  [ -n "$line" ] || { echo "error: $dist/SHA256SUMS has no tarball for $target: the release build for it failed or was skipped" >&2; exit 1; }
  sha=${line%%  *}
  name=${line#*  }
  formula=$(printf '%s\n' "$formula" | sed -e "s|@URL_$target@|$base/$name|" -e "s|@SHA_$target@|$sha|")
done
printf '%s\n' "$formula"
