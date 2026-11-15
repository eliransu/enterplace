#!/usr/bin/env bash
# Checks a Gantry release before you run it: the image and the Helm chart were signed by this repository's release
# workflows (keyless, through GitHub's OIDC identity and Sigstore), and the image carries a signed SBOM and signed SLSA
# provenance.
#
#   scripts/verify_release.sh X.Y.Z
#
# Prints the image digest to pin. Needs cosign 2.4 or later, and python3. The image and the chart are
# public: no login.
#
# Environment:
#   IMAGE    the image repository (default ghcr.io/eliransu/gantry)
#   CHART    the chart repository (default ghcr.io/eliransu/charts/gantry); CHART=none skips the chart
#   COSIGN_KEY   a public key file to verify with in place of the workflows' identity. Only for testing this script
#                against an image signed locally (`cosign sign --key`); it skips the transparency log too.
#   ALLOW_HTTP_REGISTRY=1   with COSIGN_KEY, allows a plain-HTTP local registry.
set -euo pipefail
version=${1:?usage: scripts/verify_release.sh X.Y.Z}
version=${version#v}
image=${IMAGE:-ghcr.io/eliransu/gantry}
chart=${CHART:-ghcr.io/eliransu/charts/gantry}
repo=https://github.com/eliransu/gantry

command -v cosign > /dev/null || { echo "error: cosign is not on PATH. Install it: https://docs.sigstore.dev/cosign/system_config/installation/" >&2; exit 1; }

# Who may have signed: the image workflow for the image, the release workflow for the chart, both on the version's tag.
who() {
  if [ -n "${COSIGN_KEY:-}" ]; then
    echo "--key $COSIGN_KEY --insecure-ignore-tlog=true${ALLOW_HTTP_REGISTRY:+ --allow-insecure-registry --allow-http-registry}"
  else
    echo "--certificate-identity $repo/.github/workflows/$1@refs/tags/v$version --certificate-oidc-issuer https://token.actions.githubusercontent.com"
  fi
}

fail() { echo "FAILED: $*" >&2; exit 1; }

# 1. The image signature. The tag is resolved once, and every later check uses the digest it names.
# shellcheck disable=SC2046
out=$(cosign verify $(who image.yml) "$image:$version" 2> /dev/null) \
  || fail "no valid signature on $image:$version from $(who image.yml). Do not run this image."
digest=$(python3 -c 'import json,sys; print(json.loads(next(l for l in sys.stdin.read().splitlines() if l.strip()))[0]["critical"]["image"]["docker-manifest-digest"])' <<< "$out")
echo "OK  image signed: $image@$digest"

# 2. The SBOM and the provenance, each a signed attestation on that digest. The SBOM must list the binary's crates.
# shellcheck disable=SC2046
sbom=$(cosign verify-attestation $(who image.yml) --type cyclonedx "$image@$digest" 2> /dev/null) \
  || fail "no signed CycloneDX SBOM on $image@$digest"
crates=$(python3 -c '
import base64, json, sys
statement = json.loads(base64.b64decode(json.loads(next(l for l in sys.stdin.read().splitlines() if l.strip()))["payload"]))
print(sum(c.get("purl", "").startswith("pkg:cargo/") for c in statement["predicate"].get("components", [])))' <<< "$sbom")
[ "$crates" -gt 0 ] || fail "the SBOM on $image@$digest lists no crates"
echo "OK  SBOM attested: $crates crates (cosign verify-attestation --type cyclonedx ... | jq to read it)"

# shellcheck disable=SC2046
prov=$(cosign verify-attestation $(who image.yml) --type slsaprovenance1 "$image@$digest" 2> /dev/null) \
  || fail "no signed SLSA provenance on $image@$digest"
commit=$(python3 -c '
import base64, json, sys
statement = json.loads(base64.b64decode(json.loads(next(l for l in sys.stdin.read().splitlines() if l.strip()))["payload"]))
print(statement["predicate"]["buildDefinition"]["externalParameters"]["commit"])' <<< "$prov")
echo "OK  SLSA provenance attested: built from commit $commit"

# 3. The Helm chart, an OCI artifact signed by the release workflow.
if [ "$chart" != none ]; then
  # shellcheck disable=SC2046
  cosign verify $(who release.yml) "$chart:$version" > /dev/null 2>&1 \
    || fail "no valid signature on the chart $chart:$version from $(who release.yml)"
  echo "OK  chart signed: $chart:$version"
fi

echo
echo "Verified Gantry $version. Pin the image by digest: $image@$digest"
