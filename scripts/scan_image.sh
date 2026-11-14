#!/usr/bin/env bash
# The image scan: an SBOM of what the image ships, then a vulnerability scan of that SBOM.
#
#   scripts/scan_image.sh <image ref> [sbom output file]
#
# syft reads the crate list cargo-auditable writes into the binary (the image is FROM scratch, so there is nothing
# else to read) and writes a CycloneDX SBOM; Grype scans that same SBOM, so what is scanned is exactly what the
# release attests. Fails on a high or critical vulnerability unless .grype.yaml lets it through with a reason.
# Needs syft and grype on PATH.
set -euo pipefail
cd "$(dirname "$0")/.."
ref=${1:?usage: scripts/scan_image.sh <image ref> [sbom output file]}
sbom=${2:-sbom.cdx.json}
syft scan "$ref" -q -o cyclonedx-json="$sbom"
crates=$(python3 -c 'import json,sys; print(sum(c.get("purl","").startswith("pkg:cargo/") for c in json.load(open(sys.argv[1])).get("components", [])))' "$sbom")
# A binary built without cargo-auditable gives an empty list, and a scan of nothing passes: refuse that.
if [ "$crates" -lt 50 ]; then
  echo "error: the SBOM of $ref lists $crates crates. The binary was built without cargo-auditable (see Dockerfile), so nothing would be scanned." >&2
  exit 1
fi
echo "$sbom: $crates crates"
grype "sbom:$sbom" -c .grype.yaml --fail-on high
