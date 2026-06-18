#!/usr/bin/env bash
# Build the image and prove it can still find its own corpus through
# the entrypoint, the way I will actually run it. No registry: the
# image lives in the local store and gets rebuilt when it is stale.
set -euo pipefail

cd "$(dirname "$0")/.."
ver=$(python -c "import ckptscan;print(ckptscan.__version__)")
tag="ckptscan:$ver"

podman build -t "$tag" -f Containerfile .

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

podman run --rm --entrypoint ckptscan-mkcorpus \
  -v "$work:/work:Z" "$tag" --out /work --quiet
podman run --rm --network none -v "$work:/work:ro,Z" "$tag" /work/clean
podman run --rm --network none -v "$work:/work:ro,Z" "$tag" /work/unsafe \
  && { echo "image MISSED its own unsafe corpus"; exit 1; }

echo "$tag detects its corpus and needs no network"
