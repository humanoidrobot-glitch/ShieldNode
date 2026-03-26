#!/usr/bin/env bash
set -euo pipefail

# Build the ZK-VM guest and host inside Docker.
#
# Usage (from repo root):
#   ./zkvm/scripts/build.sh          # build only
#   ./zkvm/scripts/build.sh prove    # build and run the prover

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZKVM_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$ZKVM_DIR")"

IMAGE_NAME="shieldnode-zkvm"

echo "==> Building Docker image..."
docker build -t "$IMAGE_NAME" "$ZKVM_DIR"

echo "==> Building guest + host..."
docker run --rm \
    -v "$ZKVM_DIR:/workspace" \
    "$IMAGE_NAME" \
    build --release

if [ "${1:-}" = "prove" ]; then
    echo "==> Running prover (generating ZK proof)..."
    docker run --rm \
        -v "$ZKVM_DIR:/workspace" \
        "$IMAGE_NAME" \
        run --release --bin shieldnode-zkvm-host
fi

echo "==> Done."
