#!/usr/bin/env bash
set -euo pipefail

# Build and run the ZK-VM guest and host inside Docker.
#
# Usage (from repo root):
#   ./zkvm/scripts/build.sh              # build only (CPU)
#   ./zkvm/scripts/build.sh execute      # build + execute (no proof)
#   ./zkvm/scripts/build.sh prove        # build + full proof (CPU)
#   ./zkvm/scripts/build.sh prove-gpu    # build + full proof (GPU/CUDA)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZKVM_DIR="$(dirname "$SCRIPT_DIR")"

MODE="${1:-build}"
FEATURES=""
GPU_FLAGS=""
IMAGE_NAME="shieldnode-zkvm"

if [ "$MODE" = "prove-gpu" ]; then
    IMAGE_NAME="shieldnode-zkvm-cuda"
    FEATURES="--features cuda"
    GPU_FLAGS="--gpus all"

    echo "==> Building CUDA Docker image..."
    docker build -t "$IMAGE_NAME" -f "$ZKVM_DIR/Dockerfile.cuda" "$ZKVM_DIR"
else
    echo "==> Building Docker image..."
    docker build -t "$IMAGE_NAME" "$ZKVM_DIR"
fi

echo "==> Building guest + host..."
docker run --rm $GPU_FLAGS \
    -v "$ZKVM_DIR:/workspace" \
    "$IMAGE_NAME" \
    build --release $FEATURES

case "$MODE" in
    execute)
        echo "==> Executing guest (no proof)..."
        docker run --rm $GPU_FLAGS \
            -v "$ZKVM_DIR:/workspace" \
            "$IMAGE_NAME" \
            run --release $FEATURES --bin shieldnode-zkvm-host
        ;;
    prove|prove-gpu)
        echo "==> Generating ZK proof..."
        docker run --rm $GPU_FLAGS \
            -v "$ZKVM_DIR:/workspace" \
            "$IMAGE_NAME" \
            run --release $FEATURES --bin shieldnode-zkvm-host -- prove
        ;;
esac

echo "==> Done."
