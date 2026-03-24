#!/usr/bin/env bash
set -euo pipefail

# Compile the bandwidth receipt circuit to R1CS + WASM.
#
# Prerequisites:
#   - circom >= 2.1.0  (https://docs.circom.io/getting-started/installation/)
#   - npm i -g snarkjs  (https://github.com/iden3/snarkjs)
#   - Clone dependencies into circuits/:
#       git clone https://github.com/iden3/circomlib circuits/circomlib
#       git clone https://github.com/0xPARC/circom-ecdsa circuits/circom-ecdsa
#       git clone https://github.com/vocdoni/keccak256-circom circuits/keccak256-circom

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
CIRCUIT="$CIRCUITS_DIR/bandwidth_receipt/circuit.circom"
BUILD_DIR="$CIRCUITS_DIR/build"

mkdir -p "$BUILD_DIR"

echo "==> Compiling circuit..."
circom "$CIRCUIT" \
    --r1cs \
    --wasm \
    --sym \
    -l "$CIRCUITS_DIR" \
    -o "$BUILD_DIR"

echo "==> Circuit info:"
snarkjs r1cs info "$BUILD_DIR/circuit.r1cs"

echo "==> Done. Artifacts in $BUILD_DIR/"
