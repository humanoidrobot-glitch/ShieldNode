#!/usr/bin/env bash
set -euo pipefail

# Generate a Groth16 proof from a witness (input.json).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$CIRCUITS_DIR/build"
SETUP_DIR="$CIRCUITS_DIR/trusted_setup"

INPUT="${1:-$CIRCUITS_DIR/bandwidth_receipt/input.json}"
OUTPUT_DIR="$BUILD_DIR/proof"

mkdir -p "$OUTPUT_DIR"

WASM="$BUILD_DIR/circuit_js/circuit.wasm"
ZKEY="$SETUP_DIR/circuit_final.zkey"

if [ ! -f "$WASM" ]; then
    echo "Error: $WASM not found. Run compile.sh first."
    exit 1
fi
if [ ! -f "$ZKEY" ]; then
    echo "Error: $ZKEY not found. Run setup.sh first."
    exit 1
fi

echo "==> Computing witness..."
node "$BUILD_DIR/circuit_js/generate_witness.js" "$WASM" "$INPUT" "$OUTPUT_DIR/witness.wtns"

echo "==> Generating Groth16 proof..."
START=$(date +%s%N)
snarkjs groth16 prove "$ZKEY" "$OUTPUT_DIR/witness.wtns" "$OUTPUT_DIR/proof.json" "$OUTPUT_DIR/public.json"
END=$(date +%s%N)

ELAPSED_MS=$(( (END - START) / 1000000 ))
echo "==> Proof generated in ${ELAPSED_MS}ms"

echo "==> Public inputs:"
cat "$OUTPUT_DIR/public.json"

echo ""
echo "==> Done. Proof at $OUTPUT_DIR/proof.json"
