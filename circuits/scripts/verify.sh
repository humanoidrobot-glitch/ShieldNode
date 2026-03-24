#!/usr/bin/env bash
set -euo pipefail

# Verify a Groth16 proof off-chain.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$CIRCUITS_DIR/build"
SETUP_DIR="$CIRCUITS_DIR/trusted_setup"

PROOF="${1:-$BUILD_DIR/proof/proof.json}"
PUBLIC="${2:-$BUILD_DIR/proof/public.json}"
VKEY="$SETUP_DIR/verification_key.json"

if [ ! -f "$VKEY" ]; then
    echo "Error: $VKEY not found. Run setup.sh first."
    exit 1
fi

echo "==> Verifying proof..."
snarkjs groth16 verify "$VKEY" "$PUBLIC" "$PROOF"
