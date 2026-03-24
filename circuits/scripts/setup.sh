#!/usr/bin/env bash
set -euo pipefail

# Groth16 trusted setup (development ceremony).
#
# For mainnet: replace with a proper multi-party ceremony using
# snarkjs powersoftau new/contribute/verify.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$CIRCUITS_DIR/build"
SETUP_DIR="$CIRCUITS_DIR/trusted_setup"

mkdir -p "$SETUP_DIR"

R1CS="$BUILD_DIR/circuit.r1cs"

if [ ! -f "$R1CS" ]; then
    echo "Error: $R1CS not found. Run compile.sh first."
    exit 1
fi

# Phase 1: Powers of Tau (universal, circuit-independent).
# Use 2^22 for ~3-4M constraint circuits.
PTAU="$SETUP_DIR/pot22_final.ptau"
if [ ! -f "$PTAU" ]; then
    echo "==> Downloading powers-of-tau (2^22)..."
    echo "    This is a ~700MB download for the Hermez ceremony file."
    echo "    For development, generate a smaller one with:"
    echo "      snarkjs powersoftau new bn128 22 pot22_0000.ptau"
    echo "      snarkjs powersoftau contribute pot22_0000.ptau pot22_0001.ptau --name='dev'"
    echo "      snarkjs powersoftau prepare phase2 pot22_0001.ptau $PTAU"
    echo ""
    echo "    Or download the Hermez ceremony file:"
    echo "      https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_22.ptau"
    exit 1
fi

# Phase 2: Circuit-specific setup.
echo "==> Phase 2: circuit-specific setup..."
snarkjs groth16 setup "$R1CS" "$PTAU" "$SETUP_DIR/circuit_0000.zkey"

echo "==> Contributing to ceremony (dev entropy)..."
snarkjs zkey contribute \
    "$SETUP_DIR/circuit_0000.zkey" \
    "$SETUP_DIR/circuit_final.zkey" \
    --name="ShieldNode dev ceremony" \
    -e="shieldnode-dev-entropy-$(date +%s)"

echo "==> Exporting verification key..."
snarkjs zkey export verificationkey \
    "$SETUP_DIR/circuit_final.zkey" \
    "$SETUP_DIR/verification_key.json"

echo "==> Exporting Solidity verifier..."
snarkjs zkey export solidityverifier \
    "$SETUP_DIR/circuit_final.zkey" \
    "$CIRCUITS_DIR/../contracts/src/Groth16Verifier.sol"

echo "==> Done. Setup artifacts in $SETUP_DIR/"
echo "    Solidity verifier exported to contracts/src/Groth16Verifier.sol"
