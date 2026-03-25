#!/usr/bin/env bash
set -euo pipefail

# Verify that a ShieldNode relay binary matches the reproducible build hash.
#
# Usage:
#   ./verify-build.sh <path-to-binary> [expected-hash]
#
# If expected-hash is omitted, just prints the hash.

BINARY="${1:?Usage: verify-build.sh <binary> [expected-hash]}"
EXPECTED="${2:-}"

if [ ! -f "$BINARY" ]; then
    echo "Error: $BINARY not found"
    exit 1
fi

HASH=$(sha256sum "$BINARY" | awk '{print $1}')
echo "Binary:  $BINARY"
echo "SHA-256: $HASH"

if [ -n "$EXPECTED" ]; then
    if [ "$HASH" = "$EXPECTED" ]; then
        echo "MATCH — binary matches expected hash"
        exit 0
    else
        echo "MISMATCH — binary does NOT match expected hash"
        echo "Expected: $EXPECTED"
        exit 1
    fi
fi
