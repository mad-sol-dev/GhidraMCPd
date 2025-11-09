#!/usr/bin/env bash
set -euo pipefail
: "${GHIDRA_DIR:?Set GHIDRA_DIR to your ghidra_*_PUBLIC directory}"
test -d "$GHIDRA_DIR/Ghidra" || { echo "GHIDRA_DIR invalid"; exit 1; }
echo "Using GHIDRA_DIR=$GHIDRA_DIR"
