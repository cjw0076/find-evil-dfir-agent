#!/usr/bin/env bash
# FIND EVIL! — one-command synthetic DFIR triage demo.
# Stdlib Python only. No network, no secrets, no real forensic image required.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CASE_DIR="${1:-data/synthetic/case-lab-01}"
OUT_DIR="${2:-out}"

export PYTHONPATH="$HERE/src${PYTHONPATH:+:$PYTHONPATH}"

python3 -m find_evil --case-dir "$CASE_DIR" --out "$OUT_DIR"

echo
echo "Replay the recorded reasoning trace with:"
echo "  PYTHONPATH=$HERE/src python3 -m find_evil --replay $OUT_DIR/trace.json"
