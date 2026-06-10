#!/usr/bin/env bash
# FIND EVIL! — one-command synthetic DFIR triage demo.
# Stdlib Python only. No network, no secrets, no real forensic image required.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

export PYTHONPATH="$HERE/src${PYTHONPATH:+:$PYTHONPATH}"

# `./run_demo.sh all`  -> run the eval harness across every case
if [[ "${1:-}" == "all" ]]; then
  exec python3 eval/run_eval.py
fi

CASE_DIR="${1:-data/synthetic/case-lab-01}"
OUT_DIR="${2:-out}"

python3 -m find_evil --case-dir "$CASE_DIR" --out "$OUT_DIR"

echo
echo "Replay the recorded reasoning trace with:"
echo "  PYTHONPATH=$HERE/src python3 -m find_evil --replay $OUT_DIR/trace.json"
