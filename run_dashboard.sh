#!/usr/bin/env bash
# FIND EVIL! — launch the web triage dashboard (FastAPI + vanilla JS).
# Synthetic by default, zero credentials, read-only evidence.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
export PYTHONPATH="$HERE/src${PYTHONPATH:+:$PYTHONPATH}"

PORT="${1:-8000}"

if ! python3 -c "import fastapi, uvicorn" 2>/dev/null; then
  echo "Installing web deps (fastapi, uvicorn)…"
  python3 -m pip install -q -r webapp/requirements.txt
fi

echo "FIND EVIL! dashboard → http://127.0.0.1:${PORT}"
echo "  (synthetic data, no credentials, read-only). Ctrl-C to stop."
exec python3 -m uvicorn webapp.server:app --host 127.0.0.1 --port "${PORT}"
