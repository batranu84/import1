#!/bin/bash
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
cd "$(dirname "$0")"
ROOT="$(pwd)"
REQ_FILE="$ROOT/requirements.txt"

find_python() {
  for candidate in python3.14 python3.13 python3.12 python3.11 /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 /usr/local/bin/python3.14 /usr/local/bin/python3.13 /usr/local/bin/python3.12 /usr/local/bin/python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if (3,11) <= sys.version_info < (3,15) else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$candidate"; return 0
    fi
  done
  return 1
}

PYTHON_BIN="$(find_python || true)"
if [ -z "$PYTHON_BIN" ]; then
  echo 'ERROR: Python 3.11-3.14 is required on the sensor host.' >&2
  exit 1
fi
if [ ! -x "$ROOT/.venv/bin/python" ]; then
  "$PYTHON_BIN" -m venv "$ROOT/.venv"
fi
PY="$ROOT/.venv/bin/python"
if ! "$PY" -c 'import httpx, typer, pydantic, zeroconf, mac_vendor_lookup' >/dev/null 2>&1; then
  "$PY" -m pip install --disable-pip-version-check --prefer-binary -r "$REQ_FILE"
fi
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

echo 'ShadowStrike Sensor runtime'
PRIVILEGED=0
if [ "${1:-}" = "--privileged" ]; then
  PRIVILEGED=1
  shift
fi
"$PY" -m shadowstrike tool-doctor || true
if [ "$#" -eq 0 ]; then
  echo
  echo 'Usage:'
  echo '  ./sensor.command --controller http://CONTROLLER:8765 --assessment-id ID --agent-id ID --token TOKEN --site NAME --port-profile adaptive --interval 60'
  echo '  ./sensor.command --privileged --controller http://CONTROLLER:8765 ...   # enables raw Nmap OS fingerprinting / arp-scan when authorized'
  echo
  echo 'For Nmap raw TCP/IP OS fingerprinting, run the sensor with appropriate administrator/root privileges only on an authorized assessment host.'
  exit 2
fi
if [ "$PRIVILEGED" -eq 1 ]; then
  echo 'Starting privileged sensor worker for raw-packet OS/L2 discovery. The controller remains unprivileged.'
  exec sudo env PATH="$PATH" PYTHONPATH="$PYTHONPATH" "$PY" -m shadowstrike sensor "$@"
fi
exec "$PY" -m shadowstrike sensor "$@"
