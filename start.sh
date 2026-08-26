#!/bin/sh
set -eu
cd "$(dirname "$0")"
ROOT="$(pwd)"
PORT="${SHADOWSTRIKE_PORT:-8765}"
HOST="${SHADOWSTRIKE_HOST:-127.0.0.1}"
REQ_FILE="$ROOT/requirements.txt"
INSTALL_LOG="$ROOT/shadowstrike-install.log"

is_supported_python() {
  "$1" -c 'import sys; raise SystemExit(0 if (3,11) <= sys.version_info < (3,15) else 1)' >/dev/null 2>&1
}

PYTHON_BIN="${SHADOWSTRIKE_PYTHON:-}"
if [ -n "$PYTHON_BIN" ] && ! is_supported_python "$PYTHON_BIN"; then
  PYTHON_BIN=""
fi
if [ -z "$PYTHON_BIN" ]; then
  for candidate in python3.14 python3.13 python3.12 python3.11 /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 /usr/local/bin/python3.14 /usr/local/bin/python3.13 /usr/local/bin/python3.12 /usr/local/bin/python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && is_supported_python "$candidate"; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi

if [ -z "$PYTHON_BIN" ]; then
  echo 'ERROR: Python 3.11 through 3.14 is required.' >&2
  echo 'Recommended: brew install python@3.13' >&2
  exit 1
fi

PY_MINOR="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
VENV_MINOR=""
VENV_SUPPORTED="0"
if [ -x "$ROOT/.venv/bin/python" ]; then
  VENV_MINOR="$($ROOT/.venv/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
  VENV_SUPPORTED="$($ROOT/.venv/bin/python -c 'import sys; print(1 if (3,11) <= sys.version_info < (3,15) else 0)' 2>/dev/null || echo 0)"
fi
if [ ! -x "$ROOT/.venv/bin/python" ] || [ "$VENV_SUPPORTED" != "1" ] || [ "$VENV_MINOR" != "$PY_MINOR" ]; then
  rm -rf "$ROOT/.venv"
  "$PYTHON_BIN" -m venv "$ROOT/.venv"
fi

PY="$ROOT/.venv/bin/python"
if ! "$PY" -c 'import fastapi, uvicorn, pydantic, pydantic_settings, httpx, dns, typer, rich, pypdf, cryptography, mac_vendor_lookup, zeroconf; fv=tuple(map(int, fastapi.__version__.split('.')[:2])); pv=tuple(map(int, pydantic.__version__.split('.')[:2])); sv=tuple(map(int, pydantic_settings.__version__.split('.')[:2])); raise SystemExit(0 if fv >= (0,128) and pv >= (2,13) and sv >= (2,14) else 1)' >/dev/null 2>&1; then
  "$PY" -m pip install --disable-pip-version-check --prefer-binary --upgrade -r "$REQ_FILE" >"$INSTALL_LOG" 2>&1 || {
    echo "ERROR: dependency installation failed. See $INSTALL_LOG" >&2
    exit 1
  }
fi
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
"$PY" -c 'import shadowstrike; from shadowstrike.engines.tls import TlsIntelligenceEngine; print("Runtime dependency preflight: OK")'
exec "$PY" -m shadowstrike serve --host "$HOST" --port "$PORT"
