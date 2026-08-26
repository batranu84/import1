#!/bin/bash
set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

cd "$(dirname "$0")"
ROOT="$(pwd)"
TITLE='ShadowStrike WebApp'
PORT="${SHADOWSTRIKE_PORT:-8765}"
HOST="${SHADOWSTRIKE_HOST:-127.0.0.1}"
URL="http://${HOST}:${PORT}/"
INSTALL_LOG="$ROOT/shadowstrike-install.log"
REQ_FILE="$ROOT/requirements.txt"

printf '\033]0;%s\007' "$TITLE"
printf '\n============================================================\n'
printf '  SHADOWSTRIKE - Authorized Security Assessment Platform\n'
printf '  Runtime baseline: Python 3.11-3.14\n'
printf '============================================================\n\n'

case "$ROOT" in
  *codex-file-preview*|*/var/folders/*/T/*file-preview*)
    echo 'WARNING: You opened start.command from a temporary ChatGPT/Codex preview.'
    echo 'Extract the ZIP to a permanent folder first if you want saved assessments to persist.'
    echo
    ;;
esac

is_supported_python() {
  "$1" -c 'import sys; raise SystemExit(0 if (3,11) <= sys.version_info < (3,15) else 1)' >/dev/null 2>&1
}

find_python() {
  if [ -n "${SHADOWSTRIKE_PYTHON:-}" ]; then
    if command -v "$SHADOWSTRIKE_PYTHON" >/dev/null 2>&1 && is_supported_python "$SHADOWSTRIKE_PYTHON"; then
      printf '%s\n' "$SHADOWSTRIKE_PYTHON"
      return 0
    fi
    echo "WARNING: SHADOWSTRIKE_PYTHON=$SHADOWSTRIKE_PYTHON is unavailable or outside supported Python 3.11-3.14." >&2
  fi

  # Prefer mature Python releases commonly installed on macOS, then any
  # compatible python3. Explicit Homebrew paths cover shells with a minimal PATH.
  for candidate in \
    python3.14 python3.13 python3.12 python3.11 \
    /opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 \
    /usr/local/bin/python3.14 /usr/local/bin/python3.13 /usr/local/bin/python3.12 /usr/local/bin/python3.11 \
    python3; do
    if command -v "$candidate" >/dev/null 2>&1 && is_supported_python "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

PYTHON_BIN="$(find_python || true)"
if [ -z "$PYTHON_BIN" ]; then
  echo 'ShadowStrike requires Python 3.11 through 3.14.'
  if command -v python3 >/dev/null 2>&1; then
    OLD_VERSION="$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>/dev/null || true)"
    [ -n "$OLD_VERSION" ] && echo "Detected system python3: $OLD_VERSION (not used)."
  fi
  echo

  BREW_BIN=''
  if command -v brew >/dev/null 2>&1; then
    BREW_BIN="$(command -v brew)"
  elif [ -x /opt/homebrew/bin/brew ]; then
    BREW_BIN='/opt/homebrew/bin/brew'
  elif [ -x /usr/local/bin/brew ]; then
    BREW_BIN='/usr/local/bin/brew'
  fi

  if [ -n "$BREW_BIN" ]; then
    read -r -p 'Install Python 3.13 with Homebrew now? [y/N] ' INSTALL_PY
    case "$INSTALL_PY" in
      y|Y|yes|YES)
        echo 'Installing Python 3.13 with Homebrew...'
        "$BREW_BIN" install python@3.13 || {
          echo 'ERROR: Homebrew could not install Python 3.13.'
          read -r -p 'Press Return to close... ' _
          exit 1
        }
        PYTHON_BIN="$(find_python || true)"
        ;;
    esac
  fi

  if [ -z "$PYTHON_BIN" ]; then
    echo
    echo 'Install Python 3.13, then run start.command again:'
    echo '  Homebrew:  brew install python@3.13'
    echo '  Or use the official macOS installer from python.org.'
    echo
    read -r -p 'Press Return to close... ' _
    exit 1
  fi
fi

PY_VERSION="$($PYTHON_BIN -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
PY_MINOR="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
echo "Python: $PY_VERSION ($PYTHON_BIN)"

RECREATE_VENV=0
if [ ! -x "$ROOT/.venv/bin/python" ]; then
  RECREATE_VENV=1
else
  VENV_MINOR="$($ROOT/.venv/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
  VENV_SUPPORTED="$($ROOT/.venv/bin/python -c 'import sys; print(1 if (3,11) <= sys.version_info < (3,15) else 0)' 2>/dev/null || echo 0)"
  if [ "$VENV_SUPPORTED" != "1" ] || [ "$VENV_MINOR" != "$PY_MINOR" ]; then
    echo "Existing .venv uses Python ${VENV_MINOR:-unknown}; recreating for Python $PY_MINOR..."
    RECREATE_VENV=1
  fi
fi

if [ "$RECREATE_VENV" -eq 1 ]; then
  echo 'Creating local virtual environment...'
  rm -rf "$ROOT/.venv"
  "$PYTHON_BIN" -m venv "$ROOT/.venv" || {
    echo 'ERROR: Could not create .venv.'
    read -r -p 'Press Return to close... ' _
    exit 1
  }
fi

PY="$ROOT/.venv/bin/python"
PIP_VERSION="$($PY -m pip --version 2>/dev/null || true)"
echo "pip: ${PIP_VERSION:-unavailable}"

if [ ! -f "$REQ_FILE" ]; then
  echo "ERROR: Missing dependency file: $REQ_FILE"
  read -r -p 'Press Return to close... ' _
  exit 1
fi

if ! "$PY" -c 'import fastapi, uvicorn, pydantic, pydantic_settings, httpx, dns, typer, rich, pypdf, cryptography, mac_vendor_lookup, zeroconf; fv=tuple(map(int, fastapi.__version__.split('.')[:2])); pv=tuple(map(int, pydantic.__version__.split('.')[:2])); sv=tuple(map(int, pydantic_settings.__version__.split('.')[:2])); raise SystemExit(0 if fv >= (0,128) and pv >= (2,13) and sv >= (2,14) else 1)' >/dev/null 2>&1; then
  echo 'Installing ShadowStrike runtime dependencies into .venv...'
  "$PY" -m pip install --disable-pip-version-check --prefer-binary --upgrade -r "$REQ_FILE" >"$INSTALL_LOG" 2>&1 || {
    echo
    echo 'ERROR: Dependency installation failed.'
    echo "Install log: $INSTALL_LOG"
    echo
    tail -n 30 "$INSTALL_LOG" 2>/dev/null || true
    echo
    echo 'An internet connection is normally required on the first launch.'
    read -r -p 'Press Return to close... ' _
    exit 1
  }
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

if ! "$PY" -c 'import shadowstrike, fastapi, uvicorn; from shadowstrike.engines.tls import TlsIntelligenceEngine; import sys; assert (3,11) <= sys.version_info < (3,15); print("ShadowStrike", shadowstrike.__version__); print("Runtime dependency preflight: OK")'; then
  echo 'ERROR: ShadowStrike could not be loaded from the local source tree.'
  read -r -p 'Press Return to close... ' _
  exit 1
fi

echo "Starting ShadowStrike at $URL"
echo 'Close this Terminal window or press Ctrl+C to stop the local server.'

(
  sleep 1.5
  if command -v open >/dev/null 2>&1; then
    open "$URL" >/dev/null 2>&1 || true
  fi
) &

exec "$PY" -m shadowstrike serve --host "$HOST" --port "$PORT"
