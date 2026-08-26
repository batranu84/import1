#!/bin/bash
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
cd "$(dirname "$0")"

if [ -n "${SHADOWSTRIKE_HOST:-}" ]; then
  HOST="$SHADOWSTRIKE_HOST"
else
  HOST=""
  for iface in en0 en1 bridge0; do
    if command -v ipconfig >/dev/null 2>&1; then
      candidate="$(ipconfig getifaddr "$iface" 2>/dev/null || true)"
      case "$candidate" in
        10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) HOST="$candidate"; break ;;
      esac
    fi
  done
  if [ -z "$HOST" ]; then
    HOST="0.0.0.0"
  fi
fi
export SHADOWSTRIKE_HOST="$HOST"
echo "Starting ShadowStrike controller on $HOST:${SHADOWSTRIKE_PORT:-8765} for authorized routed/VPN sensor access."
echo 'Use a host firewall/VPN to restrict who can reach this listener.'
exec ./start.command
