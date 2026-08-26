#!/bin/bash
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

echo 'ShadowStrike deep discovery tools'
echo 'Installs maintained upstream packages; ShadowStrike does not vendor or modify their source.'
if command -v brew >/dev/null 2>&1; then
  brew install nmap arp-scan
  echo 'Installed/updated Nmap and arp-scan with Homebrew.'
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y nmap arp-scan
  echo 'Installed Nmap and arp-scan with apt.'
else
  echo 'No supported package manager found. Install nmap and arp-scan from their upstream projects.' >&2
  exit 1
fi
