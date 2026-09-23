#!/bin/bash
set -e

BLOCKLIST=${AEGIS_BLOCKLIST_DIR:-/opt/aegis/blocklists}
GEOIP=${AEGIS_GEOIP_DIR:-/opt/aegis/geoip}
mkdir -p "$BLOCKLIST" "$GEOIP"

echo "[*] Blocklists refresh ho rahi hain..."

curl -s https://rules.emergingthreats.net/blockrules/compromised-ips.txt \
     -o "$BLOCKLIST/et-compromised.txt"

curl -s https://feodotracker.abuse.ch/downloads/ipblocklist.txt \
     -o "$BLOCKLIST/feodo.txt"

curl -s https://cinsscore.com/list/ci-badguys.txt \
     -o "$BLOCKLIST/ci-badguys.txt"

echo "[*] DB-IP Lite refresh ho rahi hai..."
MONTH=$(date +%Y-%m)
curl -s "https://download.db-ip.com/free/dbip-city-lite-${MONTH}.csv.gz" \
     | gunzip > "$GEOIP/dbip-city-lite.csv"

echo "[✓] Sab feeds refresh ho gayi: $(date)"
