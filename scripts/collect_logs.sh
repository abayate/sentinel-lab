#!/bin/bash
# Pulls the telemetry the detection engine analyzes out of the victim container
# and onto the host, into engine/logs/. Run this AFTER an attack chain.
#   bash scripts/collect_logs.sh
set -eu
OUT="$(dirname "$0")/../engine/logs"
mkdir -p "$OUT"

echo "[*] Collecting logs from the victim container into engine/logs/ ..."
docker exec victim cat /var/log/auth.log            > "$OUT/auth.log"            2>/dev/null || true
docker exec victim cat /var/log/syslog              > "$OUT/syslog"              2>/dev/null || true
docker exec victim cat /var/log/nginx/access.log    > "$OUT/nginx_access.log"    2>/dev/null || true
docker exec victim bash -c 'crontab -l -u alice'    > "$OUT/alice_crontab.txt"   2>/dev/null || true

echo "    auth.log         : $(wc -l < "$OUT/auth.log" 2>/dev/null || echo 0) lines"
echo "    syslog           : $(wc -l < "$OUT/syslog" 2>/dev/null || echo 0) lines"
echo "    nginx_access.log : $(wc -l < "$OUT/nginx_access.log" 2>/dev/null || echo 0) lines"
echo "    alice_crontab    : $(wc -l < "$OUT/alice_crontab.txt" 2>/dev/null || echo 0) lines"
echo "[*] Done."
