#!/bin/bash
# ATTACK 4 — Web content/path scanning (MITRE ATT&CK T1595.003: Wordlist Scanning)
# The attacker probes the web server for hidden/admin paths. Each request is logged
# by nginx; a burst of 404s from one IP is a classic scanning signature.
set -u
TARGET="${1:-victim}"

PATHS=( admin login.php wp-admin .git/config .env config.php backup.zip phpinfo.php shell.php robots.txt )
echo "[*] Probing $TARGET for sensitive/hidden web paths..."
for p in "${PATHS[@]}"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://$TARGET/$p")
  echo "    /$p -> HTTP $code"
done
echo "[*] Web scan complete — expect many 404s in the nginx access log from one source IP."
