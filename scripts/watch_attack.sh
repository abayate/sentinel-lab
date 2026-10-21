#!/bin/bash
# LIVE VIEW — watch real SSH security events appear in the victim's log as the
# attack happens. This proves the detections run on genuine OS telemetry, not a
# canned script. Run from the repo root:  bash scripts/watch_attack.sh
set -u
TARGET=victim

echo "============================================================"
echo " LIVE: tailing the victim's /var/log/auth.log"
echo " Launching an SSH brute force in 2 seconds — watch the"
echo " 'Failed password' lines appear in red, then 'Accepted' in the burst."
echo "============================================================"

# Kick off the brute force shortly after we start watching the log.
( sleep 2; docker exec attacker bash /attacks/02_ssh_bruteforce.sh "$TARGET" >/dev/null 2>&1 ) &

# Stream only NEW auth-log lines for ~20s, highlighting the security-relevant ones.
timeout 20 docker exec "$TARGET" tail -n 0 -f /var/log/auth.log \
  | grep --line-buffered -E 'Failed password|Accepted password|sudo|session opened' \
  | GREP_COLORS='mt=01;31' grep --line-buffered --color=always -E 'Failed password|$' \
  || true

echo
echo "Those lines are the actual sshd authentication events on the victim host."
echo "The detection engine reads this same log and turns the burst into a"
echo "LAB-001 'SSH Brute Force' alert (MITRE T1110.001)."
