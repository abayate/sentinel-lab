#!/bin/bash
# Orchestrator: runs the full intrusion chain in attack order, the way a real
# intrusion unfolds: recon -> brute force -> post-exploitation -> web scan.
# Run from the attacker container:  docker exec attacker bash /attacks/run_all.sh
set -u
TARGET="${1:-victim}"
HERE="$(dirname "$0")"

for step in 01_recon 02_ssh_bruteforce 03_persistence_privesc 04_web_scan; do
  echo
  echo "############################################################"
  echo "# $step"
  echo "############################################################"
  bash "$HERE/$step.sh" "$TARGET"
done
echo
echo "[*] Full attack chain complete."
