#!/bin/bash
# ATTACK 1 — Reconnaissance (MITRE ATT&CK T1595: Active Scanning)
# The attacker scans the victim to discover open ports and running services.
# This is what almost every intrusion starts with.
set -u
TARGET="${1:-victim}"

echo "[*] Scanning $TARGET for open services (nmap)..."
# -sV = probe versions, -T4 = faster timing, top 100 ports is enough for the lab.
nmap -sV -T4 --top-ports 100 "$TARGET"
echo "[*] Recon complete. The attacker now knows SSH(22) and HTTP(80) are open."
