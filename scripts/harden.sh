#!/bin/bash
# Hardening — runs INSIDE the victim. Each fix closes one hole the attacks used and
# maps to a CIS Benchmark control. Idempotent: safe to run more than once.
#   docker exec victim bash /harden.sh      (mounted in via compose)
set -u
echo "=== Sentinel Lab hardening ==="

# FIX 1 (CIS 5.2 / SSH): disable password authentication entirely.
# Kills SSH brute force at the root — no password means no password to guess.
echo "[1] Disabling SSH password authentication..."
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
# Reload sshd so the change takes effect without dropping the container.
kill -HUP "$(cat /run/sshd.pid 2>/dev/null)" 2>/dev/null || pkill -HUP sshd || true

# FIX 2 (CIS 5.3 / least privilege): remove alice's unrestricted sudo.
echo "[2] Removing alice's unrestricted sudo rights..."
rm -f /etc/sudoers.d/alice

# FIX 3 (persistence removal): wipe the attacker's malicious crontab.
echo "[3] Removing malicious cron persistence for alice..."
crontab -r -u alice 2>/dev/null || true

# FIX 4 (CIS 5.4 / password policy): expire the weak password so it must be reset.
echo "[4] Expiring the weak 'alice' password (force reset)..."
passwd -l alice >/dev/null 2>&1 || true   # lock the weak password

echo "=== Hardening complete. Re-run the attacks to see them fail. ==="
