#!/bin/bash
# A container normally runs ONE process. Our victim needs several daemons at once.
# We start each daemon binary directly (more reliable in a slim image than the
# "service" wrapper), then "tail" the auth log so the container stays alive and
# we can watch authentication activity live.

# rsyslogd must come first: it writes /var/log/auth.log, the file we analyze.
/usr/sbin/rsyslogd

# SSH daemon: the brute-force target. Needs /run/sshd (created in the Dockerfile).
/usr/sbin/sshd

# cron: scheduled-task engine, a classic persistence mechanism.
cron

# nginx: the web server. "daemon off" would block, so we let it background itself.
nginx

echo "[victim] daemons up: sshd(22) nginx(80) cron rsyslogd"
echo "[victim] weak account present for lab: alice / password123"

# Ensure the log exists, then follow it so the container keeps running and
# live login activity is visible via 'docker exec victim tail -f /var/log/auth.log'.
touch /var/log/auth.log
exec tail -F /var/log/auth.log
