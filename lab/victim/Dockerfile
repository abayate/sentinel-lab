# Victim host: a small Linux server exposing the services an attacker goes after.
# We base it on Debian 12 "bookworm" — a common, realistic server distro.
FROM debian:12-slim

# Install the services we want to defend and the tools that generate logs:
#   openssh-server  -> remote login (the #1 brute-force target)
#   nginx           -> a web server (web-scan / web-shell target)
#   cron            -> scheduled tasks (a classic persistence mechanism)
#   auditd + sudo   -> security logging and privilege escalation surface
#   rsyslog         -> writes the classic /var/log/auth.log we'll analyze
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        nginx \
        cron \
        sudo \
        auditd \
        rsyslog \
        procps \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# SSH needs this directory to exist to accept connections.
RUN mkdir -p /run/sshd

# Create an intentionally weak user account so the brute-force attack can succeed.
# This is deliberate and lives only inside the lab network — never do this on a real host.
RUN useradd -m -s /bin/bash alice \
    && echo 'alice:password123' | chpasswd

# Allow password SSH logins (so brute force is demonstrable) and log verbosely.
RUN sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config

# The entrypoint starts all our services and keeps the container alive.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
