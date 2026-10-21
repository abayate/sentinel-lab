# Attacker host: a lightweight box with the tools we use to simulate an intrusion.
FROM debian:12-slim

# Tools of the trade for our simulated attacks:
#   hydra        -> SSH/password brute forcing
#   nmap         -> port and service scanning (reconnaissance)
#   curl/wget    -> hitting the web server, downloading payloads
#   sshpass      -> scripted (non-interactive) SSH logins
#   netcat       -> simple reverse-shell / connectivity tests
RUN apt-get update && apt-get install -y --no-install-recommends \
        hydra \
        nmap \
        curl \
        wget \
        sshpass \
        openssh-client \
        netcat-openbsd \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Attack scripts get mounted in at runtime (via docker-compose volume),
# so we don't rebuild the image every time we edit an attack.
WORKDIR /attacks

# Keep the container running and idle until we 'docker exec' an attack into it.
CMD ["sleep", "infinity"]
