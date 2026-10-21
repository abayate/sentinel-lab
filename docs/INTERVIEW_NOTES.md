# Interview Notes — Sentinel Lab

Running notes so I can explain this project in depth. One section per phase:
what it is, the design decisions I made and *why*, and practice questions.

---

## Phase 1 — The lab environment (Infrastructure as Code)

### What I built
A two-host Linux lab defined entirely in a single `docker-compose.yml`:
- **victim** — a Debian 12 server running `sshd`, `nginx`, `cron`, and `rsyslog`. It has
  an intentionally weak account (`alice` / `password123`) so attacks can succeed.
- **attacker** — a Debian box with `hydra`, `nmap`, `curl`, `sshpass`, `netcat`.
- Both sit on a private `labnet` bridge network and reach each other by hostname.

### Design decisions & why
- **Docker Compose instead of VMs** — the whole environment is reproducible from one
  declarative file ("Infrastructure as Code"). `docker compose up` rebuilds the exact
  same lab on any machine. Lighter than VMs, which matters on a laptop.
- **No ports published to the host** — attacks stay *inside* the lab network. Nothing
  is exposed to the internet, so the deliberately weak account is safe.
- **Daemons launched directly in the entrypoint**, not via `service` — the `service`
  init scripts aren't reliable in a slim image, and launching `sshd`/`rsyslogd`/`cron`/
  `nginx` directly makes it obvious exactly what is running.
- **`LogLevel VERBOSE` on sshd** — produces richer auth events for detection.
- **Container stays alive with `tail -F /var/log/auth.log`** — a container needs a
  foreground process; tailing the auth log doubles as a live view of login activity.

### Linux concepts I learned here
- Services/daemons: `sshd`, `cron`, `nginx`, `rsyslogd` and what each does.
- `/var/log/auth.log` is where authentication events are recorded (via rsyslog).
- The anatomy of an auth event: `Failed password for <user> from <ip> port <p> ssh2`
  vs `Accepted password for ...`.
- Users & passwords: `useradd`, `chpasswd`, `/etc/ssh/sshd_config`.

### Proof it works
```
Failed password for alice from 172.22.0.3 port 41346 ssh2     <- failed login
Accepted password for alice from 172.22.0.3 port 41354 ssh2   <- successful login
```

### Practice questions (answer these out loud before Phase 2)
1. Why did I choose Docker Compose over spinning up VirtualBox VMs?
2. Where do SSH authentication events get logged, and what writes them there?
3. Why are no ports published to the host, and why does that make the weak
   password acceptable in this lab?
4. A container runs one process — how do I run four daemons in the victim, and why
   does the container stay running?
