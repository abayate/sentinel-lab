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

---

## Phase 2 — Attack simulation

### What I built
Four scripted attacks mapped to MITRE ATT&CK: nmap recon (T1595), hydra SSH brute
force (T1110.001), cron persistence (T1053.003) + sudo privesc (T1548.003), and a
web path scan (T1595.003), plus a `run_all.sh` that chains them in intrusion order.

### Why it matters
A detection is only credible if you can show the attack it catches. Generating my own
telemetry means I understand exactly what each log line represents.

### Practice questions
1. Walk me through how an attacker goes from a port scan to root on this host.
2. Where in the logs does a cron-persistence event show up vs a sudo event, and why?

---

## Phase 3 — Detection engine

### What I built
A Python engine that loads Sigma-style YAML rules and applies them to logs, emitting
MITRE-tagged JSON alerts. Two rule types: `match` (per-line) and `threshold` (N events
per field within a sliding time window).

### Key design decision — threshold vs match
A single failed SSH login is a typo; five in two minutes from one IP is an attack. The
threshold rule uses a per-source `deque` of event timestamps, dropping any older than
the window, and fires once the count crosses the threshold. That window logic is the
difference between a useful alert and alert fatigue.

### Why YAML rules instead of hardcoding
Rules are data, not code — analysts can add detections without touching the engine,
and the rules are reviewable/diffable in Git. This mirrors how real SIEMs (and Sigma)
separate detection content from the engine.

### Practice questions
1. How does your engine avoid alerting on a single failed login?
2. Why did you separate rules (YAML) from the engine (Python)?
3. How would you add a new detection? (answer: new YAML rule + test, CI proves it)

---

## Phase 4 — Detection-as-code (tests + CI)

### What I built
13 pytest tests: every rule has a true-positive and a false-positive test, plus
timestamp-parsing and rule-loading guards. GitHub Actions runs them on every push.

### Why it matters (this is the differentiator)
Most new grads can run a SIEM; few can show detection rules under unit test in CI. It
proves a rule actually fires on the attack AND stays quiet on benign traffic — and
that a future change can't silently break a detection.

### Practice questions
1. How do you know your detection rules actually work — and keep working?
2. What's a false-positive test and why does it matter as much as a true-positive one?

---

## Phase 5 — Hardening (before/after)

### What I built
`harden.sh` fixes each hole mapped to a CIS Benchmark control: disable SSH password
auth (5.2), remove unrestricted sudo (5.3), remove cron persistence, lock the weak
password (5.4). Then I re-ran the attacks and showed them fail.

### The money result
Before: attacker → root in under a minute. After: hydra reports the server "does not
support password authentication" and SSH login is `Permission denied`.

### Practice questions
1. Which single hardening change had the biggest impact, and why?
2. Map each fix to the attack it stops and the CIS control behind it.

---

## Phase 6 — Documentation

Two SOC incident reports (timeline, IOCs, ATT&CK, root cause, remediation), an ATT&CK
coverage map (5/6 techniques, with the gap called out honestly), this notes file, and
a full replication guide. Being able to write a clear incident report is a core
analyst skill and a strong interview artifact.
