# Sentinel Lab — Linux Attack Simulation & Detection Engine

A self-contained security lab that stands up vulnerable Linux hosts, launches
realistic attacks against them, and detects those attacks with a custom Python
detection engine driven by Sigma-style YAML rules. Everything is defined as code
and reproducible with two commands.

> **Scope & ethics:** every host runs on a private Docker network with nothing
> published to the internet. The intentionally weak credentials exist only to make
> attacks demonstrable inside the lab. Do not reuse any of this on real systems.

## Architecture

```
            labnet (private bridge network)
  ┌──────────────┐  attacks   ┌──────────────────────────────┐
  │   attacker   │ ─────────▶ │  victim (Debian 12)          │
  │  hydra nmap  │            │  sshd · nginx · cron · rsyslog│
  │  curl nc     │            │  /var/log/auth.log            │
  └──────────────┘            └──────────────┬───────────────┘
                                             │ logs
                                             ▼
                              ┌──────────────────────────────┐
                              │  Python detection engine      │
                              │  YAML rules → JSON alerts      │
                              │  tagged with MITRE ATT&CK      │
                              └──────────────────────────────┘
```

## Quick start

```bash
cd lab
docker compose up -d --build   # build + start the victim and attacker
docker compose ps              # both should be "Up"
docker compose down            # tear the lab down
```

## Project status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Lab environment (IaC: victim + attacker on a private network) | ✅ Done |
| 2 | Attack simulation (SSH brute force, persistence, privesc, web scan) mapped to ATT&CK | ⏳ Next |
| 3 | Python detection engine + YAML rules | ⏳ |
| 4 | Detection-as-code: unit tests + CI (GitHub Actions) | ⏳ |
| 5 | Hardening scripts + before/after results | ⏳ |
| 6 | Incident reports + ATT&CK coverage map | ⏳ |

## Repository layout

```
lab/        docker-compose.yml + victim/ and attacker/ Dockerfiles  (Phase 1)
scripts/    attack scripts (attacks/) and hardening scripts          (Phase 2, 5)
engine/     Python detection engine, rules/, tests/                  (Phase 3, 4)
docs/       INTERVIEW_NOTES.md, incident reports, ATT&CK coverage    (ongoing)
```
