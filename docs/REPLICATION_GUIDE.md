# Sentinel Lab — Full Replication Guide

A complete, step-by-step walkthrough to rebuild this project from an empty folder.
Each step has: the **command**, **what it does**, **what you should see** (captured
real output = your "screenshot"), and **feedback/gotchas** I hit so you don't.

> You can read this file as plain text or rendered Markdown. Total build time once
> you know the steps: ~30–45 min (most of it Docker image downloads).

---

## 0. Prerequisites & mental model

**What you need (all free):**
- Windows 11 with **WSL2 + Ubuntu** (`wsl --install` from an admin PowerShell).
- **Docker** working inside WSL (`docker --version`). Docker Desktop with WSL
  integration, or Docker installed directly in the Ubuntu distro.
- **Python 3.10+**, **git**. Ubuntu usually has both.
- A **GitHub account** to publish the repo.

**The mental model — explain this in interviews:**
> "I stand up two Linux containers on a private network: a *victim* running real
> services (SSH, web, cron) and an *attacker*. I run realistic attacks, collect the
> Linux logs, and run them through a detection engine I wrote in Python that applies
> Sigma-style YAML rules and tags each hit with its MITRE ATT&CK technique. The rules
> are unit-tested in CI, so every change is proven not to break detection. Then I
> harden the host and show the same attacks failing."

**Verify your tools first:**
```bash
docker --version && docker compose version && python3 --version && git --version
```
*What you should see* — versions printed, e.g. `Docker version 29.x`, `Docker Compose
version v5.x`, `Python 3.12.x`, `git version 2.43.x`. If any command is "not found,"
fix that before continuing.

---

## 1. Project layout

```bash
mkdir -p linuxlab && cd linuxlab && git init
mkdir -p lab/victim lab/attacker engine/rules engine/tests docs scripts/attacks .github/workflows
```
Final structure:
```
linuxlab/
├── lab/            docker-compose.yml + victim/ & attacker/ Dockerfiles
├── scripts/        attack scripts (attacks/), collect_logs.sh, harden.sh
├── engine/         detect.py, rules/*.yml, tests/, requirements.txt
├── docs/           this guide, INTERVIEW_NOTES.md, incident_reports/, ATTACK_COVERAGE.md
└── .github/workflows/ci.yml
```

**GOTCHA — line endings (critical on Windows).** Git on Windows can convert shell
scripts to CRLF, which makes Linux containers fail with `bad interpreter`. Create a
`.gitattributes` at the repo root *first*:
```
*.sh    text eol=lf
Dockerfile text eol=lf
*.yml   text eol=lf
*.py    text eol=lf
```

---

## 2. Phase 1 — Build the lab (victim + attacker)

Create the three files below (full contents are in the repo: `lab/victim/Dockerfile`,
`lab/victim/entrypoint.sh`, `lab/attacker/Dockerfile`, `lab/docker-compose.yml`).

Key points to understand:
- **victim** installs `openssh-server nginx cron sudo auditd rsyslog`, creates a weak
  user `alice:password123`, and (deliberately) grants `alice` full sudo.
- **attacker** installs `hydra nmap curl wget sshpass openssh-client netcat`.
- They share a private bridge network `labnet`; **no ports are published to the host**
  (attacks stay inside the lab).

Build and start:
```bash
cd lab
docker compose up -d --build
docker compose ps
```
*What you should see:*
```
NAME       STATUS
attacker   Up ...
victim     Up ...
```

Confirm the victim's services and that logins hit the auth log:
```bash
docker exec attacker curl -s -o /dev/null -w 'nginx: HTTP %{http_code}\n' http://victim/
docker exec attacker sshpass -p password123 ssh -o StrictHostKeyChecking=no alice@victim 'whoami'
docker exec victim grep -E 'Accepted password' /var/log/auth.log | tail -1
```
*What you should see:* `nginx: HTTP 200`, then `alice`, then an
`Accepted password for alice from 172.22.0.3 ...` line.

**GOTCHAS I hit in Phase 1:**
1. `service rsyslog start` → `unrecognized service` in the slim image. **Fix:** start
   daemons directly in `entrypoint.sh` (`/usr/sbin/rsyslogd`, `/usr/sbin/sshd`, `cron`,
   `nginx`) and drop `set -e` so one noisy service doesn't kill the container.
2. `rsyslogd: imklog: cannot open /proc/kmsg` — **harmless** in containers; auth.log
   still works. Ignore it.
3. `sshpass: Failed to run command: No such file or directory` — the attacker had
   `sshpass` but not the **`openssh-client`** (the actual `ssh` binary). Add it.
4. Privilege escalation only works if `alice` has sudo — add
   `echo 'alice ALL=(ALL) ALL' > /etc/sudoers.d/alice` in the victim Dockerfile.

---

## 3. Phase 2 — Attacks

Four scripts in `scripts/attacks/` (+ `run_all.sh` orchestrator), each mapped to MITRE:
| Script | Technique |
|--------|-----------|
| `01_recon.sh` | nmap port/service scan (T1595) |
| `02_ssh_bruteforce.sh` | hydra password guessing (T1110.001) |
| `03_persistence_privesc.sh` | cron persistence (T1053.003) + sudo privesc (T1548.003) |
| `04_web_scan.sh` | curl probing hidden paths (T1595.003) |

The attack scripts are mounted into the attacker container read-only via the compose
`volumes:` entry, so you can edit them on Windows and run immediately — no rebuild.

Run the whole chain on a fresh victim, then collect the logs:
```bash
docker compose up -d --build victim      # fresh logs
docker exec attacker bash /attacks/run_all.sh victim
cd .. && bash scripts/collect_logs.sh     # pulls logs into engine/logs/
```
*What you should see* (brute force succeeding):
```
[22][ssh] host: victim   login: alice   password: password123
1 of 1 target successfully completed, 1 valid password found
```
and privesc:
```
[sudo] password for alice: uid=0(root) gid=0(root) groups=0(root)
```
and the collector:
```
auth.log : 99 lines   syslog : 15 lines   nginx_access.log : 28 lines
```

**GOTCHA:** cron install events land in **/var/log/syslog**, not auth.log, and sudo
events land in **auth.log**. Inspect the real log lines before writing regex — don't
guess the format. (I used `grep -iE 'sudo|CRON|crontab'` on the collected logs.)

---

## 4. Phase 3 — The detection engine

`engine/detect.py` loads YAML rules from `engine/rules/` and applies them to the logs.
Two rule types:
- **match** — one alert per matching line (e.g. a successful login, a sudo-to-root).
- **threshold** — alert only when N matches share a field within a time window (e.g.
  5 failed logins from one IP in 2 min). A sliding `deque` of timestamps per group
  implements the window. *This is the core idea: a threshold tells an attack apart
  from a one-off typo.*

Five rules (`engine/rules/00X_*.yml`): LAB-001 brute force, LAB-002 successful login,
LAB-003 sudo privesc, LAB-004 cron persistence, LAB-005 web scan.

Set up Python and run it:
```bash
# IMPORTANT: build the venv on the Linux filesystem, NOT under /mnt/c (see gotcha)
python3 -m venv ~/sentinel-venv
~/sentinel-venv/bin/pip install PyYAML pytest
cd engine
~/sentinel-venv/bin/python detect.py --rules rules --logs logs --json output/alerts.json
```
*What you should see* — 11 alerts, each tagged with MITRE, e.g.:
```
🟠 [HIGH] SSH Brute Force  (LAB-001)
    MITRE ATT&CK : T1110.001
    Count        : 5 events
    Fields       : {'user': 'alice', 'src_ip': '172.22.0.3'}
...
Wrote 11 alert(s) to output/alerts.json
```

**GOTCHAS in Phase 3:**
1. **venv on `/mnt/c` is painfully slow / can hang.** Creating the virtualenv on the
   Windows-mounted filesystem took minutes and stalled. **Fix:** create it in WSL's
   native home (`~/sentinel-venv`). The code still runs against the project on `/mnt/c`.
2. Don't run `pkill -f venv` while creating a venv — it kills your own
   `python -m venv` process (the string "venv" matches). (I did this. Learn from it.)
3. The engine creates the `output/` dir automatically; if you see
   `FileNotFoundError: output/alerts.json`, you're on an older version — add
   `out.parent.mkdir(parents=True, exist_ok=True)`.

---

## 5. Phase 4 — Detection-as-code (tests + CI)

`engine/tests/test_rules.py` tests every rule two ways: it **fires** on a malicious
sample and does **not** fire on benign activity (no false positives). Plus timestamp
parsing and "all rules load" guards. 13 tests total.

```bash
cd engine && ~/sentinel-venv/bin/python -m pytest -q
```
*What you should see:*
```
.............                                                            [100%]
13 passed in 0.57s
```

`.github/workflows/ci.yml` runs these on every push/PR to GitHub (Ubuntu runner,
Python 3.12, `pip install -r requirements.txt`, `pytest -v`). This is the headline
feature: **detection rules gated by CI like application code.**

---

## 6. Phase 5 — Hardening (before/after)

`scripts/harden.sh` runs inside the victim (mounted at `/harden.sh`) and fixes every
hole, each mapped to a CIS Benchmark control:
1. `PasswordAuthentication no` (CIS 5.2) — kills SSH brute force.
2. Remove `alice`'s sudo (CIS 5.3, least privilege).
3. `crontab -r` for alice — removes persistence.
4. Lock the weak password (CIS 5.4).

```bash
cd lab && docker compose up -d victim      # attach the harden.sh mount
docker exec victim bash /harden.sh
docker exec attacker hydra -l alice -P /tmp/wordlist.txt -t 4 -I ssh://victim
```
*What you should see* — the attack now fails at the protocol level:
```
[ERROR] target ssh://172.22.0.2:22/ does not support password authentication
```
and `docker exec attacker sshpass -p password123 ssh ... alice@victim` →
`Permission denied (publickey)`. Sudo file gone, crontab empty. **That contrast
(root in <60s → fully blocked) is your strongest demo.**

---

## 7. Phase 6 — Documentation

- `docs/incident_reports/IR-001...md`, `IR-002...md` — SOC-style write-ups: timeline,
  IOCs, ATT&CK mapping, root cause, remediation. Analysts are hired to write these.
- `docs/ATTACK_COVERAGE.md` — the ATT&CK coverage map (5/6 techniques; the one gap is
  called out honestly).
- `docs/INTERVIEW_NOTES.md` — design decisions + practice questions per phase.
- `README.md` — architecture diagram + quick start.

---

## 8. Publish to GitHub
```bash
cd linuxlab
git add -A
git commit -m "Sentinel Lab: Linux attack simulation & detection engine"
gh repo create sentinel-lab --public --source=. --push     # or create via the website
```
Pin it on your profile. In your resume/LinkedIn, link straight to the repo and to
`docs/ATTACK_COVERAGE.md`.

---

## 9. One-command teardown / rebuild
```bash
cd lab && docker compose down          # stop & remove containers + network
cd lab && docker compose up -d --build # rebuild the whole lab from scratch
```
Because the entire environment is code, you can destroy and recreate it anytime — that
reproducibility is the Infrastructure-as-Code point to emphasize.

---

## 10. Quick troubleshooting index
| Symptom | Cause / Fix |
|---------|-------------|
| Container exits immediately | `set -e` + a failing `service` call. Start daemons directly; drop `set -e`. |
| `Temporary failure in name resolution` for `victim` | victim container is down; check `docker compose ps` and `docker logs victim`. |
| `sshpass: Failed to run command` | missing `openssh-client` on the attacker. |
| privesc prints "not in sudoers" | add the `/etc/sudoers.d/alice` line to the victim Dockerfile. |
| venv hangs / takes minutes | you built it under `/mnt/c`. Use `~/sentinel-venv` in WSL home. |
| `bad interpreter: No such file or directory` | CRLF line endings. Add `.gitattributes` (`*.sh text eol=lf`). |
| `FileNotFoundError: output/alerts.json` | engine must `mkdir` the output dir first. |
| empty alerts | log format ≠ your regex. `grep` the real lines and adjust the pattern. |
