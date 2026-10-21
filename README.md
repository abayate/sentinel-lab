# Sentinel Lab — Linux Attack Simulation & Detection Engine

A self-contained security lab that stands up vulnerable Linux hosts, launches
realistic attacks against them, and detects those attacks with a custom Python
detection engine driven by Sigma-style YAML rules. Everything is defined as code
and reproducible with two commands.

> **Scope & ethics:** every host runs on a private Docker network with nothing
> published to the internet. The intentionally weak credentials exist only to make
> attacks demonstrable inside the lab. Do not reuse any of this on real systems.

## Start here (how to read this repo)

New to the project? Follow this order:
1. **Run it:** `bash scripts/demo.sh` — watch the 6 steps (lab → attack → detect → test → harden → attack fails).
2. **Understand it:** this README's [Architecture](#architecture) + [Repository layout](#repository-layout).
3. **Rebuild it from scratch:** [`docs/REPLICATION_GUIDE.md`](docs/REPLICATION_GUIDE.md) — every command, expected output, and gotcha.
4. **The detection logic:** [`engine/detect.py`](engine/detect.py) + a rule like [`engine/rules/001_ssh_bruteforce.yml`](engine/rules/001_ssh_bruteforce.yml).
5. **The scenario & metrics:** [`docs/SCENARIO.md`](docs/SCENARIO.md) — threat model, detection lifecycle, and the 100%/0-FP result on a realistic dataset.
6. **The security write-ups:** [`docs/incident_reports/`](docs/incident_reports) and [`docs/ATTACK_COVERAGE.md`](docs/ATTACK_COVERAGE.md).
7. **Explain it (resume/interview):** [`docs/INTERVIEW_NOTES.md`](docs/INTERVIEW_NOTES.md) and [`docs/RESUME.md`](docs/RESUME.md).

## Impact at a glance

| | Result |
|---|---|
| 🎯 **Detection rate** | **100% — 6 of 6 attack campaigns** caught in a realistic 209-line dataset |
| 🔕 **False positives** | **0** across **138 benign + background-noise events** from dozens of IPs |
| 🧪 **Detection-as-code** | **15 unit tests**, run in CI on every push (true- **and** false-positive tests per rule) |
| ⚡ **Attack impact shown** | Attacker goes from brute-forcing a weak password to **full `root` in under a minute** |
| 🛡️ **Hardening proven** | After CIS-mapped fixes, the same brute force is **rejected at the protocol level** |
| 🧩 **Built from scratch** | Custom Python detection engine + YAML rules — not an off-the-shelf SIEM |

**Techniques detected:** SSH brute force (T1110.001) · valid-account login (T1078) ·
sudo privilege escalation (T1548.003) · cron persistence (T1053.003) · web path
scanning (T1595.003).

The headline result comes from a **realistic, production-style dataset** — legitimate
logins, normal web traffic, and the constant internet background-scanning every public
server sees, with real attack campaigns *hidden in the noise*. See
[`docs/SCENARIO.md`](docs/SCENARIO.md) for the threat model and detection lifecycle.
Reproduce the metrics with:
```bash
python3 scripts/generate_dataset.py   # build the 209-line realistic dataset
python3 engine/evaluate.py            # score detections vs. ground truth
```

See the one-command demo in [Try it end-to-end](#try-it-end-to-end), the full rebuild
in [`docs/REPLICATION_GUIDE.md`](docs/REPLICATION_GUIDE.md), and the coverage map in
[`docs/ATTACK_COVERAGE.md`](docs/ATTACK_COVERAGE.md).

## See it in action

Two ways to *watch* the security events, not just trust a script:

```bash
bash scripts/watch_attack.sh    # LIVE: stream the victim's auth.log as the brute
                                #   force runs — 'Failed password' in red, then the crack
cd engine && python3 report.py  # build the visual SOC dashboard from the real alerts
                                #   -> open engine/report.html in a browser
```

The dashboard (`engine/report.html`) shows stat cards, alerts-per-rule, the MITRE
ATT&CK techniques detected, and a filterable/searchable alert feed — generated
entirely from the engine's own `output/alerts.json`.

<!-- Add a screenshot: save it as docs/dashboard.png and this image will render here -->
![SOC dashboard](docs/dashboard.png)

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
| 2 | Attack simulation (SSH brute force, persistence, privesc, web scan) mapped to ATT&CK | ✅ Done |
| 3 | Python detection engine + YAML rules | ✅ Done |
| 4 | Detection-as-code: unit tests + CI (GitHub Actions) | ✅ Done (15 tests) |
| 5 | Hardening scripts + before/after results | ✅ Done |
| 6 | Incident reports + ATT&CK coverage map | ✅ Done |

**Results:** the engine detects 5 of 6 ATT&CK techniques across the attack chain
(11 alerts), all 15 tests pass, and after hardening the same attacks fail
(SSH brute force is rejected at the protocol level). See `docs/REPLICATION_GUIDE.md`
for a full step-by-step rebuild and `docs/ATTACK_COVERAGE.md` for the coverage map.

## Try it end-to-end

**One command** (rebuilds the lab, attacks it, detects, tests, hardens, re-attacks):
```bash
bash scripts/demo.sh
```

Or run the pipeline stage by stage:
```bash
cd lab && docker compose up -d --build        # 1. start the lab
docker exec attacker bash /attacks/run_all.sh victim   # 2. run the attacks
cd .. && bash scripts/collect_logs.sh         # 3. collect the logs
cd engine && python3 detect.py --rules rules --logs logs   # 4. detect
pytest -q                                     # 5. prove the rules work
```

## Repository layout

```
lab/        docker-compose.yml + victim/ and attacker/ Dockerfiles  (Phase 1)
scripts/    attack scripts (attacks/) and hardening scripts          (Phase 2, 5)
engine/     Python detection engine, rules/, tests/                  (Phase 3, 4)
docs/       INTERVIEW_NOTES.md, incident reports, ATT&CK coverage    (ongoing)
```
