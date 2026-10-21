# Scenario & Detection Lifecycle

This project is framed as a full detection-engineering lifecycle for a realistic
target, not a one-off script. This document is the narrative a hiring manager reads.

## The target
An internet-facing Linux server ("victim") running the services such hosts actually
expose: SSH for remote administration, an nginx web server, and cron for scheduled
jobs. Like any public host, it receives **constant background scanning** from the
internet and serves **legitimate users** at the same time.

## Threat model (who/what we defend against)
| Threat | Technique | ATT&CK |
|--------|-----------|--------|
| Opportunistic bots guessing SSH passwords | Brute force | T1110.001 |
| An attacker who cracks a weak account | Valid accounts | T1078 |
| That attacker escalating to root | Sudo abuse | T1548.003 |
| The attacker staying resident | Cron persistence | T1053.003 |
| Recon of the web app for exposed files | Wordlist scanning | T1595.003 |

## The lifecycle (how the project is structured)
1. **Build** — stand the environment up as code (Docker Compose). *(Phase 1)*
2. **Attack** — exercise the threat model with real tools (hydra, nmap, curl). *(Phase 2)*
3. **Collect** — gather the telemetry the attacks produce (auth.log, syslog, nginx). *(Phase 2)*
4. **Detect** — a Python engine applies MITRE-mapped YAML rules. *(Phase 3)*
5. **Measure** — score detections against a labeled, production-scale dataset. *(this doc)*
6. **Respond** — write SOC incident reports from the alerts. *(Phase 6)*
7. **Harden** — close the gaps (CIS controls) and re-test to confirm. *(Phase 5)*

## Two ways the engine is validated
- **Live** — real attacks run against the live container; the engine detects them on
  genuine OS logs (`scripts/demo.sh`, `scripts/watch_attack.sh`). Proves authenticity.
- **At scale** — a realistic **209-line dataset** modeled on a real day of traffic
  (`scripts/generate_dataset.py`): 14 legitimate logins, 45 background-scan failures
  from distinct IPs, 70 normal web requests, plus **6 attack campaigns hidden in the
  noise**. The engine is scored against the known ground truth.

> *Data honesty:* the dataset is **synthetic but modeled on real attack patterns**.
> Every IP is from an RFC 5737 range reserved for documentation
> (192.0.2.x, 198.51.100.x, 203.0.113.x), so no real host is implicated. This is a
> deliberate ethical choice, and a good thing to be able to explain.

## Measured results (`python3 engine/evaluate.py`)
```
Log volume analyzed     : 209 lines across 3 sources
Benign + noise events   : 138 (must NOT alert)
Attack campaigns planted: 6
Attack campaigns caught : 6
Detection rate          : 100%
False positives         : 0
```
**Why this matters:** the hard part of real detection work isn't catching an attack
in a clean lab — it's catching it *in the noise* without drowning analysts in false
alarms. The threshold logic (e.g. a brute force must be 5+ failures from one IP in a
window) is what lets the engine ignore the 45 isolated scan attempts while catching
the two real brute-force campaigns.
