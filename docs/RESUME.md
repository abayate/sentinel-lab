# Resume & Interview Text — Sentinel Lab

Copy-paste bank for your resume, LinkedIn, and interviews. Everything here reflects
what the project actually does, so you can back up every claim.

## Resume project header
> **Sentinel Lab** — Linux Detection-Engineering Project
> Python · Docker · MITRE ATT&CK · CI/CD · github.com/abayate/sentinel-lab

## Resume bullets (XYZ format — pick 3–4)
- Built a **custom Python detection engine** (Sigma-style YAML rules mapped to MITRE
  ATT&CK) that achieved a **100% detection rate — 6 of 6 attack campaigns — with zero
  false positives** across a realistic 209-line dataset of 138 benign/background-noise
  events, emitting structured, technique-tagged alerts.
- Engineered **detection-as-code** with **15 unit tests** (true- and false-positive
  cases per rule) gated in a **GitHub Actions CI pipeline**, proving each rule fires
  on attacks without false-alarming on normal activity.
- Architected a **reproducible attacker/victim lab as Infrastructure-as-Code** with
  Docker Compose on WSL2, standing up a multi-service Linux environment (SSH, web,
  cron, syslog) from a single declarative file.
- Reduced attack surface via **CIS Benchmark–mapped hardening** (disabled SSH password
  auth, enforced least-privilege sudo, removed persistence), taking the host from
  **full root compromise in under a minute to the same attack rejected at the
  protocol level**.
- Authored **SOC-style incident reports** (timeline, IOCs, root cause, remediation)
  and a **MITRE ATT&CK coverage map** documenting detection gaps and tuning steps.

## Elevator pitch (30 seconds)
> "Sentinel Lab is a detection-engineering project I built. I use Docker to run an
> attacker and a victim Linux server, simulate real attacks like SSH brute force and
> privilege escalation, and I wrote a Python engine that reads the server's logs and
> detects those attacks using YAML rules, each mapped to a MITRE ATT&CK technique. The
> rules are unit-tested in CI, and I harden the server to show the attacks failing
> afterward. It covers the whole loop: attack, detect, prevent."

## STAR answer (spoken, ~60–90s)
- **Situation:** I wanted a project proving I can do real detection-engineering work,
  not just operate a tool someone else built.
- **Task:** Build an environment where I could attack a Linux system and write the
  code that detects the attacks — attack, detect, and prevent.
- **Action:** Stood up attacker + victim containers in Docker on WSL; scripted attacks
  (SSH brute force, sudo privesc, cron persistence, web scan) mapped to MITRE ATT&CK;
  wrote a Python engine that reads the logs and applies YAML rules, including threshold
  logic so 5 failed logins in 2 minutes alert but one typo doesn't; put the rules under
  pytest in GitHub Actions CI; wrote a CIS-mapped hardening script.
- **Result:** Detects 5 of 6 techniques, 15 tests pass in CI, and after hardening the
  brute force that gave root in under a minute is rejected at the protocol level.

## "How does this scale to a real job?" (the differentiator)
> "I built it small so I understand every line, but each piece maps to how real teams
> work: my YAML rules are the same idea as Sigma, my alerts map to MITRE ATT&CK, and my
> detections are tested in CI like production detection code. At a company you'd swap my
> Python engine for a SIEM and my two containers for a real fleet — the thinking is the
> same."
