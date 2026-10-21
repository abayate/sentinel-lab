# Incident Report IR-002 — Cron Persistence and Web Path Scanning

| Field | Value |
|-------|-------|
| **Report ID** | IR-002 |
| **Severity** | High (persistence) / Medium (scanning) |
| **Status** | Resolved (remediated) |
| **Affected host** | `victim` (172.22.0.2) |
| **Source** | `attacker` (172.22.0.3) |
| **Detection** | Sentinel Lab engine — rules LAB-004, LAB-005 |

## 1. Summary
Two related activities from the same source: (a) after compromising `alice`, the
attacker installed a malicious cron job to maintain access across reboots, and
(b) the attacker scanned the web server for hidden/sensitive paths.

## 2. Timeline (UTC)
| Time | Event | Evidence / Rule |
|------|-------|-----------------|
| 19:36:05–06 | ~10 HTTP 404s from 172.22.0.3 probing `/admin`, `/.env`, `/.git/config`, `/shell.php`, … | LAB-005 (T1595.003) |
| 19:36:48 | `crontab REPLACE` for user `alice` — new scheduled job installed | LAB-004 (T1053.003) |

## 3. MITRE ATT&CK mapping
- **T1595.003** — Active Scanning: Wordlist Scanning (reconnaissance of web content)
- **T1053.003** — Scheduled Task/Job: Cron (persistence)

## 4. Indicators of Compromise (IOCs)
- One source IP generating ≥5 HTTP 404s within 60s against guessable paths.
- Requests for sensitive artifacts: `/.env`, `/.git/config`, `/shell.php`, `/backup.zip`.
- `crontab[...]: (alice) REPLACE` event in syslog.
- Beacon file `/tmp/.beacon` and a `* * * * *` cron entry for `alice`.

## 5. Impact
The cron job gives the attacker recurring code execution and survivability — the
backdoor re-runs every minute even after the original session ends. The web scan
itself caused no damage but signals active targeting.

## 6. Root cause
- Persistence was possible because the account was compromised (see IR-001).
- Web scanning is unauthenticated and cannot be fully prevented, only detected and
  rate-limited.

## 7. Remediation
- Removed the malicious crontab for `alice` (`crontab -r`), deleted `/tmp/.beacon`.
- Closed the account compromise that enabled persistence (see IR-001 remediation).
- Recommended: rate-limit / block IPs exceeding a 404 threshold (e.g. fail2ban or a
  WAF rule) and alert on requests for `.env` / `.git` paths.

## 8. Detection improvement
LAB-004 currently alerts on *any* crontab REPLACE. Tune by baselining expected
crontab changes (deployment automation) so only unexpected modifications alert.
