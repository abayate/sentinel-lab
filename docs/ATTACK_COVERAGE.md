# MITRE ATT&CK Coverage Map

Every attack in this lab is mapped to the MITRE ATT&CK technique it represents and
to the detection rule that catches it. This is how detection engineers communicate
"what can we see?" to the rest of the business.

| Tactic | Technique | ID | Attack script | Detection rule | Status |
|--------|-----------|----|--------------|----------------|--------|
| Reconnaissance | Active Scanning | T1595 | `01_recon.sh` | *(not alerted — nmap is pre-access)* | ⬜ Visibility gap |
| Reconnaissance | Active Scanning: Wordlist Scanning | T1595.003 | `04_web_scan.sh` | LAB-005 | ✅ Detected |
| Credential Access | Brute Force: Password Guessing | T1110.001 | `02_ssh_bruteforce.sh` | LAB-001 | ✅ Detected |
| Initial Access / Persistence | Valid Accounts | T1078 | `02_ssh_bruteforce.sh` | LAB-002 | ✅ Detected |
| Persistence | Scheduled Task/Job: Cron | T1053.003 | `03_persistence_privesc.sh` | LAB-004 | ✅ Detected |
| Privilege Escalation | Abuse Elevation Control: Sudo | T1548.003 | `03_persistence_privesc.sh` | LAB-003 | ✅ Detected |

**Coverage: 5 of 6 techniques detected.** The one gap (raw port scanning, T1595) is
intentional and honest — nmap happens before any access and is noisy to alert on at
the host level; it's better caught at the network layer (IDS/firewall). Calling out
gaps like this is exactly what interviewers want to hear.

## How to extend coverage
Add a rule file in `engine/rules/` and a test in `engine/tests/test_rules.py`:
1. Pick a technique from https://attack.mitre.org/
2. Generate the telemetry (a new attack script).
3. Write the YAML rule (regex + MITRE id).
4. Add a true-positive and a false-positive test.
5. CI proves it works on every push.
