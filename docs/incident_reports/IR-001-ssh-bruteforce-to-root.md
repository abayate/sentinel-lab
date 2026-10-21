# Incident Report IR-001 — SSH Brute Force Leading to Root Compromise

| Field | Value |
|-------|-------|
| **Report ID** | IR-001 |
| **Severity** | High |
| **Status** | Resolved (remediated) |
| **Affected host** | `victim` (172.22.0.2), Debian 12 |
| **Source** | `attacker` (172.22.0.3) |
| **Detection** | Sentinel Lab engine — rules LAB-001, LAB-002, LAB-003 |

## 1. Summary
An external host conducted an SSH password brute-force attack against the service
account `alice`, succeeded, and then escalated to `root` via a sudo
misconfiguration. End-to-end the attacker went from no access to full root in under
one minute, because the account used a weak password (`password123`) and had
unrestricted `sudo`.

## 2. Timeline (UTC)
| Time | Event | Evidence / Rule |
|------|-------|-----------------|
| 19:36:43 | Burst of 5+ failed SSH passwords for `alice` from 172.22.0.3 | LAB-001 (T1110.001) |
| 19:36:47 | Successful SSH password login for `alice` from 172.22.0.3 | LAB-002 (T1078) |
| 19:36:48 | `sudo ... USER=root ; COMMAND=/usr/bin/id` executed by `alice` | LAB-003 (T1548.003) |

## 3. MITRE ATT&CK mapping
- **T1110.001** — Brute Force: Password Guessing (initial access attempt)
- **T1078** — Valid Accounts (access achieved)
- **T1548.003** — Abuse Elevation Control Mechanism: Sudo (privilege escalation)

## 4. Indicators of Compromise (IOCs)
- Source IP `172.22.0.3` generating ≥5 `Failed password` events in <2 min.
- `Accepted password for alice` from that same IP immediately after.
- `sudo` command execution as `root` by a non-admin service account.

## 5. Impact
Full root-level compromise of the host. An attacker at this level can read all data,
install software, create accounts, and pivot to other hosts.

## 6. Root cause
1. Weak, guessable password on an internet-reachable SSH account.
2. SSH password authentication enabled.
3. Over-privileged account: `alice` had unrestricted `sudo` (`alice ALL=(ALL) ALL`).

## 7. Remediation (applied — see `scripts/harden.sh`)
- Disabled SSH password authentication (`PasswordAuthentication no`). *(CIS 5.2)*
- Removed `alice`'s unrestricted sudo grant. *(least privilege, CIS 5.3)*
- Locked the weak password to force a reset. *(CIS 5.4)*

**Verification:** after remediation, hydra reports
`target ssh://...:22/ does not support password authentication`, and the sudoers
grant is absent. Re-running the engine no longer produces LAB-001/002/003 alerts for
this activity.

## 8. Detection improvement
Rules LAB-001→003 already fire on this chain. Recommended enhancement: correlate the
three rules on a shared `src_ip` to raise a single high-confidence "brute force →
valid account → privesc" incident instead of three separate alerts.
