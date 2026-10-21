"""
Detection-as-code tests.

Every rule is tested two ways:
  1. It FIRES on a known-malicious log sample (true positive).
  2. It does NOT fire on benign activity (no false positive).

This is what turns a pile of regexes into trustworthy detections: the tests run in
CI on every push, so a change that breaks a rule fails the build.

Run from the engine/ directory:  pytest -v
"""
import sys
from pathlib import Path

# Make detect.py importable whether pytest is run from engine/ or repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detect import Rule, load_rules, run_match_rule, run_threshold_rule, parse_timestamp  # noqa: E402

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def get_rule(rule_id: str) -> Rule:
    for r in load_rules(RULES_DIR):
        if r.id == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not found")


# --- fixtures: tiny, hand-written log samples -------------------------------

def brute_force_lines(ip="10.0.0.9", n=6):
    base = "2026-10-21T19:36:{:02d}.000000+00:00 victim sshd[42]: "
    return [base.format(i) + f"Failed password for alice from {ip} port 5000{i} ssh2"
            for i in range(n)]


# --- LAB-001 SSH brute force (threshold) ------------------------------------

def test_bruteforce_fires_on_burst():
    rule = get_rule("LAB-001")
    alerts = run_threshold_rule(rule, brute_force_lines(n=6))
    assert len(alerts) == 1
    assert alerts[0]["fields"]["src_ip"] == "10.0.0.9"
    assert "T1110.001" in alerts[0]["mitre"]


def test_bruteforce_ignores_single_typo():
    # One failed password is a typo, not an attack: must NOT alert.
    rule = get_rule("LAB-001")
    alerts = run_threshold_rule(rule, brute_force_lines(n=1))
    assert alerts == []


def test_bruteforce_respects_time_window():
    # 6 failures spread across 10 minutes are below 5-in-2-minutes: no alert.
    rule = get_rule("LAB-001")
    lines = [f"2026-10-21T19:{m:02d}:00.000000+00:00 victim sshd[42]: "
             f"Failed password for alice from 10.0.0.9 port 5000 ssh2"
             for m in range(30, 42, 2)]  # every 2 min
    alerts = run_threshold_rule(rule, lines)
    assert alerts == []


# --- LAB-002 successful login (match) ---------------------------------------

def test_successful_login_matches():
    rule = get_rule("LAB-002")
    line = ("2026-10-21T19:36:48.000000+00:00 victim sshd[92]: "
            "Accepted password for alice from 172.22.0.3 port 56630 ssh2")
    alerts = run_match_rule(rule, [line])
    assert len(alerts) == 1
    assert alerts[0]["fields"]["user"] == "alice"


# --- LAB-003 sudo to root (match) -------------------------------------------

def test_sudo_privesc_matches():
    rule = get_rule("LAB-003")
    line = ("2026-10-21T19:36:48.000000+00:00 victim sudo:    alice : "
            "PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id")
    alerts = run_match_rule(rule, [line])
    assert len(alerts) == 1
    assert alerts[0]["fields"]["command"].strip() == "/usr/bin/id"


def test_sudo_rule_ignores_session_noise():
    # pam_unix session lines also contain "sudo:" but are not a command execution.
    rule = get_rule("LAB-003")
    line = ("2026-10-21T19:36:48.000000+00:00 victim sudo: "
            "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)")
    assert run_match_rule(rule, [line]) == []


# --- LAB-004 cron persistence (match) ---------------------------------------

def test_cron_persistence_matches():
    rule = get_rule("LAB-004")
    line = "2026-10-21T19:36:48.000000+00:00 victim crontab[90]: (alice) REPLACE (alice)"
    alerts = run_match_rule(rule, [line])
    assert len(alerts) == 1
    assert alerts[0]["fields"]["user"] == "alice"


def test_cron_execution_does_not_alert_as_install():
    # A cron JOB running (CMD) is not the same as a crontab being REPLACED.
    rule = get_rule("LAB-004")
    line = ("2026-10-21T19:37:01.000000+00:00 victim CRON[124]: (alice) "
            "CMD (/bin/bash -c \"echo beacon\")")
    assert run_match_rule(rule, [line]) == []


# --- LAB-005 web scan (threshold) -------------------------------------------

def test_web_scan_fires_on_many_404s():
    rule = get_rule("LAB-005")
    lines = [f'172.22.0.3 - - [21/Oct/2026:19:36:{i:02d} +0000] '
             f'"GET /secret{i} HTTP/1.1" 404 153 "-" "curl/7.88.1"'
             for i in range(6)]
    alerts = run_threshold_rule(rule, lines)
    assert len(alerts) == 1
    assert alerts[0]["fields"]["src_ip"] == "172.22.0.3"


def test_web_scan_ignores_normal_200s():
    rule = get_rule("LAB-005")
    lines = [f'172.22.0.3 - - [21/Oct/2026:19:36:{i:02d} +0000] '
             f'"GET /index.html HTTP/1.1" 200 512 "-" "Mozilla"'
             for i in range(10)]
    assert run_threshold_rule(rule, lines) == []


# --- timestamp parsing ------------------------------------------------------

def test_parse_iso_timestamp():
    dt = parse_timestamp("2026-10-21T19:36:48.000000+00:00 victim sshd[1]: x")
    assert dt is not None and dt.year == 2026 and dt.hour == 19


def test_parse_nginx_timestamp():
    dt = parse_timestamp('1.2.3.4 - - [21/Oct/2026:19:36:06 +0000] "GET / HTTP/1.1" 200')
    assert dt is not None and dt.month == 10 and dt.day == 21


def test_all_rules_load_cleanly():
    # Guards against a malformed YAML rule being added.
    rules = load_rules(RULES_DIR)
    assert len(rules) >= 5
    for r in rules:
        assert r.id and r.title and r.mitre
