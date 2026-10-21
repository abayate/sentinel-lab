#!/usr/bin/env python3
"""
Sentinel Lab — detection engine.

Reads collected Linux logs and applies Sigma-style YAML detection rules, emitting
alerts tagged with the MITRE ATT&CK technique they correspond to.

Two rule types:
  * match     -> every log line matching the regex produces one alert.
  * threshold -> an alert fires only when N matching lines share the same field
                 (e.g. source IP) within a sliding time window. This is how we
                 tell a single typo apart from a brute-force attack.

Usage:
    python3 detect.py --rules rules --logs logs
    python3 detect.py --rules rules --logs logs --json alerts.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import yaml


# --- Timestamp parsing -------------------------------------------------------
# Different logs stamp time differently. We normalise everything to a datetime
# so threshold windows can be compared across sources.

_NGINX_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
_NGINX_TS = re.compile(
    r"\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s([+-]\d{4})\]"
)


def parse_timestamp(line: str) -> datetime | None:
    """Return a timezone-aware datetime from a log line, or None if not found."""
    # rsyslog / auth.log / syslog: ISO-8601 at the start, e.g.
    #   2026-10-21T19:36:48.385686+00:00 victim sshd[92]: ...
    token = line.split(" ", 1)[0]
    try:
        return datetime.fromisoformat(token)
    except ValueError:
        pass

    # nginx combined log: 172.22.0.3 - - [21/Oct/2026:19:36:06 +0000] "..."
    m = _NGINX_TS.search(line)
    if m:
        day, mon, year, hh, mm, ss, tz = m.groups()
        offset_h = int(tz[:3])
        offset_m = int(tz[0] + tz[3:])
        tzinfo = timezone(
            # build the UTC offset from the +HHMM / -HHMM field
            __import__("datetime").timedelta(hours=offset_h, minutes=offset_m)
        )
        return datetime(
            int(year), _NGINX_MONTHS[mon], int(day),
            int(hh), int(mm), int(ss), tzinfo=tzinfo,
        )
    return None


# --- Rule model --------------------------------------------------------------

class Rule:
    """One detection rule loaded from a YAML file."""

    def __init__(self, data: dict, path: Path):
        try:
            self.id = data["id"]
            self.title = data["title"]
            self.source = data["source"]          # which log file key to read
            self.type = data["type"]              # "match" or "threshold"
            self.regex = re.compile(data["pattern"])
        except KeyError as exc:
            raise ValueError(f"{path.name}: rule is missing required field {exc}")

        self.description = data.get("description", "")
        self.level = data.get("level", "medium")
        self.mitre = data.get("mitre", [])
        # threshold-only fields
        self.group_by = data.get("group_by")
        self.threshold = int(data.get("threshold", 1))
        self.window_seconds = int(data.get("window_seconds", 60))

        if self.type == "threshold" and not self.group_by:
            raise ValueError(f"{path.name}: threshold rule needs 'group_by'")

    def __repr__(self) -> str:
        return f"<Rule {self.id} {self.title!r}>"


def load_rules(rules_dir: Path) -> list[Rule]:
    """Load every *.yml / *.yaml rule file in a directory."""
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("*.y*ml")):
        with path.open() as fh:
            data = yaml.safe_load(fh)
        rules.append(Rule(data, path))
    return rules


# --- Detection core ----------------------------------------------------------

def make_alert(rule: Rule, when: datetime | None, fields: dict,
               evidence: str, count: int = 1) -> dict:
    """Build a structured alert record (what a SIEM would store/forward)."""
    return {
        "rule_id": rule.id,
        "title": rule.title,
        "level": rule.level,
        "mitre": rule.mitre,
        "timestamp": when.isoformat() if when else None,
        "count": count,
        "fields": fields,
        "evidence": evidence.strip(),
    }


def run_match_rule(rule: Rule, lines: list[str]) -> list[dict]:
    """Fire one alert per matching line."""
    alerts = []
    for line in lines:
        m = rule.regex.search(line)
        if m:
            alerts.append(
                make_alert(rule, parse_timestamp(line), m.groupdict(), line)
            )
    return alerts


def run_threshold_rule(rule: Rule, lines: list[str]) -> list[dict]:
    """
    Fire one alert per group (e.g. per source IP) when >= threshold matching
    lines occur inside a sliding window of window_seconds. Uses a deque of
    recent hit times per group so memory stays bounded on large logs.
    """
    window = deque  # alias for readability below
    hits: dict[str, deque] = {}
    samples: dict[str, dict] = {}   # keep first match's fields+evidence per group
    fired: set[str] = set()
    alerts = []

    for line in lines:
        m = rule.regex.search(line)
        if not m:
            continue
        when = parse_timestamp(line)
        if when is None:
            continue
        key = m.groupdict().get(rule.group_by)
        if key is None:
            continue

        bucket = hits.setdefault(key, window())
        samples.setdefault(key, {"fields": m.groupdict(), "evidence": line, "first": when})
        bucket.append(when)

        # drop timestamps older than the window from the left
        while bucket and (when - bucket[0]).total_seconds() > rule.window_seconds:
            bucket.popleft()

        if len(bucket) >= rule.threshold and key not in fired:
            fired.add(key)
            s = samples[key]
            fields = dict(s["fields"])
            fields["event_count"] = len(bucket)
            fields["window_seconds"] = rule.window_seconds
            alerts.append(
                make_alert(rule, s["first"], fields, s["evidence"], count=len(bucket))
            )
    return alerts


def detect(rules: list[Rule], logs: dict[str, list[str]]) -> list[dict]:
    """Apply all rules to all logs and return a flat, time-sorted alert list."""
    alerts: list[dict] = []
    for rule in rules:
        lines = logs.get(rule.source)
        if lines is None:
            # a rule points at a log we didn't collect; skip quietly
            continue
        if rule.type == "match":
            alerts.extend(run_match_rule(rule, lines))
        elif rule.type == "threshold":
            alerts.extend(run_threshold_rule(rule, lines))
        else:
            raise ValueError(f"{rule.id}: unknown rule type {rule.type!r}")
    alerts.sort(key=lambda a: a["timestamp"] or "")
    return alerts


# --- Log loading & CLI -------------------------------------------------------

# Maps a rule's "source" value to the file name we collected it as.
SOURCE_FILES = {
    "auth": "auth.log",
    "syslog": "syslog",
    "nginx": "nginx_access.log",
}

LEVEL_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def load_logs(logs_dir: Path) -> dict[str, list[str]]:
    logs: dict[str, list[str]] = {}
    for source, filename in SOURCE_FILES.items():
        path = logs_dir / filename
        if path.exists():
            logs[source] = path.read_text(errors="replace").splitlines()
        else:
            logs[source] = []
    return logs


def print_report(alerts: list[dict]) -> None:
    if not alerts:
        print("No alerts. Either the logs are clean or no rule matched.")
        return
    print(f"\n{'='*70}\n  {len(alerts)} ALERT(S)\n{'='*70}")
    for a in alerts:
        icon = LEVEL_ICON.get(a["level"], "⚪")
        mitre = ", ".join(a["mitre"]) if a["mitre"] else "-"
        print(f"\n{icon} [{a['level'].upper()}] {a['title']}  ({a['rule_id']})")
        print(f"    MITRE ATT&CK : {mitre}")
        print(f"    When         : {a['timestamp']}")
        if a["count"] > 1:
            print(f"    Count        : {a['count']} events")
        shown = {k: v for k, v in a["fields"].items()
                 if k not in ("event_count", "window_seconds")}
        if shown:
            print(f"    Fields       : {shown}")
        print(f"    Evidence     : {a['evidence'][:110]}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Sentinel Lab detection engine")
    ap.add_argument("--rules", default="rules", help="directory of YAML rules")
    ap.add_argument("--logs", default="logs", help="directory of collected logs")
    ap.add_argument("--json", help="also write alerts to this JSON file")
    args = ap.parse_args(argv)

    base = Path(__file__).resolve().parent
    rules_dir = (base / args.rules) if not Path(args.rules).is_absolute() else Path(args.rules)
    logs_dir = (base / args.logs) if not Path(args.logs).is_absolute() else Path(args.logs)

    rules = load_rules(rules_dir)
    logs = load_logs(logs_dir)
    print(f"Loaded {len(rules)} rule(s); scanning "
          f"{sum(len(v) for v in logs.values())} log line(s)...")

    alerts = detect(rules, logs)
    print_report(alerts)

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)   # create output/ if needed
        out.write_text(json.dumps(alerts, indent=2))
        print(f"\nWrote {len(alerts)} alert(s) to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
