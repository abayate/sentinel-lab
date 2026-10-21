#!/usr/bin/env python3
"""
Score the detection engine against the dataset's ground truth.

Reads what generate_dataset.py planted (engine/logs/ground_truth.json), runs the
engine over the logs, and reports detection metrics a hiring manager understands:
how many real attack campaigns were caught, and how much of the benign baseline
wrongly alerted (false positives).

    python3 evaluate.py
"""
from __future__ import annotations

import json
from pathlib import Path

from detect import load_rules, load_logs, detect

BASE = Path(__file__).resolve().parent


def score(logs_dir: Path = None) -> dict:
    """Run the engine over a labeled dataset and score it against ground truth.
    Shared by the CLI report and the test suite so both use identical logic."""
    logs_dir = logs_dir or (BASE / "logs")
    gt = json.loads((logs_dir / "ground_truth.json").read_text())
    rules = load_rules(BASE / "rules")
    logs = load_logs(logs_dir)
    alerts = detect(rules, logs)

    total_lines = sum(len(v) for v in logs.values())
    benign = (gt["benign_ssh_sessions"] + gt["internet_noise_failed_logins"]
              + gt["benign_web_requests"] + gt["web_noise_404s"])

    # Did each planted attack get caught?
    #   - If the rule's alerts carry a source IP (e.g. brute force), require the IP
    #     to match the attacker's.
    #   - If the rule's events have no IP (sudo/cron are local — no network source),
    #     the rule firing at all is the catch.
    caught, missed = [], []
    for atk in gt["attacks"]:
        rule_alerts = [a for a in alerts if a["rule_id"] == atk["rule"]]
        ips = {a["fields"].get("src_ip") for a in rule_alerts if a["fields"].get("src_ip")}
        hit = bool(rule_alerts) and (not ips or atk["src_ip"] in ips)
        (caught if hit else missed).append(atk)

    # False positives: alerts whose source IP is NOT one of the attack IPs.
    attack_ips = {a["src_ip"] for a in gt["attacks"]}
    false_positives = [a for a in alerts
                       if a["fields"].get("src_ip")
                       and a["fields"]["src_ip"] not in attack_ips]

    return {"total_lines": total_lines, "benign": benign,
            "planted": len(gt["attacks"]), "caught": caught,
            "missed": missed, "false_positives": false_positives}


def main() -> int:
    r = score()
    total_lines, benign, planted = r["total_lines"], r["benign"], r["planted"]
    caught, missed, false_positives = r["caught"], r["missed"], r["false_positives"]
    detected = len(caught)
    rate = detected / planted * 100 if planted else 0

    print("=" * 60)
    print("  DETECTION EVALUATION")
    print("=" * 60)
    print(f"  Log volume analyzed     : {total_lines} lines across 3 sources")
    print(f"  Benign + noise events   : {benign} (must NOT alert)")
    print(f"  Attack campaigns planted: {planted}")
    print(f"  Attack campaigns caught : {detected}")
    print(f"  Detection rate          : {rate:.0f}%")
    print(f"  False positives         : {len(false_positives)}")
    print("-" * 60)
    for a in caught:
        print(f"  [CAUGHT]  {a['id']:<3} {a['rule']}  {a['type']}  (src {a['src_ip']})")
    for a in missed:
        print(f"  [MISSED]  {a['id']:<3} {a['rule']}  {a['type']}  (src {a['src_ip']})")
    print("=" * 60)
    if detected == planted and not false_positives:
        print("  RESULT: all attacks detected, zero false positives on the"
              " benign baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
