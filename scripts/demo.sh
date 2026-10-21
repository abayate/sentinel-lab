#!/bin/bash
# One-command demo of the whole project. Run from the repo root:
#     bash scripts/demo.sh
# It rebuilds the lab, runs the attacks, detects them, runs the tests, then
# hardens the host and shows the attack failing. This is also your interview demo.
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PY="$HOME/sentinel-venv/bin/python"
line() { printf '\n\033[1;36m%s\033[0m\n' "============================================================"; printf '\033[1;36m %s\033[0m\n' "$1"; printf '\033[1;36m%s\033[0m\n' "============================================================"; }

line "STEP 1/6  Start the lab (victim + attacker)"
( cd lab && docker compose up -d --build 2>&1 | tail -2 )
sleep 3
( cd lab && docker compose ps --format 'table {{.Name}}\t{{.Status}}' )

line "STEP 2/6  Run the attack chain (recon -> brute force -> privesc/persistence -> web scan)"
docker exec attacker bash /attacks/run_all.sh victim 2>&1 \
  | grep -E 'valid password found|uid=0|cron job installed|HTTP (404|200)|###' | head -25

line "STEP 3/6  Collect the victim's logs"
bash scripts/collect_logs.sh

line "STEP 4/6  Run the detection engine (MITRE-tagged alerts)"
( cd engine && "$PY" detect.py --rules rules --logs logs --json output/alerts.json )

line "STEP 5/6  Run the detection-as-code test suite"
( cd engine && "$PY" -m pytest -q )

line "STEP 6/6  Harden the host, then re-run the SSH brute force (it should FAIL now)"
docker exec victim bash /harden.sh 2>&1 | sed 's/^/  /'
echo "  --- brute force against hardened host: ---"
docker exec attacker hydra -l alice -P /tmp/wordlist.txt -t 4 -I ssh://victim 2>&1 \
  | grep -iE 'does not support|valid password' | sed 's/^/  /'

line "BONUS  Build the visual SOC dashboard from these alerts"
( cd engine && "$PY" report.py )

line "DEMO COMPLETE"
echo "Alerts saved to:    engine/output/alerts.json"
echo "Visual dashboard:   engine/report.html  (open it in your browser)"
echo "Read next:          docs/REPLICATION_GUIDE.md and docs/INTERVIEW_NOTES.md"
