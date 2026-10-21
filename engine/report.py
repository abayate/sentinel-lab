#!/usr/bin/env python3
"""
Turn the engine's JSON alerts into a visual, self-contained SOC dashboard webpage.

    python3 report.py                      # reads output/alerts.json -> report.html
    python3 report.py --in a.json --out b.html

The output is a single HTML file with the alert data embedded — no server, no
internet, no dependencies. Open it in any browser (or double-click it in Windows).
This is the "what a SOC analyst stares at" view of the same data.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build_html(alerts: list[dict]) -> str:
    alerts = sorted(alerts, key=lambda a: (LEVEL_ORDER.get(a["level"], 9),
                                           a.get("timestamp") or ""))
    total = len(alerts)
    highs = sum(1 for a in alerts if a["level"] in ("high", "critical"))
    mediums = sum(1 for a in alerts if a["level"] == "medium")
    techniques = sorted({t for a in alerts for t in a.get("mitre", [])})
    sources = sorted({a["fields"].get("src_ip") for a in alerts
                      if a["fields"].get("src_ip")})
    by_rule = Counter(a["title"] for a in alerts)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Alert data embedded for the client-side filter/search.
    data_json = json.dumps(alerts).replace("</", "<\\/")

    rows = "\n".join(
        f"""      <tr data-level="{a['level']}"
          data-text="{(a['title'] + ' ' + ' '.join(a.get('mitre', [])) + ' ' + json.dumps(a['fields'])).lower().replace('"', '&quot;')}">
        <td><span class="pill {a['level']}">{a['level'].upper()}</span></td>
        <td class="mono">{a.get('timestamp','') or ''}</td>
        <td><strong>{a['title']}</strong><br><span class="muted mono">{a['rule_id']}</span></td>
        <td>{' '.join(f'<span class="badge">{t}</span>' for t in a.get('mitre', []))}</td>
        <td class="mono">{a['fields'].get('src_ip','-')}</td>
        <td class="mono small">{(a['evidence'][:90] + '…') if len(a['evidence'])>90 else a['evidence']}</td>
      </tr>"""
        for a in alerts
    )

    tech_rows = "\n".join(
        f'<li><span class="badge">{t}</span></li>' for t in techniques
    )
    rule_rows = "\n".join(
        f'<div class="bar-row"><span class="bar-label">{title}</span>'
        f'<span class="bar"><span class="bar-fill" style="width:{(cnt/total*100):.0f}%"></span></span>'
        f'<span class="bar-num">{cnt}</span></div>'
        for title, cnt in by_rule.most_common()
    )

    return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Lab — Detection Dashboard</title>
<style>
  :root {{
    --bg:#0b1020; --panel:#141b2e; --panel2:#1b2440; --text:#e6ebf5;
    --muted:#8b97b5; --line:#263150; --accent:#4da3ff;
    --high:#ff5d5d; --medium:#ffb84d; --low:#4da3ff; --ok:#39d98a;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
    font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:24px 16px 60px; }}
  header h1 {{ margin:0 0 4px; font-size:24px; }}
  header p {{ margin:0; color:var(--muted); font-size:14px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
    gap:14px; margin:22px 0; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:12px;
    padding:16px; }}
  .card .num {{ font-size:30px; font-weight:700; }}
  .card .lbl {{ color:var(--muted); font-size:12px; text-transform:uppercase;
    letter-spacing:.5px; margin-top:4px; }}
  .num.high {{ color:var(--high); }} .num.med {{ color:var(--medium); }}
  .num.ok {{ color:var(--ok); }} .num.acc {{ color:var(--accent); }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }}
  @media (max-width:720px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
  .panel {{ background:var(--panel); border:1px solid var(--line); border-radius:12px;
    padding:16px; margin-bottom:14px; }}
  .panel h2 {{ margin:0 0 12px; font-size:15px; color:var(--muted);
    text-transform:uppercase; letter-spacing:.5px; }}
  .bar-row {{ display:flex; align-items:center; gap:10px; margin:8px 0; font-size:13px; }}
  .bar-label {{ width:190px; }} .bar-num {{ width:24px; text-align:right; color:var(--muted); }}
  .bar {{ flex:1; height:10px; background:var(--panel2); border-radius:6px; overflow:hidden; }}
  .bar-fill {{ display:block; height:100%; background:linear-gradient(90deg,#4da3ff,#39d98a); }}
  ul.badges {{ list-style:none; padding:0; margin:0; display:flex; flex-wrap:wrap; gap:8px; }}
  .badge {{ background:#10213f; color:#7fc0ff; border:1px solid #23457a;
    padding:2px 8px; border-radius:20px; font-size:12px; font-family:ui-monospace,monospace; }}
  .controls {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:10px; }}
  .controls input {{ flex:1; min-width:180px; background:var(--panel2); color:var(--text);
    border:1px solid var(--line); border-radius:8px; padding:8px 12px; }}
  .fbtn {{ background:var(--panel2); color:var(--text); border:1px solid var(--line);
    border-radius:8px; padding:7px 12px; cursor:pointer; font-size:13px; }}
  .fbtn.active {{ background:var(--accent); color:#06122a; border-color:var(--accent); font-weight:600; }}
  table {{ width:100%; border-collapse:collapse; }}
  th,td {{ text-align:left; padding:10px 8px; border-bottom:1px solid var(--line);
    vertical-align:top; font-size:13px; }}
  th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.5px; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .small {{ font-size:11px; color:var(--muted); }}
  .muted {{ color:var(--muted); }}
  .pill {{ padding:2px 10px; border-radius:20px; font-size:11px; font-weight:700; }}
  .pill.high,.pill.critical {{ background:rgba(255,93,93,.15); color:var(--high);
    border:1px solid rgba(255,93,93,.4); }}
  .pill.medium {{ background:rgba(255,184,77,.15); color:var(--medium);
    border:1px solid rgba(255,184,77,.4); }}
  .pill.low {{ background:rgba(77,163,255,.15); color:var(--low);
    border:1px solid rgba(77,163,255,.4); }}
  .foot {{ color:var(--muted); font-size:12px; margin-top:20px; text-align:center; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>🛡️ Sentinel Lab — Detection Dashboard</h1>
    <p>Alerts produced by the detection engine from simulated attacks · generated {generated}</p>
  </header>

  <section class="cards">
    <div class="card"><div class="num acc">{total}</div><div class="lbl">Total Alerts</div></div>
    <div class="card"><div class="num high">{highs}</div><div class="lbl">High / Critical</div></div>
    <div class="card"><div class="num med">{mediums}</div><div class="lbl">Medium</div></div>
    <div class="card"><div class="num ok">{len(techniques)}</div><div class="lbl">ATT&CK Techniques</div></div>
    <div class="card"><div class="num">{len(sources)}</div><div class="lbl">Source IPs</div></div>
  </section>

  <div class="grid2">
    <div class="panel">
      <h2>Alerts by detection rule</h2>
      {rule_rows}
    </div>
    <div class="panel">
      <h2>MITRE ATT&CK techniques detected</h2>
      <ul class="badges">
        {tech_rows}
      </ul>
    </div>
  </div>

  <div class="panel">
    <h2>Alert feed</h2>
    <div class="controls">
      <button class="fbtn active" data-f="all">All</button>
      <button class="fbtn" data-f="high">High</button>
      <button class="fbtn" data-f="medium">Medium</button>
      <input id="search" placeholder="Search IP, technique, rule…">
    </div>
    <table>
      <thead><tr>
        <th>Severity</th><th>Time (UTC)</th><th>Detection</th>
        <th>ATT&CK</th><th>Source IP</th><th>Evidence</th>
      </tr></thead>
      <tbody id="tbody">
{rows}
      </tbody>
    </table>
  </div>

  <p class="foot">Sentinel Lab · detection-as-code · github.com/abayate/sentinel-lab</p>
</div>
<script>
  const rows = Array.from(document.querySelectorAll('#tbody tr'));
  let level = 'all';
  function apply() {{
    const q = document.getElementById('search').value.toLowerCase();
    rows.forEach(r => {{
      const okLvl = level === 'all'
        || (level === 'high' && (r.dataset.level === 'high' || r.dataset.level === 'critical'))
        || r.dataset.level === level;
      const okQ = !q || r.dataset.text.includes(q);
      r.style.display = (okLvl && okQ) ? '' : 'none';
    }});
  }}
  document.querySelectorAll('.fbtn').forEach(b => b.addEventListener('click', () => {{
    document.querySelectorAll('.fbtn').forEach(x => x.classList.remove('active'));
    b.classList.add('active'); level = b.dataset.f; apply();
  }}));
  document.getElementById('search').addEventListener('input', apply);
</script>
</body>
</html>"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate the SOC dashboard HTML")
    base = Path(__file__).resolve().parent
    ap.add_argument("--in", dest="inp", default=str(base / "output" / "alerts.json"))
    ap.add_argument("--out", default=str(base / "report.html"))
    args = ap.parse_args(argv)

    alerts = json.loads(Path(args.inp).read_text())
    Path(args.out).write_text(build_html(alerts), encoding="utf-8")
    print(f"Wrote dashboard with {len(alerts)} alert(s) -> {args.out}")
    print("Open it in a browser (double-click the file, or see the command below).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
