# dashboard.py
# SentinelShield - HTML Dashboard Generator
# Reads logs and generates a visual HTML report

import json
import os
from datetime import datetime

LOG_FILE       = "logs/alerts.log"
ALERT_FILE     = "logs/alerts_summary.json"
DASHBOARD_FILE = "static/dashboard.html"

os.makedirs("static", exist_ok=True)

def parse_logs():
    events = []
    if not os.path.exists(LOG_FILE):
        return events
    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                timestamp  = line.split("]")[0].replace("[","").strip()
                ip         = line.split("IP=")[1].split("|")[0].strip()
                method     = line.split("METHOD=")[1].split("|")[0].strip()
                path       = line.split("PATH=")[1].split("|")[0].strip()
                attacks    = line.split("ATTACKS=")[1].split("|")[0].strip()
                action     = line.split("ACTION=")[1].split("|")[0].strip()
                events.append({
                    "timestamp": timestamp,
                    "ip"       : ip,
                    "method"   : method,
                    "path"     : path,
                    "attacks"  : attacks,
                    "action"   : action,
                })
            except IndexError:
                continue
    return events

def generate_dashboard():
    events  = parse_logs()
    total   = len(events)
    blocked = sum(1 for e in events if e["action"] == "BLOCKED")
    allowed = total - blocked

    # Attack type counts
    attack_counts = {}
    for e in events:
        if e["attacks"] != "None":
            for a in e["attacks"].split(","):
                a = a.strip()
                attack_counts[a] = attack_counts.get(a, 0) + 1

    # Flagged IPs
    flagged_ips = {}
    for e in events:
        if e["action"] == "BLOCKED":
            flagged_ips[e["ip"]] = flagged_ips.get(e["ip"], 0) + 1

    # Build attack rows
    attack_rows = ""
    for attack, count in attack_counts.items():
        attack_rows += f"<tr><td>{attack}</td><td>{count}</td></tr>"

    # Build IP rows
    ip_rows = ""
    for ip, count in flagged_ips.items():
        ip_rows += f"<tr><td>{ip}</td><td>{count}</td></tr>"

    # Build event rows (last 20)
    event_rows = ""
    for e in reversed(events[-20:]):
        badge = (
            '<span class="badge blocked">BLOCKED</span>'
            if e["action"] == "BLOCKED"
            else '<span class="badge allowed">ALLOWED</span>'
        )
        event_rows += f"""
        <tr>
            <td>{e['timestamp']}</td>
            <td>{e['ip']}</td>
            <td>{e['method']}</td>
            <td>{e['path'][:40]}</td>
            <td>{e['attacks']}</td>
            <td>{badge}</td>
        </tr>"""

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelShield Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 30px;
        }}
        h1 {{
            color: #58a6ff;
            font-size: 28px;
            margin-bottom: 5px;
        }}
        .subtitle {{
            color: #8b949e;
            font-size: 13px;
            margin-bottom: 30px;
        }}
        .cards {{
            display: flex;
            gap: 20px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px 30px;
            min-width: 160px;
            text-align: center;
        }}
        .card .number {{
            font-size: 42px;
            font-weight: bold;
        }}
        .card .label {{
            font-size: 13px;
            color: #8b949e;
            margin-top: 5px;
        }}
        .total  .number {{ color: #58a6ff; }}
        .block  .number {{ color: #f85149; }}
        .allow  .number {{ color: #3fb950; }}
        .section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 25px;
        }}
        .section h2 {{
            font-size: 16px;
            color: #58a6ff;
            margin-bottom: 15px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            text-align: left;
            padding: 8px 12px;
            color: #8b949e;
            border-bottom: 1px solid #30363d;
        }}
        td {{
            padding: 8px 12px;
            border-bottom: 1px solid #21262d;
        }}
        tr:hover td {{ background: #1c2128; }}
        .badge {{
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: bold;
        }}
        .blocked {{ background: #3d1c1c; color: #f85149; }}
        .allowed {{ background: #1c3d27; color: #3fb950; }}
    </style>
</head>
<body>
    <h1>🛡️ SentinelShield</h1>
    <p class="subtitle">Intrusion Detection & WAF Dashboard &nbsp;|&nbsp; Generated: {generated_at}</p>

    <div class="cards">
        <div class="card total">
            <div class="number">{total}</div>
            <div class="label">Total Requests</div>
        </div>
        <div class="card block">
            <div class="number">{blocked}</div>
            <div class="label">Blocked</div>
        </div>
        <div class="card allow">
            <div class="number">{allowed}</div>
            <div class="label">Allowed</div>
        </div>
    </div>

    <div class="section">
        <h2>⚔️ Attack Type Breakdown</h2>
        <table>
            <tr><th>Attack Type</th><th>Count</th></tr>
            {attack_rows if attack_rows else '<tr><td colspan="2">No attacks detected</td></tr>'}
        </table>
    </div>

    <div class="section">
        <h2>🚩 Flagged IP Addresses</h2>
        <table>
            <tr><th>IP Address</th><th>Blocked Requests</th></tr>
            {ip_rows if ip_rows else '<tr><td colspan="2">No flagged IPs</td></tr>'}
        </table>
    </div>

    <div class="section">
        <h2>📋 Recent Events (Last 20)</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>IP</th>
                <th>Method</th>
                <th>Path</th>
                <th>Attacks</th>
                <th>Action</th>
            </tr>
            {event_rows if event_rows else '<tr><td colspan="6">No events yet</td></tr>'}
        </table>
    </div>
</body>
</html>"""

    with open(DASHBOARD_FILE, "w") as f:
        f.write(html)

    print(f"\n  ✅ Dashboard generated → {DASHBOARD_FILE}")
    print(f"  Open it in your browser to view\n")

if __name__ == "__main__":
    generate_dashboard()
