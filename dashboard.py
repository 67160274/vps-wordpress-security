#!/usr/bin/env python3
"""
Security Dashboard Web Server
หน้าเว็บแสดงผลการวิเคราะห์ความปลอดภัย
"""

import sqlite3
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

DB_PATH = "/home/student/security-dashboard/security.db"
PORT = 8888

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Dashboard - VPS Monitor</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'Segoe UI', sans-serif; background:#0f172a; color:#e2e8f0; }
header { background:#1e293b; padding:20px 30px; border-bottom:2px solid #334155;
         display:flex; justify-content:space-between; align-items:center; }
header h1 { font-size:1.4rem; color:#38bdf8; }
header span { font-size:0.85rem; color:#94a3b8; }
.container { max-width:1200px; margin:0 auto; padding:24px; }
.grid-4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }
.grid-2 { display:grid; grid-template-columns:repeat(2,1fr); gap:16px; margin-bottom:24px; }
.card { background:#1e293b; border-radius:12px; padding:20px; border:1px solid #334155; }
.card h3 { font-size:0.8rem; color:#94a3b8; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px; }
.card .value { font-size:2rem; font-weight:700; }
.card .sub { font-size:0.8rem; color:#64748b; margin-top:4px; }
.risk-LOW { color:#22c55e; }
.risk-MEDIUM { color:#f59e0b; }
.risk-HIGH { color:#f97316; }
.risk-CRITICAL { color:#ef4444; }
.risk-UNKNOWN { color:#94a3b8; }
.badge { display:inline-block; padding:3px 10px; border-radius:20px; font-size:0.75rem; font-weight:600; }
.badge-LOW { background:#14532d; color:#22c55e; }
.badge-MEDIUM { background:#451a03; color:#f59e0b; }
.badge-HIGH { background:#431407; color:#f97316; }
.badge-CRITICAL { background:#450a0a; color:#ef4444; }
.badge-UNKNOWN { background:#1e293b; color:#94a3b8; }
table { width:100%; border-collapse:collapse; font-size:0.85rem; }
th { text-align:left; padding:10px 12px; background:#0f172a; color:#94a3b8;
     font-size:0.75rem; text-transform:uppercase; border-bottom:1px solid #334155; }
td { padding:10px 12px; border-bottom:1px solid #1e293b; }
tr:hover td { background:#334155; }
.summary-box { background:#0f172a; border-radius:8px; padding:16px; 
               border-left:3px solid #38bdf8; margin-bottom:12px; }
.rec-item { padding:8px 12px; margin:6px 0; background:#0f172a; 
            border-radius:6px; font-size:0.85rem; }
.rec-item::before { content:"→ "; color:#38bdf8; }
.chart-bar { height:8px; background:#334155; border-radius:4px; margin-top:4px; overflow:hidden; }
.chart-fill { height:100%; background:#38bdf8; border-radius:4px; }
.no-data { text-align:center; color:#64748b; padding:40px; }
.refresh-btn { background:#38bdf8; color:#0f172a; border:none; padding:8px 16px;
               border-radius:6px; cursor:pointer; font-size:0.85rem; font-weight:600; }
.attack-tag { display:inline-block; background:#1e3a5f; color:#60a5fa; 
              padding:2px 8px; border-radius:4px; font-size:0.75rem; margin:2px; }
</style>
</head>
<body>
<header>
  <h1>🛡️ Security Dashboard — wordduckpress.duckdns.org</h1>
  <div style="display:flex;gap:12px;align-items:center">
    <span id="clock"></span>
    <button class="refresh-btn" onclick="location.reload()">⟳ Refresh</button>
  </div>
</header>
<div class="container">
  {{CONTENT}}
</div>
<script>
function updateClock(){
  document.getElementById('clock').textContent = new Date().toLocaleString('th-TH');
}
setInterval(updateClock,1000); updateClock();
setTimeout(()=>location.reload(), 60000);
</script>
</body>
</html>"""

def get_data():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # ข้อมูลล่าสุด
        c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
        latest = c.fetchone()
        
        # ประวัติ 24 รายการ
        c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 24")
        history = c.fetchall()
        
        conn.close()
        return latest, history
    except:
        return None, []

def build_content(latest, history):
    if not latest:
        return '<div class="no-data"><h2>⏳ ยังไม่มีข้อมูล</h2><p>รอสแกน log ครั้งแรก...</p></div>'
    
    risk = latest["risk_level"] or "UNKNOWN"
    
    try:
        raw = json.loads(latest["raw_stats"])
        top_ips = raw.get("nginx", {}).get("top_ips", {})
        suspicious = raw.get("nginx", {}).get("suspicious_samples", [])
        status_codes = raw.get("nginx", {}).get("status_codes", {})
    except:
        top_ips, suspicious, status_codes = {}, [], {}
    
    try:
        attack_types = json.loads(latest["attack_types"] or "[]")
    except:
        attack_types = []
    
    try:
        recs = json.loads(latest["ai_recommendations"] or "[]")
    except:
        recs = []

    scan_time = latest["timestamp"][:19].replace("T", " ") if latest["timestamp"] else "-"
    
    # Stats cards
    cards = f"""
    <div class="grid-4">
      <div class="card">
        <h3>Risk Level</h3>
        <div class="value risk-{risk}">{risk}</div>
        <div class="sub">การสแกนล่าสุด: {scan_time}</div>
      </div>
      <div class="card">
        <h3>Web Requests</h3>
        <div class="value" style="color:#38bdf8">{latest['total_requests']:,}</div>
        <div class="sub">ใน {60} นาทีที่ผ่านมา</div>
      </div>
      <div class="card">
        <h3>Unique IPs</h3>
        <div class="value" style="color:#a78bfa">{latest['unique_ips']:,}</div>
        <div class="sub">IP ที่เชื่อมต่อเข้ามา</div>
      </div>
      <div class="card">
        <h3>SSH Failed</h3>
        <div class="value" style="color:#f87171">{latest['ssh_failures']:,}</div>
        <div class="sub">ครั้งที่ login ผิดพลาด</div>
      </div>
    </div>"""

    # Attack types
    attack_tags = "".join([f'<span class="attack-tag">{a}</span>' for a in attack_types]) or '<span style="color:#64748b">ไม่พบการโจมตี</span>'

    # AI Summary
    ai_section = f"""
    <div class="grid-2">
      <div class="card">
        <h3>🤖 AI Analysis Summary</h3>
        <div style="margin:12px 0">
          <span class="badge badge-{risk}">{risk} RISK</span>
          <div style="margin-top:8px">{attack_tags}</div>
        </div>
        <div class="summary-box">{latest['ai_summary'] or 'ไม่มีข้อมูล'}</div>
      </div>
      <div class="card">
        <h3>💡 AI Recommendations</h3>
        {''.join([f'<div class="rec-item">{r}</div>' for r in recs]) or '<div style="color:#64748b">ไม่มีคำแนะนำ</div>'}
      </div>
    </div>"""

    # Top IPs table
    max_req = max(top_ips.values()) if top_ips else 1
    ip_rows = ""
    for ip, count in list(top_ips.items())[:8]:
        pct = int(count/max_req*100)
        ip_rows += f"""<tr>
          <td>{ip}</td>
          <td>{count}
            <div class="chart-bar"><div class="chart-fill" style="width:{pct}%"></div></div>
          </td>
          <td><span style="color:#64748b">-</span></td>
        </tr>"""

    # Suspicious requests
    sus_rows = ""
    for s in suspicious[:6]:
        sus_rows += f"""<tr>
          <td style="color:#f87171">{s.get('ip','')}</td>
          <td style="font-family:monospace;font-size:0.8rem;color:#fbbf24">{s.get('path','')[:60]}</td>
          <td>{s.get('status','')}</td>
        </tr>"""

    tables = f"""
    <div class="grid-2">
      <div class="card">
        <h3>🌐 Top IPs ({len(top_ips)} total)</h3>
        <table>
          <tr><th>IP Address</th><th>Requests</th><th>Country</th></tr>
          {ip_rows or '<tr><td colspan="3" class="no-data">ไม่มีข้อมูล</td></tr>'}
        </table>
      </div>
      <div class="card">
        <h3>⚠️ Suspicious Requests ({len(suspicious)} total)</h3>
        <table>
          <tr><th>IP</th><th>Path</th><th>Status</th></tr>
          {sus_rows or '<tr><td colspan="3" style="color:#22c55e;padding:20px;text-align:center">✓ ไม่พบการโจมตี</td></tr>'}
        </table>
      </div>
    </div>"""

    # History table
    history_rows = ""
    for row in history:
        r = row["risk_level"] or "UNKNOWN"
        t = row["timestamp"][:19].replace("T"," ") if row["timestamp"] else "-"
        history_rows += f"""<tr>
          <td>{t}</td>
          <td><span class="badge badge-{r}">{r}</span></td>
          <td>{row['total_requests']:,}</td>
          <td>{row['unique_ips']:,}</td>
          <td style="color:#f87171">{row['ssh_failures']:,}</td>
          <td style="font-size:0.8rem;color:#94a3b8">{(row['ai_summary'] or '')[:60]}...</td>
        </tr>"""

    history_section = f"""
    <div class="card">
      <h3>📋 ประวัติการสแกน ({len(history)} รายการล่าสุด)</h3>
      <table style="margin-top:12px">
        <tr><th>เวลา</th><th>Risk</th><th>Requests</th><th>IPs</th><th>SSH Failed</th><th>สรุป AI</th></tr>
        {history_rows or '<tr><td colspan="6" class="no-data">ไม่มีประวัติ</td></tr>'}
      </table>
    </div>"""

    return cards + ai_section + tables + history_section

class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        latest, history = get_data()
        content = build_content(latest, history)
        html = HTML_TEMPLATE.replace("{{CONTENT}}", content)
        
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        pass  # ปิด access log

if __name__ == "__main__":
    print(f"Dashboard running at http://localhost:{PORT}")
    HTTPServer(("127.0.0.1", PORT), DashboardHandler).serve_forever()
