from pathlib import Path
from html import escape
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]

def make_html_report(analysed, incidents, findings):
    report_dir = ROOT / "reports"
    report_dir.mkdir(exist_ok=True)
    suspicious = analysed[analysed["prediction"] == "Suspicious"]
    rows = []
    for _, r in suspicious.head(100).iterrows():
        rows.append("<tr>" + "".join([
            f"<td>{escape(str(r.get('timestamp','')))}</td>",
            f"<td>{escape(str(r.get('source_ip','')))}</td>",
            f"<td>{escape(str(r.get('username','')))}</td>",
            f"<td>{escape(str(r.get('asset','')))}</td>",
            f"<td>{escape(str(r.get('risk_level','')))}</td>",
            f"<td>{escape(str(r.get('reason','')))}</td>",
        ]) + "</tr>")
    incident_rows = []
    for _, r in incidents.iterrows():
        incident_rows.append("<tr>" + "".join(
            f"<td>{escape(str(r.get(c,'')))}</td>" for c in
            ["incident_id", "source_ip", "first_seen", "last_seen", "alert_count", "risk_level", "assets"]
        ) + "</tr>")
    compliance_rows = []
    for _, r in findings.head(100).iterrows():
        compliance_rows.append("<tr>" + "".join(
            f"<td>{escape(str(r.get(c,'')))}</td>" for c in
            ["finding", "evidence", "risk_level", "framework", "control_reference", "recommendation"]
        ) + "</tr>")
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>CyberSentinel Security Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:30px;color:#222}} h1,h2{{color:#16324f}}
.note{{background:#fff4d6;padding:12px;border-left:4px solid #d99b00}}
table{{border-collapse:collapse;width:100%;margin:12px 0 28px;font-size:12px}}
th,td{{border:1px solid #ccc;padding:7px;text-align:left;vertical-align:top}}
th{{background:#eaf0f6}} .summary{{display:flex;gap:18px;flex-wrap:wrap}}
.card{{border:1px solid #ccc;padding:14px;min-width:130px}}
</style></head><body>
<h1>CyberSentinel Security Assessment Report</h1>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
<div class="note"><b>Important limitation:</b> This prototype uses a synthetic demonstration dataset and a model trained on rule-generated labels. Results are indicators for review, not proof of a real attack. Validate compliance references and findings before operational use.</div>
<div class="summary">
<div class="card"><b>Total events</b><br>{len(analysed)}</div>
<div class="card"><b>Flagged events</b><br>{len(suspicious)}</div>
<div class="card"><b>Potential incidents</b><br>{len(incidents)}</div>
<div class="card"><b>Compliance findings</b><br>{len(findings)}</div>
</div>
<h2>Flagged Events</h2><table><tr><th>Timestamp</th><th>Source IP</th><th>Username</th><th>Asset</th><th>Risk</th><th>Evidence / Reason</th></tr>
{''.join(rows) or '<tr><td colspan="6">No events flagged.</td></tr>'}</table>
<h2>Correlated Potential Incidents</h2><table><tr><th>ID</th><th>Source IP</th><th>First Seen</th><th>Last Seen</th><th>Alerts</th><th>Risk</th><th>Assets</th></tr>
{''.join(incident_rows) or '<tr><td colspan="7">No incidents found.</td></tr>'}</table>
<h2>Compliance Mapping and Recommendations</h2><table><tr><th>Finding</th><th>Evidence</th><th>Risk</th><th>Framework</th><th>Control Reference</th><th>Recommendation</th></tr>
{''.join(compliance_rows) or '<tr><td colspan="6">No compliance findings generated.</td></tr>'}</table>
<h2>Method and Limitations</h2>
<ul><li>Machine Learning model: Decision Tree classifier.</li>
<li>Alert correlation: source IP and a 10-minute time window.</li>
<li>Risk levels are prototype heuristics and should be tuned with security stakeholders.</li>
<li>Use verified real logs and independent labels for meaningful performance evaluation.</li>
<li>The compliance mapping is an initial reference, not a formal compliance determination.</li></ul>
</body></html>"""
    out = report_dir / "security_report.html"
    out.write_text(html, encoding="utf-8")
    analysed.to_csv(report_dir / "analysed_events.csv", index=False)
    incidents.to_csv(report_dir / "correlated_incidents.csv", index=False)
    findings.to_csv(report_dir / "compliance_findings.csv", index=False)
    print(f"Report saved to: {out}")
