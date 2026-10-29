from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from analysis_pipeline import read_logs, analyse_logs, correlate_alerts, compliance_findings
from reporting import make_html_report

logs = read_logs()
analysed = analyse_logs(logs)
incidents = correlate_alerts(analysed)
findings = compliance_findings(analysed)

make_html_report(analysed, incidents, findings)
print(f"Analysed events: {len(analysed)}")
print(f"Flagged events: {(analysed['prediction'] == 'Suspicious').sum()}")
print(f"Potential incidents: {len(incidents)}")
print("Open reports/security_report.html in your browser.")
