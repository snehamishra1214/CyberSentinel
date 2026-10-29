from pathlib import Path
import sys
from flask import Flask, request, jsonify

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from analysis_pipeline import read_logs, analyse_logs, correlate_alerts, compliance_findings
from reporting import make_html_report

app = Flask(__name__)

@app.get("/")
def home():
    return jsonify({
        "project": "CyberSentinel",
        "status": "running",
        "endpoints": {
            "GET /health": "Check API status",
            "POST /analyse": "Upload JSON array of log records for analysis"
        }
    })

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

@app.post("/analyse")
def analyse():
    payload = request.get_json(silent=True)
    if not isinstance(payload, list) or not payload:
        return jsonify({"error": "Send a non-empty JSON array of log records."}), 400
    required = ["timestamp", "source_ip", "username", "asset", "event_type",
                "failed_logins", "login_hour", "unique_ips"]
    for i, item in enumerate(payload):
        if not isinstance(item, dict):
            return jsonify({"error": f"Record {i} must be a JSON object."}), 400
        missing = [key for key in required if key not in item]
        if missing:
            return jsonify({"error": f"Record {i} is missing: {', '.join(missing)}"}), 400
        try:
            for key in ["failed_logins", "login_hour", "unique_ips"]:
                float(item[key])
        except (TypeError, ValueError):
            return jsonify({"error": f"Record {i} has non-numeric feature values."}), 400
    try:
        import pandas as pd
        df = pd.DataFrame(payload)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        if df["timestamp"].isna().any():
            return jsonify({"error": "One or more timestamps are invalid."}), 400
        result = analyse_logs(df)
        incidents = correlate_alerts(result)
        findings = compliance_findings(result)
        return jsonify({
            "events": result.where(pd.notna(result), None).to_dict(orient="records"),
            "incidents": incidents.where(pd.notna(incidents), None).to_dict(orient="records"),
            "compliance_findings": findings.where(pd.notna(findings), None).to_dict(orient="records"),
            "notice": "Prototype output only; validate results before taking security action."
        })
    except FileNotFoundError:
        return jsonify({"error": "Trained model not found. Run python src/train_model.py first."}), 500
    except Exception as exc:
        app.logger.exception("Analysis failed")
        return jsonify({"error": "Analysis failed. Check server logs and input data."}), 500

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
