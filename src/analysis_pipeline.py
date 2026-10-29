from pathlib import Path
import pandas as pd
import joblib
from datetime import timedelta

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ["failed_logins", "login_hour", "unique_ips"]

def load_model():
    return joblib.load(ROOT / "models" / "security_model.pkl")

def read_logs(csv_path=None):
    path = Path(csv_path) if csv_path else ROOT / "data" / "security_logs.csv"
    df = pd.read_csv(path)
    required = {"timestamp", "source_ip", "username", "asset", "event_type",
                "failed_logins", "login_hour", "unique_ips"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "source_ip"])
    for col in FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=FEATURES)
    return df

def analyse_logs(df):
    model = load_model()
    result = df.copy()
    result["prediction"] = model.predict(result[FEATURES])
    result["reason"] = result.apply(explain_row, axis=1)
    result["risk_level"] = result.apply(
        lambda r: "High" if r["prediction"] == "Suspicious" and r["failed_logins"] >= 9
        else ("Medium" if r["prediction"] == "Suspicious" else "Low"), axis=1
    )
    return result

def explain_row(row):
    reasons = []
    if row["failed_logins"] >= 7:
        reasons.append(f'{int(row["failed_logins"])} failed login attempts')
    if row["unique_ips"] >= 3:
        reasons.append(f'{int(row["unique_ips"])} unique IPs')
    if row["login_hour"] <= 5:
        reasons.append(f'activity at {int(row["login_hour"]):02d}:00')
    return "; ".join(reasons) if reasons else "Model classified this pattern as normal; review context if needed"

def correlate_alerts(df, window_minutes=10):
    suspicious = df[df["prediction"] == "Suspicious"].copy()
    if suspicious.empty:
        return pd.DataFrame(columns=[
            "incident_id", "source_ip", "first_seen", "last_seen", "alert_count",
            "assets", "usernames", "risk_level", "summary"
        ])
    incidents = []
    suspicious = suspicious.sort_values("timestamp")
    group_id = 0
    # Group alerts by source IP and time window. This is a simple demonstrator, not a SIEM.
    for source_ip, group in suspicious.groupby("source_ip"):
        group = group.sort_values("timestamp")
        cluster = []
        cluster_start = None
        for _, row in group.iterrows():
            if cluster_start is None or (row["timestamp"] - cluster_start).total_seconds() <= window_minutes * 60:
                if cluster_start is None:
                    cluster_start = row["timestamp"]
                cluster.append(row)
            else:
                incidents.append(make_incident(cluster, group_id + 1))
                group_id += 1
                cluster = [row]
                cluster_start = row["timestamp"]
        if cluster:
            incidents.append(make_incident(cluster, group_id + 1))
            group_id += 1
    return pd.DataFrame(incidents)

def make_incident(rows, incident_num):
    group = pd.DataFrame(rows)
    return {
        "incident_id": f"INC-{incident_num:03d}",
        "source_ip": str(group["source_ip"].iloc[0]),
        "first_seen": group["timestamp"].min().isoformat(sep=" "),
        "last_seen": group["timestamp"].max().isoformat(sep=" "),
        "alert_count": int(len(group)),
        "assets": ", ".join(sorted(group["asset"].astype(str).unique())),
        "usernames": ", ".join(sorted(group["username"].astype(str).unique())),
        "risk_level": "High" if (group["risk_level"] == "High").any() else "Medium",
        "summary": f'{len(group)} suspicious event(s) from {group["source_ip"].iloc[0]} within a {10}-minute correlation window'
    }

def compliance_findings(analysed):
    findings = []
    for _, row in analysed[analysed["prediction"] == "Suspicious"].iterrows():
        findings.append({
            "event_id": row.get("event_id", "unknown"),
            "finding": "Potential suspicious authentication activity",
            "evidence": row["reason"],
            "risk_level": row["risk_level"],
            "framework": "ISO/IEC 27001:2022 (reference for review)",
            "control_reference": "Annex A 5.15 Access control (verify applicability against the licensed/current standard)",
            "recommendation": "Review account activity, enforce MFA where appropriate, apply rate limits/lockout controls, and preserve authentication logs."
        })
    return pd.DataFrame(findings)
