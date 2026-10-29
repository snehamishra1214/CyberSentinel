from pathlib import Path
import random
import pandas as pd

random.seed(42)
rows = []

# Synthetic learning dataset. Labels are created by a transparent rule for demonstration.
for i in range(800):
    failed_logins = random.randint(0, 12)
    login_hour = random.randint(0, 23)
    unique_ips = random.randint(1, 6)
    # This is a demo rule, not proof of real-world malicious activity.
    label = "Suspicious" if failed_logins >= 7 and unique_ips >= 3 else "Normal"
    rows.append({
        "event_id": f"EVT-{i+1:04d}",
        "timestamp": f"2026-10-{random.randint(1, 28):02d} {random.randint(0,23):02d}:{random.randint(0,59):02d}:00",
        "source_ip": f"192.0.2.{random.randint(1, 20)}",
        "username": random.choice(["user01", "user02", "admin", "analyst", "guest"]),
        "asset": random.choice(["workstation-01", "server-01", "vpn-gateway", "database-01"]),
        "event_type": "login",
        "failed_logins": failed_logins,
        "login_hour": login_hour,
        "unique_ips": unique_ips,
        "severity": "High" if failed_logins >= 7 else "Low",
        "label": label
    })

out = Path(__file__).resolve().parents[1] / "data" / "security_logs.csv"
pd.DataFrame(rows).to_csv(out, index=False)
print(f"Created {len(rows)} synthetic records at {out}")
print("Important: labels are rule-generated for demonstration, not verified incident ground truth.")
