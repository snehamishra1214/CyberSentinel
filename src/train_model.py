from pathlib import Path
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "security_logs.csv"
MODEL_DIR = ROOT / "models"
REPORT_DIR = ROOT / "reports"
MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA)
features = ["failed_logins", "login_hour", "unique_ips"]
X = df[features]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
model = DecisionTreeClassifier(max_depth=4, random_state=42)
model.fit(X_train, y_train)
pred = model.predict(X_test)

print(f"Accuracy: {accuracy_score(y_test, pred):.3f}")
print("Classification report:")
print(classification_report(y_test, pred, zero_division=0))
print("Confusion matrix [rows=true, columns=predicted]:")
print(confusion_matrix(y_test, pred, labels=["Normal", "Suspicious"]))

joblib.dump(model, MODEL_DIR / "security_model.pkl")
with open(REPORT_DIR / "model_evaluation.txt", "w", encoding="utf-8") as f:
    f.write("CyberSentinel model evaluation\n")
    f.write("Dataset: synthetic rule-labelled demonstration data\n")
    f.write(f"Accuracy: {accuracy_score(y_test, pred):.3f}\n\n")
    f.write(classification_report(y_test, pred, zero_division=0))
    f.write("\nConfusion matrix [rows=true, columns=predicted]:\n")
    f.write(str(confusion_matrix(y_test, pred, labels=["Normal", "Suspicious"])))
print(f"Saved model to {MODEL_DIR / 'security_model.pkl'}")
print(f"Saved evaluation to {REPORT_DIR / 'model_evaluation.txt'}")
