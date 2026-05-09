"""
Generate dummy pkl files for testing the API without real trained models.
Run this once: python generate_dummy_models.py
"""
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from xgboost import XGBClassifier
import os

os.makedirs("models_saved", exist_ok=True)

print("Generating dummy models...")

# Dummy XGBoost (fraud — 30 features: Amount, Time, V1-V28)
xgb = XGBClassifier(n_estimators=5, use_label_encoder=False, eval_metric='logloss')
xgb.fit(np.random.rand(100, 30), np.random.randint(0, 2, 100))
joblib.dump(xgb, "models_saved/xgb_fraude.pkl")
print("✓ xgb_fraude.pkl")

# Dummy Random Forest (nids — 78 features, 14 classes)
rf = RandomForestClassifier(n_estimators=5)
rf.fit(np.random.rand(100, 78), np.random.randint(0, 14, 100))
joblib.dump(rf, "models_saved/rf_nids.pkl")
print("✓ rf_nids.pkl")

# Dummy Isolation Forest (shared)
iso = IsolationForest(n_estimators=5)
iso.fit(np.random.rand(100, 78))
joblib.dump(iso, "models_saved/iso_forest.pkl")
print("✓ iso_forest.pkl")

# Dummy scalers
sc_fraud = StandardScaler().fit(np.random.rand(100, 2))   # Amount + Time only
sc_net   = StandardScaler().fit(np.random.rand(100, 78))  # all 78 features
joblib.dump(sc_fraud, "models_saved/scaler_fraude.pkl")
joblib.dump(sc_net, "models_saved/scaler_reseau.pkl")
print("✓ scaler_fraude.pkl")
print("✓ scaler_reseau.pkl")

# Dummy LabelEncoder
le = LabelEncoder()
le.fit(["BENIGN","DDoS","PortScan","Bot","DoS Hulk","DoS GoldenEye",
        "FTP-Patator","SSH-Patator","DoS slowloris","DoS Slowhttptest",
        "Heartbleed","Web Attack Brute Force","Web Attack XSS",
        "Web Attack Sql Injection"])
joblib.dump(le, "models_saved/label_encoder_cicids.pkl")
print("✓ label_encoder_cicids.pkl")

print("\n✅ All dummy pkl files created in models_saved/")
print("You can now run: uvicorn main_api:app --reload")
