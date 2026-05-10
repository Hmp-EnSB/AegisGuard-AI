"""
API tests for AegisGuard FastAPI backend.
Run: pytest tests/test_api.py -v
"""
import pytest
from fastapi.testclient import TestClient
from main_api import app

client = TestClient(app)

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def _fraud_payload(**overrides):
    p = {
        "Time": 54000.0, "Amount": 9800.0,
        "V1": -1.35, "V2": 0.5,  "V3": 1.2,  "V4": -0.8, "V5": 0.3,
        "V6": -0.6,  "V7": 0.9,  "V8": 0.1,  "V9": -0.4, "V10": 0.7,
        "V11": -0.2, "V12": 0.5, "V13": 0.8, "V14": -0.3, "V15": 0.6,
        "V16": -0.1, "V17": 0.4, "V18": -0.7,"V19": 0.2,  "V20": 0.9,
        "V21": -0.5, "V22": 0.3, "V23": -0.8,"V24": 0.1,  "V25": 0.6,
        "V26": -0.4, "V27": 0.7, "V28": 0.02
    }
    p.update(overrides)
    return p

CICIDS_FEATURES = [
    "Destination Port","Flow Duration","Total Fwd Packets","Total Backward Packets",
    "Total Length of Fwd Packets","Total Length of Bwd Packets","Fwd Packet Length Max",
    "Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std",
    "Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean",
    "Bwd Packet Length Std","Flow Bytes/s","Flow Packets/s","Flow IAT Mean",
    "Flow IAT Std","Flow IAT Max","Flow IAT Min","Fwd IAT Total","Fwd IAT Mean",
    "Fwd IAT Std","Fwd IAT Max","Fwd IAT Min","Bwd IAT Total","Bwd IAT Mean",
    "Bwd IAT Std","Bwd IAT Max","Bwd IAT Min","Fwd PSH Flags","Bwd PSH Flags",
    "Fwd URG Flags","Bwd URG Flags","Fwd Header Length","Bwd Header Length",
    "Fwd Packets/s","Bwd Packets/s","Min Packet Length","Max Packet Length",
    "Packet Length Mean","Packet Length Std","Packet Length Variance","FIN Flag Count",
    "SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count",
    "URG Flag Count","CWE Flag Count","ECE Flag Count","Down/Up Ratio",
    "Average Packet Size","Avg Fwd Segment Size","Avg Bwd Segment Size",
    "Fwd Header Length.1","Fwd Avg Bytes/Bulk","Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate","Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate","Subflow Fwd Packets","Subflow Fwd Bytes",
    "Subflow Bwd Packets","Subflow Bwd Bytes","Init_Win_bytes_forward",
    "Init_Win_bytes_backward","act_data_pkt_fwd","min_seg_size_forward",
    "Active Mean","Active Std","Active Max","Active Min","Idle Mean",
    "Idle Std","Idle Max","Idle Min"
]

def _threat_payload(**overrides):
    p = {"features": {f: 0.5 for f in CICIDS_FEATURES}}
    p.update(overrides)
    return p

# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────
def test_health_returns_ok():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "healthy"

def test_health_all_models_loaded():
    r = client.get("/health")
    loaded = r.json()["models_loaded"]
    assert all(loaded.values()), f"Some models not loaded: {loaded}"

def test_root():
    r = client.get("/")
    assert r.status_code == 200
    assert "AegisGuard" in r.json()["message"]

# ─────────────────────────────────────────────
# POST /predict/fraud
# ─────────────────────────────────────────────
def test_fraud_valid_payload_200():
    r = client.post("/predict/fraud", json=_fraud_payload())
    assert r.status_code == 200

def test_fraud_response_schema():
    data = client.post("/predict/fraud", json=_fraud_payload()).json()
    assert "fraud_probability" in data
    assert "risk_level" in data
    assert "decision" in data
    assert "is_anomaly" in data
    assert "anomaly_score" in data
    assert "top_features" in data

def test_fraud_probability_in_range():
    data = client.post("/predict/fraud", json=_fraud_payload()).json()
    assert 0.0 <= data["fraud_probability"] <= 1.0

def test_fraud_risk_level_valid():
    data = client.post("/predict/fraud", json=_fraud_payload()).json()
    assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

def test_fraud_decision_valid():
    data = client.post("/predict/fraud", json=_fraud_payload()).json()
    assert data["decision"] in ("LEGITIMATE", "FRAUD")

def test_fraud_top_features_format():
    data = client.post("/predict/fraud", json=_fraud_payload()).json()
    assert len(data["top_features"]) <= 5
    for item in data["top_features"]:
        assert "feature" in item
        assert "shap_value" in item
        assert isinstance(item["feature"], str)
        assert isinstance(item["shap_value"], float)

def test_fraud_missing_field_422():
    payload = _fraud_payload()
    del payload["V14"]
    r = client.post("/predict/fraud", json=payload)
    assert r.status_code == 422

def test_fraud_missing_amount_422():
    payload = _fraud_payload()
    del payload["Amount"]
    r = client.post("/predict/fraud", json=payload)
    assert r.status_code == 422

def test_fraud_negative_amount_422():
    r = client.post("/predict/fraud", json=_fraud_payload(Amount=-100.0))
    assert r.status_code == 422

def test_fraud_low_amount_accepted():
    r = client.post("/predict/fraud", json=_fraud_payload(Amount=1.50))
    assert r.status_code == 200

# ─────────────────────────────────────────────
# POST /predict/threat
# ─────────────────────────────────────────────
def test_threat_valid_payload_200():
    r = client.post("/predict/threat", json=_threat_payload())
    assert r.status_code == 200

def test_threat_response_schema():
    data = client.post("/predict/threat", json=_threat_payload()).json()
    assert "threat_class" in data
    assert "confidence" in data
    assert "severity" in data
    assert "is_anomaly" in data
    assert "anomaly_score" in data
    assert "top_features" in data

def test_threat_confidence_in_range():
    data = client.post("/predict/threat", json=_threat_payload()).json()
    assert 0.0 <= data["confidence"] <= 1.0

def test_threat_severity_valid():
    data = client.post("/predict/threat", json=_threat_payload()).json()
    assert data["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

def test_threat_top_features_format():
    data = client.post("/predict/threat", json=_threat_payload()).json()
    assert len(data["top_features"]) <= 5
    for item in data["top_features"]:
        assert "feature" in item
        assert "shap_value" in item
        assert isinstance(item["feature"], str)
        assert isinstance(item["shap_value"], float)

def test_threat_missing_feature_422():
    features = {f: 0.5 for f in CICIDS_FEATURES[:-1]}  # drop last
    r = client.post("/predict/threat", json={"features": features})
    assert r.status_code == 422

def test_threat_empty_features_422():
    r = client.post("/predict/threat", json={"features": {}})
    assert r.status_code == 422