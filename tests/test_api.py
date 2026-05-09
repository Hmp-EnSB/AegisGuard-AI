from fastapi.testclient import TestClient
from main_api import app
import pytest

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert all(data["models_loaded"].values())

def test_predict_fraud_valid():
    payload = {
        "Time": 54000.0,
        "Amount": 9800.0,
        "V1": -1.35, "V2": 0.5, "V3": 1.2, "V4": -0.8,
        "V5": 0.3, "V6": -0.6, "V7": 0.9, "V8": 0.1,
        "V9": -0.4, "V10": 0.7, "V11": -0.2, "V12": 0.5,
        "V13": 0.8, "V14": -0.3, "V15": 0.6, "V16": -0.1,
        "V17": 0.4, "V18": -0.7, "V19": 0.2, "V20": 0.9,
        "V21": -0.5, "V22": 0.3, "V23": -0.8, "V24": 0.1,
        "V25": 0.6, "V26": -0.4, "V27": 0.7, "V28": 0.02
    }
    response = client.post("/predict/fraud", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "fraud_probability" in data
    assert "risk_level" in data
    assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert "decision" in data
    assert data["decision"] in ["LEGITIMATE", "FRAUD"]

def test_predict_fraud_missing_field():
    payload = {
        "Time": 54000.0,
        "Amount": 9800.0,
        "V1": -1.35
        # Missing V2-V28
    }
    response = client.post("/predict/fraud", json=payload)
    assert response.status_code == 422

def test_predict_threat_valid():
    from api.schemas.nids_schema import CICIDS_FEATURES
    payload = {
        "features": {f: 0.5 for f in CICIDS_FEATURES}
    }
    response = client.post("/predict/threat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "threat_class" in data
    assert "confidence" in data
    assert "severity" in data
    assert data["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def test_predict_threat_missing_feature():
    from api.schemas.nids_schema import CICIDS_FEATURES
    payload = {
        "features": {f: 0.5 for f in CICIDS_FEATURES[:50]}  # Only 50 features
    }
    response = client.post("/predict/threat", json=payload)
    assert response.status_code == 422
