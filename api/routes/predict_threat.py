from fastapi import APIRouter, HTTPException
from api.schemas.nids_schema import NetworkFlowInput, ThreatPredictionOutput, FeatureImportance, CICIDS_FEATURES
from api.core.model_loader import get_models
from src.explain.xai_engine import explain_network
import numpy as np

router = APIRouter(prefix="/predict", tags=["Network Intrusion Detection"])

SEVERITY_MAP = {
    "BENIGN":                   "LOW",
    "PortScan":                 "MEDIUM",
    "Bot":                      "HIGH",
    "FTP-Patator":              "HIGH",
    "SSH-Patator":              "HIGH",
    "Web Attack Brute Force":   "HIGH",
    "Web Attack XSS":           "HIGH",
    "DoS slowloris":            "CRITICAL",
    "DoS Slowhttptest":         "CRITICAL",
    "DoS Hulk":                 "CRITICAL",
    "DoS GoldenEye":            "CRITICAL",
    "DDoS":                     "CRITICAL",
    "Heartbleed":               "CRITICAL",
    "Web Attack Sql Injection": "CRITICAL",
}

@router.post("/threat", response_model=ThreatPredictionOutput)
def predict_threat(flow: NetworkFlowInput):
    try:
        models        = get_models()
        rf_model      = models["rf_nids"]
        scaler_net    = models["scaler_reseau"]
        label_encoder = models["label_encoder"]
        iso_forest    = models["iso_forest"]

        X_raw    = flow.to_array()             # shape (1, 78)
        X_scaled = scaler_net.transform(X_raw)

        pred_encoded = rf_model.predict(X_scaled)[0]
        pred_proba   = rf_model.predict_proba(X_scaled)[0]
        confidence   = float(pred_proba[pred_encoded])
        threat_class = str(label_encoder.inverse_transform([pred_encoded])[0])
        severity     = SEVERITY_MAP.get(threat_class, "MEDIUM")

        anomaly_score = float(iso_forest.score_samples(X_scaled)[0])
        is_anomaly    = iso_forest.predict(X_scaled)[0] == -1

        shap_vals    = explain_network(X_scaled, int(pred_encoded))
        top_features = sorted(
            [FeatureImportance(feature=name, shap_value=round(float(val), 4))
             for name, val in zip(CICIDS_FEATURES, shap_vals[0])],
            key=lambda x: abs(x.shap_value),
            reverse=True
        )[:5]

        return ThreatPredictionOutput(
            threat_class=threat_class,
            confidence=round(confidence, 4),
            severity=severity,
            is_anomaly=bool(is_anomaly),
            anomaly_score=round(anomaly_score, 4),
            top_features=top_features
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")