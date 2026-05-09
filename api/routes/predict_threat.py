from fastapi import APIRouter, HTTPException
from api.schemas.nids_schema import NetworkFlowInput, ThreatPredictionOutput, CICIDS_FEATURES
from api.core.model_loader import get_models
from src.explain.xai_engine import explain_network
import numpy as np

router = APIRouter(prefix="/predict", tags=["Network Intrusion Detection"])

SEVERITY_MAP = {
    "BENIGN": "LOW",
    "PortScan": "MEDIUM",
    "Bot": "HIGH",
    "DDoS": "CRITICAL",
    "DoS Hulk": "CRITICAL",
    "DoS GoldenEye": "CRITICAL",
    "FTP-Patator": "HIGH",
    "SSH-Patator": "HIGH",
    "DoS slowloris": "CRITICAL",
    "DoS Slowhttptest": "CRITICAL",
    "Heartbleed": "CRITICAL",
    "Web Attack Brute Force": "HIGH",
    "Web Attack XSS": "HIGH",
    "Web Attack Sql Injection": "CRITICAL"
}

@router.post("/threat", response_model=ThreatPredictionOutput)
def predict_threat(flow: NetworkFlowInput):
    try:
        models = get_models()
        rf_model = models["rf_nids"]
        scaler_net = models["scaler_reseau"]
        label_encoder = models["label_encoder"]
        iso_forest = models["iso_forest"]
        
        # Convert to array and scale
        X = flow.to_array()
        X_scaled = scaler_net.transform(X)
        
        # Predict class
        pred_encoded = rf_model.predict(X_scaled)[0]
        pred_proba = rf_model.predict_proba(X_scaled)[0]
        confidence = float(pred_proba[pred_encoded])
        
        threat_class = label_encoder.inverse_transform([pred_encoded])[0]
        severity = SEVERITY_MAP.get(threat_class, "MEDIUM")
        
        # Anomaly detection
        anomaly_score = float(iso_forest.score_samples(X_scaled)[0])
        is_anomaly = iso_forest.predict(X_scaled)[0] == -1
        
        # SHAP explanations for predicted class
        shap_values = explain_network(X_scaled, pred_encoded)
        feature_importance = list(zip(CICIDS_FEATURES, shap_values[0]))
        top_features = sorted(feature_importance, key=lambda x: abs(x[1]), reverse=True)[:5]
        
        return ThreatPredictionOutput(
            threat_class=threat_class,
            confidence=confidence,
            severity=severity,
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            top_features=top_features
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")
