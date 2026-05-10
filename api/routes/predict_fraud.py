from fastapi import APIRouter, HTTPException
from api.schemas.fraud_schema import TransactionInput, FraudPredictionOutput, FeatureImportance
from api.core.model_loader import get_models
from src.explain.xai_engine import explain_fraud
import numpy as np

router = APIRouter(prefix="/predict", tags=["Fraud Detection"])

_THRESHOLDS = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.85}

def _risk_level(prob: float) -> str:
    if prob < _THRESHOLDS["LOW"]:    return "LOW"
    if prob < _THRESHOLDS["MEDIUM"]: return "MEDIUM"
    if prob < _THRESHOLDS["HIGH"]:   return "HIGH"
    return "CRITICAL"

def _decision(risk: str) -> str:
    return "FRAUD" if risk in ("HIGH", "CRITICAL") else "LEGITIMATE"

@router.post("/fraud", response_model=FraudPredictionOutput)
def predict_fraud(transaction: TransactionInput):
    try:
        models       = get_models()
        xgb_model    = models["xgb_fraude"]
        scaler_fraud = models["scaler_fraude"]
        iso_forest   = models["iso_forest"]

        # Scale Amount + Time; V1-V28 are already PCA-transformed
        amount_time        = np.array([[transaction.Amount, transaction.Time]])
        amount_time_scaled = scaler_fraud.transform(amount_time)
        v_features         = np.array([[getattr(transaction, f"V{i}") for i in range(1, 29)]])
        X                  = np.hstack([amount_time_scaled, v_features])  # shape (1, 30)

        fraud_prob = float(xgb_model.predict_proba(X)[0][1])
        risk       = _risk_level(fraud_prob)
        decision   = _decision(risk)

        # Anomaly score — iso_forest is trained on 78 network features.
        # It gracefully degrades here; Salma should provide a fraud-specific iso_forest.
        try:
            anomaly_score = float(iso_forest.score_samples(X)[0])
            is_anomaly    = iso_forest.predict(X)[0] == -1
        except ValueError:
            anomaly_score = 0.0
            is_anomaly    = False

        shap_vals     = explain_fraud(X)
        feature_names = ["Amount", "Time"] + [f"V{i}" for i in range(1, 29)]
        top_features  = sorted(
            [FeatureImportance(feature=name, shap_value=round(float(val), 4))
             for name, val in zip(feature_names, shap_vals[0])],
            key=lambda x: abs(x.shap_value),
            reverse=True
        )[:5]

        return FraudPredictionOutput(
            fraud_probability=round(fraud_prob, 4),
            risk_level=risk,
            decision=decision,
            is_anomaly=is_anomaly,
            anomaly_score=round(anomaly_score, 4),
            top_features=top_features
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")