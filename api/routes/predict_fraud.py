from fastapi import APIRouter, HTTPException
from api.schemas.fraud_schema import TransactionInput, FraudPredictionOutput
from api.core.model_loader import get_models
from src.explain.xai_engine import explain_fraud
import numpy as np

router = APIRouter(prefix="/predict", tags=["Fraud Detection"])

@router.post("/fraud", response_model=FraudPredictionOutput)
def predict_fraud(transaction: TransactionInput):
    try:
        models = get_models()
        xgb_model = models["xgb_fraude"]
        scaler_fraud = models["scaler_fraude"]
        iso_forest = models["iso_forest"]
        
        # Build feature array: scale Amount + Time, keep V1-V28 as-is
        amount_time = np.array([[transaction.Amount, transaction.Time]])
        amount_time_scaled = scaler_fraud.transform(amount_time)
        
        v_features = np.array([[
            transaction.V1, transaction.V2, transaction.V3, transaction.V4,
            transaction.V5, transaction.V6, transaction.V7, transaction.V8,
            transaction.V9, transaction.V10, transaction.V11, transaction.V12,
            transaction.V13, transaction.V14, transaction.V15, transaction.V16,
            transaction.V17, transaction.V18, transaction.V19, transaction.V20,
            transaction.V21, transaction.V22, transaction.V23, transaction.V24,
            transaction.V25, transaction.V26, transaction.V27, transaction.V28
        ]])
        
        X = np.hstack([amount_time_scaled, v_features])
        
        # Get fraud probability
        fraud_prob = float(xgb_model.predict_proba(X)[0][1])
        
        # Map to risk level
        if fraud_prob < 0.3:
            risk_level = "LOW"
        elif fraud_prob < 0.6:
            risk_level = "MEDIUM"
        elif fraud_prob < 0.85:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        decision = "FRAUD" if fraud_prob >= 0.5 else "LEGITIMATE"
        
        # Anomaly detection
        anomaly_score = float(iso_forest.score_samples(X)[0])
        is_anomaly = iso_forest.predict(X)[0] == -1
        
        # SHAP explanations
        shap_values = explain_fraud(X)
        feature_names = ["Amount", "Time"] + [f"V{i}" for i in range(1, 29)]
        feature_importance = list(zip(feature_names, shap_values[0]))
        top_features = sorted(feature_importance, key=lambda x: abs(x[1]), reverse=True)[:5]
        
        return FraudPredictionOutput(
            fraud_probability=fraud_prob,
            risk_level=risk_level,
            decision=decision,
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            top_features=top_features
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")
