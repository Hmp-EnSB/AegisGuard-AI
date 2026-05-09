"""
POST /predict/fraud endpoint.
Detects financial fraud from transaction features using XGBoost + SHAP.

Requires from models_saved/:
- xgb_fraude.pkl         (trained XGBoost)
- scaler_fraude.pkl      (StandardScaler for Amount + Time)
- iso_forest.pkl         (Isolation Forest for anomaly score)

Uses xai_engine.explain_fraud() for SHAP values.
"""

from fastapi import APIRouter, HTTPException
from datetime import datetime
import numpy as np
import logging

from api.schemas.fraud_schema import TransactionInput, FraudPredictionResponse, SHAPFeature
from api.core import get_model, logger
from api.core.config import FRAUD_THRESHOLDS

try:
    from src.explain.xai_engine import explain_fraud
except ImportError:
    logger.warning("xai_engine not available yet. SHAP explanations will be empty until implemented.")
    explain_fraud = None

router = APIRouter(prefix="/predict", tags=["Fraud Detection"])


def map_fraud_probability_to_risk_level(probability: float) -> str:
    """
    Map fraud probability to risk level.
    
    Args:
        probability: Fraud probability (0-1)
    
    Returns:
        Risk level: LOW, MEDIUM, HIGH, CRITICAL
    """
    if probability < FRAUD_THRESHOLDS["low"]:
        return "LOW"
    elif probability < FRAUD_THRESHOLDS["medium"]:
        return "MEDIUM"
    elif probability < FRAUD_THRESHOLDS["high"]:
        return "HIGH"
    else:
        return "CRITICAL"


def map_risk_to_decision(risk_level: str) -> str:
    """
    Map risk level to approval decision.
    
    Args:
        risk_level: Risk classification
    
    Returns:
        Decision: APPROVED or BLOCKED
    """
    if risk_level in ["HIGH", "CRITICAL"]:
        return "BLOCKED"
    return "APPROVED"


@router.post("/fraud", response_model=FraudPredictionResponse)
async def predict_fraud(transaction: TransactionInput):
    """
    Detect financial fraud from transaction features.
    
    **Input:**
    - Amount: Transaction amount in EUR
    - Time: Seconds since dataset start
    - V1–V28: PCA-transformed features
    
    **Output:**
    - fraud_probability: 0-1 (confidence it's fraudulent)
    - risk_level: LOW / MEDIUM / HIGH / CRITICAL
    - decision: APPROVED or BLOCKED
    - top_features: Top 5 SHAP-explained features
    
    **Example:**
    ```bash
    curl -X POST http://localhost:8000/predict/fraud \\
      -H "Content-Type: application/json" \\
      -d '{
        "Amount": 9800.0,
        "Time": 54000.0,
        "V1": -1.35,
        "V2": -0.07,
        ...
        "V28": 0.02
      }'
    ```
    """
    
    try:
        # Step 1: Load models
        try:
            xgb_model = get_model("xgb_fraud")
            scaler = get_model("scaler_fraud")
            iso_forest = get_model("iso_forest")
        except FileNotFoundError as e:
            logger.error(f"Model loading failed: {e}")
            raise HTTPException(
                status_code=503,
                detail=f"Model unavailable: {str(e)}"
            )
        
        # Step 2: Build feature array
        # Fraud model expects 30 features: [Amount, Time, V1, V2, ..., V28]
        features_raw = [
            transaction.Amount,
            transaction.Time,
            transaction.V1, transaction.V2, transaction.V3, transaction.V4,
            transaction.V5, transaction.V6, transaction.V7, transaction.V8,
            transaction.V9, transaction.V10, transaction.V11, transaction.V12,
            transaction.V13, transaction.V14, transaction.V15, transaction.V16,
            transaction.V17, transaction.V18, transaction.V19, transaction.V20,
            transaction.V21, transaction.V22, transaction.V23, transaction.V24,
            transaction.V25, transaction.V26, transaction.V27, transaction.V28,
        ]
        X_raw = np.array([features_raw])
        
        # Step 3: Scale only Amount + Time (V1-V28 already PCA-transformed)
        X_scaled = X_raw.copy()
        X_scaled[0, :2] = scaler.transform(X_raw[:, :2])
        
        # Step 4: Predict fraud probability
        fraud_proba = xgb_model.predict_proba(X_scaled)[0][1]  # Class 1 = fraud
        fraud_proba = float(fraud_proba)
        
        # Step 5: Map to risk level & decision
        risk_level = map_fraud_probability_to_risk_level(fraud_proba)
        decision = map_risk_to_decision(risk_level)
        
        # Step 6: Get anomaly score from Isolation Forest
        anomaly_score = float(iso_forest.score_samples(X_scaled)[0])
        confidence = min(1.0, max(0.0, fraud_proba + (abs(anomaly_score) * 0.1)))
        
        # Step 7: SHAP explanations
        top_features = []
        if explain_fraud is not None:
            try:
                shap_values = explain_fraud(xgb_model, scaler, X_scaled)
                
                # Extract top 5 features by absolute SHAP value
                feature_names = (
                    ["Amount", "Time"] +
                    [f"V{i}" for i in range(1, 29)]
                )
                
                # Create list of (feature_name, shap_value) tuples
                feature_shap_pairs = list(zip(feature_names, shap_values[0]))
                
                # Sort by absolute value (descending)
                feature_shap_pairs.sort(key=lambda x: abs(x[1]), reverse=True)
                
                # Top 5
                top_features = [
                    SHAPFeature(feature=name, shap_value=float(value))
                    for name, value in feature_shap_pairs[:5]
                ]
            except Exception as e:
                logger.warning(f"SHAP calculation failed: {e}. Returning empty explanations.")
                top_features = []
        
        # Step 8: Build response
        response = FraudPredictionResponse(
            fraud_probability=fraud_proba,
            risk_level=risk_level,
            decision=decision,
            confidence=confidence,
            top_features=top_features,
            transaction_id=f"TXN-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{int(transaction.Amount*1000) % 100000}",
            timestamp=datetime.now().isoformat() + "Z",
        )
        
        logger.info(
            f"Fraud prediction: prob={fraud_proba:.3f} risk={risk_level} decision={decision}"
        )
        
        return response
        
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in predict_fraud: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
