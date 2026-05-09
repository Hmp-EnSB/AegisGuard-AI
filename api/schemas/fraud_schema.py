"""
Pydantic schemas for fraud detection API.
Handles transaction data validation.
"""

from pydantic import BaseModel, Field
from typing import List, Optional


class TransactionInput(BaseModel):
    """
    Input schema for fraud prediction.
    
    Matches ULB Credit Card Fraud dataset structure:
    - Time: seconds elapsed between this transaction and the first in dataset
    - Amount: transaction amount in EUR
    - V1–V28: PCA-transformed features from original card details
    """
    
    Time: float = Field(..., ge=0, description="Seconds since dataset start")
    Amount: float = Field(..., ge=0, description="Transaction amount in EUR")
    
    # PCA-transformed features (V1–V28)
    V1: float = Field(..., description="PCA feature 1")
    V2: float = Field(..., description="PCA feature 2")
    V3: float = Field(..., description="PCA feature 3")
    V4: float = Field(..., description="PCA feature 4")
    V5: float = Field(..., description="PCA feature 5")
    V6: float = Field(..., description="PCA feature 6")
    V7: float = Field(..., description="PCA feature 7")
    V8: float = Field(..., description="PCA feature 8")
    V9: float = Field(..., description="PCA feature 9")
    V10: float = Field(..., description="PCA feature 10")
    V11: float = Field(..., description="PCA feature 11")
    V12: float = Field(..., description="PCA feature 12")
    V13: float = Field(..., description="PCA feature 13")
    V14: float = Field(..., description="PCA feature 14")
    V15: float = Field(..., description="PCA feature 15")
    V16: float = Field(..., description="PCA feature 16")
    V17: float = Field(..., description="PCA feature 17")
    V18: float = Field(..., description="PCA feature 18")
    V19: float = Field(..., description="PCA feature 19")
    V20: float = Field(..., description="PCA feature 20")
    V21: float = Field(..., description="PCA feature 21")
    V22: float = Field(..., description="PCA feature 22")
    V23: float = Field(..., description="PCA feature 23")
    V24: float = Field(..., description="PCA feature 24")
    V25: float = Field(..., description="PCA feature 25")
    V26: float = Field(..., description="PCA feature 26")
    V27: float = Field(..., description="PCA feature 27")
    V28: float = Field(..., description="PCA feature 28")

    class Config:
        schema_extra = {
            "example": {
                "Time": 54000,
                "Amount": 9800.0,
                "V1": -1.35,
                "V2": -0.07,
                "V3": 2.54,
                "V4": 1.39,
                "V5": -0.31,
                "V6": -0.77,
                "V7": -0.18,
                "V8": -0.11,
                "V9": 0.69,
                "V10": -0.34,
                "V11": -0.57,
                "V12": -0.47,
                "V13": 0.15,
                "V14": -0.07,
                "V15": -0.09,
                "V16": -0.20,
                "V17": -0.11,
                "V18": 0.12,
                "V19": -0.08,
                "V20": 0.05,
                "V21": 0.03,
                "V22": -0.06,
                "V23": 0.09,
                "V24": -0.07,
                "V25": 0.11,
                "V26": 0.05,
                "V27": -0.01,
                "V28": 0.02,
            }
        }


class SHAPFeature(BaseModel):
    """Single SHAP explanation for a feature."""
    feature: str = Field(..., description="Feature name")
    shap_value: float = Field(..., description="SHAP contribution value")
    base_value: Optional[float] = Field(None, description="Model base value for context")


class FraudPredictionResponse(BaseModel):
    """
    Response schema for fraud prediction.
    Includes probability, risk level, decision, and SHAP explanation.
    """
    
    fraud_probability: float = Field(..., ge=0, le=1, description="Probability transaction is fraudulent (0-1)")
    risk_level: str = Field(..., description="Risk classification: LOW, MEDIUM, HIGH, CRITICAL")
    decision: str = Field(..., description="System decision: APPROVED or BLOCKED")
    confidence: float = Field(..., ge=0, le=1, description="Model confidence in decision")
    
    # SHAP explanations
    top_features: List[SHAPFeature] = Field(..., description="Top 5 contributing features with SHAP values")
    
    # Additional context
    transaction_id: Optional[str] = Field(None, description="Reference ID for audit trail")
    timestamp: Optional[str] = Field(None, description="Prediction timestamp (ISO 8601)")

    class Config:
        schema_extra = {
            "example": {
                "fraud_probability": 0.97,
                "risk_level": "CRITICAL",
                "decision": "BLOCKED",
                "confidence": 0.96,
                "top_features": [
                    {"feature": "Amount", "shap_value": 0.43, "base_value": 0.0},
                    {"feature": "V14", "shap_value": 0.31, "base_value": 0.0},
                    {"feature": "Time", "shap_value": 0.18, "base_value": 0.0},
                    {"feature": "V12", "shap_value": -0.12, "base_value": 0.0},
                    {"feature": "V7", "shap_value": -0.05, "base_value": 0.0}
                ],
                "transaction_id": "TXN-20260508-001234",
                "timestamp": "2026-05-08T14:23:45Z"
            }
        }
