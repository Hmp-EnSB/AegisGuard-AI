from pydantic import BaseModel, Field
from typing import List

class TransactionInput(BaseModel):
    Time: float = Field(..., description="Seconds elapsed since first transaction")
    Amount: float = Field(..., ge=0, description="Transaction amount")
    V1: float; V2: float; V3: float; V4: float; V5: float; V6: float; V7: float
    V8: float; V9: float; V10: float; V11: float; V12: float; V13: float; V14: float
    V15: float; V16: float; V17: float; V18: float; V19: float; V20: float; V21: float
    V22: float; V23: float; V24: float; V25: float; V26: float; V27: float; V28: float

    model_config = {
        "json_schema_extra": {
            "example": {
                "Time": 54000.0, "Amount": 9800.0,
                "V1": -1.35, "V2": 0.5, "V3": 1.2, "V4": -0.8, "V5": 0.3,
                "V6": -0.6, "V7": 0.9, "V8": 0.1, "V9": -0.4, "V10": 0.7,
                "V11": -0.2, "V12": 0.5, "V13": 0.8, "V14": -0.3, "V15": 0.6,
                "V16": -0.1, "V17": 0.4, "V18": -0.7, "V19": 0.2, "V20": 0.9,
                "V21": -0.5, "V22": 0.3, "V23": -0.8, "V24": 0.1,
                "V25": 0.6, "V26": -0.4, "V27": 0.7, "V28": 0.02
            }
        }
    }

class FeatureImportance(BaseModel):
    """One SHAP feature contribution."""
    feature: str
    shap_value: float

class FraudPredictionOutput(BaseModel):
    fraud_probability: float = Field(..., ge=0, le=1)
    risk_level: str = Field(..., pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    decision: str = Field(..., pattern="^(LEGITIMATE|FRAUD)$")
    is_anomaly: bool
    anomaly_score: float
    top_features: List[FeatureImportance]