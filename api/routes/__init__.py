"""API routes module."""

from .predict_fraud import router as fraud_router
from .predict_threat import router as threat_router

__all__ = ["fraud_router", "threat_router"]
