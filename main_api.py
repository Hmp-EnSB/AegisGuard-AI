"""
AegisGuard FastAPI Application Entry Point.

Hybrid cybersecurity platform combining:
- XGBoost: Financial fraud detection
- Random Forest: Network intrusion detection (14 attack types)
- Isolation Forest: Zero-day anomaly detection

All predictions include SHAP-based explainability.

Run with: uvicorn main_api:app --reload
Swagger docs: http://localhost:8000/docs
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
import logging

from api.core import (
    logger,
    load_all_models,
    get_model_status,
)
from api.core.config import (
    API_TITLE,
    API_VERSION,
    API_DESCRIPTION,
    CORS_ORIGINS,
)


# ============================================================================
# Startup / Shutdown Events
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager.
    Loads models on startup, logs on shutdown.
    """
    
    # Startup
    logger.info("=" * 60)
    logger.info(f"🛡 AegisGuard API Starting")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    logger.info("=" * 60)
    
    try:
        # Try to load models. If strict=False, API starts even if some models missing.
        load_all_models(strict=False)
        model_status = get_model_status()
        logger.info(f"Model Status: {model_status['available']}/{model_status['total']} models available")
        
        if not model_status['models_loaded']:
            logger.warning(
                "⚠️  Not all models loaded. Waiting for Salma to generate:\n"
                "   - xgb_fraude.pkl\n"
                "   - rf_nids.pkl\n"
                "   - iso_forest.pkl\n"
                "   - scaler_fraude.pkl, scaler_reseau.pkl, label_encoder_cicids.pkl"
            )
    except Exception as e:
        logger.error(f"Error during startup: {e}")
    
    yield  # App runs here
    
    # Shutdown
    logger.info("=" * 60)
    logger.info("🛡 AegisGuard API Shutting Down")
    logger.info("=" * 60)


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=API_DESCRIPTION,
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Health Check Endpoint
# ============================================================================

@app.get("/health", tags=["System"])
async def health_check():
    """
    Health check endpoint.
    Returns status of all models.
    """
    model_status = get_model_status()
    
    all_loaded = model_status['available'] == model_status['total']
    
    return {
        "status": "ok" if all_loaded else "degraded",
        "timestamp": datetime.now().isoformat(),
        "models": model_status,
    }


# ============================================================================
# TODO: Routes to be implemented
# ============================================================================

# These will be added in the next steps:
# - api/routes/predict_fraud.py      → POST /predict/fraud
# - api/routes/predict_threat.py     → POST /predict/threat
# - api/routes/explain.py            → GET /explain/{prediction_id}

# Placeholder routes (will be replaced)
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint — welcome message."""
    return {
        "message": "🛡 AegisGuard API",
        "version": API_VERSION,
        "docs": "/docs",
        "health": "/health",
        "status": "Models loading...",
    }


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler."""
    logger.warning(f"HTTP Exception: {exc.status_code} - {exc.detail}")
    return {
        "error": exc.detail,
        "status_code": exc.status_code,
        "timestamp": datetime.now().isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
