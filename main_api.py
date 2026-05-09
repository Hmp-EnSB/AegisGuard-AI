from fastapi import FastAPI
from contextlib import asynccontextmanager
from api.core.model_loader import load_all_models, get_models
from api.routes.predict_fraud import router as fraud_router
from api.routes.predict_threat import router as threat_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: load models
    print("🚀 Loading models...")
    try:
        load_all_models()
        print("✓ All models loaded successfully")
    except Exception as e:
        print(f"✗ Model loading failed: {e}")
        raise
    yield
    # Shutdown: cleanup if needed
    print("🛑 Shutting down...")

app = FastAPI(
    title="AegisGuard API",
    description="Hybrid AI Cybersecurity Platform — Network Intrusion Detection & Financial Fraud Analysis",
    version="1.0.0",
    lifespan=lifespan
)

app.include_router(fraud_router)
app.include_router(threat_router)

@app.get("/health")
def health_check():
    try:
        models = get_models()
        return {
            "status": "healthy",
            "models_loaded": {
                "xgb_fraude": models.get("xgb_fraude") is not None,
                "rf_nids": models.get("rf_nids") is not None,
                "iso_forest": models.get("iso_forest") is not None,
                "scaler_fraude": models.get("scaler_fraude") is not None,
                "scaler_reseau": models.get("scaler_reseau") is not None,
                "label_encoder": models.get("label_encoder") is not None
            }
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@app.get("/")
def root():
    return {
        "message": "AegisGuard API — Détecter. Protéger. Blinder.",
        "docs": "/docs",
        "health": "/health"
    }
