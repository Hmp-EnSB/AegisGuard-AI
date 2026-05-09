"""
Configuration and settings for AegisGuard API.
Paths, logging, and model loading configuration.
"""

import os
from pathlib import Path
import logging

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models_saved"
LOG_DIR = PROJECT_ROOT / "logs"

# Create logs directory if it doesn't exist
LOG_DIR.mkdir(exist_ok=True)

# Model file paths
MODEL_PATHS = {
    "xgb_fraud": MODELS_DIR / "xgb_fraude.pkl",
    "rf_nids": MODELS_DIR / "rf_nids.pkl",
    "iso_forest": MODELS_DIR / "iso_forest.pkl",
    "scaler_fraud": MODELS_DIR / "scaler_fraude.pkl",
    "scaler_network": MODELS_DIR / "scaler_reseau.pkl",
    "label_encoder": MODELS_DIR / "label_encoder_cicids.pkl",
}

# API Settings
API_TITLE = "AegisGuard — Cybersecurity AI Platform"
API_VERSION = "1.0.0"
API_DESCRIPTION = """
🛡 Real-time hybrid AI platform for:
- **Financial Fraud Detection** (XGBoost on ULB dataset)
- **Network Intrusion Detection** (Random Forest on CICIDS2017)
- **Anomaly Detection** (Isolation Forest)

Every prediction includes SHAP-based explainability.
"""

# Security & Performance
CORS_ORIGINS = ["*"]  # In production, restrict to frontend domain
PREDICTION_TIMEOUT = 5.0  # seconds
MAX_BATCH_SIZE = 100
ENABLE_SECURITY_LOGGING = True

# Fraud Model Thresholds
FRAUD_THRESHOLDS = {
    "low": 0.3,
    "medium": 0.6,
    "high": 0.8,
}

# Severity Mapping for Network Attacks
ATTACK_SEVERITY = {
    "BENIGN": "INFO",
    "FTP-Patator": "HIGH",
    "SSH-Patator": "HIGH",
    "DoS_Hulk": "CRITICAL",
    "DoS_Slowhttptest": "CRITICAL",
    "DoS_Slowloris": "CRITICAL",
    "DoS_GoldenEye": "CRITICAL",
    "Heartbleed": "HIGH",
    "Botnet": "CRITICAL",
    "Web_Attack_Brute_Force": "HIGH",
    "Web_Attack_XSS": "HIGH",
    "Web_Attack_SQL_Injection": "HIGH",
    "Infiltration": "CRITICAL",
    "PortScan": "MEDIUM",
    "DDoS": "CRITICAL",
}

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "api.log"),
        logging.StreamHandler(),
    ],
)

logger = logging.getLogger(__name__)
