import joblib
from pathlib import Path
from typing import Dict, Any

_models_cache: Dict[str, Any] = {}

# Use absolute path anchored to this file — works no matter where uvicorn is launched from
_MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models_saved"

def load_all_models() -> None:
    """Load all pkl files from models_saved/ into memory cache."""
    required_files = {
        "xgb_fraude":    "xgb_fraude.pkl",
        "rf_nids":       "rf_nids.pkl",
        "iso_forest":    "iso_forest.pkl",
        "scaler_fraude": "scaler_fraude.pkl",
        "scaler_reseau": "scaler_reseau.pkl",
        "label_encoder": "label_encoder_cicids.pkl",
    }
    for key, filename in required_files.items():
        filepath = _MODELS_DIR / filename
        if not filepath.exists():
            raise FileNotFoundError(
                f"Missing: {filepath}\n"
                f"Run: python generate_dummy_models.py"
            )
        _models_cache[key] = joblib.load(filepath)
    print(f"[OK] Loaded {len(_models_cache)} models from {_MODELS_DIR}")

def get_models() -> Dict[str, Any]:
    if not _models_cache:
        raise RuntimeError("Models not loaded. Did startup lifespan run?")
    return _models_cache