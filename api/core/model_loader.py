import joblib
from pathlib import Path
from typing import Dict, Any

_models_cache: Dict[str, Any] = {}

def load_all_models() -> None:
    """Load all 6 pkl files from models_saved/ into memory cache."""
    base_path = Path("models_saved")
    
    required_files = {
        "xgb_fraude": "xgb_fraude.pkl",
        "rf_nids": "rf_nids.pkl",
        "iso_forest": "iso_forest.pkl",
        "scaler_fraude": "scaler_fraude.pkl",
        "scaler_reseau": "scaler_reseau.pkl",
        "label_encoder": "label_encoder_cicids.pkl"
    }
    
    for key, filename in required_files.items():
        filepath = base_path / filename
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        _models_cache[key] = joblib.load(filepath)
    
    print(f"✓ Loaded {len(_models_cache)} models successfully")

def get_models() -> Dict[str, Any]:
    """Return cached models dict."""
    if not _models_cache:
        raise RuntimeError("Models not loaded. Call load_all_models() first.")
    return _models_cache
