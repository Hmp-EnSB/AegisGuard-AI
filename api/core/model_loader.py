"""
Model loading and caching logic for AegisGuard API.
Loads pkl models on startup and caches them in memory.

Waits for these models from Salma (data engineer):
- xgb_fraude.pkl
- rf_nids.pkl
- iso_forest.pkl
- scaler_fraude.pkl
- scaler_reseau.pkl
- label_encoder_cicids.pkl
"""

import joblib
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from .config import MODEL_PATHS, logger

# Global model cache
_MODELS_CACHE: Dict[str, Any] = {}
_MODELS_LOADED = False


def check_model_files_exist() -> Dict[str, bool]:
    """
    Check which model files exist.
    Returns dict showing availability of each model.
    """
    status = {}
    for model_name, model_path in MODEL_PATHS.items():
        status[model_name] = Path(model_path).exists()
        if not status[model_name]:
            logger.warning(f"Model file not found: {model_path}")
    return status


def load_model(model_name: str) -> Any:
    """
    Load a single model from disk with caching.
    
    Args:
        model_name: Key from MODEL_PATHS (e.g., 'xgb_fraud', 'rf_nids')
    
    Returns:
        Loaded model object or None if file missing
        
    Raises:
        ValueError: If model_name not found in MODEL_PATHS
        FileNotFoundError: If model file doesn't exist
    """
    
    if model_name not in MODEL_PATHS:
        raise ValueError(f"Unknown model: {model_name}. Available: {list(MODEL_PATHS.keys())}")
    
    # Return cached model if already loaded
    if model_name in _MODELS_CACHE:
        logger.debug(f"Returning cached model: {model_name}")
        return _MODELS_CACHE[model_name]
    
    model_path = MODEL_PATHS[model_name]
    
    if not Path(model_path).exists():
        raise FileNotFoundError(
            f"Model file not found: {model_path}\n"
            f"Please ensure Salma has generated and uploaded: {model_name}.pkl"
        )
    
    try:
        logger.info(f"Loading model: {model_path}")
        model = joblib.load(model_path)
        _MODELS_CACHE[model_name] = model
        logger.info(f"Successfully loaded: {model_name}")
        return model
    except Exception as e:
        logger.error(f"Failed to load {model_name}: {str(e)}")
        raise


def load_all_models(strict: bool = False) -> Dict[str, bool]:
    """
    Load all models at API startup.
    
    Args:
        strict: If True, raise error if ANY model is missing.
               If False, load available models and log warnings.
    
    Returns:
        Dict showing loaded status: {"model_name": True/False, ...}
    """
    
    global _MODELS_LOADED
    
    logger.info("Loading all models...")
    loaded_status = {}
    failed_models = []
    
    for model_name in MODEL_PATHS.keys():
        try:
            load_model(model_name)
            loaded_status[model_name] = True
            logger.info(f"✓ {model_name}")
        except FileNotFoundError as e:
            loaded_status[model_name] = False
            failed_models.append(model_name)
            logger.warning(f"✗ {model_name}: {str(e)}")
        except Exception as e:
            loaded_status[model_name] = False
            failed_models.append(model_name)
            logger.error(f"✗ {model_name}: {str(e)}")
    
    if failed_models:
        msg = f"Failed to load models: {', '.join(failed_models)}"
        if strict:
            logger.error(msg)
            raise RuntimeError(msg)
        else:
            logger.warning(msg)
    
    _MODELS_LOADED = True if not failed_models else False
    return loaded_status


def get_model(model_name: str) -> Any:
    """
    Get a model from cache. Load if not already cached.
    
    Args:
        model_name: Key from MODEL_PATHS
    
    Returns:
        Loaded model object
    
    Raises:
        FileNotFoundError: If model file doesn't exist
    """
    
    if model_name not in _MODELS_CACHE:
        return load_model(model_name)
    return _MODELS_CACHE[model_name]


def get_model_status() -> Dict[str, Any]:
    """
    Get current status of all models.
    
    Returns:
        Status dict: {
            "models_loaded": bool,
            "cached_models": list of loaded model names,
            "files_exist": dict of file existence status,
            "total": int,
            "available": int
        }
    """
    
    files_status = check_model_files_exist()
    
    return {
        "models_loaded": _MODELS_LOADED,
        "cached_models": list(_MODELS_CACHE.keys()),
        "files_exist": files_status,
        "total": len(MODEL_PATHS),
        "available": sum(files_status.values()),
    }


def clear_cache():
    """Clear all cached models. Use for testing or memory cleanup."""
    global _MODELS_CACHE, _MODELS_LOADED
    _MODELS_CACHE.clear()
    _MODELS_LOADED = False
    logger.info("Model cache cleared")
