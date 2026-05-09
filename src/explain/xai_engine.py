"""
SHAP-based explainability engine for AegisGuard.
Generates per-feature importance scores for fraud & threat predictions.

Integrates SHAP TreeExplainer with XGBoost and Random Forest models.

TODO (Hiba):
- Implement explain_fraud() with XGBoost TreeExplainer
- Implement explain_threat() with Random Forest TreeExplainer
- Handle SHAP value slicing for multi-class RF (need to extract by predicted class)

Reference:
- SHAP XGBoost: shap.TreeExplainer(xgb_model)
- SHAP Random Forest: shap.TreeExplainer(rf_model)
- For RF multi-class: shap_values[0][:, predicted_class_idx]
"""

import numpy as np
import logging

logger = logging.getLogger(__name__)


def explain_fraud(xgb_model, scaler, X_scaled):
    """
    Generate SHAP explanations for fraud prediction.
    
    Args:
        xgb_model: Trained XGBoost classifier
        scaler: StandardScaler (fraud — 2 features: Amount, Time)
        X_scaled: Scaled feature array (shape: [1, 30])
    
    Returns:
        SHAP values (shape: [1, 30]) — one importance value per feature
        
    Implementation guide:
        1. Import shap: import shap
        2. Create explainer: explainer = shap.TreeExplainer(xgb_model)
        3. Get values: shap_values = explainer.shap_values(X_scaled)
        4. XGBoost binary class returns (n_samples, n_features) automatically
        5. Return shap_values[0] if 2D array, else shap_values
    """
    
    try:
        import shap
        
        logger.info("Creating SHAP TreeExplainer for XGBoost fraud model...")
        explainer = shap.TreeExplainer(xgb_model)
        
        # Get SHAP values
        shap_values = explainer.shap_values(X_scaled)
        
        # Handle different return shapes depending on XGBoost version
        if isinstance(shap_values, list):
            # Binary classification might return list — take class 1 (fraud)
            return shap_values[1] if len(shap_values) > 1 else shap_values[0]
        elif len(shap_values.shape) == 3:
            # Multi-output shape: [n_samples, n_features, n_classes]
            return shap_values[0, :, 1]  # Class 1 = fraud
        else:
            # Normal binary: [n_samples, n_features]
            return shap_values[0]
            
    except ImportError:
        logger.warning("SHAP not installed. Returning zeros.")
        return np.zeros(X_scaled.shape[1])
    except Exception as e:
        logger.error(f"SHAP calculation failed: {e}")
        return np.zeros(X_scaled.shape[1])


def explain_threat(rf_model, scaler, X_scaled, predicted_class_idx):
    """
    Generate SHAP explanations for threat prediction.
    
    Args:
        rf_model: Trained Random Forest classifier (14 classes)
        scaler: StandardScaler (network — 78 features)
        X_scaled: Scaled feature array (shape: [1, 78])
        predicted_class_idx: Index of the predicted class (0-13)
    
    Returns:
        SHAP values for the predicted class (shape: [78]) — one importance per feature
        
    Implementation guide:
        1. Import shap: import shap
        2. Create explainer: explainer = shap.TreeExplainer(rf_model)
        3. Get values: shap_values = explainer.shap_values(X_scaled)
        4. RF multi-class returns list of arrays (one per class): [14, n_samples, n_features]
        5. Extract for this prediction: shap_values[predicted_class_idx][0]
        6. Return 1D array of 78 values
    """
    
    try:
        import shap
        
        logger.info("Creating SHAP TreeExplainer for Random Forest threat model...")
        explainer = shap.TreeExplainer(rf_model)
        
        # Get SHAP values
        shap_values = explainer.shap_values(X_scaled)
        
        # Random Forest with 14 classes returns list:
        # shap_values[class_idx] = [n_samples, n_features]
        if isinstance(shap_values, list):
            # Extract SHAP values for the predicted class
            return shap_values[predicted_class_idx][0]
        else:
            # Fallback if not list (different sklearn version)
            if len(shap_values.shape) == 3:
                # Shape: [n_classes, n_samples, n_features]
                return shap_values[predicted_class_idx, 0, :]
            else:
                # Unexpected shape, return zeros
                logger.warning(f"Unexpected SHAP shape: {shap_values.shape}")
                return np.zeros(X_scaled.shape[1])
                
    except ImportError:
        logger.warning("SHAP not installed. Returning zeros.")
        return np.zeros(X_scaled.shape[1])
    except Exception as e:
        logger.error(f"SHAP calculation failed: {e}")
        return np.zeros(X_scaled.shape[1])


def explain_batch_fraud(xgb_model, scaler, X_scaled_batch):
    """
    Generate SHAP explanations for batch fraud predictions.
    
    Args:
        xgb_model: Trained XGBoost classifier
        scaler: StandardScaler
        X_scaled_batch: Batch of scaled features (shape: [n_samples, 30])
    
    Returns:
        SHAP values (shape: [n_samples, 30])
    """
    
    try:
        import shap
        explainer = shap.TreeExplainer(xgb_model)
        shap_values = explainer.shap_values(X_scaled_batch)
        
        if isinstance(shap_values, list):
            return shap_values[1] if len(shap_values) > 1 else shap_values[0]
        elif len(shap_values.shape) == 3:
            return shap_values[:, :, 1]
        else:
            return shap_values
            
    except Exception as e:
        logger.error(f"Batch SHAP calculation failed: {e}")
        return np.zeros_like(X_scaled_batch)


def explain_batch_threat(rf_model, scaler, X_scaled_batch, predicted_class_indices):
    """
    Generate SHAP explanations for batch threat predictions.
    
    Args:
        rf_model: Trained Random Forest classifier
        scaler: StandardScaler
        X_scaled_batch: Batch of scaled features (shape: [n_samples, 78])
        predicted_class_indices: Array of predicted class indices (shape: [n_samples])
    
    Returns:
        SHAP values for each sample's predicted class (shape: [n_samples, 78])
    """
    
    try:
        import shap
        explainer = shap.TreeExplainer(rf_model)
        shap_values = explainer.shap_values(X_scaled_batch)
        
        if isinstance(shap_values, list):
            # Extract SHAP values for each sample's predicted class
            results = np.zeros_like(X_scaled_batch)
            for i, class_idx in enumerate(predicted_class_indices):
                results[i] = shap_values[class_idx][i]
            return results
        else:
            logger.warning("Unexpected SHAP format for batch processing")
            return np.zeros_like(X_scaled_batch)
            
    except Exception as e:
        logger.error(f"Batch SHAP calculation failed: {e}")
        return np.zeros_like(X_scaled_batch)
