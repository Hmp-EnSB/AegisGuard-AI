"""
POST /predict/threat endpoint.
Classifies network traffic into 14 attack types using Random Forest + SHAP.

Requires from models_saved/:
- rf_nids.pkl              (trained Random Forest for 14 classes)
- scaler_reseau.pkl        (StandardScaler for all 78 features)
- label_encoder_cicids.pkl (LabelEncoder to decode predicted class)
- iso_forest.pkl           (Isolation Forest for anomaly score)

Uses xai_engine.explain_threat() for SHAP values.
"""

from fastapi import APIRouter, HTTPException
from datetime import datetime
import numpy as np
import logging

from api.schemas.nids_schema import NetworkFlowInput, ThreatPredictionResponse, SHAPFeature
from api.core import get_model, logger
from api.core.config import ATTACK_SEVERITY

try:
    from src.explain.xai_engine import explain_threat
except ImportError:
    logger.warning("xai_engine not available yet. SHAP explanations will be empty until implemented.")
    explain_threat = None

router = APIRouter(prefix="/predict", tags=["Network Intrusion Detection"])


# List of all 78 CICIDS2017 features in correct order
# This MUST match the order used by Salma when training the model
CICIDS2017_FEATURES = [
    "Dst_Port", "Protocol", "Flow_Duration", "Total_Fwd_Packets", "Total_Bwd_Packets",
    "Total_Length_Fwd_Packets", "Total_Length_Bwd_Packets", "Fwd_Packet_Length_Max",
    "Fwd_Packet_Length_Min", "Fwd_Packet_Length_Mean", "Fwd_Packet_Length_Std",
    "Bwd_Packet_Length_Max", "Bwd_Packet_Length_Min", "Bwd_Packet_Length_Mean",
    "Bwd_Packet_Length_Std", "FIN_Flag_Count", "SYN_Flag_Count", "RST_Flag_Count",
    "PSH_Flag_Count", "ACK_Flag_Count", "URG_Flag_Count", "CWE_Flag_Count",
    "ECE_Flag_Count", "Flow_IAT_Mean", "Flow_IAT_Std", "Flow_IAT_Max", "Flow_IAT_Min",
    "Fwd_IAT_Mean", "Fwd_IAT_Std", "Fwd_IAT_Max", "Fwd_IAT_Min", "Bwd_IAT_Mean",
    "Bwd_IAT_Std", "Bwd_IAT_Max", "Bwd_IAT_Min", "Fwd_PSH_Flags", "Bwd_PSH_Flags",
    "Fwd_URG_Flags", "Bwd_URG_Flags", "Fwd_Header_Length", "Bwd_Header_Length",
    "Fwd_Packets_Per_Second", "Bwd_Packets_Per_Second", "Min_Packet_Length",
    "Max_Packet_Length", "Packet_Length_Mean", "Packet_Length_Std",
    "Packet_Length_Variance", "FIN_Flag_Cnt", "SYN_Flag_Cnt", "RST_Flag_Cnt",
    "PSH_Flag_Cnt", "ACK_Flag_Cnt", "URG_Flag_Cnt", "CWR_Flag_Count", "ECE_Flag_Cnt",
    "Down_Up_Ratio", "Average_Packet_Size", "Avg_Fwd_Segment_Size", "Avg_Bwd_Segment_Size",
    "Fwd_Avg_Bytes_Bulk", "Fwd_Avg_Packets_Bulk", "Fwd_Avg_Bulk_Rate", "Bwd_Avg_Bytes_Bulk",
    "Bwd_Avg_Packets_Bulk", "Bwd_Avg_Bulk_Rate", "Subflow_Fwd_Packets", "Subflow_Fwd_Bytes",
    "Subflow_Bwd_Packets", "Subflow_Bwd_Bytes", "Init_Win_bytes_Forward",
    "Init_Win_bytes_Backward", "act_data_pkt_fwd", "min_seg_size_forward", "Active_Mean",
    "Active_Std", "Active_Max", "Active_Min", "Idle_Mean", "Idle_Std", "Idle_Max", "Idle_Min",
]

assert len(CICIDS2017_FEATURES) == 78, f"Expected 78 features, got {len(CICIDS2017_FEATURES)}"


@router.post("/threat", response_model=ThreatPredictionResponse)
async def predict_threat(network_flow: NetworkFlowInput):
    """
    Classify network flow into one of 14 attack types (or BENIGN).
    
    **Input:**
    78 network flow statistics (Dst_Port, Protocol, Flow_Duration, etc.)
    
    **Output:**
    - threat_class: One of 14 attack types or BENIGN
    - confidence: 0-1 classification confidence
    - severity: INFO / LOW / MEDIUM / HIGH / CRITICAL
    - is_anomaly: Boolean (Isolation Forest result)
    - top_features: Top 5 SHAP-explained features for this prediction
    - all_predictions: Probability for each of 14 classes (for dashboard visualization)
    
    **Example:**
    ```bash
    curl -X POST http://localhost:8000/predict/threat \\
      -H "Content-Type: application/json" \\
      -d '{
        "Dst_Port": 443,
        "Protocol": 6,
        "Flow_Duration": 2500000,
        ...
        "Idle_Min": 100000
      }'
    ```
    """
    
    try:
        # Step 1: Load models
        try:
            rf_model = get_model("rf_nids")
            scaler = get_model("scaler_network")
            label_encoder = get_model("label_encoder")
            iso_forest = get_model("iso_forest")
        except FileNotFoundError as e:
            logger.error(f"Model loading failed: {e}")
            raise HTTPException(
                status_code=503,
                detail=f"Model unavailable: {str(e)}"
            )
        
        # Step 2: Convert input to correctly ordered numpy array
        # Must match CICIDS2017_FEATURES order exactly
        X_raw = np.array([[
            network_flow.Dst_Port, network_flow.Protocol, network_flow.Flow_Duration,
            network_flow.Total_Fwd_Packets, network_flow.Total_Bwd_Packets,
            network_flow.Total_Length_Fwd_Packets, network_flow.Total_Length_Bwd_Packets,
            network_flow.Fwd_Packet_Length_Max, network_flow.Fwd_Packet_Length_Min,
            network_flow.Fwd_Packet_Length_Mean, network_flow.Fwd_Packet_Length_Std,
            network_flow.Bwd_Packet_Length_Max, network_flow.Bwd_Packet_Length_Min,
            network_flow.Bwd_Packet_Length_Mean, network_flow.Bwd_Packet_Length_Std,
            network_flow.FIN_Flag_Count, network_flow.SYN_Flag_Count,
            network_flow.RST_Flag_Count, network_flow.PSH_Flag_Count,
            network_flow.ACK_Flag_Count, network_flow.URG_Flag_Count,
            network_flow.CWE_Flag_Count, network_flow.ECE_Flag_Count,
            network_flow.Flow_IAT_Mean, network_flow.Flow_IAT_Std,
            network_flow.Flow_IAT_Max, network_flow.Flow_IAT_Min,
            network_flow.Fwd_IAT_Mean, network_flow.Fwd_IAT_Std,
            network_flow.Fwd_IAT_Max, network_flow.Fwd_IAT_Min,
            network_flow.Bwd_IAT_Mean, network_flow.Bwd_IAT_Std,
            network_flow.Bwd_IAT_Max, network_flow.Bwd_IAT_Min,
            network_flow.Fwd_PSH_Flags, network_flow.Bwd_PSH_Flags,
            network_flow.Fwd_URG_Flags, network_flow.Bwd_URG_Flags,
            network_flow.Fwd_Header_Length, network_flow.Bwd_Header_Length,
            network_flow.Fwd_Packets_Per_Second, network_flow.Bwd_Packets_Per_Second,
            network_flow.Min_Packet_Length, network_flow.Max_Packet_Length,
            network_flow.Packet_Length_Mean, network_flow.Packet_Length_Std,
            network_flow.Packet_Length_Variance, network_flow.FIN_Flag_Cnt,
            network_flow.SYN_Flag_Cnt, network_flow.RST_Flag_Cnt,
            network_flow.PSH_Flag_Cnt, network_flow.ACK_Flag_Cnt,
            network_flow.URG_Flag_Cnt, network_flow.CWR_Flag_Count,
            network_flow.ECE_Flag_Cnt, network_flow.Down_Up_Ratio,
            network_flow.Average_Packet_Size, network_flow.Avg_Fwd_Segment_Size,
            network_flow.Avg_Bwd_Segment_Size, network_flow.Fwd_Avg_Bytes_Bulk,
            network_flow.Fwd_Avg_Packets_Bulk, network_flow.Fwd_Avg_Bulk_Rate,
            network_flow.Bwd_Avg_Bytes_Bulk, network_flow.Bwd_Avg_Packets_Bulk,
            network_flow.Bwd_Avg_Bulk_Rate, network_flow.Subflow_Fwd_Packets,
            network_flow.Subflow_Fwd_Bytes, network_flow.Subflow_Bwd_Packets,
            network_flow.Subflow_Bwd_Bytes, network_flow.Init_Win_bytes_Forward,
            network_flow.Init_Win_bytes_Backward, network_flow.act_data_pkt_fwd,
            network_flow.min_seg_size_forward, network_flow.Active_Mean,
            network_flow.Active_Std, network_flow.Active_Max, network_flow.Active_Min,
            network_flow.Idle_Mean, network_flow.Idle_Std, network_flow.Idle_Max,
            network_flow.Idle_Min,
        ]])
        
        # Step 3: Scale all 78 features
        X_scaled = scaler.transform(X_raw)
        
        # Step 4: Predict attack class
        pred_encoded = rf_model.predict(X_scaled)[0]
        threat_class = label_encoder.inverse_transform([pred_encoded])[0]
        
        # Step 5: Get confidence (max probability from all 14 classes)
        pred_proba_all = rf_model.predict_proba(X_scaled)[0]
        confidence = float(max(pred_proba_all))
        
        # Step 6: Map to severity
        severity = ATTACK_SEVERITY.get(threat_class, "MEDIUM")
        
        # Step 7: Anomaly detection
        anomaly_score = float(iso_forest.score_samples(X_scaled)[0])
        is_anomaly = anomaly_score < 0  # Isolation Forest returns negative scores for anomalies
        
        # Step 8: SHAP explanations
        top_features = []
        if explain_threat is not None:
            try:
                shap_values = explain_threat(rf_model, scaler, X_scaled, pred_encoded)
                
                # Create list of (feature_name, shap_value) tuples
                feature_shap_pairs = list(zip(CICIDS2017_FEATURES, shap_values))
                
                # Sort by absolute value (descending)
                feature_shap_pairs.sort(key=lambda x: abs(x[1]), reverse=True)
                
                # Top 5
                top_features = [
                    SHAPFeature(feature=name, shap_value=float(value))
                    for name, value in feature_shap_pairs[:5]
                ]
            except Exception as e:
                logger.warning(f"SHAP calculation failed: {e}. Returning empty explanations.")
                top_features = []
        
        # Step 9: All predictions (for dashboard visualization)
        all_predictions = {
            label_encoder.inverse_transform([i])[0]: float(prob)
            for i, prob in enumerate(pred_proba_all)
        }
        
        # Step 10: Build response
        response = ThreatPredictionResponse(
            threat_class=threat_class,
            confidence=confidence,
            severity=severity,
            top_features=top_features,
            all_predictions=all_predictions,
            flow_id=f"FLOW-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{network_flow.Dst_Port}",
            timestamp=datetime.now().isoformat() + "Z",
        )
        
        logger.info(
            f"Threat prediction: class={threat_class} conf={confidence:.3f} "
            f"severity={severity} anomaly={is_anomaly}"
        )
        
        return response
        
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in predict_threat: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
