"""
Pydantic schemas for Network Intrusion Detection System (NIDS) API.
Handles CICIDS2017 network flow data validation.
"""

from pydantic import BaseModel, Field
from typing import List, Optional


class NetworkFlowInput(BaseModel):
    """
    Input schema for network threat prediction.
    
    Contains 78 features extracted from CICIDS2017 network flows:
    - Flow statistics (duration, packets, bytes)
    - Protocol-specific metrics (TCP flags, window sizes)
    - Inter-arrival time statistics
    """
    
    # Flow Duration and Packet/Byte Counts
    Dst_Port: int = Field(..., ge=0, le=65535, description="Destination port")
    Protocol: int = Field(..., ge=0, le=255, description="Protocol number (TCP=6, UDP=17, etc)")
    Flow_Duration: float = Field(..., ge=0, description="Total duration of the flow in microseconds")
    Total_Fwd_Packets: int = Field(..., ge=0, description="Total packets in forward direction")
    Total_Bwd_Packets: int = Field(..., ge=0, description="Total packets in backward direction")
    Total_Length_Fwd_Packets: int = Field(..., ge=0, description="Total bytes forward")
    Total_Length_Bwd_Packets: int = Field(..., ge=0, description="Total bytes backward")
    
    # Packet Length Statistics
    Fwd_Packet_Length_Max: float = Field(..., ge=0, description="Max forward packet size")
    Fwd_Packet_Length_Min: float = Field(..., ge=0, description="Min forward packet size")
    Fwd_Packet_Length_Mean: float = Field(..., ge=0, description="Mean forward packet size")
    Fwd_Packet_Length_Std: float = Field(..., ge=0, description="Std dev forward packet size")
    Bwd_Packet_Length_Max: float = Field(..., ge=0, description="Max backward packet size")
    Bwd_Packet_Length_Min: float = Field(..., ge=0, description="Min backward packet size")
    Bwd_Packet_Length_Mean: float = Field(..., ge=0, description="Mean backward packet size")
    Bwd_Packet_Length_Std: float = Field(..., ge=0, description="Std dev backward packet size")
    
    # Flag Counts
    FIN_Flag_Count: int = Field(..., ge=0, description="Number of FIN flags")
    SYN_Flag_Count: int = Field(..., ge=0, description="Number of SYN flags")
    RST_Flag_Count: int = Field(..., ge=0, description="Number of RST flags")
    PSH_Flag_Count: int = Field(..., ge=0, description="Number of PSH flags")
    ACK_Flag_Count: int = Field(..., ge=0, description="Number of ACK flags")
    URG_Flag_Count: int = Field(..., ge=0, description="Number of URG flags")
    CWE_Flag_Count: int = Field(..., ge=0, description="Number of CWE flags")
    ECE_Flag_Count: int = Field(..., ge=0, description="Number of ECE flags")
    
    # Flow IAT (Inter-Arrival Time) Statistics
    Flow_IAT_Mean: float = Field(..., ge=0, description="Mean time between packets")
    Flow_IAT_Std: float = Field(..., ge=0, description="Std dev of inter-arrival times")
    Flow_IAT_Max: float = Field(..., ge=0, description="Max inter-arrival time")
    Flow_IAT_Min: float = Field(..., ge=0, description="Min inter-arrival time")
    
    # Forward IAT Statistics
    Fwd_IAT_Mean: float = Field(..., ge=0, description="Mean forward inter-arrival time")
    Fwd_IAT_Std: float = Field(..., ge=0, description="Std dev forward IAT")
    Fwd_IAT_Max: float = Field(..., ge=0, description="Max forward IAT")
    Fwd_IAT_Min: float = Field(..., ge=0, description="Min forward IAT")
    
    # Backward IAT Statistics
    Bwd_IAT_Mean: float = Field(..., ge=0, description="Mean backward inter-arrival time")
    Bwd_IAT_Std: float = Field(..., ge=0, description="Std dev backward IAT")
    Bwd_IAT_Max: float = Field(..., ge=0, description="Max backward IAT")
    Bwd_IAT_Min: float = Field(..., ge=0, description="Min backward IAT")
    
    # TCP Window Size Statistics
    Fwd_PSH_Flags: int = Field(..., ge=0, description="Forward push flags")
    Bwd_PSH_Flags: int = Field(..., ge=0, description="Backward push flags")
    Fwd_URG_Flags: int = Field(..., ge=0, description="Forward urgent flags")
    Bwd_URG_Flags: int = Field(..., ge=0, description="Backward urgent flags")
    Fwd_Header_Length: int = Field(..., ge=0, description="Forward header bytes")
    Bwd_Header_Length: int = Field(..., ge=0, description="Backward header bytes")
    Fwd_Packets_Per_Second: float = Field(..., ge=0, description="Forward packets per second")
    Bwd_Packets_Per_Second: float = Field(..., ge=0, description="Backward packets per second")
    Min_Packet_Length: float = Field(..., ge=0, description="Minimum packet size in flow")
    Max_Packet_Length: float = Field(..., ge=0, description="Maximum packet size in flow")
    Packet_Length_Mean: float = Field(..., ge=0, description="Mean packet size")
    Packet_Length_Std: float = Field(..., ge=0, description="Std dev packet size")
    Packet_Length_Variance: float = Field(..., ge=0, description="Variance of packet length")
    
    # Additional Flow Metrics
    FIN_Flag_Cnt: int = Field(..., ge=0, description="Total FIN flags")
    SYN_Flag_Cnt: int = Field(..., ge=0, description="Total SYN flags")
    RST_Flag_Cnt: int = Field(..., ge=0, description="Total RST flags")
    PSH_Flag_Cnt: int = Field(..., ge=0, description="Total PSH flags")
    ACK_Flag_Cnt: int = Field(..., ge=0, description="Total ACK flags")
    URG_Flag_Cnt: int = Field(..., ge=0, description="Total URG flags")
    CWR_Flag_Count: int = Field(..., ge=0, description="Total CWR flags")
    ECE_Flag_Cnt: int = Field(..., ge=0, description="Total ECE flags")
    Down_Up_Ratio: float = Field(..., ge=0, description="Ratio of down to up packets")
    Average_Packet_Size: float = Field(..., ge=0, description="Average packet size")
    Avg_Fwd_Segment_Size: float = Field(..., ge=0, description="Average forward segment size")
    Avg_Bwd_Segment_Size: float = Field(..., ge=0, description="Average backward segment size")
    Fwd_Avg_Bytes_Bulk: float = Field(..., ge=0, description="Forward average bulk size")
    Fwd_Avg_Packets_Bulk: float = Field(..., ge=0, description="Forward average packets/bulk")
    Fwd_Avg_Bulk_Rate: float = Field(..., ge=0, description="Forward bulk rate")
    Bwd_Avg_Bytes_Bulk: float = Field(..., ge=0, description="Backward average bulk size")
    Bwd_Avg_Packets_Bulk: float = Field(..., ge=0, description="Backward average packets/bulk")
    Bwd_Avg_Bulk_Rate: float = Field(..., ge=0, description="Backward bulk rate")
    Subflow_Fwd_Packets: int = Field(..., ge=0, description="Forward subflow packets")
    Subflow_Fwd_Bytes: int = Field(..., ge=0, description="Forward subflow bytes")
    Subflow_Bwd_Packets: int = Field(..., ge=0, description="Backward subflow packets")
    Subflow_Bwd_Bytes: int = Field(..., ge=0, description="Backward subflow bytes")
    Init_Win_bytes_Forward: int = Field(..., ge=0, description="Initial window size forward")
    Init_Win_bytes_Backward: int = Field(..., ge=0, description="Initial window size backward")
    act_data_pkt_fwd: int = Field(..., ge=0, description="Active data packets forward")
    min_seg_size_forward: int = Field(..., ge=0, description="Minimum segment size forward")
    Active_Mean: float = Field(..., ge=0, description="Mean active time")
    Active_Std: float = Field(..., ge=0, description="Std dev active time")
    Active_Max: float = Field(..., ge=0, description="Max active time")
    Active_Min: float = Field(..., ge=0, description="Min active time")
    Idle_Mean: float = Field(..., ge=0, description="Mean idle time")
    Idle_Std: float = Field(..., ge=0, description="Std dev idle time")
    Idle_Max: float = Field(..., ge=0, description="Max idle time")
    Idle_Min: float = Field(..., ge=0, description="Min idle time")

    class Config:
        schema_extra = {
            "example": {
                "Dst_Port": 443,
                "Protocol": 6,
                "Flow_Duration": 2500000,
                "Total_Fwd_Packets": 150,
                "Total_Bwd_Packets": 145,
                "Total_Length_Fwd_Packets": 75000,
                "Total_Length_Bwd_Packets": 82000,
                "Fwd_Packet_Length_Max": 1500,
                "Fwd_Packet_Length_Min": 64,
                "Fwd_Packet_Length_Mean": 500,
                "Fwd_Packet_Length_Std": 250,
                "Bwd_Packet_Length_Max": 1500,
                "Bwd_Packet_Length_Min": 64,
                "Bwd_Packet_Length_Mean": 565,
                "Bwd_Packet_Length_Std": 280,
                "FIN_Flag_Count": 0,
                "SYN_Flag_Count": 1,
                "RST_Flag_Count": 0,
                "PSH_Flag_Count": 5,
                "ACK_Flag_Count": 140,
                "URG_Flag_Count": 0,
                "CWE_Flag_Count": 0,
                "ECE_Flag_Count": 0,
                "Flow_IAT_Mean": 15000,
                "Flow_IAT_Std": 8000,
                "Flow_IAT_Max": 35000,
                "Flow_IAT_Min": 1000,
                "Fwd_IAT_Mean": 16000,
                "Fwd_IAT_Std": 8500,
                "Fwd_IAT_Max": 36000,
                "Fwd_IAT_Min": 1000,
                "Bwd_IAT_Mean": 14000,
                "Bwd_IAT_Std": 7500,
                "Bwd_IAT_Max": 34000,
                "Bwd_IAT_Min": 1000,
                "Fwd_PSH_Flags": 2,
                "Bwd_PSH_Flags": 3,
                "Fwd_URG_Flags": 0,
                "Bwd_URG_Flags": 0,
                "Fwd_Header_Length": 6000,
                "Bwd_Header_Length": 5800,
                "Fwd_Packets_Per_Second": 60,
                "Bwd_Packets_Per_Second": 58,
                "Min_Packet_Length": 64,
                "Max_Packet_Length": 1500,
                "Packet_Length_Mean": 531,
                "Packet_Length_Std": 265,
                "Packet_Length_Variance": 70225,
                "FIN_Flag_Cnt": 0,
                "SYN_Flag_Cnt": 1,
                "RST_Flag_Cnt": 0,
                "PSH_Flag_Cnt": 5,
                "ACK_Flag_Cnt": 140,
                "URG_Flag_Cnt": 0,
                "CWR_Flag_Count": 0,
                "ECE_Flag_Cnt": 0,
                "Down_Up_Ratio": 0.97,
                "Average_Packet_Size": 531,
                "Avg_Fwd_Segment_Size": 500,
                "Avg_Bwd_Segment_Size": 565,
                "Fwd_Avg_Bytes_Bulk": 5000,
                "Fwd_Avg_Packets_Bulk": 10,
                "Fwd_Avg_Bulk_Rate": 2,
                "Bwd_Avg_Bytes_Bulk": 5000,
                "Bwd_Avg_Packets_Bulk": 10,
                "Bwd_Avg_Bulk_Rate": 2,
                "Subflow_Fwd_Packets": 75,
                "Subflow_Fwd_Bytes": 37500,
                "Subflow_Bwd_Packets": 72,
                "Subflow_Bwd_Bytes": 41000,
                "Init_Win_bytes_Forward": 64240,
                "Init_Win_bytes_Backward": 65535,
                "act_data_pkt_fwd": 150,
                "min_seg_size_forward": 64,
                "Active_Mean": 500000,
                "Active_Std": 250000,
                "Active_Max": 1000000,
                "Active_Min": 100000,
                "Idle_Mean": 1000000,
                "Idle_Std": 500000,
                "Idle_Max": 2000000,
                "Idle_Min": 100000
            }
        }


class SHAPFeature(BaseModel):
    """Single SHAP explanation for a feature."""
    feature: str = Field(..., description="Feature name")
    shap_value: float = Field(..., description="SHAP contribution value")


class ThreatPredictionResponse(BaseModel):
    """
    Response schema for network threat prediction.
    Classifies network connection into one of 14 attack types.
    """
    
    threat_class: str = Field(..., description="Detected attack class (BENIGN or one of 13 attack types)")
    confidence: float = Field(..., ge=0, le=1, description="Classification confidence (0-1)")
    severity: str = Field(..., description="Severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    
    # SHAP explanations
    top_features: List[SHAPFeature] = Field(..., description="Top 5 contributing features with SHAP values")
    
    # Additional context
    all_predictions: Optional[dict] = Field(None, description="Probability for each attack class (14 total)")
    flow_id: Optional[str] = Field(None, description="Reference ID for audit trail")
    timestamp: Optional[str] = Field(None, description="Prediction timestamp (ISO 8601)")

    class Config:
        schema_extra = {
            "example": {
                "threat_class": "DDoS",
                "confidence": 0.97,
                "severity": "CRITICAL",
                "top_features": [
                    {"feature": "Flow_Duration", "shap_value": 0.52},
                    {"feature": "Total_Fwd_Packets", "shap_value": 0.28},
                    {"feature": "Fwd_Packet_Length_Mean", "shap_value": 0.15},
                    {"feature": "PSH_Flag_Count", "shap_value": -0.08},
                    {"feature": "Bwd_IAT_Mean", "shap_value": -0.05}
                ],
                "all_predictions": {
                    "BENIGN": 0.001,
                    "FTP-Patator": 0.001,
                    "SSH-Patator": 0.001,
                    "DoS_Hulk": 0.02,
                    "DoS_Slowhttptest": 0.01,
                    "DoS_Slowloris": 0.015,
                    "DoS_GoldenEye": 0.02,
                    "Heartbleed": 0.001,
                    "Botnet": 0.005,
                    "Web_Attack_Brute_Force": 0.003,
                    "Web_Attack_XSS": 0.002,
                    "Web_Attack_SQL_Injection": 0.002,
                    "Infiltration": 0.001,
                    "PortScan": 0.07,
                    "DDoS": 0.97
                },
                "flow_id": "FLOW-20260508-001234",
                "timestamp": "2026-05-08T14:23:45Z"
            }
        }
