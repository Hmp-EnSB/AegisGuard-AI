# Sample API Payloads for Testing

## Fraud Detection — POST /predict/fraud

### Sample 1: High-value transaction
```json
{
  "Time": 54000.0,
  "Amount": 9800.0,
  "V1": -1.35,
  "V2": 0.5,
  "V3": 1.2,
  "V4": -0.8,
  "V5": 0.3,
  "V6": -0.6,
  "V7": 0.9,
  "V8": 0.1,
  "V9": -0.4,
  "V10": 0.7,
  "V11": -0.2,
  "V12": 0.5,
  "V13": 0.8,
  "V14": -0.3,
  "V15": 0.6,
  "V16": -0.1,
  "V17": 0.4,
  "V18": -0.7,
  "V19": 0.2,
  "V20": 0.9,
  "V21": -0.5,
  "V22": 0.3,
  "V23": -0.8,
  "V24": 0.1,
  "V25": 0.6,
  "V26": -0.4,
  "V27": 0.7,
  "V28": 0.02
}
```

### Sample 2: Low-value transaction
```json
{
  "Time": 12000.0,
  "Amount": 25.50,
  "V1": 0.1,
  "V2": -0.2,
  "V3": 0.3,
  "V4": 0.15,
  "V5": -0.05,
  "V6": 0.25,
  "V7": -0.1,
  "V8": 0.08,
  "V9": 0.12,
  "V10": -0.18,
  "V11": 0.22,
  "V12": -0.14,
  "V13": 0.19,
  "V14": 0.11,
  "V15": -0.09,
  "V16": 0.16,
  "V17": -0.13,
  "V18": 0.21,
  "V19": -0.07,
  "V20": 0.14,
  "V21": 0.09,
  "V22": -0.11,
  "V23": 0.17,
  "V24": -0.06,
  "V25": 0.13,
  "V26": 0.08,
  "V27": -0.15,
  "V28": 0.05
}
```

---

## Network Intrusion — POST /predict/threat

### Sample 1: Minimal payload (all features = 0.5)
```json
{
  "features": {
    "Destination Port": 0.5,
    "Flow Duration": 0.5,
    "Total Fwd Packets": 0.5,
    "Total Backward Packets": 0.5,
    "Total Length of Fwd Packets": 0.5,
    "Total Length of Bwd Packets": 0.5,
    "Fwd Packet Length Max": 0.5,
    "Fwd Packet Length Min": 0.5,
    "Fwd Packet Length Mean": 0.5,
    "Fwd Packet Length Std": 0.5,
    "Bwd Packet Length Max": 0.5,
    "Bwd Packet Length Min": 0.5,
    "Bwd Packet Length Mean": 0.5,
    "Bwd Packet Length Std": 0.5,
    "Flow Bytes/s": 0.5,
    "Flow Packets/s": 0.5,
    "Flow IAT Mean": 0.5,
    "Flow IAT Std": 0.5,
    "Flow IAT Max": 0.5,
    "Flow IAT Min": 0.5,
    "Fwd IAT Total": 0.5,
    "Fwd IAT Mean": 0.5,
    "Fwd IAT Std": 0.5,
    "Fwd IAT Max": 0.5,
    "Fwd IAT Min": 0.5,
    "Bwd IAT Total": 0.5,
    "Bwd IAT Mean": 0.5,
    "Bwd IAT Std": 0.5,
    "Bwd IAT Max": 0.5,
    "Bwd IAT Min": 0.5,
    "Fwd PSH Flags": 0.5,
    "Bwd PSH Flags": 0.5,
    "Fwd URG Flags": 0.5,
    "Bwd URG Flags": 0.5,
    "Fwd Header Length": 0.5,
    "Bwd Header Length": 0.5,
    "Fwd Packets/s": 0.5,
    "Bwd Packets/s": 0.5,
    "Min Packet Length": 0.5,
    "Max Packet Length": 0.5,
    "Packet Length Mean": 0.5,
    "Packet Length Std": 0.5,
    "Packet Length Variance": 0.5,
    "FIN Flag Count": 0.5,
    "SYN Flag Count": 0.5,
    "RST Flag Count": 0.5,
    "PSH Flag Count": 0.5,
    "ACK Flag Count": 0.5,
    "URG Flag Count": 0.5,
    "CWE Flag Count": 0.5,
    "ECE Flag Count": 0.5,
    "Down/Up Ratio": 0.5,
    "Average Packet Size": 0.5,
    "Avg Fwd Segment Size": 0.5,
    "Avg Bwd Segment Size": 0.5,
    "Fwd Header Length.1": 0.5,
    "Fwd Avg Bytes/Bulk": 0.5,
    "Fwd Avg Packets/Bulk": 0.5,
    "Fwd Avg Bulk Rate": 0.5,
    "Bwd Avg Bytes/Bulk": 0.5,
    "Bwd Avg Packets/Bulk": 0.5,
    "Bwd Avg Bulk Rate": 0.5,
    "Subflow Fwd Packets": 0.5,
    "Subflow Fwd Bytes": 0.5,
    "Subflow Bwd Packets": 0.5,
    "Subflow Bwd Bytes": 0.5,
    "Init_Win_bytes_forward": 0.5,
    "Init_Win_bytes_backward": 0.5,
    "act_data_pkt_fwd": 0.5,
    "min_seg_size_forward": 0.5,
    "Active Mean": 0.5,
    "Active Std": 0.5,
    "Active Max": 0.5,
    "Active Min": 0.5,
    "Idle Mean": 0.5,
    "Idle Std": 0.5,
    "Idle Max": 0.5,
    "Idle Min": 0.5
  }
}
```

### Sample 2: Realistic DDoS-like pattern
```json
{
  "features": {
    "Destination Port": 80,
    "Flow Duration": 120000,
    "Total Fwd Packets": 1500,
    "Total Backward Packets": 50,
    "Total Length of Fwd Packets": 90000,
    "Total Length of Bwd Packets": 3000,
    "Fwd Packet Length Max": 1500,
    "Fwd Packet Length Min": 40,
    "Fwd Packet Length Mean": 60,
    "Fwd Packet Length Std": 15,
    "Bwd Packet Length Max": 100,
    "Bwd Packet Length Min": 40,
    "Bwd Packet Length Mean": 60,
    "Bwd Packet Length Std": 10,
    "Flow Bytes/s": 750,
    "Flow Packets/s": 12.5,
    "Flow IAT Mean": 80,
    "Flow IAT Std": 20,
    "Flow IAT Max": 500,
    "Flow IAT Min": 10,
    "Fwd IAT Total": 120000,
    "Fwd IAT Mean": 80,
    "Fwd IAT Std": 20,
    "Fwd IAT Max": 500,
    "Fwd IAT Min": 10,
    "Bwd IAT Total": 120000,
    "Bwd IAT Mean": 2400,
    "Bwd IAT Std": 500,
    "Bwd IAT Max": 5000,
    "Bwd IAT Min": 100,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 30000,
    "Bwd Header Length": 1000,
    "Fwd Packets/s": 12.5,
    "Bwd Packets/s": 0.4,
    "Min Packet Length": 40,
    "Max Packet Length": 1500,
    "Packet Length Mean": 60,
    "Packet Length Std": 15,
    "Packet Length Variance": 225,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1500,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 50,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 30,
    "Average Packet Size": 60,
    "Avg Fwd Segment Size": 60,
    "Avg Bwd Segment Size": 60,
    "Fwd Header Length.1": 30000,
    "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0,
    "Fwd Avg Bulk Rate": 0,
    "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0,
    "Bwd Avg Bulk Rate": 0,
    "Subflow Fwd Packets": 1500,
    "Subflow Fwd Bytes": 90000,
    "Subflow Bwd Packets": 50,
    "Subflow Bwd Bytes": 3000,
    "Init_Win_bytes_forward": 8192,
    "Init_Win_bytes_backward": 8192,
    "act_data_pkt_fwd": 1500,
    "min_seg_size_forward": 20,
    "Active Mean": 1000,
    "Active Std": 200,
    "Active Max": 2000,
    "Active Min": 500,
    "Idle Mean": 100,
    "Idle Std": 20,
    "Idle Max": 200,
    "Idle Min": 50
  }
}
```

---

## How to Use

1. Copy one of the payloads above
2. Go to http://localhost:8000/docs
3. Click on the endpoint you want to test
4. Click "Try it out"
5. Paste the payload
6. Click "Execute"
7. See the response below

---

## Expected Response Format

### Fraud Response
```json
{
  "fraud_probability": 0.85,
  "risk_level": "HIGH",
  "decision": "FRAUD",
  "is_anomaly": true,
  "anomaly_score": -0.15,
  "top_features": [
    ["V14", 0.42],
    ["Amount", 0.38],
    ["V10", -0.31],
    ["V12", 0.28],
    ["V4", -0.25]
  ]
}
```

### Threat Response
```json
{
  "threat_class": "DDoS",
  "confidence": 0.92,
  "severity": "CRITICAL",
  "is_anomaly": false,
  "anomaly_score": 0.05,
  "top_features": [
    ["Flow Packets/s", 0.65],
    ["Total Fwd Packets", 0.58],
    ["SYN Flag Count", 0.52],
    ["Down/Up Ratio", 0.48],
    ["Flow Duration", -0.42]
  ]
}
```
