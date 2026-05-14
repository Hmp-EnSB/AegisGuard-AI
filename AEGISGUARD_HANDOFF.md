# AegisGuard — Backend Handoff & Dashboard Integration Guide

> **Status:** Backend pillar complete · 20/20 tests passing · API live  
> **Date:** May 2026 · Youth Nexus Cyber AI Challenge · ENSA Kénitra

---

## What Was Built — Backend Pillar (Complete)

The entire FastAPI backend has been built, tested, and verified with Salma's real trained models. Here is everything that is now running and ready.

### Files Delivered

```
api/
├── core/model_loader.py        — loads 6 pkl files at startup, caches in memory
├── schemas/fraud_schema.py     — Pydantic model: 30 fraud features + output schema
├── schemas/nids_schema.py      — Pydantic model: 78 CICIDS2017 features + output schema
└── routes/
    ├── predict_fraud.py        — POST /predict/fraud
    └── predict_threat.py       — POST /predict/threat

main_api.py                     — FastAPI entrypoint with lifespan + health check
src/explain/xai_engine.py       — Real SHAP TreeExplainer (Salma's implementation, fixed)
tests/test_api.py               — 20/20 automated pytest suite
```

### Models Loaded at Runtime

| File | Type | Features | Status |
|---|---|---|---|
| `xgb_fraude.pkl` | XGBClassifier | 30 | ✅ Verified |
| `rf_nids.pkl` | RandomForestClassifier | 77 | ✅ Verified |
| `iso_forest.pkl` | IsolationForest | 77 | ✅ Verified |
| `scaler_fraude.pkl` | StandardScaler | 2 (Amount + Time) | ✅ Verified |
| `scaler_reseau.pkl` | StandardScaler | 77 | ✅ Verified |
| `label_encoder_cicids.pkl` | LabelEncoder | 14 classes | ✅ Verified |

### API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Welcome message |
| `GET` | `/health` | Model loading status |
| `POST` | `/predict/fraud` | Financial fraud detection |
| `POST` | `/predict/threat` | Network intrusion detection |
| `GET` | `/docs` | Swagger UI — interactive docs |

### Test Results

```
pytest tests/test_api.py -v
================================================= 20 passed in 6.47s ==
```

All 20 tests green covering: health check, root, fraud valid/invalid payloads,
fraud schema validation, threat valid/invalid payloads, threat schema validation,
422 error handling for missing and malformed inputs.

---

## How to Start the API

```bash
# Step 1 — activate the virtual environment
.venv\Scripts\activate

# Step 2 — start the server
uvicorn main_api:app --reload --host 0.0.0.0 --port 8000
```

Watch for these confirmation lines in the terminal:

```
[STARTUP] Loading models...
[OK] Loaded 6 models from .../models_saved
[OK] All models loaded successfully
INFO:     Application startup complete.
```

Swagger UI is then available at: **http://localhost:8000/docs**

---

## What the Dashboard Developer Needs to Know

The dashboard is built with Streamlit and communicates with the API over HTTP.
The API must be running before the dashboard is started.

### Startup Order (non-negotiable)

```
Terminal 1 → uvicorn main_api:app --reload --host 127.0.0.1 --port 8000
Terminal 2 → streamlit run app/dashboard.py
```

If the API is not running, every button in the dashboard will throw a connection error.

---

### Calling the API from Streamlit

#### Fraud Detection

```python
import requests

payload = {
    "Time": 54000.0,
    "Amount": 9800.0,
    "V1": -1.35, "V2": 0.5, "V3": 1.2, "V4": -0.8,
    # ... all 30 features
}

response = requests.post("http://localhost:8000/predict/fraud", json=payload, timeout=5)
result = response.json()
```

**Fields available in `result`:**

| Field | Type | Description |
|---|---|---|
| `fraud_probability` | float 0–1 | Raw XGBoost probability |
| `risk_level` | str | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `decision` | str | `LEGITIMATE` or `FRAUD` |
| `is_anomaly` | bool | Isolation Forest flag |
| `anomaly_score` | float | Isolation Forest score |
| `top_features` | list | `[{"feature": "Amount", "shap_value": 0.43}, ...]` |

#### Network Intrusion Detection

```python
payload = {
    "features": {
        "Destination Port": 80,
        "Flow Duration": 120000,
        "Total Fwd Packets": 1500,
        # ... all 77 features
    }
}

response = requests.post("http://localhost:8000/predict/threat", json=payload, timeout=5)
result = response.json()
```

**Fields available in `result`:**

| Field | Type | Description |
|---|---|---|
| `threat_class` | str | e.g. `DDoS`, `FTP-Patator`, `BENIGN` |
| `confidence` | float 0–1 | Random Forest class probability |
| `severity` | str | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `is_anomaly` | bool | Isolation Forest flag |
| `anomaly_score` | float | Isolation Forest score |
| `top_features` | list | `[{"feature": "Flow Duration", "shap_value": 0.52}, ...]` |

#### Health Check

```python
response = requests.get("http://localhost:8000/health")
# Use this to verify the API is up before rendering any UI
```

---

### Dashboard Tabs to Build

#### Tab 1 — Fraud Simulator
- Input form: `Amount` (number input), `Time` (slider), `V1`–`V28` (sliders or number inputs)
- On submit: `POST /predict/fraud`
- Display: Plotly gauge for `fraud_probability`, colored badge for `risk_level`, FRAUD/LEGITIMATE banner, SHAP bar chart from `top_features`

#### Tab 2 — Network Simulator
- Input form: dropdowns/sliders for key features (Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets)
- Default values pre-filled for the other 73 features
- On submit: `POST /predict/threat`
- Display: attack class label with icon, severity badge, confidence gauge, SHAP waterfall from `top_features`

#### Tab 3 — SHAP Visualizations
- Plotly bar chart (waterfall style) using `top_features` from the last prediction
- Static ROC-AUC chart using model performance targets as reference data
- Beeswarm style: run multiple predictions and accumulate SHAP values

#### Tab 4 — SOC Alert Panel
- Append each prediction call to `st.session_state` list
- Display as a color-coded table: CRITICAL = red, HIGH = orange, MEDIUM = yellow, LOW = green
- CSV export button using `st.download_button`

---

### Severity Color Mapping

```python
SEVERITY_COLORS = {
    "LOW":      "#22c55e",   # green
    "MEDIUM":   "#f59e0b",   # amber
    "HIGH":     "#f97316",   # orange
    "CRITICAL": "#ef4444",   # red
}
```

### Attack Class Icons

```python
THREAT_ICONS = {
    "BENIGN":              "✅",
    "DDoS":                "🔴",
    "PortScan":            "🔍",
    "Bot":                 "🤖",
    "DoS Hulk":            "💥",
    "DoS GoldenEye":       "💥",
    "DoS slowloris":       "💥",
    "DoS Slowhttptest":    "💥",
    "FTP-Patator":         "🔑",
    "SSH-Patator":         "🔑",
    "Web Attack Brute Force": "🌐",
    "Web Attack XSS":      "🌐",
    "Web Attack Sql Injection": "🌐",
    "Heartbleed":          "💔",
    "Infiltration":        "👤",
}
```

---

### Error Handling in the Dashboard

```python
try:
    response = requests.post(url, json=payload, timeout=5)
    if response.status_code == 200:
        result = response.json()
        # render results
    elif response.status_code == 422:
        st.error("Invalid input — check all required fields are filled.")
    else:
        st.error(f"API error {response.status_code}")

except requests.exceptions.ConnectionError:
    st.error("❌ Cannot connect to API. Start the API first: uvicorn main_api:app --reload")
except requests.exceptions.Timeout:
    st.error("⏱️ API timeout — check the server is running correctly.")
```

---

### Sample Payloads for Testing

**High-risk fraud transaction:**
```json
{
  "Time": 54000.0, "Amount": 9800.0,
  "V1": -1.35, "V2": -0.07, "V3": 2.54, "V4": 1.38,
  "V5": -0.34, "V6": -0.50, "V7": 1.80, "V8": -0.29,
  "V9": 0.29, "V10": -0.82, "V11": 0.97, "V12": -0.28,
  "V13": -0.20, "V14": -1.11, "V15": 0.14, "V16": -0.45,
  "V17": -0.24, "V18": 0.10, "V19": 0.35, "V20": 0.06,
  "V21": 0.19, "V22": 0.21, "V23": -0.01, "V24": 0.22,
  "V25": 0.02, "V26": 0.20, "V27": 0.01, "V28": 0.01
}
```

**DDoS-like network flow:**
```json
{
  "features": {
    "Destination Port": 80, "Flow Duration": 120000,
    "Total Fwd Packets": 1500, "Total Backward Packets": 50,
    "SYN Flag Count": 1500, "ACK Flag Count": 50,
    "Flow Bytes/s": 750, "Flow Packets/s": 12.5
  }
}
```
*(Fill remaining features with 0 — the API accepts partial feature dicts with defaults)*

---

## Key Dates

| Event | Date |
|---|---|
| Submission deadline | **May 15, 2026** |
| Pitch day | **May 20, 2026** |
| Location | ENSA Kénitra — Ibn Tofaïl University |

---

*AegisGuard · Aegis AI Team · ENSA Kénitra · Youth Nexus Cyber AI Challenge 2026*
