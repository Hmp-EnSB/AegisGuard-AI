# 🛡 AegisGuard — Hybrid AI Cybersecurity Platform

> **Détecter. Protéger. Blinder.**  
> AI-powered hybrid platform for Network Intrusion Detection & Financial Fraud Analysis
## 📌 Project Overview

**AegisGuard** is a real-time cybersecurity platform that combines three ML models into one unified detection system:

| Model | Dataset | Task |
|---|---|---|
| 🌲 Random Forest | CICIDS2017 | Network intrusion detection — 14 attack types |
| 💡 XGBoost | ULB/Kaggle | Financial fraud detection — binary classification |
| 🔮 Isolation Forest | Both | Zero-day anomaly detection — unsupervised |

All predictions are explained variable-by-variable via **SHAP (SHapley Additive exPlanations)**, served through a **FastAPI** backend, and visualized in an interactive **Streamlit SOC Dashboard**.

Built for the **Youth Nexus Cyber AI Challenge — 1st Edition** | ENSA Kénitra | 2026

---

## 👥 Team — Aegis AI

| Member | Role | Pillar |
|---|---|---|
| **Salma Ouaya** | Data Engineer & ML Core | D + M |
| **Hiba Chaoui** | Backend Engineer (FastAPI + XAI) | A |
| **Abdoule Hady** | Frontend & Présentation (Streamlit + Rapport) | U |

---

## ⚡ Quick Setup — Under 5 Minutes

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/AegisGuard.git
cd AegisGuard
```

### 2. Create virtual environment
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Download datasets

**CICIDS2017** (Network Intrusion):
```
https://www.unb.ca/cic/datasets/ids-2017.html
→ Download all 8 CSV files → place in data/raw/
```

**ULB Credit Card Fraud**:
```
https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud
→ Download creditcard.csv → place in data/raw/
```

### 5. Run the API
```bash
uvicorn main_api:app --reload --host 0.0.0.0 --port 8000
```
→ Swagger UI available at: `http://localhost:8000/docs`

### 6. Run the SOC Dashboard
```bash
streamlit run app/dashboard.py
```
→ Dashboard available at: `http://localhost:8501`

---

## 📁 Project Structure

```
AegisGuard/
│
├── .venv/                          # Virtual environment (not committed)
├── requirements.txt                # All dependencies
├── README.md                       # This file
├── main_api.py                     # FastAPI entrypoint
│
├── data/
│   ├── raw/
│   │   ├── creditcard.csv          # ULB Fraud dataset (150MB)
│   │   ├── Monday-WorkingHours.pcap_ISCX.csv
│   │   ├── Tuesday-WorkingHours.pcap_ISCX.csv
│   │   ├── Wednesday-WorkingHours.pcap_ISCX.csv
│   │   ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
│   │   ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
│   │   ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
│   │   ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
│   │   └── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
│   └── processed/
│       ├── fraud_train.pkl
│       ├── fraud_test.pkl
│       ├── network_train.pkl
│       └── network_test.pkl
│
├── notebooks/
│   ├── 01_eda_fraude.ipynb         # EDA — ULB fraud dataset
│   ├── 02_eda_reseau.ipynb         # EDA — CICIDS2017 network dataset
│   └── 03_model_training.ipynb     # Model training & evaluation
│
├── src/
│   ├── __init__.py
│   ├── data/
│   │   ├── loader.py               # Load & concat CSV files
│   │   └── processor.py            # SMOTE, Scaler, Encoder, clean inf/NaN
│   ├── models/
│   │   ├── fraud_model.py          # XGBoost — ULB fraud
│   │   ├── nids_model.py           # Random Forest — CICIDS2017 (14 classes)
│   │   └── anomaly.py              # Isolation Forest — zero-day detection
│   └── explain/
│       └── xai_engine.py           # SHAP TreeExplainer for RF + XGBoost
│
├── api/
│   ├── __init__.py
│   ├── core/
│   ├── schemas/
│   │   ├── fraud_schema.py         # Pydantic model: Amount, Time, V1–V28
│   │   └── nids_schema.py          # Pydantic model: 78 CICIDS2017 features
│   └── routes/
│       ├── predict_fraud.py        # POST /predict/fraud
│       └── predict_threat.py       # POST /predict/threat
│
├── app/
│   ├── dashboard.py                # Streamlit SOC Dashboard
│   ├── components/
│   └── styles/
│
├── models_saved/
│   ├── xgb_fraude.pkl              # Trained XGBoost model
│   ├── rf_nids.pkl                 # Trained Random Forest (14 classes)
│   ├── iso_forest.pkl              # Trained Isolation Forest
│   └── scaler_encoder.pkl          # StandardScaler + LabelEncoder
│
└── tests/
    ├── test_api.py                 # API endpoint tests
    └── test_models.py              # Model unit tests
```

---

## 🔌 API Endpoints

### POST `/predict/fraud`
Detect financial fraud from transaction features.

**Request body:**
```json
{
  "Amount": 9800.0,
  "Time": 54000.0,
  "V1": -1.35,
  "V2": -0.07,
  ...
  "V28": 0.02
}
```

**Response:**
```json
{
  "fraud_probability": 0.97,
  "risk_level": "HIGH",
  "decision": "BLOCKED",
  "top_features": [
    {"feature": "Amount", "shap_value": 0.43},
    {"feature": "Time", "shap_value": 0.31}
  ]
}
```

---

### POST `/predict/threat`
Classify network connection into one of 14 attack types.

**Response:**
```json
{
  "threat_class": "DDoS",
  "confidence": 0.97,
  "severity": "CRITICAL",
  "top_features": [
    {"feature": "Flow Duration", "shap_value": 0.52},
    {"feature": "Fwd Packet Length", "shap_value": 0.28}
  ]
}
```

---

### GET `/health`
```json
{
  "status": "ok",
  "models_loaded": {
    "random_forest": true,
    "xgboost": true,
    "isolation_forest": true
  }
}
```

---

## 📊 Model Performance Targets

| Model | Metric | Target |
|---|---|---|
| Random Forest (NIDS) | F1 macro | > 0.95 |
| XGBoost (Fraud) | ROC-AUC | > 0.98 |
| XGBoost (Fraud) | False positive rate | < 5% |
| FastAPI | Response latency | < 100ms |

---

## 🔍 SHAP Explainability

Every prediction returns a SHAP explanation — the exact contribution of each input feature to the decision:

```
Transaction BLOCKED — Fraud probability: 97%

Top contributing features:
  Amount       ████████████████  +0.43
  Time         ████████████      +0.31
  V14          ████████          +0.18
  V4           ██████            -0.12  (reduces fraud probability)
```

---

## ⚙️ Requirements

```
pandas>=2.0
numpy>=1.24
scikit-learn>=1.4
xgboost>=2.0
imbalanced-learn>=0.11
shap>=0.44
fastapi>=0.110
uvicorn>=0.27
pydantic>=2.5
streamlit>=1.32
plotly>=5.18
matplotlib>=3.7
seaborn>=0.12
requests>=2.31
joblib>=1.3
```

Install all:
```bash
pip install -r requirements.txt
```

---

## 🧪 Running Tests

```bash
# Test API endpoints
pytest tests/test_api.py -v

# Test model predictions
pytest tests/test_models.py -v

# Run all tests
pytest tests/ -v
```

---

## 📋 Attack Types Detected (CICIDS2017)

| Category | Attack Types |
|---|---|
| DoS | Slowloris, Slowhttptest, Hulk, GoldenEye |
| DDoS | UDP Flood |
| Brute Force | FTP-Patator, SSH-Patator |
| Web Attack | XSS, SQL Injection, Brute Force |
| Other | PortScan, Bot, Heartbleed, Infiltration |
| Normal | BENIGN traffic |

---

## 📜 Regulatory Compliance

| Standard | Coverage |
|---|---|
| **Loi 09-08 (Maroc)** | SHAP audit trail, data anonymization |
| **ISO/IEC 42001:2023** | AI transparency, human supervision |
| **GDPR (reference)** | Data minimization, right to explanation |

---

## 🗓 Key Dates

| Event | Date |
|---|---|
| Project submission | **May 15, 2026** |
| Pitch day | **May 20, 2026** |
| Location | ENSA Kénitra — Ibn Tofaïl University |

---

## 📄 License

MIT License — Open source, freely deployable.

---

*Équipe Aegis AI · ENSA Kénitra · Youth Nexus Cyber AI Challenge 2026*v
