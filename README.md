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
| **Abdoule Hady** | Frontend Engineer (Streamlit + Rapport) | U |

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
│   │   └── CICIDS2017 8 CSV files
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
│   ├── data/
│   │   ├── loader.py               # Load & concat CSV files
│   │   └── processor.py            # SMOTE, Scaler, Encoder, clean inf/NaN
│   ├── models/
│   │   ├── fraud_model.py          # XGBoost — ULB fraud
│   │   ├── nids_model.py           # Random Forest — CICIDS2017
│   │   └── anomaly.py              # Isolation Forest
│   └── explain/
│       └── xai_engine.py           # SHAP TreeExplainer
│
├── api/
│   ├── core/
│   │   ├── config.py               # Configuration
│   │   └── model_loader.py         # Model loading logic
│   ├── schemas/
│   │   ├── fraud_schema.py         # Pydantic: Transaction input/output
│   │   └── nids_schema.py          # Pydantic: NetworkFlow input/output
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
│   ├── xgb_fraude.pkl              # Trained XGBoost
│   ├── rf_nids.pkl                 # Trained Random Forest
│   ├── iso_forest.pkl              # Trained Isolation Forest
│   ├── scaler_fraude.pkl           # StandardScaler
│   ├── scaler_reseau.pkl           # StandardScaler
│   └── label_encoder_cicids.pkl    # LabelEncoder
│
└── tests/
    ├── test_api.py                 # API tests
    └── test_models.py              # Model tests
```

---

## 🔌 API Endpoints

### `GET /health`
Health check — returns model loading status.

### `POST /predict/fraud`
**TBD by Hiba** — Detect financial fraud.

Request:
```json
{
  "Amount": 9800.0,
  "Time": 54000.0,
  "V1": -1.35,
  ...
  "V28": 0.02
}
```

### `POST /predict/threat`
**TBD by Hiba** — Classify network attack.

Response includes: threat class, confidence, SHAP explanations.

---

## 📊 Model Performance Targets

| Model | Metric | Target |
|---|---|---|
| Random Forest (NIDS) | F1 macro | > 0.95 |
| XGBoost (Fraud) | ROC-AUC | > 0.98 |

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
```

---

## 🧪 Running Tests

```bash
pytest tests/test_api.py -v
pytest tests/test_models.py -v
pytest tests/ -v
```

---

## 📜 Regulatory Compliance

| Standard | Coverage |
|---|---|
| **Loi 09-08 (Maroc)** | SHAP audit trail, data anonymization |
| **ISO/IEC 42001:2023** | AI transparency, human supervision |
| **GDPR (reference)** | Data minimization, right to explanation |

---

*Équipe Aegis AI · ENSA Kénitra · Youth Nexus Cyber AI Challenge 2026*
