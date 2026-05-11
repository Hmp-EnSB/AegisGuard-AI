# 🚀 Hiba's FastAPI Backend — Quick Start

## ✅ All 6 Tasks Complete

| Task | File | Status |
|------|------|--------|
| 10 | `api/schemas/fraud_schema.py` | ✅ Done |
| 11 | `api/schemas/nids_schema.py` | ✅ Done |
| 12 | `api/core/model_loader.py` | ✅ Done |
| 13 | `api/routes/predict_fraud.py` | ✅ Done |
| 14 | `api/routes/predict_threat.py` | ✅ Done |
| 15 | `main_api.py` | ✅ Done |
| 20 | `tests/test_api.py` | ✅ Done |

---

## 🧪 Test Right Now (No Waiting for Salma)

### Step 1: Generate dummy models
```bash
python generate_dummy_models.py
```
This creates 6 dummy pkl files in `models_saved/` so you can test the full API.

### Step 2: Start the API
```bash
uvicorn main_api:app --reload --host 0.0.0.0 --port 8000
```

### Step 3: Open Swagger UI
Go to: **http://localhost:8000/docs**

You'll see:
- `GET /health` — check model loading status
- `POST /predict/fraud` — test fraud detection
- `POST /predict/threat` — test network intrusion detection

### Step 4: Test fraud endpoint
Click **POST /predict/fraud** → Try it out → paste this:
```json
{
  "Time": 54000.0,
  "Amount": 9800.0,
  "V1": -1.35, "V2": 0.5, "V3": 1.2, "V4": -0.8,
  "V5": 0.3, "V6": -0.6, "V7": 0.9, "V8": 0.1,
  "V9": -0.4, "V10": 0.7, "V11": -0.2, "V12": 0.5,
  "V13": 0.8, "V14": -0.3, "V15": 0.6, "V16": -0.1,
  "V17": 0.4, "V18": -0.7, "V19": 0.2, "V20": 0.9,
  "V21": -0.5, "V22": 0.3, "V23": -0.8, "V24": 0.1,
  "V25": 0.6, "V26": -0.4, "V27": 0.7, "V28": 0.02
}
```

### Step 5: Run tests
```bash
pytest tests/test_api.py -v
```

---

## 🔄 When Salma's Real Models Are Ready

1. **Replace pkl files**: Copy her 6 pkl files from `models_saved/` into your `models_saved/`
2. **Update xai_engine.py**: Replace `src/explain/xai_engine.py` with her real SHAP implementation
3. **Restart API**: `uvicorn main_api:app --reload`
4. **Re-run tests**: `pytest tests/test_api.py -v`

That's it. Zero code changes needed in your API files.

---

## 📋 What to Confirm with Salma

1. **SHAP function names**: Confirm she uses `explain_fraud(X)` and `explain_network(X, predicted_class)`
2. **Scaler coverage**: 
   - `scaler_fraude` only scales Amount + Time (not V1-V28)
   - `scaler_reseau` scales all 78 features
3. **Label encoder**: Confirm the 14 class names match the SEVERITY_MAP in `predict_threat.py`

---

## 🎯 Your API Endpoints

### `GET /health`
Returns model loading status.

### `POST /predict/fraud`
**Input**: 30 features (Time, Amount, V1-V28)  
**Output**: fraud_probability, risk_level, decision, is_anomaly, top_features

### `POST /predict/threat`
**Input**: 78 CICIDS features as dict  
**Output**: threat_class, confidence, severity, is_anomaly, top_features

---

## 🐛 Troubleshooting

**Models not loading?**
- Check `models_saved/` has all 6 pkl files
- Run `python generate_dummy_models.py` to create test files

**Import errors?**
- Make sure all `__init__.py` files exist in `api/`, `api/core/`, `api/schemas/`, `api/routes/`

**Tests failing?**
- Start the API first: `uvicorn main_api:app --reload`
- Then run: `pytest tests/test_api.py -v`

---

**Your backend pillar is complete and ready to demo! 🎉**
