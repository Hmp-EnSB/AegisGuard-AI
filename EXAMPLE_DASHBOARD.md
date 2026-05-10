# 🎯 Example Dashboard

## 🚀 How to run the example

### 1. Installer les dépendances
```bash
pip install streamlit requests plotly
```

### 2. Start the API (in one terminal)
```bash
py -m uvicorn main_api:app --host 127.0.0.1 --port 8000
```

### 3. Start the dashboard (in another terminal)
```bash
streamlit run example_dashboard.py
```

### 4. Open in browser
The dashboard opens automatically at: **http://localhost:8501**

---

## 📖 What the example shows

### Page 1: Fraud Detection
- Enter amount and time
- Click "Analyser la transaction"
- See fraud probability, risk level, and decision
- Gauge chart + top 5 SHAP features

### Page 2: Network Intrusion Detection
- Enter network flow data (port, duration, packets)
- Click "Analyser le flux réseau"
- See threat type (DDoS, PortScan, etc.), confidence, severity
- Gauge chart + top 5 SHAP indicators

---

## 💡 How to adapt for your dashboard

### The important code is here:

**For fraud:**
```python
response = requests.post(
    "http://localhost:8000/predict/fraud",
    json=transaction_data
)
result = response.json()
# Use result['fraud_probability'], result['risk_level'], etc.
```

**For threats:**
```python
response = requests.post(
    "http://localhost:8000/predict/threat",
    json=network_flow_data
)
result = response.json()
# Use result['threat_class'], result['confidence'], etc.
```

---

## 🎨 Ideas for your final dashboard

1. **Home page** - Global statistics
2. **Fraud detection** - Form + results
3. **Intrusion detection** - Form + results
4. **History** - List of recent detections
5. **Charts** - Evolution over time
6. **Alerts** - Real-time notifications

---

## ❓ Common issues

**"Connection refused"**
→ API is not running. Start it: `py -m uvicorn main_api:app --host 127.0.0.1 --port 8000`

**"Timeout"**
→ API is taking too long. Check that it's running correctly.

**"422 Unprocessable Entity"**
→ Missing fields in request. Check that you're sending all features.

---

## 📞 Questions?

Check the API documentation at **http://localhost:8000/docs** when the API is running! 🚀
