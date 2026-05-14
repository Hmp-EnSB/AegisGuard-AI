import streamlit as st
import requests
import numpy as np
from datetime import datetime

from app.components.gauge import display_gauge
from app.components.shap_display import display_shap
from app.components.alerts import add_alert, show_alerts, export_alerts
from app.components.kpi import show_kpis
from app.components.charts import show_charts
from app.utils.generator import generate_network_flow

API_URL = "http://127.0.0.1:8000"

st.set_page_config(page_title="AegisGuard SOC", layout="wide")

# ---------------- SIDEBAR ----------------
st.sidebar.title("🛡️ AegisGuard")
page = st.sidebar.radio(
    "Navigation",
    ["Fraud Detection", "Network Intrusion", "SOC Analytics"]
)

# ---------------- HEALTH ----------------
try:
    health = requests.get(f"{API_URL}/health").json()
    if health["status"] == "healthy":
        st.sidebar.success("🟢 API OK")
    else:
        st.sidebar.error("🔴 API ERROR")
except:
    st.sidebar.error("🔴 API DOWN")

# ---------------- FRAUD ----------------
if page == "Fraud Detection":
    st.title("💳 Fraud Detection")

    col1, col2 = st.columns(2)

    with col1:
        amount = st.number_input("Amount", 0.0, 10000.0, 500.0)
        time = st.number_input("Time", 0.0, 100000.0, 50000.0)

        if st.button("🎲 Randomize V Features"):
            st.session_state.v_values = np.random.normal(0, 1, 28)

        if "v_values" not in st.session_state:
            st.session_state.v_values = np.zeros(28)

        v_vals = []
        for i in range(28):
            val = st.number_input(
                f"V{i+1}",
                value=float(st.session_state.v_values[i]),
                key=f"v_{i}"
            )
            v_vals.append(val)

        if st.button("🚀 Predict Fraud"):
            payload = {
                "Time": time,
                "Amount": amount,
                **{f"V{i+1}": v_vals[i] for i in range(28)}
            }

            res = requests.post(f"{API_URL}/predict/fraud", json=payload)

            if res.status_code == 200:
                data = res.json()

                display_gauge(data["fraud_probability"], data["risk_level"])
                st.subheader(f"Decision: {data['decision']}")

                display_shap(data["top_features"])

                add_alert("FRAUD", data["risk_level"], data)

    with col2:
        st.info("Simulate and detect fraudulent transactions")

# ---------------- NETWORK ----------------
elif page == "Network Intrusion":
    st.title("🌐 Network Intrusion Detection")

    if st.button("🎲 Simulate Network Flow"):
        flow = generate_network_flow()

        res = requests.post(
            f"{API_URL}/predict/threat",
            json={"features": flow}
        )

        if res.status_code == 200:
            data = res.json()

            display_gauge(data["confidence"], data["severity"])
            st.subheader(f"Attack: {data['threat_class']}")
            st.write(f"Anomaly: {data['is_anomaly']}")

            display_shap(data["top_features"])

            add_alert("NETWORK", data["severity"], data)

# ---------------- ANALYTICS ----------------
elif page == "SOC Analytics":
    st.title("📊 SOC Analytics")

    show_kpis()
    show_charts()
    show_alerts()
    export_alerts()