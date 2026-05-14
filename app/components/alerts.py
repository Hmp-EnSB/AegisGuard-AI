import streamlit as st
import pandas as pd
from datetime import datetime

PRIORITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

def add_alert(alert_type, severity, data):
    if "alerts" not in st.session_state:
        st.session_state.alerts = []

    st.session_state.alerts.append({
        "time": datetime.now(),
        "type": alert_type,
        "severity": severity,
        "data": data
    })

def show_alerts():
    alerts = st.session_state.get("alerts", [])

    if not alerts:
        st.info("No alerts yet")
        return

    df = pd.DataFrame(alerts)

    df["priority"] = df["severity"].map(PRIORITY_ORDER)
    df = df.sort_values("priority", ascending=False)

    st.dataframe(df.drop(columns=["priority"]), use_container_width=True)

def export_alerts():
    alerts = st.session_state.get("alerts", [])

    if not alerts:
        return

    df = pd.DataFrame(alerts)
    csv = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        "📥 Export Alerts CSV",
        csv,
        "alerts.csv",
        "text/csv"
    )