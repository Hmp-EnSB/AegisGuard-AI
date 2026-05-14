import streamlit as st

SEVERITY_COLORS = {
    "LOW": "#22c55e", "MEDIUM": "#f59e0b", "HIGH": "#f97316", "CRITICAL": "#ef4444",
}

def show_kpis():
    alerts = st.session_state.get("alerts", [])

    total = len(alerts)
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    high = sum(1 for a in alerts if a["severity"] == "HIGH")
    fraud_count = sum(1 for a in alerts if a["type"] == "FRAUD")
    threat_count = sum(1 for a in alerts if a["type"] == "THREAT")

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Detections", total)
    col2.metric("🔴 Critical", critical, delta=None)
    col3.metric("🟠 High Severity", high)
    col4.metric("💳 Fraud Alerts", fraud_count)
    col5.metric("🌐 Network Threats", threat_count)