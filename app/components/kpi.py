import streamlit as st

def show_kpis():
    alerts = st.session_state.get("alerts", [])

    total = len(alerts)
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")

    col1, col2 = st.columns(2)

    col1.metric("Total Alerts", total)
    col2.metric("Critical Alerts", critical)