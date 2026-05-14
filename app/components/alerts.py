import streamlit as st
import pandas as pd
from datetime import datetime

PRIORITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

SEVERITY_COLORS = {
    "LOW": "#22c55e", "MEDIUM": "#f59e0b", "HIGH": "#f97316", "CRITICAL": "#ef4444",
}

def add_alert(alert_type, severity, data):
    if "alerts" not in st.session_state:
        st.session_state.alerts = []
    st.session_state.alerts.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "data": str(data),
    })

def show_alerts():
    alerts = st.session_state.get("alerts", [])
    if not alerts:
        st.info("No alerts yet. Run predictions in the simulator tabs.")
        return

    df = pd.DataFrame(alerts)
    df["priority"] = df["severity"].map(PRIORITY_ORDER)
    df = df.sort_values("priority", ascending=False).drop(columns=["priority"])

    # Color-coded severity column
    def highlight_severity(val):
        color = SEVERITY_COLORS.get(val, "#888")
        return f"background-color: {color}22; color: {color}; font-weight: bold"

    styled = df.style.map(highlight_severity, subset=["severity"])
    st.dataframe(styled, use_container_width=True, hide_index=True)

def export_alerts():
    alerts = st.session_state.get("alerts", [])
    if not alerts:
        return
    df = pd.DataFrame(alerts)
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Export Alerts CSV",
        csv,
        f"aegisguard_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        "text/csv",
        use_container_width=True,
    )
