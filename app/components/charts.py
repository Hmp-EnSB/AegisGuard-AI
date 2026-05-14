import streamlit as st
import pandas as pd

def show_charts():
    alerts = st.session_state.get("alerts", [])

    if not alerts:
        return

    df = pd.DataFrame(alerts)

    st.subheader("Alerts Distribution")
    st.bar_chart(df["severity"].value_counts())