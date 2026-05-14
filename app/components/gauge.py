import plotly.graph_objects as go
import streamlit as st

COLOR_MAP = {
    "LOW": "green",
    "MEDIUM": "orange",
    "HIGH": "red",
    "CRITICAL": "purple"
}

def display_gauge(value, level):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value * 100,
        title={'text': f"Risk: {level}"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': COLOR_MAP.get(level, "gray")}
        }
    ))

    st.plotly_chart(fig, use_container_width=True)