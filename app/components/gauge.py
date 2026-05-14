import plotly.graph_objects as go
import streamlit as st

COLOR_MAP = {
    "LOW": "#22c55e",
    "MEDIUM": "#f59e0b",
    "HIGH": "#f97316",
    "CRITICAL": "#ef4444",
}

def display_gauge(value, level):
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=round(value * 100, 1),
        number={"suffix": "%", "font": {"size": 28, "color": "#e2e8f0"}},
        title={"text": f"Risk Level: <b>{level}</b>", "font": {"size": 16, "color": "#94a3b8"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#4b5563", "tickfont": {"color": "#94a3b8"}},
            "bar": {"color": COLOR_MAP.get(level, "#6b7280"), "thickness": 0.3},
            "bgcolor": "#1e2433",
            "bordercolor": "#2d3748",
            "steps": [
                {"range": [0, 30], "color": "#0d2818"},
                {"range": [30, 60], "color": "#2d1f00"},
                {"range": [60, 85], "color": "#2d1200"},
                {"range": [85, 100], "color": "#2d0808"},
            ],
            "threshold": {
                "line": {"color": COLOR_MAP.get(level, "gray"), "width": 3},
                "thickness": 0.8,
                "value": value * 100,
            },
        },
    ))
    fig.update_layout(
        paper_bgcolor="#0e1117",
        font={"color": "#e2e8f0"},
        height=280,
        margin=dict(t=60, b=20, l=30, r=30),
    )
    st.plotly_chart(fig, use_container_width=True)
