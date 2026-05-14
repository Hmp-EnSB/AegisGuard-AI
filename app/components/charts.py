import streamlit as st
import plotly.graph_objects as go
import pandas as pd

SEVERITY_COLORS = {
    "LOW": "#22c55e", "MEDIUM": "#f59e0b", "HIGH": "#f97316", "CRITICAL": "#ef4444",
}

def show_alert_timeline():
    alerts = st.session_state.get("alerts", [])
    if len(alerts) < 2:
        return

    df = pd.DataFrame(alerts)
    df["count"] = 1

    fig = go.Figure()
    for sev, color in SEVERITY_COLORS.items():
        subset = df[df["severity"] == sev]
        if not subset.empty:
            fig.add_trace(go.Bar(
                name=sev,
                x=subset.index,
                y=subset["count"],
                marker_color=color,
                opacity=0.85,
            ))

    fig.update_layout(
        title="Alert Timeline",
        barmode="stack",
        paper_bgcolor="#0e1117",
        plot_bgcolor="#161b27",
        font=dict(color="#e2e8f0"),
        xaxis=dict(title="Event #", gridcolor="#2d3748"),
        yaxis=dict(title="Count", gridcolor="#2d3748"),
        height=300,
    )
    st.plotly_chart(fig, use_container_width=True)

def show_severity_distribution():
    alerts = st.session_state.get("alerts", [])
    if not alerts:
        return

    df = pd.DataFrame(alerts)
    dist = df["severity"].value_counts().reset_index()
    dist.columns = ["Severity", "Count"]
    colors = [SEVERITY_COLORS.get(s, "#888") for s in dist["Severity"]]

    fig = go.Figure(go.Pie(
        labels=dist["Severity"],
        values=dist["Count"],
        marker_colors=colors,
        hole=0.4,
        textfont=dict(color="#e2e8f0"),
    ))
    fig.update_layout(
        paper_bgcolor="#0e1117",
        font=dict(color="#e2e8f0"),
        height=300,
    )
    st.plotly_chart(fig, use_container_width=True)