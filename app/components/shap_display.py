import streamlit as st
import plotly.graph_objects as go

def display_shap(features):
    if not features:
        return

    st.markdown("#### 🔍 SHAP Top Feature Contributions")

    feats = [f["feature"] for f in features]
    vals = [f["shap_value"] for f in features]

    fig = go.Figure(go.Bar(
        x=vals,
        y=feats,
        orientation="h",
        marker=dict(
            color=["#ef4444" if v > 0 else "#22c55e" for v in vals],
            opacity=0.85,
            line=dict(width=0),
        ),
        text=[f"{v:+.4f}" for v in vals],
        textposition="outside",
        textfont=dict(color="#94a3b8", size=11),
    ))

    fig.update_layout(
        paper_bgcolor="#0e1117",
        plot_bgcolor="#161b27",
        font=dict(color="#e2e8f0", size=12),
        xaxis=dict(
            title="SHAP Value (impact on prediction)",
            gridcolor="#2d3748",
            zerolinecolor="#4b5563",
            tickfont=dict(color="#94a3b8"),
        ),
        yaxis=dict(
            autorange="reversed",
            tickfont=dict(color="#cbd5e1"),
        ),
        height=max(250, len(features) * 38),
        margin=dict(t=20, b=40, l=10, r=80),
        bargap=0.3,
    )

    st.plotly_chart(fig, use_container_width=True)

    # Inline text fallback
    with st.expander("📋 Raw SHAP Values", expanded=False):
        for f in features:
            val = f["shap_value"]
            color = "#ef4444" if val > 0 else "#22c55e"
            direction = "↑ increases risk" if val > 0 else "↓ decreases risk"
            st.markdown(
                f"**{f['feature']}** → "
                f"<span style='color:{color}; font-weight:bold'>{val:+.4f}</span> "
                f"<span style='color:#6b7280; font-size:0.85em'>{direction}</span>",
                unsafe_allow_html=True,
            )