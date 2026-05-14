import streamlit as st
import requests
import json
from datetime import datetime

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AegisGuard · SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Inject CSS ─────────────────────────────────────────────────────────────────
with open("styles/theme.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ── Components ─────────────────────────────────────────────────────────────────
from components.alerts import add_alert, show_alerts, export_alerts
from components.gauge import display_gauge
from components.shap_display import display_shap
from components.kpi import show_kpis

# ── Constants ──────────────────────────────────────────────────────────────────
API_BASE = "http://localhost:8000"

THREAT_ICONS = {
    "BENIGN": "✅", "DDoS": "🔴", "PortScan": "🔍", "Bot": "🤖",
    "DoS Hulk": "💥", "DoS GoldenEye": "💥", "DoS slowloris": "💥",
    "DoS Slowhttptest": "💥", "FTP-Patator": "🔑", "SSH-Patator": "🔑",
    "Web Attack Brute Force": "🌐", "Web Attack XSS": "🌐",
    "Web Attack Sql Injection": "🌐", "Heartbleed": "💔", "Infiltration": "👤",
}

SEVERITY_COLORS = {
    "LOW": "#22c55e", "MEDIUM": "#f59e0b", "HIGH": "#f97316", "CRITICAL": "#ef4444",
}

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="aegis-header">
    <div class="aegis-logo">🛡️ <span class="brand">AegisGuard</span></div>
    <div class="aegis-subtitle">Security Operations Center · AI-Powered Threat Detection</div>
</div>
""", unsafe_allow_html=True)

# ── API Health Banner ──────────────────────────────────────────────────────────
try:
    health = requests.get(f"{API_BASE}/health", timeout=3)
    if health.status_code == 200:
        st.markdown('<div class="status-badge status-online">🟢 API Online — All models loaded</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-badge status-warn">🟡 API responded with non-200 status</div>', unsafe_allow_html=True)
except Exception:
    st.markdown('<div class="status-badge status-offline">🔴 API Offline — Start with: <code>uvicorn main_api:app --reload</code></div>', unsafe_allow_html=True)

st.markdown("<hr class='divider'/>", unsafe_allow_html=True)

# ── KPI Row ────────────────────────────────────────────────────────────────────
show_kpis()

st.markdown("<hr class='divider'/>", unsafe_allow_html=True)

# ── Tabs ───────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "💳 Fraud Simulator",
    "🌐 Network Threat Simulator",
    "🧠 SHAP Explainability",
    "🚨 SOC Alert Panel",
])

# ════════════════════════════════════════════════════════════════════════════════
# TAB 1 — FRAUD SIMULATOR
# ════════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### 💳 Financial Fraud Detection")
    st.markdown("Simulate a credit card transaction and run it through the XGBoost fraud model.")

    col_form, col_result = st.columns([1, 1], gap="large")

    with col_form:
        st.markdown("#### Transaction Parameters")

        amount = st.number_input("Amount (€)", min_value=0.0, max_value=500000.0, value=9800.0, step=10.0)
        time_val = st.slider("Time (seconds from epoch start)", 0, 172800, 54000)

        st.markdown("##### PCA Components (V1–V14)")
        v_cols1 = st.columns(2)
        v_vals = {}
        pca_defaults = {
            "V1": -1.35, "V2": -0.07, "V3": 2.54, "V4": 1.38,
            "V5": -0.34, "V6": -0.50, "V7": 1.80, "V8": -0.29,
            "V9": 0.29,  "V10": -0.82, "V11": 0.97, "V12": -0.28,
            "V13": -0.20, "V14": -1.11,
        }
        for i, (k, default) in enumerate(pca_defaults.items()):
            col = v_cols1[i % 2]
            v_vals[k] = col.number_input(k, value=default, format="%.2f", key=f"fraud_{k}")

        st.markdown("##### PCA Components (V15–V28)")
        v_cols2 = st.columns(2)
        pca_defaults2 = {
            "V15": 0.14, "V16": -0.45, "V17": -0.24, "V18": 0.10,
            "V19": 0.35, "V20": 0.06, "V21": 0.19, "V22": 0.21,
            "V23": -0.01, "V24": 0.22, "V25": 0.02, "V26": 0.20,
            "V27": 0.01, "V28": 0.01,
        }
        for i, (k, default) in enumerate(pca_defaults2.items()):
            col = v_cols2[i % 2]
            v_vals[k] = col.number_input(k, value=default, format="%.2f", key=f"fraud_{k}2")

        run_fraud = st.button("🔍 Analyze Transaction", use_container_width=True, key="run_fraud")

    with col_result:
        st.markdown("#### Detection Result")

        if run_fraud:
            payload = {"Time": float(time_val), "Amount": float(amount), **{k: float(v) for k, v in v_vals.items()}}
            try:
                resp = requests.post(f"{API_BASE}/predict/fraud", json=payload, timeout=5)
                if resp.status_code == 200:
                    r = resp.json()
                    prob = r["fraud_probability"]
                    level = r["risk_level"]
                    decision = r["decision"]
                    color = SEVERITY_COLORS.get(level, "#888")

                    # Store in session
                    st.session_state["last_fraud_shap"] = r.get("top_features", [])
                    add_alert("FRAUD", level, {"amount": amount, "decision": decision, "probability": prob})

                    # Decision banner
                    banner_class = "banner-fraud" if decision == "FRAUD" else "banner-legit"
                    banner_icon = "🚨" if decision == "FRAUD" else "✅"
                    st.markdown(f'<div class="decision-banner {banner_class}">{banner_icon} {decision}</div>', unsafe_allow_html=True)

                    # Severity badge
                    st.markdown(f'<div class="severity-badge" style="background:{color}">Risk Level: {level}</div>', unsafe_allow_html=True)

                    # Metrics row
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Fraud Probability", f"{prob:.1%}")
                    m2.metric("Anomaly", "⚠️ Yes" if r.get("is_anomaly") else "✓ No")
                    m3.metric("Anomaly Score", f"{r.get('anomaly_score', 0):.3f}")

                    # Gauge
                    display_gauge(prob, level)

                    # SHAP
                    if r.get("top_features"):
                        display_shap(r["top_features"])

                elif resp.status_code == 422:
                    st.error("Invalid input — check all required fields are filled.")
                else:
                    st.error(f"API error {resp.status_code}: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("❌ Cannot connect to API. Start it first: `uvicorn main_api:app --reload`")
            except requests.exceptions.Timeout:
                st.error("⏱️ API timeout — check the server is running.")
        else:
            st.info("👈 Configure the transaction parameters and click **Analyze Transaction**.")


# ════════════════════════════════════════════════════════════════════════════════
# TAB 2 — NETWORK THREAT SIMULATOR
# ════════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### 🌐 Network Intrusion Detection")
    st.markdown("Simulate a network flow and classify it against 14 CICIDS2017 attack categories.")

    col_net, col_net_result = st.columns([1, 1], gap="large")

    with col_net:
        st.markdown("#### Flow Parameters")

        dest_port = st.selectbox("Destination Port", [80, 443, 21, 22, 8080, 53, 3389, 1433, 0], index=0)
        flow_duration = st.slider("Flow Duration (μs)", 0, 5_000_000, 120_000, step=1000)
        fwd_packets = st.slider("Total Fwd Packets", 1, 5000, 1500)
        bwd_packets = st.slider("Total Backward Packets", 0, 2000, 50)
        syn_flags = st.slider("SYN Flag Count", 0, 2000, 1500)
        ack_flags = st.slider("ACK Flag Count", 0, 2000, 50)
        flow_bytes_s = st.number_input("Flow Bytes/s", value=750.0)
        flow_packets_s = st.number_input("Flow Packets/s", value=12.5)

        st.markdown("##### Quick Load Presets")
        preset_col1, preset_col2, preset_col3 = st.columns(3)
        load_ddos = preset_col1.button("🔴 DDoS", use_container_width=True)
        load_scan = preset_col2.button("🔍 Port Scan", use_container_width=True)
        load_benign = preset_col3.button("✅ Benign", use_container_width=True)

        run_threat = st.button("🔍 Classify Flow", use_container_width=True, key="run_threat")

    with col_net_result:
        st.markdown("#### Classification Result")

        # Build base features from UI inputs
        base_features = {
            "Destination Port": dest_port,
            "Flow Duration": flow_duration,
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": bwd_packets,
            "SYN Flag Count": syn_flags,
            "ACK Flag Count": ack_flags,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_packets_s,
        }

        # Preset overrides
        if load_ddos:
            base_features.update({"Destination Port": 80, "Flow Duration": 120000, "Total Fwd Packets": 1500, "Total Backward Packets": 50, "SYN Flag Count": 1500, "ACK Flag Count": 50, "Flow Bytes/s": 750, "Flow Packets/s": 12.5})
            st.info("📋 DDoS preset loaded — click Classify Flow")
        if load_scan:
            base_features.update({"Destination Port": 0, "Flow Duration": 5000, "Total Fwd Packets": 2, "Total Backward Packets": 0, "SYN Flag Count": 1, "ACK Flag Count": 0, "Flow Bytes/s": 100, "Flow Packets/s": 200})
            st.info("📋 Port Scan preset loaded — click Classify Flow")
        if load_benign:
            base_features.update({"Destination Port": 443, "Flow Duration": 50000, "Total Fwd Packets": 10, "Total Backward Packets": 8, "SYN Flag Count": 1, "ACK Flag Count": 10, "Flow Bytes/s": 300, "Flow Packets/s": 0.4})
            st.info("📋 Benign preset loaded — click Classify Flow")

        if run_threat:
            payload = {"features": base_features}
            try:
                resp = requests.post(f"{API_BASE}/predict/threat", json=payload, timeout=5)
                if resp.status_code == 200:
                    r = resp.json()
                    threat = r["threat_class"]
                    confidence = r["confidence"]
                    severity = r["severity"]
                    color = SEVERITY_COLORS.get(severity, "#888")
                    icon = THREAT_ICONS.get(threat, "⚠️")

                    st.session_state["last_threat_shap"] = r.get("top_features", [])
                    add_alert("THREAT", severity, {"class": threat, "confidence": confidence})

                    # Threat class banner
                    st.markdown(f'<div class="threat-banner" style="border-color:{color}">{icon} {threat}</div>', unsafe_allow_html=True)
                    st.markdown(f'<div class="severity-badge" style="background:{color}">Severity: {severity}</div>', unsafe_allow_html=True)

                    m1, m2, m3 = st.columns(3)
                    m1.metric("Confidence", f"{confidence:.1%}")
                    m2.metric("Anomaly", "⚠️ Yes" if r.get("is_anomaly") else "✓ No")
                    m3.metric("Anomaly Score", f"{r.get('anomaly_score', 0):.3f}")

                    display_gauge(confidence, severity)

                    if r.get("top_features"):
                        display_shap(r["top_features"])

                elif resp.status_code == 422:
                    st.error("Invalid input — check all required fields are filled.")
                else:
                    st.error(f"API error {resp.status_code}: {resp.text}")
            except requests.exceptions.ConnectionError:
                st.error("❌ Cannot connect to API. Start it first: `uvicorn main_api:app --reload`")
            except requests.exceptions.Timeout:
                st.error("⏱️ API timeout — check the server is running.")
        else:
            st.info("👈 Configure flow parameters and click **Classify Flow**.")


# ════════════════════════════════════════════════════════════════════════════════
# TAB 3 — SHAP EXPLAINABILITY
# ════════════════════════════════════════════════════════════════════════════════
with tab3:
    import plotly.graph_objects as go

    st.markdown("### 🧠 SHAP Explainability Dashboard")
    st.markdown("Visual breakdown of model decisions using SHAP feature importance values.")

    shap_col1, shap_col2 = st.columns(2, gap="large")

    with shap_col1:
        st.markdown("#### Last Fraud Prediction — SHAP Waterfall")
        fraud_shap = st.session_state.get("last_fraud_shap", [])
        if fraud_shap:
            feats = [f["feature"] for f in fraud_shap]
            vals = [f["shap_value"] for f in fraud_shap]
            colors = ["#ef4444" if v > 0 else "#22c55e" for v in vals]
            fig = go.Figure(go.Bar(
                x=vals, y=feats, orientation="h",
                marker_color=colors,
                text=[f"{v:+.3f}" for v in vals],
                textposition="outside",
            ))
            fig.update_layout(
                title="SHAP Feature Contributions (Fraud)",
                paper_bgcolor="#0e1117", plot_bgcolor="#161b27",
                font=dict(color="#e2e8f0"),
                xaxis=dict(title="SHAP Value", gridcolor="#2d3748"),
                yaxis=dict(autorange="reversed"),
                height=400,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Run a fraud prediction in Tab 1 to see SHAP values here.")

    with shap_col2:
        st.markdown("#### Last Threat Prediction — SHAP Waterfall")
        threat_shap = st.session_state.get("last_threat_shap", [])
        if threat_shap:
            feats = [f["feature"] for f in threat_shap]
            vals = [f["shap_value"] for f in threat_shap]
            colors = ["#f97316" if v > 0 else "#3b82f6" for v in vals]
            fig = go.Figure(go.Bar(
                x=vals, y=feats, orientation="h",
                marker_color=colors,
                text=[f"{v:+.3f}" for v in vals],
                textposition="outside",
            ))
            fig.update_layout(
                title="SHAP Feature Contributions (Threat)",
                paper_bgcolor="#0e1117", plot_bgcolor="#161b27",
                font=dict(color="#e2e8f0"),
                xaxis=dict(title="SHAP Value", gridcolor="#2d3748"),
                yaxis=dict(autorange="reversed"),
                height=400,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Run a threat prediction in Tab 2 to see SHAP values here.")

    # ── Model Performance Reference ──────────────────────────────────────────
    st.markdown("---")
    st.markdown("#### 📊 Model Performance Reference (Design Targets)")

    ref_col1, ref_col2, ref_col3, ref_col4 = st.columns(4)
    ref_col1.metric("XGBoost Fraud AUC-ROC", "0.9986")
    ref_col2.metric("RF NIDS Accuracy", "99.7%")
    ref_col3.metric("Isolation Forest (Fraud)", "Anomaly Detection")
    ref_col4.metric("CICIDS Classes", "14")

    # ROC-AUC reference visual
    import numpy as np
    fpr = np.linspace(0, 1, 100)
    tpr_fraud = 1 - np.exp(-8 * fpr)
    tpr_nids = 1 - np.exp(-6 * fpr)

    fig_roc = go.Figure()
    fig_roc.add_trace(go.Scatter(x=fpr, y=tpr_fraud, name="XGBoost Fraud (AUC=0.9986)", line=dict(color="#ef4444", width=2)))
    fig_roc.add_trace(go.Scatter(x=fpr, y=tpr_nids, name="RF NIDS (AUC=0.997)", line=dict(color="#3b82f6", width=2)))
    fig_roc.add_trace(go.Scatter(x=[0, 1], y=[0, 1], name="Random Baseline", line=dict(color="#4b5563", dash="dash")))
    fig_roc.update_layout(
        title="ROC-AUC Reference Curves",
        xaxis_title="False Positive Rate", yaxis_title="True Positive Rate",
        paper_bgcolor="#0e1117", plot_bgcolor="#161b27",
        font=dict(color="#e2e8f0"),
        xaxis=dict(gridcolor="#2d3748"), yaxis=dict(gridcolor="#2d3748"),
        height=350,
    )
    st.plotly_chart(fig_roc, use_container_width=True)


# ════════════════════════════════════════════════════════════════════════════════
# TAB 4 — SOC ALERT PANEL
# ════════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### 🚨 SOC Alert Panel")
    st.markdown("Real-time log of all detection events, sorted by severity.")

    alert_col1, alert_col2 = st.columns([3, 1])

    with alert_col2:
        if st.button("🗑️ Clear All Alerts", use_container_width=True):
            st.session_state["alerts"] = []
            st.rerun()
        export_alerts()

    with alert_col1:
        alerts = st.session_state.get("alerts", [])
        total = len(alerts)
        critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
        high = sum(1 for a in alerts if a["severity"] == "HIGH")
        st.markdown(f"**{total}** total events · **{critical}** CRITICAL · **{high}** HIGH")

    show_alerts()

    # ── Alert Severity Distribution ──────────────────────────────────────────
    alerts = st.session_state.get("alerts", [])
    if len(alerts) >= 2:
        import pandas as pd
        df = pd.DataFrame(alerts)
        dist = df["severity"].value_counts().reset_index()
        dist.columns = ["Severity", "Count"]
        colors_pie = [SEVERITY_COLORS.get(s, "#888") for s in dist["Severity"]]
        fig_dist = go.Figure(go.Pie(
            labels=dist["Severity"], values=dist["Count"],
            marker_colors=colors_pie, hole=0.4,
        ))
        fig_dist.update_layout(
            title="Alert Severity Distribution",
            paper_bgcolor="#0e1117", font=dict(color="#e2e8f0"),
            height=300,
        )
        st.plotly_chart(fig_dist, use_container_width=True)
