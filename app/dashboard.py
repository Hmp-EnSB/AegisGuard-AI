"""
AegisGuard SOC Dashboard · dashboard.py
Neon-Glass Cyber Command — live SOC interface with FastAPI backend and mock fallback.

Run:
    pip install streamlit plotly pandas numpy requests
    streamlit run dashboard.py
"""

import os
import random
import time
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime, timedelta

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="AegisGuard · SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Inject CSS ──────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_CSS  = os.path.join(_HERE, "styles", "theme.css")
if os.path.exists(_CSS):
    with open(_CSS, encoding="utf-8") as _f:
        st.markdown(f"<style>{_f.read()}</style>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# DESIGN TOKENS
# ═══════════════════════════════════════════════════════════════════════════════
SEV_COLOR = {
    "LOW":      "#22c55e",
    "MEDIUM":   "#f59e0b",
    "HIGH":     "#f97316",
    "CRITICAL": "#ef4444",
}
SEV_BG = {
    "LOW":      "#0d2818",
    "MEDIUM":   "#2d1f00",
    "HIGH":     "#2d1200",
    "CRITICAL": "#2d0808",
}

_GRID = "rgba(45,55,72,0.35)"
_G0   = "rgba(13,40,24,0.55)"
_G1   = "rgba(45,31,0,0.55)"
_G2   = "rgba(45,18,0,0.55)"
_G3   = "rgba(45,8,8,0.55)"

# ═══════════════════════════════════════════════════════════════════════════════
# MOCK DATA
# ═══════════════════════════════════════════════════════════════════════════════
FRAUD_SHAP = [
    {"feature": "V14",    "shap_value": -0.8821},
    {"feature": "V4",     "shap_value":  0.6234},
    {"feature": "Amount", "shap_value":  0.4512},
    {"feature": "V10",    "shap_value": -0.3891},
    {"feature": "V12",    "shap_value":  0.2743},
    {"feature": "V17",    "shap_value": -0.2156},
    {"feature": "V7",     "shap_value":  0.1834},
]
NIDS_SHAP = [
    {"feature": "Destination Port",  "shap_value":  1.241},
    {"feature": "Flow Duration",     "shap_value":  0.892},
    {"feature": "Total Fwd Packets", "shap_value":  0.651},
    {"feature": "Flow Bytes/s",      "shap_value": -0.512},
    {"feature": "Flow Packets/s",    "shap_value":  0.421},
    {"feature": "SYN Flag Count",    "shap_value":  0.315},
    {"feature": "ACK Flag Count",    "shap_value": -0.218},
]
ANOMALY_SHAP = [
    {"feature": "Traffic_Vol",   "shap_value":  0.951},
    {"feature": "Avg_Pkt_Size",  "shap_value": -0.742},
    {"feature": "Unique_IPs",    "shap_value":  0.612},
    {"feature": "Failed_Logins", "shap_value":  0.589},
    {"feature": "CPU_Usage",     "shap_value":  0.412},
    {"feature": "Mem_Usage",     "shap_value": -0.356},
    {"feature": "Request_Rate",  "shap_value":  0.211},
]

SOURCES    = ["192.168.1.104", "10.0.0.5", "api.internal", "gateway-01",
              "db-cluster", "fw-edge-01", "eu-west-lb"]
ALERT_DESC = {
    "FRAUD":   ["High value transaction anomaly", "Unusual location login",
                "Multiple failed card attempts", "Velocity check failure",
                "Suspicious PCA components"],
    "THREAT":  ["Possible DDoS activity", "Port scanning detected",
                "SSH brute force attempt", "SQL injection payload",
                "Malicious payload in body"],
    "ANOMALY": ["Spike in network traffic", "Unusual user agent string",
                "Unexpected lateral movement", "CPU spike on auth service",
                "High volume of 404s"],
}
MODELS = [
    {"name": "RF NIDS",          "acc": "98.2%", "f1": "0.981", "inf": "12ms",  "trained": "2026-03-12"},
    {"name": "XGBoost Fraud",    "acc": "99.1%", "f1": "0.988", "inf": "18ms",  "trained": "2026-03-14"},
    {"name": "Isolation Forest", "acc": "N/A",   "f1": "N/A",   "inf": " 8ms",  "trained": "2026-03-10"},
]

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ═══════════════════════════════════════════════════════════════════════════════
def _seed_alerts():
    now = datetime.now()
    sev_map = {
        "FRAUD":   ["HIGH", "CRITICAL", "MEDIUM", "MEDIUM"],
        "THREAT":  ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "LOW"],
        "ANOMALY": ["LOW", "MEDIUM", "HIGH", "HIGH"],
    }
    rows = []
    for _ in range(18):
        atype = random.choice(["FRAUD", "THREAT", "ANOMALY"])
        sev   = random.choice(sev_map[atype])
        t     = now - timedelta(seconds=random.randint(0, 86400))
        rows.append({
            "id":          f"ALR-{random.randint(0, 9999):04d}",
            "time":        t.strftime("%I:%M:%S %p"),
            "type":        atype,
            "severity":    sev,
            "description": random.choice(ALERT_DESC[atype]),
            "source":      random.choice(SOURCES),
        })
    rows.sort(key=lambda x: x["time"], reverse=True)
    return rows


if "alerts" not in st.session_state:
    st.session_state.alerts = _seed_alerts()

if "live_counts" not in st.session_state:
    st.session_state.live_counts = {
        "total_detections": 1248,
        "fraud_attempts":   42,
        "network_threats":  89,
        "anomalies":        312,
    }


def add_alert(atype, sev, desc, src="system"):
    st.session_state.alerts.insert(0, {
        "id":          f"ALR-{random.randint(0, 9999):04d}",
        "time":        datetime.now().strftime("%I:%M:%S %p"),
        "type":        atype,
        "severity":    sev,
        "description": desc,
        "source":      src,
    })
    lc = st.session_state.live_counts
    lc["total_detections"] += 1
    if atype == "FRAUD":
        lc["fraud_attempts"] += 1
    elif atype == "THREAT":
        lc["network_threats"] += 1
    elif atype == "ANOMALY":
        lc["anomalies"] += 1


if "api_online" not in st.session_state:
    st.session_state.api_online  = None
    st.session_state.api_latency = 0
    st.session_state.api_info    = {}

# ═══════════════════════════════════════════════════════════════════════════════
# API HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════════════
def check_api_health():
    if not HAS_REQUESTS:
        return False, 0, {"error": "requests not installed"}
    try:
        start = time.time()
        for ep in ["/health", "/healthz"]:
            try:
                r = requests.get(f"http://localhost:8000{ep}", timeout=3)
                if r.status_code == 200:
                    return True, round((time.time() - start) * 1000, 1), r.json()
            except Exception:
                continue
        return False, round((time.time() - start) * 1000, 1), {"status": "timeout"}
    except Exception as e:
        return False, 0, {"error": str(e)}

# ═══════════════════════════════════════════════════════════════════════════════
# UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def sev_badge(sev: str) -> str:
    return f'<span class="sev sev-{sev}">{sev}</span>'


def kpi_card(label: str, value, variant: str = "", icon: str = "") -> str:
    return f"""
<div class="kpi-card {variant}">
    <div>
        <span class="kpi-label">{label}</span>
        <span class="kpi-value">{value}</span>
    </div>
    <div class="kpi-icon">{icon}</div>
</div>"""


def model_stat_row(label: str, value: str) -> str:
    return (
        '<div style="display:flex;justify-content:space-between;align-items:center;'
        'font-family:\'JetBrains Mono\',monospace;font-size:0.72rem;color:#94a3b8;'
        'padding:5px 0;border-bottom:1px solid rgba(45,55,90,0.3);">'
        f'<span>{label}</span>'
        f'<span style="color:#e2e8f0;font-weight:500;">{value}</span>'
        "</div>"
    )


def model_card(name, acc, f1, inf, trained) -> str:
    return f"""
<div class="model-card">
    <div class="model-card-header">
        <span class="model-name">{name}</span>
        <span class="badge-operational">● OPERATIONAL</span>
    </div>
    {model_stat_row("Accuracy", acc)}
    {model_stat_row("F1 Score", f1)}
    {model_stat_row("Inference Time", inf)}
    {model_stat_row("Last Trained", trained)}
</div>"""


def _plotly_dark(height=280, t=20, b=40, l=10, r=20):
    return dict(
        paper_bgcolor="#0e1117",
        plot_bgcolor="#161b27",
        font=dict(color="#e2e8f0", family="JetBrains Mono", size=11),
        height=height,
        margin=dict(t=t, b=b, l=l, r=r),
    )


def _axis(**kw):
    return dict(
        gridcolor=_GRID,
        zerolinecolor="rgba(75,85,99,0.5)",
        tickfont=dict(color="#94a3b8", size=10),
        **kw,
    )


def gauge(value: float, level: str):
    c = SEV_COLOR.get(level, "#3b82f6")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=round(value * 100, 1),
        number={"suffix": "%", "font": {"size": 34, "color": "#e2e8f0", "family": "Inter"}},
        title={"text": f"Risk Level: <b>{level}</b>",
               "font": {"size": 13, "color": "#94a3b8", "family": "JetBrains Mono"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#4b5563",
                     "tickfont": {"color": "#94a3b8", "size": 10}},
            "bar":         {"color": c, "thickness": 0.28},
            "bgcolor":     "#1e2433",
            "bordercolor": "#2d3748",
            "steps": [
                {"range": [0,  30], "color": _G0},
                {"range": [30, 60], "color": _G1},
                {"range": [60, 85], "color": _G2},
                {"range": [85,100], "color": _G3},
            ],
            "threshold": {"line": {"color": c, "width": 3}, "thickness": 0.8, "value": value * 100},
        },
    ))
    fig.update_layout(
        paper_bgcolor="#0e1117",
        font={"color": "#e2e8f0"},
        height=260,
        margin=dict(t=60, b=20, l=30, r=30),
    )
    st.plotly_chart(fig, use_container_width=True)


def shap_chart(features, title="SHAP Feature Contributions"):
    if title:
        st.markdown(f"#### {title}")
    feats  = [f["feature"]    for f in features]
    vals   = [f["shap_value"] for f in features]
    colors = ["#ef4444" if v > 0 else "#22c55e" for v in vals]

    fig = go.Figure(go.Bar(
        x=vals, y=feats, orientation="h",
        marker=dict(color=colors, opacity=0.88, line=dict(width=0)),
        text=[f"{v:+.4f}" for v in vals],
        textposition="outside",
        textfont=dict(color="#94a3b8", size=11, family="JetBrains Mono"),
        hovertemplate="<b>%{y}</b><br>SHAP: %{x:+.4f}<extra></extra>",
    ))
    fig.update_layout(
        **_plotly_dark(max(240, len(features) * 44), t=20, b=40, l=10, r=90),
        xaxis=_axis(title="SHAP Value (impact on prediction)"),
        yaxis=dict(autorange="reversed", tickfont=dict(color="#cbd5e1", size=11)),
        bargap=0.3,
    )
    st.plotly_chart(fig, use_container_width=True)

    # top factor callout
    top  = max(features, key=lambda f: abs(f["shap_value"]))
    val  = top["shap_value"]
    col  = "#ef4444" if val > 0 else "#22c55e"
    dire = "increases" if val > 0 else "decreases"
    st.markdown(
        f'<div style="background:rgba(8,12,24,0.8);border:1px solid rgba(45,55,90,0.6);'
        f'border-radius:8px;padding:0.6rem 1rem;font-family:\'JetBrains Mono\',monospace;'
        f'font-size:0.74rem;color:#94a3b8;margin-top:0.5rem;">'
        f'Top factor: <span style="color:{col};font-weight:700">{top["feature"]}</span> '
        f'{dire} risk by <span style="color:{col}">{val:+.3f}</span>.</div>',
        unsafe_allow_html=True,
    )

    with st.expander("📋 Raw SHAP Values"):
        for f in features:
            v    = f["shap_value"]
            c    = "#ef4444" if v > 0 else "#22c55e"
            dire = "↑ increases risk" if v > 0 else "↓ decreases risk"
            st.markdown(
                f"**{f['feature']}** → "
                f"<span style='color:{c};font-weight:700'>{v:+.4f}</span> "
                f"<span style='color:#6b7280;font-size:0.85em'>{dire}</span>",
                unsafe_allow_html=True,
            )


def timeline_chart(alerts_list):
    if len(alerts_list) < 2:
        st.info("Not enough alerts for timeline.")
        return
    df = pd.DataFrame(alerts_list)
    df["count"] = 1
    fig = go.Figure()
    for sev, color in SEV_COLOR.items():
        sub = df[df["severity"] == sev]
        if not sub.empty:
            fig.add_trace(go.Bar(name=sev, x=sub.index, y=sub["count"],
                                 marker_color=color, opacity=0.85))
    fig.update_layout(
        **_plotly_dark(280),
        barmode="stack",
        xaxis=_axis(title="Event #"),
        yaxis=_axis(title="Count"),
        legend=dict(orientation="h", y=-0.35, font=dict(size=10)),
    )
    st.plotly_chart(fig, use_container_width=True)


def donut_chart(alerts_list, colors_map, label_key="severity", height=300):
    if not alerts_list:
        return
    df   = pd.DataFrame(alerts_list)
    dist = df[label_key].value_counts().reset_index()
    dist.columns = [label_key, "Count"]
    cols = [colors_map.get(s, "#888") for s in dist[label_key]]
    fig  = go.Figure(go.Pie(
        labels=dist[label_key],
        values=dist["Count"],
        marker_colors=cols,
        hole=0.48,
        textfont=dict(color="#e2e8f0", family="JetBrains Mono", size=11),
    ))
    fig.update_layout(
        paper_bgcolor="#0e1117",
        font=dict(color="#e2e8f0"),
        height=height,
        margin=dict(t=10, b=10),
        legend=dict(font=dict(family="JetBrains Mono", size=11)),
    )
    st.plotly_chart(fig, use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
<div style="padding:1rem 0 0.5rem;text-align:center;">
    <div style="font-family:'Inter',sans-serif;font-size:1.5rem;font-weight:800;
    letter-spacing:-0.02em;line-height:1.1;">
        🛡️&nbsp;<span style="background:linear-gradient(135deg,#06b6d4,#3b82f6,#8b5cf6);
        -webkit-background-clip:text;-webkit-text-fill-color:transparent;
        background-clip:text;">AegisGuard</span>
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
    color:#94a3b8;letter-spacing:0.15em;text-transform:uppercase;margin-top:4px;">
        SOC · AI Defense
    </div>
</div>
<hr style="border:none;border-top:1px solid #2d3748;margin:0.5rem 0 0.8rem;"/>
""", unsafe_allow_html=True)

    # API health
    if st.session_state.api_online is None:
        online, lat, info = check_api_health()
        st.session_state.api_online  = online
        st.session_state.api_latency = lat
        st.session_state.api_info    = info

    api_on = st.session_state.api_online
    if api_on:
        dot_class    = "api-online"
        status_text  = "ONLINE"
        status_class = "api-value-online"
        lat_text     = f"· {st.session_state.api_latency}ms"
    elif api_on is False:
        dot_class    = "api-offline"
        status_text  = "OFFLINE"
        status_class = "api-value-offline"
        lat_text     = ""
    else:
        dot_class    = "api-checking"
        status_text  = "CHECKING"
        status_class = ""
        lat_text     = ""

    st.markdown(f"""
<div class="sidebar-api-card">
    <div class="api-dot {dot_class}"></div>
    <span class="sidebar-api-text">
        API <span class="{status_class}">{status_text}</span>
    </span>
    <span class="sidebar-latency">{lat_text}</span>
</div>
""", unsafe_allow_html=True)

    if st.button("🔄 Refresh API", use_container_width=True, key="refresh_api"):
        st.session_state.api_online = None
        st.rerun()

    st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)
    st.markdown('<span class="sidebar-label">MAIN</span>', unsafe_allow_html=True)

    page = st.radio(
        "nav",
        label_visibility="collapsed",
        options=[
            "Overview",
            "Network NIDS",
            "Fraud Detection",
            "Anomalies",
            "SHAP Explainability",
            "SOC Alerts",
            "System Health",
        ],
    )

# ═══════════════════════════════════════════════════════════════════════════════
# HEADER STATUS BAR
# ═══════════════════════════════════════════════════════════════════════════════
alerts  = st.session_state.alerts
lc      = st.session_state.live_counts
n_crit  = sum(1 for a in alerts if a["severity"] == "CRITICAL")
n_high  = sum(1 for a in alerts if a["severity"] == "HIGH")
n_total = len(alerts)

hc = st.columns([1, 1, 1, 1.4, 1, 1, 1])
hc[0].markdown('<div class="header-pill pill-model">● RF NIDS</div>',    unsafe_allow_html=True)
hc[1].markdown('<div class="header-pill pill-model">● XGBoost</div>',    unsafe_allow_html=True)
hc[2].markdown('<div class="header-pill pill-model">● ISO Forest</div>', unsafe_allow_html=True)
hc[3].markdown("""
<div class="scan-bar-wrapper">
    <span style="font-size:0.75rem;color:#06b6d4;">⚡</span>
    <div class="scan-bar-track"><div class="scan-bar-fill"></div></div>
    <span class="scan-label">Scanning</span>
</div>
""", unsafe_allow_html=True)
hc[4].markdown(
    f'<div class="header-pill pill-threat">CRITICAL '
    f'<b style="color:#ef4444">{n_crit}</b></div>', unsafe_allow_html=True)
hc[5].markdown(
    f'<div class="header-pill pill-threat">HIGH '
    f'<b style="color:#f97316">{n_high}</b></div>', unsafe_allow_html=True)
hc[6].markdown(
    f'<div class="header-pill pill-threat">TOTAL '
    f'<b style="color:#e2e8f0">{n_total}</b></div>', unsafe_allow_html=True)

st.markdown("<hr class='divider'/>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════════
if page == "Overview":
    st.markdown("## Overview")

    k = st.columns(5, gap="small")
    k[0].markdown(kpi_card("Total Detections", f"{lc['total_detections']:,}", "kpi-cyan",    "⚡"), unsafe_allow_html=True)
    k[1].markdown(kpi_card("Critical Alerts",  n_crit,                        "kpi-red",     "🛡️"), unsafe_allow_html=True)
    k[2].markdown(kpi_card("Fraud Attempts",   lc["fraud_attempts"],          "kpi-amber",   "💳"), unsafe_allow_html=True)
    k[3].markdown(kpi_card("Network Threats",  lc["network_threats"],         "kpi-blue",    "🌐"), unsafe_allow_html=True)
    k[4].markdown(kpi_card("Anomalies",        lc["anomalies"],               "kpi-green",   "🧠"), unsafe_allow_html=True)

    st.markdown("<hr class='divider'/>", unsafe_allow_html=True)

    m = st.columns(3, gap="small")
    for col, mdl in zip(m, MODELS):
        col.markdown(
            model_card(mdl["name"], mdl["acc"], mdl["f1"], mdl["inf"], mdl["trained"]),
            unsafe_allow_html=True,
        )

    st.markdown("<hr class='divider'/>", unsafe_allow_html=True)

    tbl_col, pie_col = st.columns([3, 2], gap="large")

    with tbl_col:
        st.markdown("### Live Alerts")
        df = pd.DataFrame(alerts[:10])
        rows_html = "".join([
            f"<tr>"
            f"<td>{sev_badge(r['severity'])}</td>"
            f"<td>{r['type']}</td>"
            f"<td>{r['time']}</td>"
            f"<td>{r['description']}</td>"
            f"</tr>"
            for _, r in df.iterrows()
        ])
        st.markdown(f"""
<table>
  <thead><tr>
    <th>Severity</th><th>Type</th><th>Time</th><th>Description</th>
  </tr></thead>
  <tbody>{rows_html}</tbody>
</table>
""", unsafe_allow_html=True)

    with pie_col:
        st.markdown("### Severity Distribution")
        donut_chart(alerts, SEV_COLOR, "severity", height=380)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: NETWORK NIDS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Network NIDS":
    st.markdown("## 🌐 Network Intrusion Detection")
    st.caption("Simulate a network flow and classify it against CICIDS2017 attack categories.")

    form_col, res_col = st.columns([1, 1], gap="large")

    with form_col:
        st.markdown("#### Flow Parameters")
        dest_port     = st.selectbox("Destination Port", [80, 443, 21, 22, 8080, 53, 3389, 0], index=0)
        flow_duration = st.slider("Flow Duration (μs)",     100_000, 5_000_000, 1_500_000, step=10_000)
        fwd_packets   = st.slider("Total Fwd Packets",      1,       5000,      15)
        bwd_packets   = st.slider("Total Backward Packets", 0,       2000,      12)
        syn_flags     = st.slider("SYN Flag Count",         0,       200,       1)
        ack_flags     = st.slider("ACK Flag Count",         0,       200,       10)
        c1, c2 = st.columns(2)
        flow_bytes_s = c1.number_input("Flow Bytes/s",   value=1_500.0, min_value=0.0)
        flow_pkts_s  = c2.number_input("Flow Packets/s", value=25.0,    min_value=0.0)

        st.markdown("##### Quick Presets")
        pc1, pc2, pc3 = st.columns(3)
        if pc1.button("🔴 DDoS",     use_container_width=True, key="nids_ddos"):
            st.session_state["nids_preset"] = "DDoS"
        if pc2.button("🔍 PortScan", use_container_width=True, key="nids_scan"):
            st.session_state["nids_preset"] = "PortScan"
        if pc3.button("✅ Benign",   use_container_width=True, key="nids_ben"):
            st.session_state["nids_preset"] = "Benign"

        # ── Live API call OR mock ──────────────────────────────────────────
        classify_btn = st.button("🔍 Classify Flow", use_container_width=True,
                                 key="run_nids", type="primary")

    with res_col:
        st.markdown("#### Classification Result")

        if classify_btn:
            features_payload = {
                "Destination Port":       dest_port,
                "Flow Duration":          flow_duration,
                "Total Fwd Packets":      fwd_packets,
                "Total Backward Packets": bwd_packets,
                "SYN Flag Count":         syn_flags,
                "ACK Flag Count":         ack_flags,
                "Flow Bytes/s":           float(flow_bytes_s),
                "Flow Packets/s":         float(flow_pkts_s),
            }
            live_result = None
            if HAS_REQUESTS and st.session_state.api_online:
                try:
                    resp = requests.post(
                        "http://localhost:8000/predict/threat",
                        json={"features": features_payload}, timeout=5,
                    )
                    if resp.status_code == 200:
                        data       = resp.json()
                        tc         = data.get("threat_class", "UNKNOWN")
                        sev        = data.get("severity", "LOW")
                        conf       = data.get("confidence", 0.5)
                        live_shap  = data.get("top_features", NIDS_SHAP)
                        live_result = {
                            "tc": tc, "sev": sev,
                            "prob": 1 - conf if tc == "BENIGN" else conf,
                            "conf": conf, "shap": live_shap, "source": "live",
                        }
                except Exception:
                    pass

            if live_result is None:
                # Mock fallback
                if fwd_packets > 1000 or flow_pkts_s > 5000:
                    tc, sev = "DDoS",     "CRITICAL"
                elif bwd_packets == 0 and dest_port not in [443, 80]:
                    tc, sev = "PortScan", "HIGH"
                elif flow_duration > 3_000_000:
                    tc, sev = "DoS Hulk", "MEDIUM"
                elif syn_flags > 100:
                    tc, sev = "Bot",      "MEDIUM"
                else:
                    tc, sev = "BENIGN",   "LOW"

                prob_map = {"LOW": 0.03, "MEDIUM": 0.65, "HIGH": 0.89, "CRITICAL": 0.98}
                conf_map = {"LOW": 0.98, "MEDIUM": 0.87, "HIGH": 0.94, "CRITICAL": 0.99}
                live_result = {
                    "tc": tc, "sev": sev,
                    "prob": prob_map[sev], "conf": conf_map[sev],
                    "shap": NIDS_SHAP, "source": "mock",
                }

            st.session_state["nids_result"] = live_result
            if live_result["sev"] != "LOW":
                add_alert("THREAT", live_result["sev"],
                          f"Network threat detected: {live_result['tc']}", "fw-edge-01")

        if "nids_result" in st.session_state:
            r   = st.session_state["nids_result"]
            c   = SEV_COLOR[r["sev"]]
            src = r.get("source", "mock")
            src_badge = (
                '<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.6rem;'
                f'color:{"#22c55e" if src=="live" else "#f59e0b"}">● {"LIVE API" if src=="live" else "MOCK DATA"}</span>'
            )
            st.markdown(src_badge, unsafe_allow_html=True)
            st.markdown(
                f'<div class="threat-banner" style="background:{SEV_BG[r["sev"]]};'
                f'border-color:{c};color:{c};">{r["tc"]} DETECTED</div>',
                unsafe_allow_html=True,
            )
            st.markdown(sev_badge(r["sev"]), unsafe_allow_html=True)
            m1, m2 = st.columns(2)
            m1.metric("Threat Probability", f"{r['prob']:.1%}")
            m2.metric("Model Confidence",   f"{r['conf']:.1%}")
            gauge(r["prob"], r["sev"])
            shap_chart(r.get("shap", NIDS_SHAP), "SHAP Feature Contributions")
        else:
            st.info("👈 Configure flow parameters and click **Classify Flow**.")

    st.markdown("<hr class='divider'/>", unsafe_allow_html=True)
    bc1, bc2 = st.columns(2, gap="large")

    with bc1:
        st.markdown("### Alert Timeline (24h)")
        timeline_chart(alerts)

    with bc2:
        st.markdown("### Threat Distribution")
        df_td = pd.DataFrame([
            {"Threat": "DDoS",       "Count": 420},
            {"Threat": "PortScan",   "Count": 215},
            {"Threat": "Bot",        "Count": 180},
            {"Threat": "DoS Hulk",   "Count":  95},
            {"Threat": "Web Attack", "Count":  45},
        ])
        fig = go.Figure(go.Bar(
            x=df_td["Count"], y=df_td["Threat"], orientation="h",
            marker_color="#06b6d4", opacity=0.85,
        ))
        fig.update_layout(
            **_plotly_dark(280),
            xaxis=_axis(title="Count"),
            yaxis=dict(autorange="reversed", tickfont=dict(color="#cbd5e1", size=11)),
        )
        st.plotly_chart(fig, use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: FRAUD DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Fraud Detection":
    st.markdown("## 💳 Financial Fraud Detection")
    st.caption("Simulate a credit card transaction and run it through the XGBoost fraud model.")

    form_col, res_col = st.columns([1, 1], gap="large")

    with form_col:
        st.markdown("#### Transaction Parameters")
        amount   = st.number_input("Amount (€)", min_value=0.01, max_value=500_000.0,
                                   value=9_800.00, step=50.0, format="%.2f")
        time_val = st.slider("Time (seconds from epoch start)", 0, 172_800, 54_000, step=600)

        st.markdown("##### PCA Components V1–V7")
        pc1 = st.columns(4)
        v: dict = {}
        for i, (k, d) in enumerate(
            {"V1": -1.35, "V2": -0.07, "V3": 2.54, "V4": 1.38,
             "V5": -0.34, "V6": -0.50, "V7": 1.80}.items()
        ):
            v[k] = pc1[i % 4].number_input(k, value=d, format="%.2f", key=f"v1_{k}")

        st.markdown("##### PCA Components V8–V14")
        pc2 = st.columns(4)
        for i, (k, d) in enumerate(
            {"V8": -0.29, "V9": 0.29, "V10": -0.82, "V11": 0.97,
             "V12": -0.28, "V13": -0.20, "V14": -1.11}.items()
        ):
            v[k] = pc2[i % 4].number_input(k, value=d, format="%.2f", key=f"v2_{k}")

        st.markdown("##### PCA Components V15–V28")
        pc3 = st.columns(4)
        for i, (k, d) in enumerate({
            "V15":  0.14, "V16": -0.45, "V17": -0.24, "V18":  0.10,
            "V19":  0.35, "V20":  0.06, "V21":  0.19, "V22":  0.21,
            "V23": -0.01, "V24":  0.22, "V25":  0.02, "V26":  0.20,
            "V27":  0.01, "V28":  0.01,
        }.items()):
            v[k] = pc3[i % 4].number_input(k, value=d, format="%.2f", key=f"v3_{k}")

        analyze_btn = st.button("🔍 Analyze Transaction", use_container_width=True,
                                key="run_fraud", type="primary")

    with res_col:
        st.markdown("#### Detection Result")

        if analyze_btn:
            live_result = None
            if HAS_REQUESTS and st.session_state.api_online:
                try:
                    payload = {"Time": float(time_val), "Amount": float(amount),
                               **{k: float(val) for k, val in v.items()}}
                    resp = requests.post(
                        "http://localhost:8000/predict/fraud",
                        json=payload, timeout=5,
                    )
                    if resp.status_code == 200:
                        data      = resp.json()
                        prob      = data.get("fraud_probability", 0.5)
                        sev       = data.get("risk_level", "MEDIUM")
                        decision  = data.get("decision", "LEGITIMATE")
                        ascore    = data.get("anomaly_score", 0.0)
                        live_shap = data.get("top_features", FRAUD_SHAP)
                        live_result = {
                            "is_fraud": decision == "FRAUD",
                            "sev": sev, "prob": prob,
                            "ascore": ascore, "shap": live_shap, "source": "live",
                        }
                except Exception:
                    pass

            if live_result is None:
                # Mock fallback
                if amount > 10_000:
                    is_fraud, sev, prob, ascore = True,  "CRITICAL", 0.98, 0.95
                elif amount > 5_000:
                    is_fraud, sev, prob, ascore = True,  "HIGH",     0.89, 0.82
                elif abs(v.get("V1", 0)) > 2 or abs(v.get("V14", 0)) > 1.5:
                    is_fraud, sev, prob, ascore = True,  "MEDIUM",   0.65, 0.68
                else:
                    is_fraud, sev, prob, ascore = False, "LOW",      0.05, 0.12
                live_result = {
                    "is_fraud": is_fraud, "sev": sev, "prob": prob,
                    "ascore": ascore, "shap": FRAUD_SHAP, "source": "mock",
                }

            st.session_state["fraud_result"] = live_result
            if live_result["sev"] != "LOW":
                add_alert("FRAUD", live_result["sev"],
                          f"Suspicious transaction €{amount:,.2f}", "payment-gw-eu")

        if "fraud_result" in st.session_state:
            r   = st.session_state["fraud_result"]
            src = r.get("source", "mock")
            src_badge = (
                '<span style="font-family:\'JetBrains Mono\',monospace;font-size:0.6rem;'
                f'color:{"#22c55e" if src=="live" else "#f59e0b"}">● {"LIVE API" if src=="live" else "MOCK DATA"}</span>'
            )
            st.markdown(src_badge, unsafe_allow_html=True)

            cls = "banner-fraud" if r["is_fraud"] else "banner-legit"
            ico = "🚨 FRAUD DETECTED" if r["is_fraud"] else "✅ LEGITIMATE TRANSACTION"
            st.markdown(f'<div class="banner {cls}">{ico}</div>', unsafe_allow_html=True)
            st.markdown(
                f'<div style="text-align:center;margin-bottom:0.8rem;">'
                f'{sev_badge(r["sev"])}</div>',
                unsafe_allow_html=True,
            )
            m1, m2, m3 = st.columns(3)
            m1.metric("Fraud Probability", f"{r['prob']:.1%}")
            m2.metric("Is Anomaly",        "Yes ⚠️" if r["ascore"] > 0.5 else "No ✓")
            m3.metric("Anomaly Score",     f"{r['ascore']:.3f}")
            gauge(r["prob"], r["sev"])
            shap_chart(r.get("shap", FRAUD_SHAP), "SHAP Feature Contributions")
        else:
            st.info("👈 Configure transaction parameters and click **Analyze Transaction**.")

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: ANOMALIES
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Anomalies":
    st.markdown("## 🧠 Anomaly Detection")
    st.caption("Isolation Forest results from unsupervised anomaly detection.")

    a1, a2, a3, a4 = st.columns(4)
    a1.metric("Anomaly Rate",  "3.4%")
    a2.metric("Flagged Today", "47")
    a3.metric("Avg Score",     "0.612")
    a4.metric("Threshold",     "0.500")

    st.markdown("<hr class='divider'/>", unsafe_allow_html=True)

    np.random.seed(42)
    n      = 120
    normal = np.random.randn(n, 2) * 0.6
    anomal = np.random.randn(20, 2) * 2.2
    s_norm = np.random.uniform(0.05, 0.45, n)

    sc1, sc2 = st.columns(2, gap="large")

    with sc1:
        st.markdown("### Anomaly Scatter Plot")
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=normal[:, 0], y=normal[:, 1], mode="markers",
                                 marker=dict(color="#3b82f6", size=6, opacity=0.7), name="Normal"))
        fig.add_trace(go.Scatter(x=anomal[:, 0], y=anomal[:, 1], mode="markers",
                                 marker=dict(color="#ef4444", size=9, opacity=0.9, symbol="x"),
                                 name="Anomaly"))
        fig.update_layout(**_plotly_dark(300), xaxis=_axis(), yaxis=_axis(),
                          legend=dict(font=dict(size=10)))
        st.plotly_chart(fig, use_container_width=True)

    with sc2:
        st.markdown("### Anomaly Score Timeline")
        scores = s_norm[:50].copy()
        for si in [12, 25, 38, 45]:
            scores[si] = np.random.uniform(0.62, 0.95)
        idx = list(range(50))
        fig2 = go.Figure()
        fig2.add_trace(go.Scatter(
            x=idx, y=scores, mode="lines+markers",
            line=dict(color="#06b6d4", width=2),
            marker=dict(
                color=["#ef4444" if s > 0.5 else "#06b6d4" for s in scores],
                size=6,
            ),
            name="Anomaly Score",
        ))
        fig2.add_hline(y=0.5, line=dict(color="#f59e0b", dash="dash", width=1.5))
        fig2.update_layout(**_plotly_dark(300),
                           xaxis=_axis(title="Sample Index"),
                           yaxis={**_axis(title="Score"), "range": [0, 1]})
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("### Flagged Records")
    rng2 = random.Random(99)
    rows = []
    for _ in range(15):
        rows.append({
            "ID":          f"ANO-{rng2.randint(1000, 9999)}",
            "Time":        (datetime.now() - timedelta(minutes=rng2.randint(0, 1440))).strftime("%H:%M:%S"),
            "Score":       round(rng2.uniform(0.51, 0.98), 3),
            "Traffic_Vol": round(rng2.uniform(1000, 50000), 1),
            "CPU_Usage":   round(rng2.uniform(20, 95), 1),
            "Status":      rng2.choice(["Flagged", "Investigating", "Resolved"]),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SHAP EXPLAINABILITY
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "SHAP Explainability":
    st.markdown("## 🔬 SHAP Explainability")
    st.caption("Feature contribution analysis across all three AI models.")

    s1, s2, s3 = st.columns(3, gap="large")

    for col, name, desc, data in [
        (s1, "RF NIDS Model",    "Random Forest · CICIDS2017 · 78 features",        NIDS_SHAP),
        (s2, "XGBoost Fraud",    "XGBoost · ULB Credit Card · 30 features",         FRAUD_SHAP),
        (s3, "Isolation Forest", "Isolation Forest · System telemetry · 7 features", ANOMALY_SHAP),
    ]:
        col.markdown(f"""
<div class="model-card" style="margin-bottom:1rem;">
    <div class="model-card-header">
        <span class="model-name">{name}</span>
        <span class="badge-operational">● OPERATIONAL</span>
    </div>
    <p style="font-size:0.74rem;color:#94a3b8;
    font-family:'JetBrains Mono',monospace;">{desc}</p>
</div>
""", unsafe_allow_html=True)
        with col:
            shap_chart(data, "")

    st.markdown("<hr class='divider'/>", unsafe_allow_html=True)
    st.markdown("""
<div class="shap-guide">
    <div class="model-card-header" style="margin-bottom:0.5rem;">
        <span class="model-name" style="color:#06b6d4;">ⓘ SHAP Interpretation Guide</span>
    </div>
    <span style="color:#ef4444">■</span>
    <b style="color:#e2e8f0"> Positive SHAP value</b> — Feature pushes the prediction
    <b style="color:#ef4444">toward risk / fraud / anomaly</b>.
    The larger the bar, the stronger the push.<br/>
    <span style="color:#22c55e">■</span>
    <b style="color:#e2e8f0"> Negative SHAP value</b> — Feature pushes the prediction
    <b style="color:#22c55e">away from risk</b>, acting as a mitigating factor.<br/>
    <span style="color:#06b6d4">■</span>
    <b style="color:#e2e8f0"> Magnitude</b> — The absolute bar size indicates how strongly
    that feature influences the final model output.
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SOC ALERTS
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "SOC Alerts":
    st.markdown("## 🚨 SOC Alert Panel")

    t1, t2, t3, t4 = st.columns([3, 2, 1, 1])
    search_q   = t1.text_input("Search", placeholder="Search description, type, source…",
                                label_visibility="collapsed")
    sev_filter = t2.selectbox("Filter", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                               label_visibility="collapsed")
    if t3.button("🔄 Reset", use_container_width=True):
        st.session_state.alerts = _seed_alerts()
        st.rerun()
    if t4.button("📥 CSV", use_container_width=True):
        csv = pd.DataFrame(alerts).to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇ Download", csv,
            f"aegisguard_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "text/csv",
        )

    filtered = [a for a in alerts if sev_filter == "ALL" or a["severity"] == sev_filter]
    if search_q:
        sq       = search_q.lower()
        filtered = [a for a in filtered
                    if sq in a["description"].lower()
                    or sq in a["type"].lower()
                    or sq in a["source"].lower()]
    pri = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    filtered.sort(key=lambda x: pri.get(x["severity"], 0), reverse=True)

    s1, s2, s3, s4 = st.columns(4)
    s1.metric("🔴 Critical", sum(1 for a in filtered if a["severity"] == "CRITICAL"))
    s2.metric("🟠 High",     sum(1 for a in filtered if a["severity"] == "HIGH"))
    s3.metric("🟡 Medium",   sum(1 for a in filtered if a["severity"] == "MEDIUM"))
    s4.metric("🟢 Low",      sum(1 for a in filtered if a["severity"] == "LOW"))

    if filtered:
        rows_html = "".join([
            f"<tr><td>{r['id']}</td><td>{sev_badge(r['severity'])}</td>"
            f"<td>{r['type']}</td><td>{r['time']}</td>"
            f"<td>{r['description']}</td><td>{r['source']}</td></tr>"
            for r in filtered
        ])
        st.markdown(f"""
<br/>
<table>
  <thead><tr>
    <th>ID</th><th>Severity</th><th>Type</th>
    <th>Time</th><th>Description</th><th>Source</th>
  </tr></thead>
  <tbody>{rows_html}</tbody>
</table>
""", unsafe_allow_html=True)
    else:
        st.info("No alerts match the current filter.")

    st.markdown("<hr class='divider'/>", unsafe_allow_html=True)
    ch1, ch2 = st.columns(2, gap="large")
    with ch1:
        st.markdown("### Alert Timeline")
        timeline_chart(alerts)
    with ch2:
        st.markdown("### Alert Type Distribution")
        TYPE_COLORS = {"FRAUD": "#f97316", "THREAT": "#ef4444", "ANOMALY": "#8b5cf6"}
        donut_chart(alerts, TYPE_COLORS, "type", height=300)

# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: SYSTEM HEALTH
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "System Health":
    st.markdown("## ⚙️ System Health")
    st.markdown('<div class="sys-ok">🟢 ALL SYSTEMS OPERATIONAL</div>', unsafe_allow_html=True)

    mh1, mh2, mh3 = st.columns(3, gap="large")
    for col, name, details in [
        (mh1, "RF NIDS", {
            "Version":    "v2.4.1", "Dataset":  "CICIDS2017",
            "Accuracy":   "98.2%",  "F1 Score": "0.981",
            "Features":   "78",     "Estimators": "200",
        }),
        (mh2, "XGBoost Fraud", {
            "Version":   "v1.8.0", "Dataset":   "ULB Credit Card",
            "Precision": "99.1%",  "Recall":    "80.4%",
            "Features":  "30",     "Trees":     "300",
        }),
        (mh3, "Isolation Forest", {
            "Version":       "v1.2.0", "Contamination": "0.001",
            "n_estimators":  "100",    "Max Features":  "1.0",
            "Max Samples":   "auto",   "Bootstrap":     "False",
        }),
    ]:
        rows = "".join(model_stat_row(k, val) for k, val in details.items())
        col.markdown(f"""
<div class="model-card">
    <div class="model-card-header">
        <span class="model-name">{name}</span>
        <span class="badge-operational">● OPERATIONAL</span>
    </div>
    {rows}
</div>
""", unsafe_allow_html=True)

    st.markdown("<hr class='divider'/>", unsafe_allow_html=True)
    lat_col, res_col = st.columns(2, gap="large")

    with lat_col:
        st.markdown("### API Endpoint Latencies")
        st.dataframe(pd.DataFrame([
            {"Endpoint": "GET  /healthz",        "Latency (ms)":  2, "Status": "200 OK"},
            {"Endpoint": "POST /predict/fraud",  "Latency (ms)": 18, "Status": "200 OK"},
            {"Endpoint": "POST /predict/threat", "Latency (ms)": 14, "Status": "200 OK"},
            {"Endpoint": "GET  /shap/fraud",     "Latency (ms)": 45, "Status": "200 OK"},
            {"Endpoint": "GET  /shap/nids",      "Latency (ms)": 38, "Status": "200 OK"},
        ]), use_container_width=True, hide_index=True)

    with res_col:
        st.markdown("### Resource Usage")
        for label, val, color in [
            ("CPU Usage",    23, "#06b6d4"),
            ("Memory Usage", 67, "#f59e0b"),
            ("GPU Usage",     8, "#22c55e"),
            ("Disk I/O",     34, "#8b5cf6"),
        ]:
            st.markdown(
                f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.8rem;'
                f'color:#94a3b8;margin-bottom:3px;">{label} — '
                f'<b style="color:{color}">{val}%</b></div>',
                unsafe_allow_html=True,
            )
            st.progress(val / 100)
            st.markdown("<div style='height:4px'/>", unsafe_allow_html=True)

    st.markdown("<hr class='divider'/>", unsafe_allow_html=True)
    st.markdown("### Response Time Trend")
    rng3 = random.Random(77)
    hours     = list(range(24))
    latencies = [rng3.uniform(8, 22) for _ in hours]
    latencies[14] = 45
    latencies[18] = 38
    fig_lat = go.Figure()
    fig_lat.add_trace(go.Scatter(
        x=hours, y=latencies, mode="lines+markers",
        line=dict(color="#06b6d4", width=2),
        marker=dict(
            color=["#ef4444" if l > 35 else "#06b6d4" for l in latencies],
            size=5,
        ),
        fill="tozeroy",
        fillcolor="rgba(6,182,212,0.07)",
        name="Avg Latency (ms)",
    ))
    fig_lat.add_hline(y=30, line=dict(color="#f59e0b", dash="dash", width=1.5))
    fig_lat.update_layout(
        **_plotly_dark(240),
        xaxis=_axis(title="Hour of Day"),
        yaxis=_axis(title="Latency (ms)"),
    )
    st.plotly_chart(fig_lat, use_container_width=True)
