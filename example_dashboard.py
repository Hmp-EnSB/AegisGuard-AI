"""
AegisGuard Example Dashboard
Example showing how to use the AegisGuard API
"""
import streamlit as st
import requests
import plotly.graph_objects as go

# Configuration de la page
st.set_page_config(
    page_title="AegisGuard Demo",
    page_icon="🛡️",
    layout="wide"
)

# URL de l'API
API_URL = "http://localhost:8000"

# Titre
st.title("🛡️ AegisGuard - Example Dashboard")
st.markdown("**Example Dashboard** - How to use the AegisGuard API")

# Sidebar pour choisir le type de détection
detection_type = st.sidebar.selectbox(
    "Type de détection",
    ["Détection de Fraude", "Détection d'Intrusion Réseau"]
)

# ============================================
# 1. DÉTECTION DE FRAUDE
# ============================================
if detection_type == "Détection de Fraude":
    st.header("💳 Détection de Fraude Bancaire")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📥 Données de transaction")
        
        # Formulaire simplifié
        amount = st.number_input("Montant (€)", value=9800.0, min_value=0.0)
        time = st.number_input("Temps (secondes)", value=54000.0, min_value=0.0)
        
        st.info("Les features V1-V28 sont générées automatiquement pour la démo")
        
        # Bouton pour prédire
        if st.button("🔍 Analyser la transaction", type="primary"):
            # Créer le payload avec des valeurs par défaut pour V1-V28
            transaction = {
                "Time": time,
                "Amount": amount,
                "V1": -1.35, "V2": 0.5, "V3": 1.2, "V4": -0.8,
                "V5": 0.3, "V6": -0.6, "V7": 0.9, "V8": 0.1,
                "V9": -0.4, "V10": 0.7, "V11": -0.2, "V12": 0.5,
                "V13": 0.8, "V14": -0.3, "V15": 0.6, "V16": -0.1,
                "V17": 0.4, "V18": -0.7, "V19": 0.2, "V20": 0.9,
                "V21": -0.5, "V22": 0.3, "V23": -0.8, "V24": 0.1,
                "V25": 0.6, "V26": -0.4, "V27": 0.7, "V28": 0.02
            }
            
            try:
                # Appeler l'API de Hiba
                with st.spinner("Analyse en cours..."):
                    response = requests.post(
                        f"{API_URL}/predict/fraud",
                        json=transaction,
                        timeout=5
                    )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    with col2:
                        st.subheader("📊 Résultats de l'analyse")
                        
                        # Probabilité de fraude
                        fraud_prob = result['fraud_probability']
                        st.metric(
                            "Probabilité de fraude",
                            f"{fraud_prob:.1%}",
                            delta=None
                        )
                        
                        # Niveau de risque avec couleur
                        risk_level = result['risk_level']
                        risk_colors = {
                            "LOW": "🟢",
                            "MEDIUM": "🟡",
                            "HIGH": "🟠",
                            "CRITICAL": "🔴"
                        }
                        st.metric(
                            "Niveau de risque",
                            f"{risk_colors.get(risk_level, '')} {risk_level}"
                        )
                        
                        # Décision finale
                        decision = result['decision']
                        if decision == "FRAUD":
                            st.error(f"🚨 **FRAUDE DÉTECTÉE**")
                        else:
                            st.success(f"✅ **TRANSACTION LÉGITIME**")
                        
                        # Anomalie
                        if result['is_anomaly']:
                            st.warning("⚠️ Comportement anormal détecté")
                        
                        # Jauge de probabilité
                        fig = go.Figure(go.Indicator(
                            mode="gauge+number",
                            value=fraud_prob * 100,
                            title={'text': "Probabilité de fraude (%)"},
                            gauge={
                                'axis': {'range': [None, 100]},
                                'bar': {'color': "darkred"},
                                'steps': [
                                    {'range': [0, 30], 'color': "lightgreen"},
                                    {'range': [30, 60], 'color': "yellow"},
                                    {'range': [60, 85], 'color': "orange"},
                                    {'range': [85, 100], 'color': "red"}
                                ],
                                'threshold': {
                                    'line': {'color': "red", 'width': 4},
                                    'thickness': 0.75,
                                    'value': 50
                                }
                            }
                        ))
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Top 5 features SHAP
                        st.subheader("🔍 Top 5 indicateurs (SHAP)")
                        for feature_data in result['top_features']:
                            feature = feature_data['feature']
                            shap_val = feature_data['shap_value']
                            
                            # Barre de progression colorée
                            color = "red" if shap_val > 0 else "green"
                            st.markdown(f"**{feature}**: {shap_val:.4f}")
                            st.progress(min(abs(shap_val), 1.0))
                
                else:
                    st.error(f"❌ Erreur API: {response.status_code}")
                    st.json(response.json())
            
            except requests.exceptions.ConnectionError:
                st.error("❌ Impossible de se connecter à l'API. Assure-toi que l'API tourne sur http://localhost:8000")
            except requests.exceptions.Timeout:
                st.error("⏱️ Timeout - L'API met trop de temps à répondre")
            except Exception as e:
                st.error(f"❌ Erreur: {str(e)}")

# ============================================
# 2. DÉTECTION D'INTRUSION RÉSEAU
# ============================================
else:
    st.header("🌐 Détection d'Intrusion Réseau")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📥 Données de flux réseau")
        
        # Formulaire simplifié
        dest_port = st.number_input("Port de destination", value=80, min_value=0, max_value=65535)
        flow_duration = st.number_input("Durée du flux (ms)", value=120000, min_value=0)
        total_fwd_packets = st.number_input("Paquets forward", value=1500, min_value=0)
        total_bwd_packets = st.number_input("Paquets backward", value=50, min_value=0)
        
        st.info("Les 74 autres features CICIDS sont générées automatiquement pour la démo")
        
        # Bouton pour prédire
        if st.button("🔍 Analyser le flux réseau", type="primary"):
            # Créer le payload avec toutes les 78 features
            # (valeurs par défaut pour la démo)
            network_flow = {
                "features": {
                    "Destination Port": dest_port,
                    "Flow Duration": flow_duration,
                    "Total Fwd Packets": total_fwd_packets,
                    "Total Backward Packets": total_bwd_packets,
                    "Total Length of Fwd Packets": 90000,
                    "Total Length of Bwd Packets": 3000,
                    "Fwd Packet Length Max": 1500,
                    "Fwd Packet Length Min": 40,
                    "Fwd Packet Length Mean": 60,
                    "Fwd Packet Length Std": 15,
                    "Bwd Packet Length Max": 100,
                    "Bwd Packet Length Min": 40,
                    "Bwd Packet Length Mean": 60,
                    "Bwd Packet Length Std": 10,
                    "Flow Bytes/s": 750,
                    "Flow Packets/s": 12.5,
                    "Flow IAT Mean": 80,
                    "Flow IAT Std": 20,
                    "Flow IAT Max": 500,
                    "Flow IAT Min": 10,
                    "Fwd IAT Total": 120000,
                    "Fwd IAT Mean": 80,
                    "Fwd IAT Std": 20,
                    "Fwd IAT Max": 500,
                    "Fwd IAT Min": 10,
                    "Bwd IAT Total": 120000,
                    "Bwd IAT Mean": 2400,
                    "Bwd IAT Std": 500,
                    "Bwd IAT Max": 5000,
                    "Bwd IAT Min": 100,
                    "Fwd PSH Flags": 0,
                    "Bwd PSH Flags": 0,
                    "Fwd URG Flags": 0,
                    "Bwd URG Flags": 0,
                    "Fwd Header Length": 30000,
                    "Bwd Header Length": 1000,
                    "Fwd Packets/s": 12.5,
                    "Bwd Packets/s": 0.4,
                    "Min Packet Length": 40,
                    "Max Packet Length": 1500,
                    "Packet Length Mean": 60,
                    "Packet Length Std": 15,
                    "Packet Length Variance": 225,
                    "FIN Flag Count": 0,
                    "SYN Flag Count": 1500,
                    "RST Flag Count": 0,
                    "PSH Flag Count": 0,
                    "ACK Flag Count": 50,
                    "URG Flag Count": 0,
                    "CWE Flag Count": 0,
                    "ECE Flag Count": 0,
                    "Down/Up Ratio": 30,
                    "Average Packet Size": 60,
                    "Avg Fwd Segment Size": 60,
                    "Avg Bwd Segment Size": 60,
                    "Fwd Header Length.1": 30000,
                    "Fwd Avg Bytes/Bulk": 0,
                    "Fwd Avg Packets/Bulk": 0,
                    "Fwd Avg Bulk Rate": 0,
                    "Bwd Avg Bytes/Bulk": 0,
                    "Bwd Avg Packets/Bulk": 0,
                    "Bwd Avg Bulk Rate": 0,
                    "Subflow Fwd Packets": 1500,
                    "Subflow Fwd Bytes": 90000,
                    "Subflow Bwd Packets": 50,
                    "Subflow Bwd Bytes": 3000,
                    "Init_Win_bytes_forward": 8192,
                    "Init_Win_bytes_backward": 8192,
                    "act_data_pkt_fwd": 1500,
                    "min_seg_size_forward": 20,
                    "Active Mean": 1000,
                    "Active Std": 200,
                    "Active Max": 2000,
                    "Active Min": 500,
                    "Idle Mean": 100,
                    "Idle Std": 20,
                    "Idle Max": 200,
                    "Idle Min": 50
                }
            }
            
            try:
                # Appeler l'API de Hiba
                with st.spinner("Analyse en cours..."):
                    response = requests.post(
                        f"{API_URL}/predict/threat",
                        json=network_flow,
                        timeout=5
                    )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    with col2:
                        st.subheader("📊 Résultats de l'analyse")
                        
                        # Type de menace
                        threat_class = result['threat_class']
                        confidence = result['confidence']
                        severity = result['severity']
                        
                        # Badge de menace
                        threat_icons = {
                            "BENIGN": "✅",
                            "DDoS": "🔴",
                            "PortScan": "🔍",
                            "Bot": "🤖",
                            "DoS Hulk": "💥",
                            "Heartbleed": "💔"
                        }
                        icon = threat_icons.get(threat_class, "⚠️")
                        
                        st.metric(
                            "Type de menace",
                            f"{icon} {threat_class}"
                        )
                        
                        st.metric(
                            "Confiance",
                            f"{confidence:.1%}"
                        )
                        
                        # Sévérité avec couleur
                        severity_colors = {
                            "LOW": "🟢",
                            "MEDIUM": "🟡",
                            "HIGH": "🟠",
                            "CRITICAL": "🔴"
                        }
                        st.metric(
                            "Sévérité",
                            f"{severity_colors.get(severity, '')} {severity}"
                        )
                        
                        # Alerte selon sévérité
                        if severity == "CRITICAL":
                            st.error("🚨 **MENACE CRITIQUE DÉTECTÉE**")
                        elif severity == "HIGH":
                            st.warning("⚠️ **MENACE ÉLEVÉE**")
                        elif threat_class == "BENIGN":
                            st.success("✅ **TRAFIC NORMAL**")
                        
                        # Anomalie zero-day
                        if result['is_anomaly']:
                            st.warning("🔍 Anomalie zero-day détectée")
                        
                        # Jauge de confiance
                        fig = go.Figure(go.Indicator(
                            mode="gauge+number",
                            value=confidence * 100,
                            title={'text': "Confiance (%)"},
                            gauge={
                                'axis': {'range': [None, 100]},
                                'bar': {'color': "darkblue"},
                                'steps': [
                                    {'range': [0, 50], 'color': "lightgray"},
                                    {'range': [50, 75], 'color': "yellow"},
                                    {'range': [75, 100], 'color': "lightgreen"}
                                ]
                            }
                        ))
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Top 5 indicateurs SHAP
                        st.subheader("🔍 Top 5 indicateurs d'attaque (SHAP)")
                        for feature_data in result['top_features']:
                            feature = feature_data['feature']
                            shap_val = feature_data['shap_value']
                            
                            st.markdown(f"**{feature}**: {shap_val:.4f}")
                            st.progress(min(abs(shap_val), 1.0))
                
                else:
                    st.error(f"❌ Erreur API: {response.status_code}")
                    st.json(response.json())
            
            except requests.exceptions.ConnectionError:
                st.error("❌ Impossible de se connecter à l'API. Assure-toi que l'API tourne sur http://localhost:8000")
            except requests.exceptions.Timeout:
                st.error("⏱️ Timeout - L'API met trop de temps à répondre")
            except Exception as e:
                st.error(f"❌ Erreur: {str(e)}")

# ============================================
# FOOTER
# ============================================
st.sidebar.markdown("---")
st.sidebar.markdown("### 📖 Documentation")
st.sidebar.markdown("[API Docs](http://localhost:8000/docs)")
st.sidebar.markdown("[Health Check](http://localhost:8000/health)")

st.sidebar.markdown("---")
st.sidebar.info("""
**Comment ça marche ?**

1. L'API de Hiba tourne sur localhost:8000
2. Ce dashboard fait des requêtes POST vers l'API
3. L'API retourne les prédictions en JSON
4. Le dashboard affiche les résultats

**Source code:** Check `example_dashboard.py` to see how to call the API!
""")
